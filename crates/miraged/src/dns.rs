//! Privacy-preserving RFC 1035 DNS client and RAM-only bounded TTL cache.
//!
//! Sends queries exclusively to the configured local recursive resolver
//! (zero EDNS Client Subnet / ECS) unless explicit system DNS fallback is
//! enabled, and never writes DNS state or hostnames to disk.

use core::time::Duration;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Instant;

use tokio::net::UdpSocket;

/// Maximum DNS entries cached in RAM before pruning/evicting stale items.
const MAX_DNS_CACHE_ENTRIES: usize = 4_096;

/// Per-query timeout when contacting the configured local recursive resolver.
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum RFC 1035 UDP response packet size.
const MAX_DNS_UDP_PACKET: usize = 4096;

#[derive(Clone)]
struct CachedDnsEntry {
    ips: Vec<IpAddr>,
    expires_at: Instant,
}

/// Private DNS resolver with RAM-only bounded TTL cache.
pub struct DnsResolver {
    resolver_addr: SocketAddr,
    allow_system_dns: bool,
    cache: Mutex<HashMap<String, CachedDnsEntry>>,
}

impl DnsResolver {
    /// Creates a new DNS resolver targeting `resolver_addr` (e.g. a local
    /// `unbound` container with QNAME minimization and ECS disabled).
    #[must_use]
    pub fn new(resolver_addr: SocketAddr, allow_system_dns: bool) -> Self {
        Self {
            resolver_addr,
            allow_system_dns,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Resolves `domain` to one or more `IpAddr`s without leaking ECS.
    pub async fn resolve(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let key = domain.to_ascii_lowercase();
        let now = Instant::now();

        {
            let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = guard.get(&key) {
                if entry.expires_at > now {
                    return Some(entry.ips.clone());
                }
            }
            guard.remove(&key);
        }

        let resolved = if let Some(ips) = self.query_rfc1035(&key).await {
            Some(ips)
        } else if self.allow_system_dns {
            resolve_via_system(&key).await
        } else {
            None
        };

        if let Some((ips, ttl_secs)) = resolved {
            if !ips.is_empty() {
                let bounded_ttl = ttl_secs.clamp(5, 3600);
                let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
                if guard.len() >= MAX_DNS_CACHE_ENTRIES {
                    guard.retain(|_, v| v.expires_at > now);
                    if guard.len() >= MAX_DNS_CACHE_ENTRIES {
                        // Evict only the soonest-to-expire entry rather than wiping the whole cache.
                        if let Some(oldest_key) = guard
                            .iter()
                            .min_by_key(|(_, v)| v.expires_at)
                            .map(|(k, _)| k.clone())
                        {
                            guard.remove(&oldest_key);
                        }
                    }
                }
                if let Some(expires_at) =
                    now.checked_add(Duration::from_secs(u64::from(bounded_ttl)))
                {
                    guard.insert(
                        key,
                        CachedDnsEntry {
                            ips: ips.clone(),
                            expires_at,
                        },
                    );
                }
                return Some(ips);
            }
        }

        None
    }

    async fn query_rfc1035(&self, domain: &str) -> Option<(Vec<IpAddr>, u32)> {
        let mut out_ips = Vec::new();
        let mut min_ttl = u32::MAX;

        // Query A (1) and AAAA (28) concurrently against the private recursive resolver.
        let (a_res, aaaa_res) = tokio::join!(
            query_single_rr(self.resolver_addr, domain, 1),
            query_single_rr(self.resolver_addr, domain, 28)
        );

        if let Some((ips, ttl)) = a_res {
            out_ips.extend(ips);
            min_ttl = min_ttl.min(ttl);
        }
        if let Some((ips, ttl)) = aaaa_res {
            out_ips.extend(ips);
            min_ttl = min_ttl.min(ttl);
        }

        if out_ips.is_empty() {
            None
        } else {
            Some((out_ips, if min_ttl == u32::MAX { 60 } else { min_ttl }))
        }
    }
}

async fn resolve_via_system(domain: &str) -> Option<(Vec<IpAddr>, u32)> {
    let addrs = tokio::time::timeout(DNS_QUERY_TIMEOUT, tokio::net::lookup_host((domain, 0u16)))
        .await
        .ok()?
        .ok()?;
    let ips: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
    if ips.is_empty() {
        None
    } else {
        Some((ips, 60))
    }
}

async fn query_single_rr(
    resolver_addr: SocketAddr,
    domain: &str,
    qtype: u16,
) -> Option<(Vec<IpAddr>, u32)> {
    let mut tx_bytes = [0u8; 2];
    getrandom::fill(&mut tx_bytes).ok()?;
    let tx_id = u16::from_be_bytes(tx_bytes);

    let packet = build_dns_query(tx_id, domain, qtype)?;
    let bind_addr = if resolver_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind_addr).await.ok()?;
    sock.connect(resolver_addr).await.ok()?;
    sock.send(&packet).await.ok()?;

    let mut resp = [0u8; MAX_DNS_UDP_PACKET];
    let n = tokio::time::timeout(DNS_QUERY_TIMEOUT, sock.recv(&mut resp))
        .await
        .ok()?
        .ok()?;
    let slice = resp.get(..n)?;
    // Verify the echoed Question section matches our query packet (case-insensitive).
    let expected_question = packet.get(12..)?;
    let echoed_question = slice.get(12..packet.len())?;
    if !echoed_question.eq_ignore_ascii_case(expected_question) {
        return None;
    }
    parse_dns_response(slice, tx_id)
}

/// Encodes an RFC 1035 DNS query packet with RD=1 and NO EDNS/ECS options.
#[must_use]
pub fn build_dns_query(tx_id: u16, domain: &str, qtype: u16) -> Option<Vec<u8>> {
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Standard query, RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        let len_u8 = u8::try_from(label.len()).ok()?;
        pkt.push(len_u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // Root label
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    Some(pkt)
}

/// Parses `A` and `AAAA` answers from an RFC 1035 DNS response packet.
#[must_use]
pub fn parse_dns_response(pkt: &[u8], expected_tx_id: u16) -> Option<(Vec<IpAddr>, u32)> {
    if pkt.len() < 12 {
        return None;
    }
    let tx_id = u16::from_be_bytes([*pkt.first()?, *pkt.get(1)?]);
    if tx_id != expected_tx_id {
        return None;
    }
    let flags = u16::from_be_bytes([*pkt.get(2)?, *pkt.get(3)?]);
    // QR must be 1 (response), TC (bit 9) must be 0 (not truncated), RCODE (low 4 bits) must be 0 (NOERROR)
    if (flags & 0x8000) == 0 || (flags & 0x0200) != 0 || (flags & 0x000F) != 0 {
        return None;
    }

    let qdcount = usize::from(u16::from_be_bytes([*pkt.get(4)?, *pkt.get(5)?]));
    let ancount = usize::from(u16::from_be_bytes([*pkt.get(6)?, *pkt.get(7)?]));
    if qdcount != 1 {
        return None;
    }

    let mut offset = 12usize;
    for _ in 0..qdcount {
        offset = skip_dns_name(pkt, offset)?;
        offset = offset.checked_add(4)?;
        if offset > pkt.len() {
            return None;
        }
    }

    let mut ips = Vec::new();
    let mut min_ttl = u32::MAX;

    for _ in 0..ancount {
        offset = skip_dns_name(pkt, offset)?;
        let hdr = pkt.get(offset..offset.checked_add(10)?)?;
        let rtype = u16::from_be_bytes([*hdr.first()?, *hdr.get(1)?]);
        let rclass = u16::from_be_bytes([*hdr.get(2)?, *hdr.get(3)?]);
        let ttl = u32::from_be_bytes([*hdr.get(4)?, *hdr.get(5)?, *hdr.get(6)?, *hdr.get(7)?]);
        let rdlength = usize::from(u16::from_be_bytes([*hdr.get(8)?, *hdr.get(9)?]));
        offset = offset.checked_add(10)?;

        let rdata_end = offset.checked_add(rdlength)?;
        let rdata = pkt.get(offset..rdata_end)?;
        offset = rdata_end;

        if rclass == 1 {
            if rtype == 1 && rdlength == 4 {
                let ip = Ipv4Addr::new(
                    *rdata.first()?,
                    *rdata.get(1)?,
                    *rdata.get(2)?,
                    *rdata.get(3)?,
                );
                ips.push(IpAddr::V4(ip));
                min_ttl = min_ttl.min(ttl);
            } else if rtype == 28 && rdlength == 16 {
                let mut raw = [0u8; 16];
                raw.copy_from_slice(rdata);
                ips.push(IpAddr::V6(Ipv6Addr::from(raw)));
                min_ttl = min_ttl.min(ttl);
            }
        }
    }

    if ips.is_empty() {
        None
    } else {
        Some((ips, if min_ttl == u32::MAX { 60 } else { min_ttl }))
    }
}

fn skip_dns_name(pkt: &[u8], start: usize) -> Option<usize> {
    let mut idx = start;
    for _ in 0..128 {
        let b = *pkt.get(idx)?;
        if b == 0 {
            return idx.checked_add(1);
        }
        if (b & 0xC0) == 0xC0 {
            // Compression pointer consumes 2 bytes at current position and must point backwards >= 12.
            let b2 = *pkt.get(idx.checked_add(1)?)?;
            let ptr_offset = usize::from(u16::from_be_bytes([b & 0x3F, b2]));
            if ptr_offset < 12 || ptr_offset >= idx {
                return None;
            }
            let next = idx.checked_add(2)?;
            return if next <= pkt.len() { Some(next) } else { None };
        }
        if (b & 0xC0) != 0 {
            return None;
        }
        let label_len = usize::from(b);
        idx = idx.checked_add(1)?.checked_add(label_len)?;
        if idx > pkt.len() {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_parses_rfc1035_dns_packet() {
        let q = build_dns_query(0x1234, "example.com", 1);
        assert!(q.is_some());
        let Some(query) = q else { return };

        // Construct a minimal response with compression pointer 0xC00C -> A 93.184.216.34
        let mut resp = query.clone();
        if let Some(flags) = resp.get_mut(2..4) {
            flags.copy_from_slice(&0x8180u16.to_be_bytes());
        }
        if let Some(ancount) = resp.get_mut(6..8) {
            ancount.copy_from_slice(&1u16.to_be_bytes());
        }
        resp.extend_from_slice(&[0xC0, 0x0C]); // Name pointer
        resp.extend_from_slice(&1u16.to_be_bytes()); // A
        resp.extend_from_slice(&1u16.to_be_bytes()); // IN
        resp.extend_from_slice(&300u32.to_be_bytes()); // TTL 300s
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLEN 4
        resp.extend_from_slice(&[93, 184, 216, 34]);

        let parsed = parse_dns_response(&resp, 0x1234);
        assert_eq!(
            parsed,
            Some((vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))], 300))
        );

        // Truncated (TC=1, 0x0200) DNS response must be rejected.
        let mut tc_resp = resp.clone();
        if let Some(flags) = tc_resp.get_mut(2..4) {
            flags.copy_from_slice(&0x8380u16.to_be_bytes());
        }
        assert!(parse_dns_response(&tc_resp, 0x1234).is_none());

        // Forward/self compression pointer (pointing to offset >= current idx) must be rejected.
        let mut loop_resp = query;
        if let Some(flags) = loop_resp.get_mut(2..4) {
            flags.copy_from_slice(&0x8180u16.to_be_bytes());
        }
        if let Some(ancount) = loop_resp.get_mut(6..8) {
            ancount.copy_from_slice(&1u16.to_be_bytes());
        }
        let self_offset = u16::try_from(loop_resp.len()).unwrap_or(0);
        loop_resp.extend_from_slice(&(0xC000u16 | self_offset).to_be_bytes());
        loop_resp.extend_from_slice(&1u16.to_be_bytes());
        loop_resp.extend_from_slice(&1u16.to_be_bytes());
        loop_resp.extend_from_slice(&60u32.to_be_bytes());
        loop_resp.extend_from_slice(&4u16.to_be_bytes());
        loop_resp.extend_from_slice(&[1, 2, 3, 4]);
        assert!(parse_dns_response(&loop_resp, 0x1234).is_none());
    }
}
