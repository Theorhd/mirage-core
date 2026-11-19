//! Privacy-preserving RFC 1035 DNS client and RAM-only bounded TTL cache.
//!
//! Features:
//! - Zero EDNS Client Subnet (ECS) and zero disk persistence.
//! - RFC 8305-style early-return A/AAAA family racing (50 ms grace window after
//!   the first family answers so a slow/broken IPv6 path never stalls IPv4 for 2s).
//! - Stale-While-Revalidate (serve-stale for up to 60s with background refresh)
//!   so short-TTL video CDNs never trigger foreground DNS pauses.
//! - Singleflight coalescing to deduplicate concurrent lookups for the same host.
//! - Short negative caching (5s) to absorb repeated failures on dead hosts.

use core::time::Duration;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::watch;

/// Maximum DNS entries cached in RAM before pruning/evicting stale items.
const MAX_DNS_CACHE_ENTRIES: usize = 4_096;

/// Per-query timeout when contacting the configured local recursive resolver.
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// RFC 8305 Resolution Delay: max time to wait for the second address family
/// (`AAAA` or `A`) once the first family has already answered.
const DNS_FAMILY_RACE_GRACE: Duration = Duration::from_millis(50);

/// Duration after TTL expiry during which cached IPs can still be served
/// immediately while a deduplicated background refresh runs.
const DNS_STALE_WINDOW: Duration = Duration::from_secs(60);

/// Short negative cache TTL for failed lookups (prevents repeated 2s stalls).
const DNS_NEGATIVE_TTL: Duration = Duration::from_secs(5);

/// Maximum RFC 1035 UDP response packet size.
const MAX_DNS_UDP_PACKET: usize = 4096;

#[derive(Clone)]
struct CachedDnsEntry {
    ips: Vec<IpAddr>,
    fresh_until: Instant,
    stale_until: Instant,
}

type InFlightTx = watch::Sender<Option<Option<Vec<IpAddr>>>>;

struct DnsInner {
    resolver_addr: SocketAddr,
    allow_system_dns: bool,
    cache: Mutex<HashMap<String, CachedDnsEntry>>,
    in_flight: Mutex<HashMap<String, InFlightTx>>,
}

struct InFlightGuard {
    inner: Arc<DnsInner>,
    key: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let mut guard = self
            .inner
            .in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard.remove(&self.key);
    }
}

/// Private DNS resolver with RAM-only bounded TTL cache, serve-stale refresh,
/// early-return A/AAAA racing, and singleflight coalescing.
#[derive(Clone)]
pub struct DnsResolver {
    inner: Arc<DnsInner>,
}

impl DnsResolver {
    /// Creates a new DNS resolver targeting `resolver_addr` (e.g. a local
    /// `unbound` container with QNAME minimization and ECS disabled).
    #[must_use]
    pub fn new(resolver_addr: SocketAddr, allow_system_dns: bool) -> Self {
        Self {
            inner: Arc::new(DnsInner {
                resolver_addr,
                allow_system_dns,
                cache: Mutex::new(HashMap::new()),
                in_flight: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Synchronous RAM-only cache probe (returns fresh or serve-stale entries
    /// without blocking on network I/O; triggers a background refresh on stale hit).
    #[must_use]
    pub fn lookup_cached(&self, domain: &str, v4_only: bool) -> Option<Vec<IpAddr>> {
        let domain_lower = domain.to_ascii_lowercase();
        let key = cache_key(&domain_lower, v4_only);
        let now = Instant::now();
        let entry = {
            let guard = self.inner.cache.lock().unwrap_or_else(|e| e.into_inner());
            guard.get(&key).cloned()
        }?;

        if entry.ips.is_empty() {
            return None;
        }
        if entry.fresh_until > now {
            return Some(entry.ips);
        }
        if entry.stale_until > now {
            self.spawn_background_refresh(domain_lower, key, v4_only);
            return Some(entry.ips);
        }
        None
    }

    /// Resolves `domain` to one or more `IpAddr`s without leaking ECS.
    pub async fn resolve(&self, domain: &str) -> Option<Vec<IpAddr>> {
        self.resolve_for_strategy(domain, false).await
    }

    /// Resolves `domain`, skipping `AAAA` queries when `v4_only` is `true`.
    pub async fn resolve_for_strategy(&self, domain: &str, v4_only: bool) -> Option<Vec<IpAddr>> {
        let domain_lower = domain.to_ascii_lowercase();
        let key = cache_key(&domain_lower, v4_only);
        let now = Instant::now();

        {
            let mut guard = self.inner.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = guard.get(&key) {
                if entry.fresh_until > now {
                    return if entry.ips.is_empty() {
                        None
                    } else {
                        Some(entry.ips.clone())
                    };
                }
                if entry.stale_until > now && !entry.ips.is_empty() {
                    let ips = entry.ips.clone();
                    drop(guard);
                    self.spawn_background_refresh(domain_lower, key, v4_only);
                    return Some(ips);
                }
            }
            guard.remove(&key);
        }

        // Singleflight: coalesce concurrent misses for the exact same cache key.
        let maybe_waiter = {
            let mut flight = self
                .inner
                .in_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = flight.get(&key) {
                Some(tx.subscribe())
            } else {
                let (tx, _rx) = watch::channel(None);
                flight.insert(key.clone(), tx);
                None
            }
        };

        if let Some(mut rx) = maybe_waiter {
            if rx.borrow().is_none() {
                let _ = rx.changed().await;
            }
            if let Some(result) = rx.borrow().clone() {
                return result;
            }
            // Leader was cancelled before publishing; fall through and perform a direct lookup.
            return self.execute_lookup(&domain_lower, &key, v4_only).await;
        }

        let _guard = InFlightGuard {
            inner: Arc::clone(&self.inner),
            key: key.clone(),
        };
        let result = self.execute_lookup(&domain_lower, &key, v4_only).await;

        let tx_opt = {
            let mut flight = self
                .inner
                .in_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            flight.remove(&key)
        };
        if let Some(tx) = tx_opt {
            let _ = tx.send(Some(result.clone()));
        }

        result
    }

    fn spawn_background_refresh(&self, domain_lower: String, key: String, v4_only: bool) {
        let should_spawn = {
            let mut flight = self
                .inner
                .in_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if flight.contains_key(&key) {
                false
            } else {
                let (tx, _rx) = watch::channel(None);
                flight.insert(key.clone(), tx);
                true
            }
        };
        if !should_spawn {
            return;
        }

        let resolver = self.clone();
        tokio::spawn(async move {
            let _guard = InFlightGuard {
                inner: Arc::clone(&resolver.inner),
                key: key.clone(),
            };
            let result = resolver.execute_lookup(&domain_lower, &key, v4_only).await;
            let tx_opt = {
                let mut flight = resolver
                    .inner
                    .in_flight
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                flight.remove(&key)
            };
            if let Some(tx) = tx_opt {
                let _ = tx.send(Some(result));
            }
        });
    }

    async fn execute_lookup(
        &self,
        domain_lower: &str,
        key: &str,
        v4_only: bool,
    ) -> Option<Vec<IpAddr>> {
        let resolved = if let Some(ips) = self.query_rfc1035(domain_lower, v4_only).await {
            Some(ips)
        } else if self.inner.allow_system_dns {
            resolve_via_system(domain_lower, v4_only).await
        } else {
            None
        };

        let now = Instant::now();
        if let Some((ips, ttl_secs)) = resolved {
            if !ips.is_empty() {
                let bounded_ttl = ttl_secs.clamp(5, 3600);
                if let Some(fresh_until) =
                    now.checked_add(Duration::from_secs(u64::from(bounded_ttl)))
                {
                    let stale_until = fresh_until
                        .checked_add(DNS_STALE_WINDOW)
                        .unwrap_or(fresh_until);
                    self.insert_cache_entry(
                        key.to_string(),
                        CachedDnsEntry {
                            ips: ips.clone(),
                            fresh_until,
                            stale_until,
                        },
                        now,
                    );
                }
                return Some(ips);
            }
        }

        // Negative cache to prevent repeated 2s stalls on unresolvable domains.
        if let Some(neg_until) = now.checked_add(DNS_NEGATIVE_TTL) {
            self.insert_cache_entry(
                key.to_string(),
                CachedDnsEntry {
                    ips: Vec::new(),
                    fresh_until: neg_until,
                    stale_until: neg_until,
                },
                now,
            );
        }
        None
    }

    fn insert_cache_entry(&self, key: String, entry: CachedDnsEntry, now: Instant) {
        let mut guard = self.inner.cache.lock().unwrap_or_else(|e| e.into_inner());
        // RFC 8767 serve-stale: never overwrite a still-valid stale entry with a negative
        // lookup result on transient upstream packet loss; simply back off the next refresh.
        if entry.ips.is_empty() {
            if let Some(existing) = guard.get_mut(&key) {
                if !existing.ips.is_empty() && existing.stale_until > now {
                    existing.fresh_until = entry.fresh_until.min(existing.stale_until);
                    return;
                }
            }
        }
        if guard.len() >= MAX_DNS_CACHE_ENTRIES {
            guard.retain(|_, v| v.stale_until > now);
            if guard.len() >= MAX_DNS_CACHE_ENTRIES {
                if let Some(oldest_key) = guard
                    .iter()
                    .min_by_key(|(_, v)| v.stale_until)
                    .map(|(k, _)| k.clone())
                {
                    guard.remove(&oldest_key);
                }
            }
        }
        guard.insert(key, entry);
    }

    async fn query_rfc1035(&self, domain: &str, v4_only: bool) -> Option<(Vec<IpAddr>, u32)> {
        if v4_only {
            return query_single_rr(self.inner.resolver_addr, domain, 1).await;
        }

        let mut out_ips = Vec::new();
        let mut min_ttl = u32::MAX;

        // Race A (1) and AAAA (28) concurrently with an RFC 8305 early-return
        // grace window (50 ms) once the first family yields usable IPs.
        let a_fut = query_single_rr(self.inner.resolver_addr, domain, 1);
        let aaaa_fut = query_single_rr(self.inner.resolver_addr, domain, 28);
        tokio::pin!(a_fut);
        tokio::pin!(aaaa_fut);

        tokio::select! {
            a_res = &mut a_fut => {
                if let Some((ips, ttl)) = a_res {
                    out_ips.extend(ips);
                    min_ttl = min_ttl.min(ttl);
                    if let Ok(Some((ips6, ttl6))) = tokio::time::timeout(DNS_FAMILY_RACE_GRACE, &mut aaaa_fut).await {
                        out_ips.extend(ips6);
                        min_ttl = min_ttl.min(ttl6);
                    }
                } else if let Some((ips6, ttl6)) = aaaa_fut.await {
                    out_ips.extend(ips6);
                    min_ttl = min_ttl.min(ttl6);
                }
            }
            aaaa_res = &mut aaaa_fut => {
                if let Some((ips6, ttl6)) = aaaa_res {
                    out_ips.extend(ips6);
                    min_ttl = min_ttl.min(ttl6);
                    if let Ok(Some((ips4, ttl4))) = tokio::time::timeout(DNS_FAMILY_RACE_GRACE, &mut a_fut).await {
                        out_ips.extend(ips4);
                        min_ttl = min_ttl.min(ttl4);
                    }
                } else if let Some((ips4, ttl4)) = a_fut.await {
                    out_ips.extend(ips4);
                    min_ttl = min_ttl.min(ttl4);
                }
            }
        }

        if out_ips.is_empty() {
            None
        } else {
            Some((out_ips, if min_ttl == u32::MAX { 60 } else { min_ttl }))
        }
    }
}

fn cache_key(domain_lower: &str, v4_only: bool) -> String {
    if v4_only {
        format!("4:{domain_lower}")
    } else {
        domain_lower.to_string()
    }
}

async fn resolve_via_system(domain: &str, v4_only: bool) -> Option<(Vec<IpAddr>, u32)> {
    let addrs = tokio::time::timeout(DNS_QUERY_TIMEOUT, tokio::net::lookup_host((domain, 0u16)))
        .await
        .ok()?
        .ok()?;
    let ips: Vec<IpAddr> = addrs
        .map(|sa| sa.ip())
        .filter(|ip| !v4_only || ip.is_ipv4())
        .collect();
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

    #[tokio::test]
    async fn early_return_and_singleflight_prevent_aaaa_stalls() {
        use core::sync::atomic::{AtomicUsize, Ordering};

        let Ok(mock_sock) = UdpSocket::bind("127.0.0.1:0").await else {
            return;
        };
        let Ok(mock_addr) = mock_sock.local_addr() else {
            return;
        };
        let a_queries = Arc::new(AtomicUsize::new(0));
        let a_queries_srv = Arc::clone(&a_queries);

        let srv = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, peer)) = mock_sock.recv_from(&mut buf).await else {
                    break;
                };
                let Some(req) = buf.get(..n) else {
                    continue;
                };
                if req.len() < 16 {
                    continue;
                }
                // QTYPE is the 2nd-to-last u16 in a standard question section.
                let qtype_off = req.len().saturating_sub(4);
                let qtype = match (req.get(qtype_off), req.get(qtype_off.saturating_add(1))) {
                    (Some(&b0), Some(&b1)) => u16::from_be_bytes([b0, b1]),
                    _ => continue,
                };
                if qtype == 1 {
                    a_queries_srv.fetch_add(1, Ordering::Relaxed);
                    // Simulate a brief 20ms upstream latency so concurrent callers coalesce.
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    let mut resp = req.to_vec();
                    if let Some(flags) = resp.get_mut(2..4) {
                        flags.copy_from_slice(&0x8180u16.to_be_bytes());
                    }
                    if let Some(ancount) = resp.get_mut(6..8) {
                        ancount.copy_from_slice(&1u16.to_be_bytes());
                    }
                    resp.extend_from_slice(&[0xC0, 0x0C]);
                    resp.extend_from_slice(&1u16.to_be_bytes());
                    resp.extend_from_slice(&1u16.to_be_bytes());
                    resp.extend_from_slice(&120u32.to_be_bytes());
                    resp.extend_from_slice(&4u16.to_be_bytes());
                    resp.extend_from_slice(&[93, 184, 216, 34]);
                    let _ = mock_sock.send_to(&resp, peer).await;
                }
                // Intentionally drop AAAA (qtype == 28) to simulate broken/blackholed IPv6 DNS.
            }
        });

        let resolver = DnsResolver::new(mock_addr, false);
        let start = Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let r = resolver.clone();
            tasks.push(tokio::spawn(async move {
                r.resolve("video-cdn.example.com").await
            }));
        }
        for t in tasks {
            let res = t.await;
            assert!(res.is_ok());
            if let Ok(ips) = res {
                assert_eq!(ips, Some(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]));
            }
        }
        let elapsed = start.elapsed();
        // Early-return (50ms grace) + 20ms mock reply must finish far faster than the 2s timeout!
        assert!(
            elapsed < Duration::from_millis(500),
            "DNS early-return stalled unexpectedly: {elapsed:?}"
        );
        // Singleflight must coalesce all 8 concurrent callers into a single A query.
        assert_eq!(a_queries.load(Ordering::Relaxed), 1);
        assert!(resolver
            .lookup_cached("video-cdn.example.com", false)
            .is_some());
        // Case-insensitive synchronous cache lookup must also hit.
        assert_eq!(
            resolver.lookup_cached("Video-CDN.Example.COM", false),
            Some(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
        );

        srv.abort();
    }
}
