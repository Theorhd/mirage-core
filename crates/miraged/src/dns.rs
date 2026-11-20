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

use mirage_core::egress::is_valid_domain;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{watch, Semaphore};

/// Maximum DNS entries cached in RAM before pruning/evicting stale items.
const MAX_DNS_CACHE_ENTRIES: usize = 4_096;

/// Maximum concurrent background serve-stale refreshes (`SEC-12`).
const MAX_BACKGROUND_DNS_REFRESHES: usize = 32;

/// Maximum concurrent in-flight DNS queries across the resolver (`SEC-12`).
const MAX_IN_FLIGHT_DNS_QUERIES: usize = 256;

/// Opportunistic cache sweep interval so stale entries do not linger at low traffic (`SEC-42`).
const CACHE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

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

/// Maximum RFC 1035 / EDNS0 UDP response packet size.
const MAX_DNS_UDP_PACKET: usize = 4096;

/// Maximum DNS-over-TCP response message size (`16 KiB`).
const MAX_DNS_TCP_PACKET: usize = 16 * 1024;

/// EDNS0 UDP payload size advertised in OPT RR (`1232` bytes per DNS Flag Day 2020).
const EDNS0_UDP_PAYLOAD_SIZE: u16 = 1232;

/// Synchronous RAM-only DNS cache lookup result.
#[derive(Debug, Clone)]
pub enum CachedLookup {
    /// Fresh or serve-stale IPs found in RAM.
    Hit(Arc<[IpAddr]>),
    /// Active negative cache hit (unresolvable domain; do not spawn background work).
    NegativeHit,
    /// Cache miss (requires asynchronous resolution).
    Miss,
}

#[derive(Clone)]
struct CachedDnsEntry {
    ips: Arc<[IpAddr]>,
    fresh_until: Instant,
    stale_until: Instant,
}

struct DnsCache {
    entries: HashMap<String, CachedDnsEntry>,
    last_sweep: Instant,
}

impl DnsCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            last_sweep: Instant::now(),
        }
    }

    fn sweep_if_due(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_sweep) >= CACHE_SWEEP_INTERVAL {
            self.entries.retain(|_, v| v.stale_until > now);
            self.last_sweep = now;
        }
    }
}

type InFlightTx = watch::Sender<Option<Option<Arc<[IpAddr]>>>>;

struct DnsInner {
    resolver_addr: SocketAddr,
    allow_system_dns: bool,
    cache: Mutex<DnsCache>,
    in_flight: Mutex<HashMap<String, InFlightTx>>,
    refresh_sem: Arc<Semaphore>,
    in_flight_sem: Arc<Semaphore>,
}

struct InFlightGuard {
    inner: Arc<DnsInner>,
    key: String,
    disarmed: bool,
}

impl InFlightGuard {
    fn complete(mut self, result: Option<Arc<[IpAddr]>>) {
        self.disarmed = true;
        let tx_opt = {
            let mut flight = self
                .inner
                .in_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            flight.remove(&self.key)
        };
        if let Some(tx) = tx_opt {
            let _ = tx.send(Some(result));
        }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        let tx_opt = {
            let mut flight = self
                .inner
                .in_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            flight.remove(&self.key)
        };
        if let Some(tx) = tx_opt {
            let _ = tx.send(Some(None));
        }
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
                cache: Mutex::new(DnsCache::new()),
                in_flight: Mutex::new(HashMap::new()),
                refresh_sem: Arc::new(Semaphore::new(MAX_BACKGROUND_DNS_REFRESHES)),
                in_flight_sem: Arc::new(Semaphore::new(MAX_IN_FLIGHT_DNS_QUERIES)),
            }),
        }
    }

    /// Synchronous RAM-only cache probe (returns fresh or serve-stale entries
    /// without blocking on network I/O; triggers a bounded background refresh on stale hit).
    #[must_use]
    pub fn lookup_cached(&self, domain: &str, v4_only: bool) -> CachedLookup {
        let Some(domain_norm) = normalize_domain(domain) else {
            return CachedLookup::NegativeHit;
        };
        let key = cache_key(&domain_norm, v4_only);
        let now = Instant::now();
        let entry = {
            let mut guard = self.inner.cache.lock().unwrap_or_else(|e| e.into_inner());
            guard.sweep_if_due(now);
            guard.entries.get(&key).cloned()
        };
        let Some(entry) = entry else {
            return CachedLookup::Miss;
        };

        if entry.ips.is_empty() {
            return if entry.fresh_until > now {
                CachedLookup::NegativeHit
            } else {
                CachedLookup::Miss
            };
        }
        if entry.fresh_until > now {
            return CachedLookup::Hit(entry.ips);
        }
        if entry.stale_until > now {
            self.spawn_background_refresh(domain_norm, key, v4_only);
            return CachedLookup::Hit(entry.ips);
        }
        CachedLookup::Miss
    }

    /// Resolves `domain` to one or more `IpAddr`s without leaking ECS.
    pub async fn resolve(&self, domain: &str) -> Option<Arc<[IpAddr]>> {
        self.resolve_for_strategy(domain, false).await
    }

    /// Resolves `domain`, skipping `AAAA` queries when `v4_only` is `true`.
    pub async fn resolve_for_strategy(&self, domain: &str, v4_only: bool) -> Option<Arc<[IpAddr]>> {
        let domain_norm = normalize_domain(domain)?;
        let key = cache_key(&domain_norm, v4_only);
        let now = Instant::now();

        {
            let mut guard = self.inner.cache.lock().unwrap_or_else(|e| e.into_inner());
            guard.sweep_if_due(now);
            if let Some(entry) = guard.entries.get(&key) {
                if entry.fresh_until > now {
                    return if entry.ips.is_empty() {
                        None
                    } else {
                        Some(Arc::clone(&entry.ips))
                    };
                }
                if entry.stale_until > now && !entry.ips.is_empty() {
                    let ips = Arc::clone(&entry.ips);
                    drop(guard);
                    self.spawn_background_refresh(domain_norm, key, v4_only);
                    return Some(ips);
                }
            }
            guard.entries.remove(&key);
        }

        // Singleflight with bounded retry if an in-flight leader is cancelled.
        for _attempt in 0..3 {
            enum Role {
                Wait(watch::Receiver<Option<Option<Arc<[IpAddr]>>>>),
                Lead(tokio::sync::OwnedSemaphorePermit),
            }

            let role = {
                let mut flight = self
                    .inner
                    .in_flight
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if let Some(tx) = flight.get(&key) {
                    Some(Role::Wait(tx.subscribe()))
                } else if let Ok(permit) = Arc::clone(&self.inner.in_flight_sem).try_acquire_owned()
                {
                    let (tx, _rx) = watch::channel(None);
                    flight.insert(key.clone(), tx);
                    Some(Role::Lead(permit))
                } else {
                    None
                }
            };

            let role = role?;

            match role {
                Role::Wait(mut rx) => {
                    if rx.borrow().is_none() {
                        let _ = rx.changed().await;
                    }
                    if let Some(result) = rx.borrow().clone() {
                        return result;
                    }
                    // Leader dropped before publishing; loop to elect a single new leader.
                    continue;
                }
                Role::Lead(_permit) => {
                    let guard = InFlightGuard {
                        inner: Arc::clone(&self.inner),
                        key: key.clone(),
                        disarmed: false,
                    };
                    let result = self.execute_lookup(&domain_norm, &key, v4_only).await;
                    guard.complete(result.clone());
                    return result;
                }
            }
        }
        None
    }

    fn spawn_background_refresh(&self, domain_norm: String, key: String, v4_only: bool) {
        let Ok(refresh_permit) = Arc::clone(&self.inner.refresh_sem).try_acquire_owned() else {
            return;
        };
        let Ok(flight_permit) = Arc::clone(&self.inner.in_flight_sem).try_acquire_owned() else {
            return;
        };

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
            let _refresh_permit = refresh_permit;
            let _flight_permit = flight_permit;
            let guard = InFlightGuard {
                inner: Arc::clone(&resolver.inner),
                key: key.clone(),
                disarmed: false,
            };
            let result = resolver.execute_lookup(&domain_norm, &key, v4_only).await;
            guard.complete(result);
        });
    }

    async fn execute_lookup(
        &self,
        domain_norm: &str,
        key: &str,
        v4_only: bool,
    ) -> Option<Arc<[IpAddr]>> {
        let resolved = match self.query_rfc1035(domain_norm, v4_only).await {
            DnsQueryOutcome::Answer(ips, ttl) => Some((ips, ttl)),
            DnsQueryOutcome::EmptyOrNxDomain => None,
            DnsQueryOutcome::TransportError => {
                if self.inner.allow_system_dns {
                    resolve_via_system(domain_norm, v4_only).await
                } else {
                    None
                }
            }
        };

        let now = Instant::now();
        if let Some((ips, ttl_secs)) = resolved {
            if !ips.is_empty() {
                let shared_ips: Arc<[IpAddr]> = Arc::from(ips);
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
                            ips: Arc::clone(&shared_ips),
                            fresh_until,
                            stale_until,
                        },
                        now,
                    );
                }
                return Some(shared_ips);
            }
        }

        // Negative cache to prevent repeated 2s stalls on unresolvable domains.
        if let Some(neg_until) = now.checked_add(DNS_NEGATIVE_TTL) {
            self.insert_cache_entry(
                key.to_string(),
                CachedDnsEntry {
                    ips: Arc::from([]),
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
        guard.sweep_if_due(now);
        // RFC 8767 serve-stale: never overwrite a still-valid stale entry with a negative
        // lookup result on transient upstream packet loss; simply back off the next refresh.
        if entry.ips.is_empty() {
            if let Some(existing) = guard.entries.get_mut(&key) {
                if !existing.ips.is_empty() && existing.stale_until > now {
                    existing.fresh_until = entry.fresh_until.min(existing.stale_until);
                    return;
                }
            }
        }
        if !guard.entries.contains_key(&key) && guard.entries.len() >= MAX_DNS_CACHE_ENTRIES {
            guard.entries.retain(|_, v| v.stale_until > now);
            if guard.entries.len() >= MAX_DNS_CACHE_ENTRIES {
                if let Some(oldest_key) = guard
                    .entries
                    .iter()
                    .min_by_key(|(_, v)| v.stale_until)
                    .map(|(k, _)| k.clone())
                {
                    guard.entries.remove(&oldest_key);
                }
            }
        }
        guard.entries.insert(key, entry);
    }

    async fn query_rfc1035(&self, domain: &str, v4_only: bool) -> DnsQueryOutcome {
        if v4_only {
            return query_single_rr(self.inner.resolver_addr, domain, 1).await;
        }

        let mut out_ips = Vec::new();
        let mut min_ttl: Option<u32> = None;
        let mut any_transport_err = false;
        let mut any_nxdomain_or_nodata = false;

        let record_outcome = |res: DnsQueryOutcome,
                              ips: &mut Vec<IpAddr>,
                              min_ttl: &mut Option<u32>,
                              t_err: &mut bool,
                              empty: &mut bool| {
            match res {
                DnsQueryOutcome::Answer(v, ttl) => {
                    ips.extend(v);
                    *min_ttl = Some(min_ttl.map_or(ttl, |cur| cur.min(ttl)));
                }
                DnsQueryOutcome::EmptyOrNxDomain => *empty = true,
                DnsQueryOutcome::TransportError => *t_err = true,
            }
        };

        // Race A (1) and AAAA (28) concurrently with an RFC 8305 early-return
        // grace window (50 ms) once the first family yields usable IPs.
        let a_fut = query_single_rr(self.inner.resolver_addr, domain, 1);
        let aaaa_fut = query_single_rr(self.inner.resolver_addr, domain, 28);
        tokio::pin!(a_fut);
        tokio::pin!(aaaa_fut);

        tokio::select! {
            a_res = &mut a_fut => {
                record_outcome(a_res, &mut out_ips, &mut min_ttl, &mut any_transport_err, &mut any_nxdomain_or_nodata);
                if !out_ips.is_empty() {
                    if let Ok(aaaa_res) = tokio::time::timeout(DNS_FAMILY_RACE_GRACE, &mut aaaa_fut).await {
                        record_outcome(aaaa_res, &mut out_ips, &mut min_ttl, &mut any_transport_err, &mut any_nxdomain_or_nodata);
                    }
                } else {
                    let aaaa_res = aaaa_fut.await;
                    record_outcome(aaaa_res, &mut out_ips, &mut min_ttl, &mut any_transport_err, &mut any_nxdomain_or_nodata);
                }
            }
            aaaa_res = &mut aaaa_fut => {
                record_outcome(aaaa_res, &mut out_ips, &mut min_ttl, &mut any_transport_err, &mut any_nxdomain_or_nodata);
                if !out_ips.is_empty() {
                    if let Ok(a_res) = tokio::time::timeout(DNS_FAMILY_RACE_GRACE, &mut a_fut).await {
                        record_outcome(a_res, &mut out_ips, &mut min_ttl, &mut any_transport_err, &mut any_nxdomain_or_nodata);
                    }
                } else {
                    let a_res = a_fut.await;
                    record_outcome(a_res, &mut out_ips, &mut min_ttl, &mut any_transport_err, &mut any_nxdomain_or_nodata);
                }
            }
        }

        if !out_ips.is_empty() {
            DnsQueryOutcome::Answer(out_ips, min_ttl.unwrap_or(60))
        } else if any_nxdomain_or_nodata && !any_transport_err {
            DnsQueryOutcome::EmptyOrNxDomain
        } else if any_transport_err {
            DnsQueryOutcome::TransportError
        } else {
            DnsQueryOutcome::EmptyOrNxDomain
        }
    }
}

enum DnsQueryOutcome {
    Answer(Vec<IpAddr>, u32),
    EmptyOrNxDomain,
    TransportError,
}

fn normalize_domain(domain: &str) -> Option<String> {
    if !is_valid_domain(domain) {
        return None;
    }
    let trimmed = domain.strip_suffix('.').unwrap_or(domain);
    Some(trimmed.to_ascii_lowercase())
}

fn cache_key(domain_norm: &str, v4_only: bool) -> String {
    if v4_only {
        format!("4:{domain_norm}")
    } else {
        domain_norm.to_string()
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

enum ParsedWireStatus {
    Answer(Vec<IpAddr>, u32),
    EmptyOrNxDomain,
    Truncated,
    MismatchOrMalformed,
}

async fn query_single_rr(resolver_addr: SocketAddr, domain: &str, qtype: u16) -> DnsQueryOutcome {
    let mut tx_bytes = [0u8; 2];
    if getrandom::fill(&mut tx_bytes).is_err() {
        return DnsQueryOutcome::TransportError;
    }
    let tx_id = u16::from_be_bytes(tx_bytes);

    let Some(packet) = build_dns_query(tx_id, domain, qtype) else {
        return DnsQueryOutcome::EmptyOrNxDomain;
    };
    let Some(question_end) = packet.len().checked_sub(11) else {
        return DnsQueryOutcome::EmptyOrNxDomain;
    };
    let expected_question = packet.get(12..question_end).unwrap_or(&[]);

    let bind_addr = if resolver_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let Ok(sock) = UdpSocket::bind(bind_addr).await else {
        return DnsQueryOutcome::TransportError;
    };
    if sock.connect(resolver_addr).await.is_err() {
        return DnsQueryOutcome::TransportError;
    }
    if sock.send(&packet).await.is_err() {
        return DnsQueryOutcome::TransportError;
    }

    let mut resp = vec![0u8; MAX_DNS_UDP_PACKET];
    let Some(deadline) = tokio::time::Instant::now().checked_add(DNS_QUERY_TIMEOUT) else {
        return DnsQueryOutcome::TransportError;
    };

    for _attempt in 0..4 {
        let Ok(recv_res) = tokio::time::timeout_at(deadline, sock.recv(&mut resp)).await else {
            return DnsQueryOutcome::TransportError;
        };
        let Ok(n) = recv_res else {
            return DnsQueryOutcome::TransportError;
        };
        let Some(slice) = resp.get(..n) else {
            return DnsQueryOutcome::TransportError;
        };
        if slice
            .get(12..question_end)
            .map(|echo| echo.eq_ignore_ascii_case(expected_question))
            != Some(true)
        {
            continue;
        }
        match parse_dns_wire(slice, tx_id, qtype) {
            ParsedWireStatus::Answer(ips, ttl) => return DnsQueryOutcome::Answer(ips, ttl),
            ParsedWireStatus::EmptyOrNxDomain => return DnsQueryOutcome::EmptyOrNxDomain,
            ParsedWireStatus::Truncated => {
                return query_single_rr_tcp(
                    resolver_addr,
                    tx_id,
                    &packet,
                    expected_question,
                    qtype,
                )
                .await;
            }
            ParsedWireStatus::MismatchOrMalformed => continue,
        }
    }

    DnsQueryOutcome::TransportError
}

async fn query_single_rr_tcp(
    resolver_addr: SocketAddr,
    tx_id: u16,
    udp_packet: &[u8],
    expected_question: &[u8],
    qtype: u16,
) -> DnsQueryOutcome {
    let Ok(Ok(mut stream)) =
        tokio::time::timeout(DNS_QUERY_TIMEOUT, TcpStream::connect(resolver_addr)).await
    else {
        return DnsQueryOutcome::TransportError;
    };
    let _ = stream.set_nodelay(true);

    let Ok(len_u16) = u16::try_from(udp_packet.len()) else {
        return DnsQueryOutcome::TransportError;
    };
    let mut tcp_req = Vec::with_capacity(2usize.saturating_add(udp_packet.len()));
    tcp_req.extend_from_slice(&len_u16.to_be_bytes());
    tcp_req.extend_from_slice(udp_packet);

    let io_res = tokio::time::timeout(DNS_QUERY_TIMEOUT, async {
        stream.write_all(&tcp_req).await?;
        let mut len_hdr = [0u8; 2];
        stream.read_exact(&mut len_hdr).await?;
        let resp_len = usize::from(u16::from_be_bytes(len_hdr));
        if !(12..=MAX_DNS_TCP_PACKET).contains(&resp_len) {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await?;
        Ok(resp_buf)
    })
    .await;

    let Ok(Ok(resp_buf)) = io_res else {
        return DnsQueryOutcome::TransportError;
    };
    let q_end = 12usize.saturating_add(expected_question.len());
    if resp_buf
        .get(12..q_end)
        .map(|echo| echo.eq_ignore_ascii_case(expected_question))
        != Some(true)
    {
        return DnsQueryOutcome::TransportError;
    }

    match parse_dns_wire(&resp_buf, tx_id, qtype) {
        ParsedWireStatus::Answer(ips, ttl) => DnsQueryOutcome::Answer(ips, ttl),
        ParsedWireStatus::EmptyOrNxDomain => DnsQueryOutcome::EmptyOrNxDomain,
        ParsedWireStatus::Truncated | ParsedWireStatus::MismatchOrMalformed => {
            DnsQueryOutcome::TransportError
        }
    }
}

/// Encodes an RFC 1035 DNS query packet with RD=1, minimal EDNS0 OPT (1232B UDP, zero ECS).
#[must_use]
pub fn build_dns_query(tx_id: u16, domain: &str, qtype: u16) -> Option<Vec<u8>> {
    let norm = normalize_domain(domain)?;
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Standard query, RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT = 1 (EDNS0 OPT)

    for label in norm.split('.') {
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

    // Minimal EDNS0 OPT RR (11 bytes, zero ECS):
    // NAME = 0x00 (root), TYPE = 41, UDP payload = 1232, extRCODE/ver/flags = 0, RDLEN = 0
    pkt.push(0);
    pkt.extend_from_slice(&41u16.to_be_bytes());
    pkt.extend_from_slice(&EDNS0_UDP_PAYLOAD_SIZE.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    Some(pkt)
}

/// Parses `A` or `AAAA` answers matching `expected_qtype` from an RFC 1035 DNS
/// response packet, verifying owner names / CNAME chain and `OPCODE`.
#[must_use]
pub fn parse_dns_response(
    pkt: &[u8],
    expected_tx_id: u16,
    expected_qtype: u16,
) -> Option<(Vec<IpAddr>, u32)> {
    match parse_dns_wire(pkt, expected_tx_id, expected_qtype) {
        ParsedWireStatus::Answer(ips, ttl) => Some((ips, ttl)),
        _ => None,
    }
}

fn parse_dns_wire(pkt: &[u8], expected_tx_id: u16, expected_qtype: u16) -> ParsedWireStatus {
    if pkt.len() < 12 {
        return ParsedWireStatus::MismatchOrMalformed;
    }
    let (Some(&b0), Some(&b1), Some(&b2), Some(&b3)) =
        (pkt.first(), pkt.get(1), pkt.get(2), pkt.get(3))
    else {
        return ParsedWireStatus::MismatchOrMalformed;
    };
    let tx_id = u16::from_be_bytes([b0, b1]);
    if tx_id != expected_tx_id {
        return ParsedWireStatus::MismatchOrMalformed;
    }
    let flags = u16::from_be_bytes([b2, b3]);
    // QR must be 1 (response), OPCODE (bits 11..15) must be 0 (standard query).
    if (flags & 0x8000) == 0 || (flags & 0x7800) != 0 {
        return ParsedWireStatus::MismatchOrMalformed;
    }
    // Truncated (TC=1) -> caller falls back to DNS-over-TCP.
    if (flags & 0x0200) != 0 {
        return ParsedWireStatus::Truncated;
    }
    let rcode = flags & 0x000F;
    if rcode == 3 {
        // NXDOMAIN is authoritative empty result (do not fall back to system DNS).
        return ParsedWireStatus::EmptyOrNxDomain;
    }
    if rcode != 0 {
        return ParsedWireStatus::MismatchOrMalformed;
    }

    let (Some(&qd0), Some(&qd1), Some(&an0), Some(&an1)) =
        (pkt.get(4), pkt.get(5), pkt.get(6), pkt.get(7))
    else {
        return ParsedWireStatus::MismatchOrMalformed;
    };
    let qdcount = usize::from(u16::from_be_bytes([qd0, qd1]));
    let ancount = usize::from(u16::from_be_bytes([an0, an1]));
    if qdcount != 1 {
        return ParsedWireStatus::MismatchOrMalformed;
    }

    let Some((qname, after_qname)) = decode_dns_name(pkt, 12) else {
        return ParsedWireStatus::MismatchOrMalformed;
    };
    let Some(q_tail) = pkt.get(after_qname..after_qname.saturating_add(4)) else {
        return ParsedWireStatus::MismatchOrMalformed;
    };
    let qtype_wire =
        u16::from_be_bytes([*q_tail.first().unwrap_or(&0), *q_tail.get(1).unwrap_or(&0)]);
    let qclass_wire =
        u16::from_be_bytes([*q_tail.get(2).unwrap_or(&0), *q_tail.get(3).unwrap_or(&0)]);
    if qtype_wire != expected_qtype || qclass_wire != 1 {
        return ParsedWireStatus::MismatchOrMalformed;
    }

    let mut offset = after_qname.saturating_add(4);
    let mut current_target = qname;
    let mut cname_hops = 0usize;
    let mut ips = Vec::new();
    let mut min_ttl: Option<u32> = None;

    for _ in 0..ancount {
        let Some((owner_name, next_off)) = decode_dns_name(pkt, offset) else {
            return ParsedWireStatus::MismatchOrMalformed;
        };
        offset = next_off;
        let Some(hdr_end) = offset.checked_add(10) else {
            return ParsedWireStatus::MismatchOrMalformed;
        };
        let Some(hdr) = pkt.get(offset..hdr_end) else {
            return ParsedWireStatus::MismatchOrMalformed;
        };
        let rtype = u16::from_be_bytes([*hdr.first().unwrap_or(&0), *hdr.get(1).unwrap_or(&0)]);
        let rclass = u16::from_be_bytes([*hdr.get(2).unwrap_or(&0), *hdr.get(3).unwrap_or(&0)]);
        let raw_ttl = u32::from_be_bytes([
            *hdr.get(4).unwrap_or(&0),
            *hdr.get(5).unwrap_or(&0),
            *hdr.get(6).unwrap_or(&0),
            *hdr.get(7).unwrap_or(&0),
        ]);
        // RFC 2181 §8: if MSB is set, treat TTL as 0.
        let ttl = if (raw_ttl & 0x8000_0000) != 0 {
            0
        } else {
            raw_ttl
        };
        let rdlength = usize::from(u16::from_be_bytes([
            *hdr.get(8).unwrap_or(&0),
            *hdr.get(9).unwrap_or(&0),
        ]));
        offset = hdr_end;

        let Some(rdata_end) = offset.checked_add(rdlength) else {
            return ParsedWireStatus::MismatchOrMalformed;
        };
        let Some(rdata) = pkt.get(offset..rdata_end) else {
            return ParsedWireStatus::MismatchOrMalformed;
        };

        // Reject out-of-bailiwick owner names (DNS cache poisoning protection, SEC-11).
        if !owner_name.eq_ignore_ascii_case(&current_target) {
            return ParsedWireStatus::MismatchOrMalformed;
        }

        if rclass == 1 {
            if rtype == 5 {
                // CNAME chain advance
                cname_hops = cname_hops.saturating_add(1);
                if cname_hops > 8 {
                    return ParsedWireStatus::MismatchOrMalformed;
                }
                let Some((cname_target, cname_end)) = decode_dns_name(pkt, offset) else {
                    return ParsedWireStatus::MismatchOrMalformed;
                };
                if cname_end != rdata_end {
                    return ParsedWireStatus::MismatchOrMalformed;
                }
                current_target = cname_target;
                min_ttl = Some(min_ttl.map_or(ttl, |cur| cur.min(ttl)));
            } else if rtype == expected_qtype {
                if rtype == 1 && rdlength == 4 {
                    let ip = Ipv4Addr::new(
                        *rdata.first().unwrap_or(&0),
                        *rdata.get(1).unwrap_or(&0),
                        *rdata.get(2).unwrap_or(&0),
                        *rdata.get(3).unwrap_or(&0),
                    );
                    ips.push(IpAddr::V4(ip));
                    min_ttl = Some(min_ttl.map_or(ttl, |cur| cur.min(ttl)));
                } else if rtype == 28 && rdlength == 16 {
                    let mut raw = [0u8; 16];
                    raw.copy_from_slice(rdata);
                    ips.push(IpAddr::V6(Ipv6Addr::from(raw)));
                    min_ttl = Some(min_ttl.map_or(ttl, |cur| cur.min(ttl)));
                }
            }
        }
        offset = rdata_end;
    }

    if ips.is_empty() {
        ParsedWireStatus::EmptyOrNxDomain
    } else {
        ParsedWireStatus::Answer(ips, min_ttl.unwrap_or(60))
    }
}

/// Decodes a compressed RFC 1035 domain name starting at `start`, returning
/// `(lowercased_domain, wire_end_offset_after_name_or_first_pointer)`.
/// Enforces strictly backward compression pointers, max 16 pointer hops, and max 253 chars.
fn decode_dns_name(pkt: &[u8], start: usize) -> Option<(String, usize)> {
    let mut idx = start;
    let mut out = String::new();
    let mut end_offset: Option<usize> = None;
    let mut hops = 0usize;

    for _ in 0..128 {
        let b = *pkt.get(idx)?;
        if b == 0 {
            let final_end = end_offset.unwrap_or_else(|| idx.saturating_add(1));
            if out.is_empty() {
                return Some((String::from("."), final_end));
            }
            return Some((out, final_end));
        }
        if (b & 0xC0) == 0xC0 {
            hops = hops.saturating_add(1);
            if hops > 16 {
                return None;
            }
            let b2 = *pkt.get(idx.checked_add(1)?)?;
            let ptr_offset = usize::from(u16::from_be_bytes([b & 0x3F, b2]));
            // Compression pointer must point strictly backwards and past the 12-byte header.
            if ptr_offset < 12 || ptr_offset >= idx {
                return None;
            }
            if end_offset.is_none() {
                let next = idx.checked_add(2)?;
                if next > pkt.len() {
                    return None;
                }
                end_offset = Some(next);
            }
            idx = ptr_offset;
            continue;
        }
        if (b & 0xC0) != 0 {
            return None;
        }
        let label_len = usize::from(b);
        if label_len > 63 {
            return None;
        }
        let label_start = idx.checked_add(1)?;
        let label_end = label_start.checked_add(label_len)?;
        let label_bytes = pkt.get(label_start..label_end)?;
        let label_str = core::str::from_utf8(label_bytes).ok()?;
        if !label_str
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        if out.len().saturating_add(label_str.len()) > 253 {
            return None;
        }
        out.push_str(&label_str.to_ascii_lowercase());
        idx = label_end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip_opt_to_resp_base(query: &[u8]) -> Option<(Vec<u8>, u16)> {
        let (_, q_tail_start) = decode_dns_name(query, 12)?;
        let q_end = q_tail_start.checked_add(4)?;
        let qtype_bytes = query.get(q_tail_start..q_tail_start.checked_add(2)?)?;
        let qtype = u16::from_be_bytes([*qtype_bytes.first()?, *qtype_bytes.get(1)?]);
        let mut resp = query.get(..q_end)?.to_vec();
        if let Some(flags) = resp.get_mut(2..4) {
            flags.copy_from_slice(&0x8180u16.to_be_bytes());
        }
        if let Some(arcount) = resp.get_mut(10..12) {
            arcount.copy_from_slice(&0u16.to_be_bytes());
        }
        Some((resp, qtype))
    }

    #[test]
    fn builds_and_parses_rfc1035_dns_packet() -> Result<(), &'static str> {
        let query = build_dns_query(0x1234, "example.com", 1).ok_or("build query")?;
        let (mut resp, _) = strip_opt_to_resp_base(&query).ok_or("strip opt")?;
        if let Some(ancount) = resp.get_mut(6..8) {
            ancount.copy_from_slice(&1u16.to_be_bytes());
        }
        resp.extend_from_slice(&[0xC0, 0x0C]); // Name pointer
        resp.extend_from_slice(&1u16.to_be_bytes()); // A
        resp.extend_from_slice(&1u16.to_be_bytes()); // IN
        resp.extend_from_slice(&300u32.to_be_bytes()); // TTL 300s
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLEN 4
        resp.extend_from_slice(&[93, 184, 216, 34]);

        let parsed = parse_dns_response(&resp, 0x1234, 1);
        assert_eq!(
            parsed,
            Some((vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))], 300))
        );

        // Wrong QTYPE (AAAA on A query) must be rejected (SEC-11).
        assert!(parse_dns_response(&resp, 0x1234, 28).is_none());

        // Truncated (TC=1, 0x0200) DNS response must be rejected by parse_dns_response.
        let mut tc_resp = resp.clone();
        if let Some(flags) = tc_resp.get_mut(2..4) {
            flags.copy_from_slice(&0x8380u16.to_be_bytes());
        }
        assert!(parse_dns_response(&tc_resp, 0x1234, 1).is_none());

        // Out-of-bailiwick owner name in Answer section must be rejected (SEC-11).
        let (mut oob_resp, _) = strip_opt_to_resp_base(&query).ok_or("strip opt")?;
        if let Some(ancount) = oob_resp.get_mut(6..8) {
            ancount.copy_from_slice(&1u16.to_be_bytes());
        }
        oob_resp.extend_from_slice(&[4, b'e', b'v', b'i', b'l', 3, b'c', b'o', b'm', 0]);
        oob_resp.extend_from_slice(&1u16.to_be_bytes());
        oob_resp.extend_from_slice(&1u16.to_be_bytes());
        oob_resp.extend_from_slice(&60u32.to_be_bytes());
        oob_resp.extend_from_slice(&4u16.to_be_bytes());
        oob_resp.extend_from_slice(&[127, 0, 0, 1]);
        assert!(parse_dns_response(&oob_resp, 0x1234, 1).is_none());

        // TTL with MSB set must be treated as 0 (RFC 2181 §8).
        let (mut msb_resp, _) = strip_opt_to_resp_base(&query).ok_or("strip opt")?;
        if let Some(ancount) = msb_resp.get_mut(6..8) {
            ancount.copy_from_slice(&1u16.to_be_bytes());
        }
        msb_resp.extend_from_slice(&[0xC0, 0x0C]);
        msb_resp.extend_from_slice(&1u16.to_be_bytes());
        msb_resp.extend_from_slice(&1u16.to_be_bytes());
        msb_resp.extend_from_slice(&0x8000_0100u32.to_be_bytes());
        msb_resp.extend_from_slice(&4u16.to_be_bytes());
        msb_resp.extend_from_slice(&[93, 184, 216, 34]);
        assert_eq!(
            parse_dns_response(&msb_resp, 0x1234, 1),
            Some((vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))], 0))
        );

        // Forward/self compression pointer (pointing to offset >= current idx) must be rejected.
        let (mut loop_resp, _) = strip_opt_to_resp_base(&query).ok_or("strip opt")?;
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
        assert!(parse_dns_response(&loop_resp, 0x1234, 1).is_none());
        Ok(())
    }

    #[tokio::test]
    async fn early_return_and_singleflight_prevent_aaaa_stalls() -> std::io::Result<()> {
        use core::sync::atomic::{AtomicUsize, Ordering};

        let mock_sock = UdpSocket::bind("127.0.0.1:0").await?;
        let mock_addr = mock_sock.local_addr()?;
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
                let Some((mut resp, qtype)) = strip_opt_to_resp_base(req) else {
                    continue;
                };
                if qtype == 1 {
                    a_queries_srv.fetch_add(1, Ordering::Relaxed);
                    // Simulate a brief 20ms upstream latency so concurrent callers coalesce.
                    tokio::time::sleep(Duration::from_millis(20)).await;
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
            let ips = t.await.map_err(std::io::Error::other)?;
            assert_eq!(
                ips.as_deref(),
                Some(&[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))][..])
            );
        }
        let elapsed = start.elapsed();
        // Early-return (50ms grace) + 20ms mock reply must finish far faster than the 2s timeout!
        assert!(
            elapsed < Duration::from_millis(500),
            "DNS early-return stalled unexpectedly: {elapsed:?}"
        );
        // Singleflight must coalesce all 8 concurrent callers into a single A query.
        assert_eq!(a_queries.load(Ordering::Relaxed), 1);
        assert!(matches!(
            resolver.lookup_cached("video-cdn.example.com", false),
            CachedLookup::Hit(_)
        ));
        // Case-insensitive + trailing-dot normalized synchronous cache lookup must also hit.
        match resolver.lookup_cached("Video-CDN.Example.COM.", false) {
            CachedLookup::Hit(ips) => {
                assert_eq!(&*ips, &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
            }
            other => assert!(
                matches!(other, CachedLookup::Hit(_)),
                "unexpected: {other:?}"
            ),
        }

        srv.abort();
        Ok(())
    }
}
