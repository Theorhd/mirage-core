//! Shared outbound target resolution, anti-SSRF validation, and RFC 8305
//! Happy Eyeballs TCP connection dialing with socket tuning.

use core::net::{IpAddr, SocketAddr};
use core::time::Duration;

use mirage_core::egress::{normalize_ip, EgressPolicy, TransportProtocol};
use mirage_core::vless::VlessAddress;
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use crate::config::{Config, IpStrategy, VlessConfig};
use crate::dns::{CachedLookup, DnsResolver};
use crate::metrics::Metrics;
use crate::net_opt::tune_tcp_stream;

/// Maximum validated candidate IPs retained per outbound dial.
const MAX_CANDIDATE_TARGETS: usize = 8;

/// Default Happy Eyeballs delay before starting the next address-family attempt.
const DEFAULT_HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(75);

/// Default TCP keepalive idle duration applied to outbound sockets.
const DEFAULT_TCP_KEEPALIVE: Duration = Duration::from_secs(30);

/// Overall budget for establishing an outbound TCP connection.
const OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Owned, `'static` egress policy context usable across spawned Mux tasks.
#[derive(Debug, Clone, Copy)]
pub struct EgressContext {
    pub listen_addr: SocketAddr,
    pub dest_addr: SocketAddr,
    pub local_ip: Option<IpAddr>,
    pub allow_private_egress: bool,
    pub allow_smtp_port_25: bool,
    pub block_quic: bool,
    pub ip_strategy: IpStrategy,
    pub happy_eyeballs_delay: Duration,
    pub tcp_keepalive: Duration,
    pub half_close_timeout: Duration,
}

impl EgressContext {
    /// Captures egress policy bounds from active daemon config and socket local IP.
    #[must_use]
    pub const fn from_config(
        config: &Config,
        vless_cfg: &VlessConfig,
        local_ip: Option<IpAddr>,
    ) -> Self {
        Self {
            listen_addr: config.listen_addr(),
            dest_addr: config.dest_addr(),
            local_ip,
            allow_private_egress: vless_cfg.allow_private_egress(),
            allow_smtp_port_25: vless_cfg.allow_smtp_port_25(),
            block_quic: vless_cfg.block_quic(),
            ip_strategy: vless_cfg.ip_strategy(),
            happy_eyeballs_delay: config.happy_eyeballs_delay(),
            tcp_keepalive: config.tcp_keepalive(),
            half_close_timeout: config.half_close_timeout(),
        }
    }

    /// Builds the `EgressPolicy` snapshot for target/peer validation.
    #[must_use]
    pub fn build_policy(&self) -> EgressPolicy {
        let mut blocked_ips = Vec::with_capacity(3);
        // Always block all daemon/dest/local IPs in production (`allow_private_egress = false`).
        // When `allow_private_egress = true` (local dev/tests), skip loopback IPs from whole-IP
        // deny and instead enforce exact `SocketAddr` self-loop protection below.
        for ip in [
            Some(self.listen_addr.ip()),
            Some(self.dest_addr.ip()),
            self.local_ip,
        ]
        .into_iter()
        .flatten()
        {
            let canon = match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
                IpAddr::V4(_) => ip,
            };
            if (!self.allow_private_egress || !canon.is_loopback()) && !canon.is_unspecified() {
                blocked_ips.push(canon);
            }
        }

        EgressPolicy {
            allow_private_egress: self.allow_private_egress,
            allow_smtp_port_25: self.allow_smtp_port_25,
            block_quic: self.block_quic,
            blocked_ips,
        }
    }

    /// Returns `true` if `addr` targets our own listening socket or pinned `dest_addr`,
    /// including multi-homed host IPs when `listen_addr` is wildcard (`0.0.0.0` / `::`).
    fn is_self_loop_socket(&self, validated: SocketAddr) -> bool {
        let norm_ip = normalize_ip(validated.ip());
        let listen_norm = normalize_ip(self.listen_addr.ip());
        let dest_norm = normalize_ip(self.dest_addr.ip());
        if validated.port() == self.listen_addr.port() {
            if norm_ip == listen_norm {
                return true;
            }
            if self.listen_addr.ip().is_unspecified() && is_local_interface_ip(validated.ip()) {
                return true;
            }
        }
        validated.port() == self.dest_addr.port() && norm_ip == dest_norm
    }

    fn validate_candidates(
        &self,
        candidate_ips: &[IpAddr],
        port: u16,
        proto: TransportProtocol,
        metrics: &Metrics,
    ) -> Vec<SocketAddr> {
        if proto == TransportProtocol::Udp && port == 443 && self.block_quic {
            metrics.inc_quic_blocked();
            metrics.inc_egress_blocked();
            return Vec::new();
        }
        if candidate_ips.is_empty() {
            return Vec::new();
        }

        let policy = self.build_policy();
        let mut v6 = Vec::new();
        let mut v4 = Vec::new();
        for &ip in candidate_ips {
            if self.ip_strategy == IpStrategy::V4Only && ip.is_ipv6() {
                continue;
            }
            if let Ok(validated) = policy.validate_target(ip, port, proto) {
                if self.is_self_loop_socket(validated) {
                    continue;
                }
                match validated {
                    SocketAddr::V6(_) => {
                        if !v6.contains(&validated) {
                            v6.push(validated);
                        }
                    }
                    SocketAddr::V4(_) => {
                        if !v4.contains(&validated) {
                            v4.push(validated);
                        }
                    }
                }
            }
        }

        let interleaved = interleave_happy_eyeballs(&v4, &v6, self.ip_strategy);
        if interleaved.is_empty() {
            metrics.inc_egress_blocked();
        }
        interleaved
    }

    /// Synchronous cache-only lookup + `EgressPolicy` validation.
    ///
    /// Returns `Some(targets)` for literal IPs, blocked QUIC, or DNS cache/negative hits;
    /// returns `None` ONLY when a domain requires an asynchronous DNS network query.
    #[must_use]
    pub fn try_resolve_cached_and_validate(
        &self,
        addr: &VlessAddress,
        port: u16,
        proto: TransportProtocol,
        dns_resolver: Option<&DnsResolver>,
        metrics: &Metrics,
    ) -> Option<Vec<SocketAddr>> {
        if proto == TransportProtocol::Udp && port == 443 && self.block_quic {
            metrics.inc_quic_blocked();
            metrics.inc_egress_blocked();
            return Some(Vec::new());
        }

        let v4_only = self.ip_strategy == IpStrategy::V4Only;
        match addr {
            VlessAddress::Ipv4(v4) => {
                Some(self.validate_candidates(&[IpAddr::V4(*v4)], port, proto, metrics))
            }
            VlessAddress::Ipv6(v6) => {
                Some(self.validate_candidates(&[IpAddr::V6(*v6)], port, proto, metrics))
            }
            VlessAddress::Domain(domain) => {
                let resolver = dns_resolver?;
                match resolver.lookup_cached(domain, v4_only) {
                    CachedLookup::Hit(ips) => {
                        Some(self.validate_candidates(&ips, port, proto, metrics))
                    }
                    CachedLookup::NegativeHit => Some(Vec::new()),
                    CachedLookup::Miss => None,
                }
            }
        }
    }

    /// Evaluates `EgressPolicy` over `(addr, port)` and returns all permitted
    /// socket addresses interleaved for Happy Eyeballs dialing.
    pub async fn resolve_and_validate(
        &self,
        addr: &VlessAddress,
        port: u16,
        proto: TransportProtocol,
        dns_resolver: Option<&DnsResolver>,
        metrics: &Metrics,
    ) -> Vec<SocketAddr> {
        if proto == TransportProtocol::Udp && port == 443 && self.block_quic {
            metrics.inc_quic_blocked();
            metrics.inc_egress_blocked();
            return Vec::new();
        }

        let v4_only = self.ip_strategy == IpStrategy::V4Only;
        match addr {
            VlessAddress::Ipv4(v4) => {
                self.validate_candidates(&[IpAddr::V4(*v4)], port, proto, metrics)
            }
            VlessAddress::Ipv6(v6) => {
                self.validate_candidates(&[IpAddr::V6(*v6)], port, proto, metrics)
            }
            VlessAddress::Domain(domain) => {
                let Some(resolver) = dns_resolver else {
                    return Vec::new();
                };
                let Some(ips) = resolver.resolve_for_strategy(domain, v4_only).await else {
                    return Vec::new();
                };
                self.validate_candidates(&ips, port, proto, metrics)
            }
        }
    }
}

fn is_local_interface_ip(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

/// Interleaves IPv4 and IPv6 candidates according to `strategy` so Happy Eyeballs
/// naturally falls back across families if one path is unreachable.
fn interleave_happy_eyeballs(
    v4: &[SocketAddr],
    v6: &[SocketAddr],
    strategy: IpStrategy,
) -> Vec<SocketAddr> {
    let mut out = Vec::with_capacity(MAX_CANDIDATE_TARGETS);
    if strategy == IpStrategy::V4Only {
        for &addr4 in v4.iter().take(MAX_CANDIDATE_TARGETS) {
            out.push(addr4);
        }
        return out;
    }

    let (primary, secondary) = match strategy {
        IpStrategy::PreferV6 => (v6, v4),
        IpStrategy::PreferV4 | IpStrategy::V4Only => (v4, v6),
    };

    let max_len = primary.len().max(secondary.len());
    for i in 0..max_len {
        if out.len() >= MAX_CANDIDATE_TARGETS {
            break;
        }
        if let Some(&first) = primary.get(i) {
            out.push(first);
        }
        if out.len() >= MAX_CANDIDATE_TARGETS {
            break;
        }
        if let Some(&second) = secondary.get(i) {
            out.push(second);
        }
    }
    out
}

/// Connects to the first reachable `SocketAddr` using RFC 8305 Happy Eyeballs
/// pacing with default latency-optimized timings (`75 ms` head-start, `30s` keepalive).
pub async fn connect_happy_eyeballs(targets: &[SocketAddr]) -> Option<TcpStream> {
    connect_happy_eyeballs_with_options(
        targets,
        DEFAULT_HAPPY_EYEBALLS_DELAY,
        DEFAULT_TCP_KEEPALIVE,
    )
    .await
}

/// Connects to the first reachable `SocketAddr` using configurable Happy Eyeballs
/// pacing and TCP keepalive/nodelay socket tuning.
pub async fn connect_happy_eyeballs_with_options(
    targets: &[SocketAddr],
    head_start: Duration,
    tcp_keepalive: Duration,
) -> Option<TcpStream> {
    let first = *targets.first()?;
    if targets.len() == 1 {
        let stream = tokio::time::timeout(OUTBOUND_CONNECT_TIMEOUT, TcpStream::connect(first))
            .await
            .ok()?
            .ok()?;
        tune_tcp_stream(&stream, tcp_keepalive);
        return Some(stream);
    }

    let res = tokio::time::timeout(OUTBOUND_CONNECT_TIMEOUT, async {
        let mut join_set: JoinSet<Option<TcpStream>> = JoinSet::new();
        let mut next_idx = 1usize;
        join_set.spawn(async move { TcpStream::connect(first).await.ok() });

        loop {
            if next_idx < targets.len() {
                let timer = tokio::time::sleep(head_start);
                tokio::pin!(timer);

                tokio::select! {
                    joined = join_set.join_next() => {
                        match joined {
                            Some(Ok(Some(stream))) => {
                                tune_tcp_stream(&stream, tcp_keepalive);
                                return Some(stream);
                            }
                            Some(_) => {
                                if let Some(&addr) = targets.get(next_idx) {
                                    next_idx = next_idx.saturating_add(1);
                                    join_set.spawn(async move { TcpStream::connect(addr).await.ok() });
                                }
                            }
                            None => return None,
                        }
                    }
                    () = &mut timer => {
                        if let Some(&addr) = targets.get(next_idx) {
                            next_idx = next_idx.saturating_add(1);
                            join_set.spawn(async move { TcpStream::connect(addr).await.ok() });
                        }
                    }
                }
            } else {
                match join_set.join_next().await {
                    Some(Ok(Some(stream))) => {
                        tune_tcp_stream(&stream, tcp_keepalive);
                        return Some(stream);
                    }
                    Some(_) => {}
                    None => return None,
                }
            }
        }
    })
    .await;

    res.ok().flatten()
}
