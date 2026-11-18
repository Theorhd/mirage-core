//! Shared outbound target resolution, anti-SSRF validation, and RFC 8305
//! Happy Eyeballs TCP connection dialing.

use core::net::{IpAddr, SocketAddr};
use core::time::Duration;

use mirage_core::egress::EgressPolicy;
use mirage_core::vless::VlessAddress;
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use crate::config::{Config, VlessConfig};
use crate::dns::DnsResolver;
use crate::metrics::Metrics;

/// Maximum validated candidate IPs retained per outbound dial.
const MAX_CANDIDATE_TARGETS: usize = 8;

/// Happy Eyeballs delay before starting the next address-family attempt.
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

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
        }
    }

    /// Evaluates `EgressPolicy` over `(addr, port)` and returns all permitted
    /// socket addresses interleaved for Happy Eyeballs dialing.
    pub async fn resolve_and_validate(
        &self,
        addr: &VlessAddress,
        port: u16,
        is_tcp: bool,
        dns_resolver: Option<&DnsResolver>,
        metrics: &Metrics,
    ) -> Vec<SocketAddr> {
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
            if !self.allow_private_egress || !ip.is_loopback() {
                blocked_ips.push(ip);
            }
        }

        let policy = EgressPolicy {
            allow_private_egress: self.allow_private_egress,
            allow_smtp_port_25: self.allow_smtp_port_25,
            blocked_ips,
        };

        let candidate_ips: Vec<IpAddr> = match addr {
            VlessAddress::Ipv4(v4) => vec![IpAddr::V4(*v4)],
            VlessAddress::Ipv6(v6) => vec![IpAddr::V6(*v6)],
            VlessAddress::Domain(domain) => {
                let Some(resolver) = dns_resolver else {
                    return Vec::new();
                };
                resolver.resolve(domain).await.unwrap_or_default()
            }
        };

        if candidate_ips.is_empty() {
            return Vec::new();
        }

        let mut v6 = Vec::new();
        let mut v4 = Vec::new();
        for ip in candidate_ips {
            if let Ok(validated) = policy.validate_target(ip, port, is_tcp) {
                if validated == self.listen_addr || validated == self.dest_addr {
                    continue;
                }
                match validated {
                    SocketAddr::V6(_) => v6.push(validated),
                    SocketAddr::V4(_) => v4.push(validated),
                }
            }
        }

        let interleaved = interleave_happy_eyeballs(&v4, &v6);
        if interleaved.is_empty() {
            metrics.inc_egress_blocked();
        }
        interleaved
    }
}

/// Interleaves IPv6 and IPv4 candidates so Happy Eyeballs naturally falls back
/// across families if one path is unreachable.
fn interleave_happy_eyeballs(v4: &[SocketAddr], v6: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut out = Vec::with_capacity(MAX_CANDIDATE_TARGETS);
    let max_len = v4.len().max(v6.len());
    for i in 0..max_len {
        if out.len() >= MAX_CANDIDATE_TARGETS {
            break;
        }
        if let Some(&addr4) = v4.get(i) {
            out.push(addr4);
        }
        if out.len() >= MAX_CANDIDATE_TARGETS {
            break;
        }
        if let Some(&addr6) = v6.get(i) {
            out.push(addr6);
        }
    }
    out
}

/// Connects to the first reachable `SocketAddr` using RFC 8305 Happy Eyeballs
/// pacing (`250 ms` head-start per attempt before racing the next candidate).
pub async fn connect_happy_eyeballs(targets: &[SocketAddr]) -> Option<TcpStream> {
    let first = *targets.first()?;
    if targets.len() == 1 {
        let stream = tokio::time::timeout(OUTBOUND_CONNECT_TIMEOUT, TcpStream::connect(first))
            .await
            .ok()?
            .ok()?;
        let _ = stream.set_nodelay(true);
        return Some(stream);
    }

    let res = tokio::time::timeout(OUTBOUND_CONNECT_TIMEOUT, async {
        let mut join_set: JoinSet<Option<TcpStream>> = JoinSet::new();
        let mut next_idx = 1usize;
        join_set.spawn(async move { TcpStream::connect(first).await.ok() });

        loop {
            if next_idx < targets.len() {
                let timer = tokio::time::sleep(HAPPY_EYEBALLS_DELAY);
                tokio::pin!(timer);

                tokio::select! {
                    joined = join_set.join_next() => {
                        match joined {
                            Some(Ok(Some(stream))) => {
                                let _ = stream.set_nodelay(true);
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
                        let _ = stream.set_nodelay(true);
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
