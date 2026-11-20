//! Sans-I/O anti-SSRF egress policy evaluated on resolved destination IPs.
//!
//! Normalizes IPv4-mapped (`::ffff:0:0/96`) and well-known NAT64 (`64:ff9b::/96`)
//! IPv6 addresses to IPv4 before checking deny-lists, rejects local-use NAT64
//! (`64:ff9b:1::/48`) and non-global IPv6 space outside `2000::/3`, blocks
//! private/loopback/link-local/metadata/multicast ranges, blocks daemon listen
//! addresses, and blocks TCP port 25 (SMTP) by default.

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Transport protocol evaluated by [`EgressPolicy::validate_target`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    /// TCP stream (`SO_STREAM`).
    Tcp,
    /// UDP datagram flow.
    Udp,
}

/// Reason an outbound VLESS target was denied by egress policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EgressError {
    /// Destination IP falls within a denied private, loopback, metadata, or reserved range.
    DeniedIpRange,
    /// Destination IP matches a blocked local/listener address.
    DeniedSelfAddress,
    /// Destination port (e.g. TCP/25 SMTP) is denied by default policy.
    DeniedPort,
}

impl fmt::Display for EgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeniedIpRange => f.write_str("destination IP falls in a denied range"),
            Self::DeniedSelfAddress => f.write_str("destination IP matches a local/self address"),
            Self::DeniedPort => f.write_str("destination port is denied by egress policy"),
        }
    }
}

impl core::error::Error for EgressError {}

/// Configurable anti-SSRF egress policy applied after DNS resolution.
#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    /// Allow routing to private/internal IP ranges (default `false`).
    pub allow_private_egress: bool,
    /// Allow outbound TCP port 25 (SMTP) (default `false`).
    pub allow_smtp_port_25: bool,
    /// Block outbound UDP port 443 (QUIC/HTTP3) to force streaming clients onto
    /// HTTPS/TCP where XTLS-Vision DirectCopy eliminates double encryption and
    /// QUIC-over-TCP congestion meltdown (default `false`).
    pub block_quic: bool,
    /// Additional explicitly blocked IPs (e.g., daemon listen & `dest` IPs).
    pub blocked_ips: Vec<IpAddr>,
}

impl EgressPolicy {
    /// Validates a resolved `(IpAddr, port)` target before opening an outbound
    /// socket. Always connect directly to the returned `SocketAddr` without
    /// re-resolving DNS to prevent DNS rebinding.
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:0:0/96`) are canonicalized to `IpAddr::V4`
    /// so downstream self-loop comparisons cannot be bypassed via IPv6 notation.
    pub fn validate_target(
        &self,
        ip: IpAddr,
        port: u16,
        proto: TransportProtocol,
    ) -> Result<SocketAddr, EgressError> {
        if port == 0 {
            return Err(EgressError::DeniedPort);
        }
        if proto == TransportProtocol::Tcp && port == 25 && !self.allow_smtp_port_25 {
            return Err(EgressError::DeniedPort);
        }
        if proto == TransportProtocol::Udp && port == 443 && self.block_quic {
            return Err(EgressError::DeniedPort);
        }
        let canonical_ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        if self.is_self_blocked(canonical_ip) {
            return Err(EgressError::DeniedSelfAddress);
        }
        if !self.allow_private_egress && !is_public_ip(canonical_ip) {
            return Err(EgressError::DeniedIpRange);
        }
        Ok(SocketAddr::new(canonical_ip, port))
    }

    fn is_self_blocked(&self, ip: IpAddr) -> bool {
        let norm = normalize_ip(ip);
        self.blocked_ips
            .iter()
            .any(|blocked| *blocked == ip || normalize_ip(*blocked) == norm)
    }
}

/// Validates a DNS domain name against strict RFC 1035 / RFC 1123 host rules:
/// - Total length `1..=253` (after optional single trailing `.`)
/// - Each label `1..=63` ASCII characters in `[A-Za-z0-9_-]`
/// - Rejects IPv4 literals, control characters, whitespace, slashes, and `..`
#[must_use]
pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 254 {
        return false;
    }
    let trimmed = domain.strip_suffix('.').unwrap_or(domain);
    if trimmed.is_empty() || trimmed.len() > 253 || trimmed.ends_with('.') {
        return false;
    }
    if trimmed.parse::<Ipv4Addr>().is_ok() {
        return false;
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return false;
        }
    }
    true
}

/// Normalizes IPv4-mapped, SIIT IPv4-translated, IPv4-compatible, and NAT64 IPv6
/// addresses to IPv4 when applicable.
#[must_use]
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            if let Some(v4) = extract_embedded_v4(v6) {
                return IpAddr::V4(v4);
            }
            IpAddr::V6(v6)
        }
    }
}

/// Returns `true` if `ip` is globally routable (not in any RFC/iana reserved,
/// private, loopback, link-local, metadata, documentation, or tunneling deny-list).
#[must_use]
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ipv4(v4);
            }
            if let Some(v4) = extract_nat64_v4(v6) {
                return is_public_ipv4(v4);
            }
            is_public_ipv6(v6)
        }
    }
}

fn extract_embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = extract_nat64_v4(v6) {
        return Some(v4);
    }
    let segs = v6.segments();
    // SIIT IPv4-translated: ::ffff:0:w.x.y.z/96 (RFC 2765)
    let is_siit = segs.first() == Some(&0)
        && segs.get(1) == Some(&0)
        && segs.get(2) == Some(&0)
        && segs.get(3) == Some(&0)
        && segs.get(4) == Some(&0xffff)
        && segs.get(5) == Some(&0);
    // Deprecated IPv4-compatible: ::w.x.y.z/96 (excluding :: and ::1)
    let is_v4_compat = !v6.is_unspecified()
        && !v6.is_loopback()
        && segs.first() == Some(&0)
        && segs.get(1) == Some(&0)
        && segs.get(2) == Some(&0)
        && segs.get(3) == Some(&0)
        && segs.get(4) == Some(&0)
        && segs.get(5) == Some(&0);
    if is_siit || is_v4_compat {
        let hi = *segs.get(6)?;
        let lo = *segs.get(7)?;
        let hi_b = hi.to_be_bytes();
        let lo_b = lo.to_be_bytes();
        return Some(Ipv4Addr::new(
            *hi_b.first()?,
            *hi_b.get(1)?,
            *lo_b.first()?,
            *lo_b.get(1)?,
        ));
    }
    None
}

fn extract_nat64_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let segs = v6.segments();
    // Well-known NAT64 prefix ONLY: 64:ff9b::/96 (RFC 6052).
    // Local-use NAT64 (64:ff9b:1::/48, RFC 8215) supports variable-length prefixes
    // and must NOT be unwrapped as a /96; it is denied by the 2000::/3 IPv6 allowlist.
    let [0x0064, 0xff9b, 0, 0, 0, 0, hi, lo] = segs else {
        return None;
    };
    let [h0, h1] = hi.to_be_bytes();
    let [l0, l1] = lo.to_be_bytes();
    Some(Ipv4Addr::new(h0, h1, l0, l1))
}

#[must_use]
const fn is_public_ipv4(v4: Ipv4Addr) -> bool {
    let [a, b, c, _d] = v4.octets();
    // 0.0.0.0/8 (unspecified/current network)
    if a == 0 {
        return false;
    }
    // 10.0.0.0/8 (RFC1918)
    if a == 10 {
        return false;
    }
    // 100.64.0.0/10 (CGNAT)
    if a == 100 && (b & 0xC0) == 64 {
        return false;
    }
    // 127.0.0.0/8 (loopback)
    if a == 127 {
        return false;
    }
    // 169.254.0.0/16 (link-local / cloud metadata)
    if a == 169 && b == 254 {
        return false;
    }
    // 172.16.0.0/12 (RFC1918)
    if a == 172 && (b & 0xF0) == 16 {
        return false;
    }
    // 192.0.0.0/24 (IETF protocol assignments) & 192.0.2.0/24 (TEST-NET-1)
    if a == 192 && b == 0 && (c == 0 || c == 2) {
        return false;
    }
    // 192.88.99.0/24 (6to4 relay)
    if a == 192 && b == 88 && c == 99 {
        return false;
    }
    // 192.168.0.0/16 (RFC1918)
    if a == 192 && b == 168 {
        return false;
    }
    // 198.18.0.0/15 (benchmark)
    if a == 198 && (b == 18 || b == 19) {
        return false;
    }
    // 198.51.100.0/24 (TEST-NET-2)
    if a == 198 && b == 51 && c == 100 {
        return false;
    }
    // 203.0.113.0/24 (TEST-NET-3)
    if a == 203 && b == 0 && c == 113 {
        return false;
    }
    // 224.0.0.0/4 (multicast) & 240.0.0.0/4 (reserved / broadcast 255.255.255.255)
    if a >= 224 {
        return false;
    }
    true
}

#[must_use]
const fn is_public_ipv6(v6: Ipv6Addr) -> bool {
    let [s0, s1, ..] = v6.segments();

    // Strict allowlist: only IANA Global Unicast space (2000::/3) is permitted.
    // This denies 0000::/8, 0100::/64, 64:ff9b:1::/48, 0200::/7, 4000::/2,
    // 5f00::/16, fc00::/7 (ULA), fe00::/9, fe80::/10, fec0::/10, and ff00::/8.
    if (s0 & 0xE000) != 0x2000 {
        return false;
    }
    // 2001::/23 (IETF protocol assignments: Teredo, Benchmarking, ORCHID/v2, 2001:30::/28, etc.)
    if s0 == 0x2001 && (s1 & 0xFE00) == 0x0000 {
        return false;
    }
    // 2001:db8::/32 (documentation, RFC 3849)
    if s0 == 0x2001 && s1 == 0x0db8 {
        return false;
    }
    // 2002::/16 (6to4, RFC 3056)
    if s0 == 0x2002 {
        return false;
    }
    // 3fff::/20 (documentation, RFC 9637)
    if s0 == 0x3FFF && (s1 & 0xF000) == 0x0000 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::AddrParseError;

    #[test]
    fn denies_all_private_metadata_nat64_and_smtp_targets() -> Result<(), AddrParseError> {
        let policy = EgressPolicy {
            allow_private_egress: false,
            allow_smtp_port_25: false,
            block_quic: false,
            blocked_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))],
        };

        let denied_cases = [
            ("0.0.0.1", 443),
            ("10.0.0.1", 443),
            ("100.64.0.1", 443),
            ("127.0.0.1", 8080),
            ("169.254.169.254", 80),
            ("172.16.5.4", 443),
            ("192.0.0.1", 443),
            ("192.0.2.1", 443),
            ("192.88.99.1", 443),
            ("192.168.1.1", 443),
            ("198.18.0.1", 443),
            ("198.51.100.1", 443),
            ("203.0.113.1", 443),
            ("224.0.0.1", 443),
            ("255.255.255.255", 443),
            ("::", 443),
            ("::1", 443),
            ("::7f00:1", 443),
            ("::a9fe:a9fe", 80),
            ("::ffff:0:7f00:1", 443),
            ("::ffff:127.0.0.1", 443),
            ("::ffff:169.254.169.254", 80),
            ("64:ff9b::10.0.0.1", 443),
            ("64:ff9b:1::192.168.1.1", 443),
            ("64:ff9b:1::1.1.1.1", 443),
            ("64:ff9b:1:a9fe:00a9:fe00:0101:0101", 443),
            ("100::1", 443),
            ("100:0:0:1::1", 443),
            ("2001::1", 443),
            ("2001:2::1", 443),
            ("2001:10::1", 443),
            ("2001:20::1", 443),
            ("2001:30::1", 443),
            ("2001:db8::1", 443),
            ("2002:0a00:0001::1", 443),
            ("3fff::1", 443),
            ("5f00::1", 443),
            ("fc00::1", 443),
            ("fe00::1", 443),
            ("fe80::1", 443),
            ("fec0::1", 443),
            ("ff02::1", 443),
            ("1.1.1.1", 25),
            ("198.51.100.10", 443),
        ];

        for (ip_str, port) in denied_cases {
            let ip: IpAddr = ip_str.parse()?;
            assert!(
                policy
                    .validate_target(ip, port, TransportProtocol::Tcp)
                    .is_err(),
                "expected {ip_str}:{port} to be denied"
            );
        }

        let allowed_cases = [
            ("1.1.1.1", 443),
            ("8.8.8.8", 53),
            ("2606:4700:4700::1111", 443),
            ("2001:4860:4860::8888", 443),
            ("64:ff9b::1.1.1.1", 443),
            ("::ffff:1.1.1.1", 443),
        ];
        for (ip_str, port) in allowed_cases {
            let ip: IpAddr = ip_str.parse()?;
            assert!(
                policy
                    .validate_target(ip, port, TransportProtocol::Tcp)
                    .is_ok(),
                "expected {ip_str}:{port} to be allowed"
            );
        }

        // IPv4-mapped IPv6 addresses must canonicalize to IPv4 so self-loop checks apply.
        let v4_mapped_loop: IpAddr = "::ffff:127.0.0.1".parse()?;
        let priv_policy = EgressPolicy {
            allow_private_egress: true,
            allow_smtp_port_25: false,
            block_quic: false,
            blocked_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        };
        assert_eq!(
            priv_policy.validate_target(v4_mapped_loop, 443, TransportProtocol::Tcp),
            Err(EgressError::DeniedSelfAddress)
        );
        Ok(())
    }

    #[test]
    fn block_quic_rejects_udp_443_only() {
        let policy = EgressPolicy {
            allow_private_egress: false,
            allow_smtp_port_25: false,
            block_quic: true,
            blocked_ips: Vec::new(),
        };
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(
            policy.validate_target(ip, 443, TransportProtocol::Udp),
            Err(EgressError::DeniedPort)
        );
        assert!(policy
            .validate_target(ip, 443, TransportProtocol::Tcp)
            .is_ok());
        assert!(policy
            .validate_target(ip, 53, TransportProtocol::Udp)
            .is_ok());
    }

    #[test]
    fn domain_validation_rejects_control_chars_ip_literals_and_bad_labels() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("cdn-01._tls.example.com."));
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("."));
        assert!(!is_valid_domain("example.com.."));
        assert!(!is_valid_domain("127.0.0.1"));
        assert!(!is_valid_domain("bad/host.com"));
        assert!(!is_valid_domain("bad\0host.com"));
        assert!(!is_valid_domain("bad host.com"));
        assert!(!is_valid_domain(&"a".repeat(64)));
    }
}
