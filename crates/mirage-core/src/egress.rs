//! Sans-I/O anti-SSRF egress policy evaluated on resolved destination IPs.
//!
//! Normalizes IPv4-mapped (`::ffff:0:0/96`) and NAT64 (`64:ff9b::/96`,
//! `64:ff9b:1::/48`) IPv6 addresses to IPv4 before checking deny-lists, blocks
//! private/loopback/link-local/metadata/multicast ranges, blocks daemon listen
//! addresses, and blocks TCP port 25 (SMTP) by default.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Reason an outbound VLESS target was denied by egress policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressError {
    /// Destination IP falls within a denied private, loopback, metadata, or reserved range.
    DeniedIpRange,
    /// Destination IP matches a blocked local/listener address.
    DeniedSelfAddress,
    /// Destination port (e.g. TCP/25 SMTP) is denied by default policy.
    DeniedPort,
}

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
    pub fn validate_target(
        &self,
        ip: IpAddr,
        port: u16,
        is_tcp: bool,
    ) -> Result<SocketAddr, EgressError> {
        if port == 0 {
            return Err(EgressError::DeniedPort);
        }
        if is_tcp && port == 25 && !self.allow_smtp_port_25 {
            return Err(EgressError::DeniedPort);
        }
        if !is_tcp && port == 443 && self.block_quic {
            return Err(EgressError::DeniedPort);
        }
        if self.is_self_blocked(ip) {
            return Err(EgressError::DeniedSelfAddress);
        }
        if !self.allow_private_egress && !is_public_ip(ip) {
            return Err(EgressError::DeniedIpRange);
        }
        Ok(SocketAddr::new(ip, port))
    }

    fn is_self_blocked(&self, ip: IpAddr) -> bool {
        let norm = normalize_ip(ip);
        self.blocked_ips
            .iter()
            .any(|blocked| *blocked == ip || normalize_ip(*blocked) == norm)
    }
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
    // Well-known NAT64 prefix: 64:ff9b::/96
    let is_well_known = segs.first() == Some(&0x0064)
        && segs.get(1) == Some(&0xff9b)
        && segs.get(2) == Some(&0)
        && segs.get(3) == Some(&0)
        && segs.get(4) == Some(&0)
        && segs.get(5) == Some(&0);
    // Local-use NAT64 prefix: 64:ff9b:1::/48
    let is_local_use = segs.first() == Some(&0x0064)
        && segs.get(1) == Some(&0xff9b)
        && segs.get(2) == Some(&0x0001);

    if is_well_known || is_local_use {
        let hi = *segs.get(6)?;
        let lo = *segs.get(7)?;
        let hi_b = hi.to_be_bytes();
        let lo_b = lo.to_be_bytes();
        Some(Ipv4Addr::new(
            *hi_b.first()?,
            *hi_b.get(1)?,
            *lo_b.first()?,
            *lo_b.get(1)?,
        ))
    } else {
        None
    }
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
    let segs = v6.segments();
    let s0 = segs[0];
    let s1 = segs[1];

    // 0000::/8 (IANA reserved by protocol, includes ::/128, ::1/128, ::/96 IPv4-compatible, and SIIT ::ffff:0:0/96)
    if (s0 & 0xFF00) == 0x0000 {
        return false;
    }
    // 100::/64 (discard-only, RFC 6666)
    if s0 == 0x0100 && s1 == 0 && segs[2] == 0 && segs[3] == 0 {
        return false;
    }
    // 2001::/32 (Teredo, RFC 4380)
    if s0 == 0x2001 && s1 == 0 {
        return false;
    }
    // 2001:2::/48 (Benchmarking, RFC 5180)
    if s0 == 0x2001 && s1 == 0x0002 && segs[2] == 0 {
        return false;
    }
    // 2001:10::/28 & 2001:20::/28 (ORCHID / ORCHIDv2, RFC 4843 / RFC 7343)
    if s0 == 0x2001 && ((s1 & 0xFFF0) == 0x0010 || (s1 & 0xFFF0) == 0x0020) {
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
    // 5f00::/16 (SRv6 SIDs, RFC 9602)
    if s0 == 0x5F00 {
        return false;
    }
    // fc00::/7 (ULA, RFC 4193)
    if (s0 & 0xFE00) == 0xFC00 {
        return false;
    }
    // fe80::/10 (link-local)
    if (s0 & 0xFFC0) == 0xFE80 {
        return false;
    }
    // fec0::/10 (deprecated site-local)
    if (s0 & 0xFFC0) == 0xFEC0 {
        return false;
    }
    // ff00::/8 (multicast)
    if (s0 & 0xFF00) == 0xFF00 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_all_private_metadata_nat64_and_smtp_targets() {
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
            ("100::1", 443),
            ("2001::1", 443),
            ("2001:2::1", 443),
            ("2001:10::1", 443),
            ("2001:20::1", 443),
            ("2001:db8::1", 443),
            ("2002:0a00:0001::1", 443),
            ("3fff::1", 443),
            ("5f00::1", 443),
            ("fc00::1", 443),
            ("fe80::1", 443),
            ("fec0::1", 443),
            ("ff02::1", 443),
            ("1.1.1.1", 25),
            ("198.51.100.10", 443),
        ];

        for (ip_str, port) in denied_cases {
            let parsed = ip_str.parse::<IpAddr>();
            assert!(parsed.is_ok(), "invalid test IP {ip_str}");
            let Ok(ip) = parsed else {
                return;
            };
            assert!(
                policy.validate_target(ip, port, true).is_err(),
                "expected {ip_str}:{port} to be denied"
            );
        }

        let allowed_cases = [
            ("1.1.1.1", 443),
            ("8.8.8.8", 53),
            ("2606:4700:4700::1111", 443),
            ("64:ff9b::1.1.1.1", 443),
            ("::ffff:1.1.1.1", 443),
        ];
        for (ip_str, port) in allowed_cases {
            let parsed = ip_str.parse::<IpAddr>();
            assert!(parsed.is_ok(), "invalid test IP {ip_str}");
            let Ok(ip) = parsed else {
                return;
            };
            assert!(
                policy.validate_target(ip, port, true).is_ok(),
                "expected {ip_str}:{port} to be allowed"
            );
        }
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
            policy.validate_target(ip, 443, false),
            Err(EgressError::DeniedPort)
        );
        assert!(policy.validate_target(ip, 443, true).is_ok());
        assert!(policy.validate_target(ip, 53, false).is_ok());
    }
}
