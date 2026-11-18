//! Binary VLESS protocol codec (Version 0, UUID, Protobuf Addons, TCP/UDP).
//!
//! Operates strictly Sans-I/O, verifies client UUIDs in constant time across
//! the entire allowlist without early exit, and zeroizes parsed header bytes
//! (which contain target destination PII) from the receive buffer.

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Supported VLESS wire version.
pub const VLESS_VERSION_0: u8 = 0x00;

/// Maximum length of a domain name inside a VLESS request header.
const MAX_DOMAIN_LEN: usize = 255;

/// Maximum encoded VLESS Addons protobuf length (fits in `u8`).
const MAX_ADDONS_LEN: usize = 255;

/// VLESS UUID credential (`ZeroizeOnDrop`, redacted `Debug`, constant-time equality).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VlessUuid {
    bytes: Box<[u8; 16]>,
}

impl VlessUuid {
    /// Constructs a `VlessUuid` from 16 raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self {
            bytes: Box::new(bytes),
        }
    }

    /// Parses a UUID string (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` or 32 hex chars).
    pub fn from_str_hex(input: &str) -> Result<Self, VlessError> {
        let trimmed = input.trim();
        let mut raw = [0u8; 16];
        let mut nibbles = [0u8; 32];
        let mut count = 0usize;

        for b in trimmed.bytes() {
            if b == b'-' {
                continue;
            }
            let val = match b {
                b'0'..=b'9' => b.saturating_sub(b'0'),
                b'a'..=b'f' => b.saturating_sub(b'a').saturating_add(10),
                b'A'..=b'F' => b.saturating_sub(b'A').saturating_add(10),
                _ => return Err(VlessError::InvalidUuidFormat),
            };
            let Some(slot) = nibbles.get_mut(count) else {
                return Err(VlessError::InvalidUuidFormat);
            };
            *slot = val;
            count = count.saturating_add(1);
        }

        if count != 32 {
            nibbles.zeroize();
            return Err(VlessError::InvalidUuidFormat);
        }

        for (i, dst) in raw.iter_mut().enumerate() {
            let hi_idx = i.saturating_mul(2);
            let lo_idx = hi_idx.saturating_add(1);
            let hi = *nibbles.get(hi_idx).ok_or(VlessError::InvalidUuidFormat)?;
            let lo = *nibbles.get(lo_idx).ok_or(VlessError::InvalidUuidFormat)?;
            *dst = (hi << 4) | lo;
        }
        nibbles.zeroize();

        let out = Self::from_bytes(raw);
        raw.zeroize();
        Ok(out)
    }

    /// Returns the raw 16-byte UUID slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    /// Constant-time comparison against another 16-byte UUID slice.
    #[must_use]
    pub fn ct_eq_bytes(&self, other: &[u8; 16]) -> bool {
        bool::from(self.bytes.as_slice().ct_eq(other.as_slice()))
    }
}

impl fmt::Debug for VlessUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VlessUuid([REDACTED])")
    }
}

/// VLESS transport command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    /// TCP stream (`0x01`).
    Tcp,
    /// UDP packet stream (`0x02`).
    Udp,
    /// Mux (`0x03`).
    Mux,
}

/// VLESS flow control addon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessFlow {
    /// Standard unpadded VLESS stream.
    None,
    /// `xtls-rprx-vision` (and `xtls-rprx-vision-udp443`).
    Vision { allow_udp443: bool },
}

/// VLESS target destination address (redacted `Debug` to prevent PII leaks).
#[derive(Clone, PartialEq, Eq)]
pub enum VlessAddress {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

impl Zeroize for VlessAddress {
    fn zeroize(&mut self) {
        match self {
            Self::Ipv4(v4) => *v4 = Ipv4Addr::UNSPECIFIED,
            Self::Domain(dom) => dom.zeroize(),
            Self::Ipv6(v6) => *v6 = Ipv6Addr::UNSPECIFIED,
        }
    }
}

impl fmt::Debug for VlessAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4(_) => f.write_str("VlessAddress::Ipv4([REDACTED])"),
            Self::Domain(_) => f.write_str("VlessAddress::Domain([REDACTED])"),
            Self::Ipv6(_) => f.write_str("VlessAddress::Ipv6([REDACTED])"),
        }
    }
}

/// Decoded VLESS request header (`ZeroizeOnDrop`, redacted `Debug`).
#[derive(Clone)]
pub struct VlessRequest {
    /// Protocol version (`0`).
    pub version: u8,
    /// Authenticated client UUID.
    pub uuid: VlessUuid,
    /// Requested flow control addon.
    pub flow: VlessFlow,
    /// Transport command (`Tcp`, `Udp`, `Mux`).
    pub command: VlessCommand,
    /// Target destination address.
    pub address: VlessAddress,
    /// Target destination port.
    pub port: u16,
    /// Number of bytes consumed by the VLESS header at the start of the stream.
    pub header_len: usize,
}

impl Drop for VlessRequest {
    fn drop(&mut self) {
        self.address.zeroize();
        self.port.zeroize();
    }
}

impl fmt::Debug for VlessRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlessRequest")
            .field("version", &self.version)
            .field("flow", &self.flow)
            .field("command", &self.command)
            .field("header_len", &self.header_len)
            .finish()
    }
}

/// Errors encountered while decoding or validating a VLESS header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessError {
    /// Invalid UUID string syntax.
    InvalidUuidFormat,
    /// Unsupported VLESS protocol version (only `0x00` is supported).
    UnsupportedVersion,
    /// Client UUID did not match any configured credential.
    UnauthorizedUuid,
    /// Malformed VLESS Addons protobuf payload.
    MalformedAddons,
    /// Unsupported or malformed VLESS flow string.
    UnsupportedFlow,
    /// Unsupported VLESS command byte.
    UnsupportedCommand,
    /// Malformed target address or domain name.
    MalformedAddress,
    /// Vision flow is invalid for non-443 UDP requests.
    InvalidVisionUdp,
    /// UDP packet framing exceeded maximum length.
    MalformedUdpPacket,
}

/// Result of attempting to parse a VLESS request header from a buffered slice.
#[derive(Debug)]
pub enum VlessParseOutcome {
    /// More bytes are needed before the full header can be decoded.
    NeedMoreData,
    /// Header decoded and authenticated; the header prefix in `buf` has been wiped.
    Parsed(Box<VlessRequest>),
    /// Invalid version, unauthorized UUID, or malformed header.
    Invalid(VlessError),
}

/// Parses a VLESS request header from `buf`, validating the 16-byte UUID in
/// constant time across ALL `allowed_uuids` without early exit.
///
/// On success, the parsed header bytes `buf[..header_len]` are immediately
/// zeroized in place so destination PII does not linger in the receive buffer.
pub fn parse_vless_request(buf: &mut [u8], allowed_uuids: &[VlessUuid]) -> VlessParseOutcome {
    let Some(&version) = buf.first() else {
        return VlessParseOutcome::NeedMoreData;
    };
    if version != VLESS_VERSION_0 {
        return VlessParseOutcome::Invalid(VlessError::UnsupportedVersion);
    }

    if buf.len() < 18 {
        return VlessParseOutcome::NeedMoreData;
    }

    let Some(uuid_slice) = buf.get(1..17) else {
        return VlessParseOutcome::NeedMoreData;
    };
    let mut uuid_raw = [0u8; 16];
    uuid_raw.copy_from_slice(uuid_slice);

    // Constant-time scan over every allowed UUID without early exit.
    let mut matched = Choice::from(0u8);
    for allowed in allowed_uuids {
        matched |= Choice::from(u8::from(allowed.ct_eq_bytes(&uuid_raw)));
    }
    if !bool::from(matched) {
        uuid_raw.zeroize();
        return VlessParseOutcome::Invalid(VlessError::UnauthorizedUuid);
    }

    let Some(&addons_len_u8) = buf.get(17) else {
        uuid_raw.zeroize();
        return VlessParseOutcome::NeedMoreData;
    };
    let addons_len = usize::from(addons_len_u8);
    if addons_len > MAX_ADDONS_LEN {
        uuid_raw.zeroize();
        return VlessParseOutcome::Invalid(VlessError::MalformedAddons);
    }

    let Some(cmd_offset) = 18usize.checked_add(addons_len) else {
        uuid_raw.zeroize();
        return VlessParseOutcome::Invalid(VlessError::MalformedAddons);
    };
    let Some(min_with_cmd) = cmd_offset.checked_add(1) else {
        uuid_raw.zeroize();
        return VlessParseOutcome::Invalid(VlessError::MalformedAddons);
    };
    if buf.len() < min_with_cmd {
        uuid_raw.zeroize();
        return VlessParseOutcome::NeedMoreData;
    }

    let addons_slice = buf.get(18..cmd_offset).unwrap_or(&[]);
    let flow = match parse_addons_protobuf(addons_slice) {
        Ok(f) => f,
        Err(e) => {
            uuid_raw.zeroize();
            return VlessParseOutcome::Invalid(e);
        }
    };

    let Some(&cmd_byte) = buf.get(cmd_offset) else {
        uuid_raw.zeroize();
        return VlessParseOutcome::NeedMoreData;
    };
    let command = match cmd_byte {
        0x01 => VlessCommand::Tcp,
        0x02 => VlessCommand::Udp,
        0x03 => VlessCommand::Mux,
        _ => {
            uuid_raw.zeroize();
            return VlessParseOutcome::Invalid(VlessError::UnsupportedCommand);
        }
    };

    let (address, port, header_len) = match command {
        VlessCommand::Mux => (
            VlessAddress::Domain("v1.mux.cool".to_owned()),
            0u16,
            min_with_cmd,
        ),
        VlessCommand::Tcp | VlessCommand::Udp => {
            let Some(after_cmd) = buf.get(min_with_cmd..) else {
                uuid_raw.zeroize();
                return VlessParseOutcome::NeedMoreData;
            };
            match parse_port_then_address(after_cmd) {
                Ok(None) => {
                    uuid_raw.zeroize();
                    return VlessParseOutcome::NeedMoreData;
                }
                Ok(Some((addr, port, consumed))) => {
                    let Some(total) = min_with_cmd.checked_add(consumed) else {
                        uuid_raw.zeroize();
                        return VlessParseOutcome::Invalid(VlessError::MalformedAddress);
                    };
                    (addr, port, total)
                }
                Err(e) => {
                    uuid_raw.zeroize();
                    return VlessParseOutcome::Invalid(e);
                }
            }
        }
    };

    if command == VlessCommand::Udp {
        if let VlessFlow::Vision { allow_udp443 } = flow {
            if !allow_udp443 || port != 443 {
                uuid_raw.zeroize();
                return VlessParseOutcome::Invalid(VlessError::InvalidVisionUdp);
            }
        }
    }

    // Wipe parsed header bytes (UUID + destination PII) from caller buffer.
    if let Some(hdr_slice) = buf.get_mut(..header_len) {
        hdr_slice.zeroize();
    }

    let uuid = VlessUuid::from_bytes(uuid_raw);
    uuid_raw.zeroize();

    VlessParseOutcome::Parsed(Box::new(VlessRequest {
        version,
        uuid,
        flow,
        command,
        address,
        port,
        header_len,
    }))
}

/// Encodes the 2-byte VLESS response header (`version = 0x00, addons_len = 0x00`).
#[must_use]
pub const fn encode_vless_response_header() -> [u8; 2] {
    [VLESS_VERSION_0, 0x00]
}

/// Encodes a single VLESS UDP packet (`2-byte big-endian length || payload`).
pub fn encode_udp_packet(payload: &[u8]) -> Result<Vec<u8>, VlessError> {
    let len_u16 = u16::try_from(payload.len()).map_err(|_| VlessError::MalformedUdpPacket)?;
    let mut out = Vec::with_capacity(2usize.saturating_add(payload.len()));
    out.extend_from_slice(&len_u16.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Attempts to decode one VLESS UDP packet (`2-byte big-endian length || payload`)
/// from `buf`, returning `Ok(Some((payload, consumed)))` or `Ok(None)` if incomplete.
pub fn decode_udp_packet(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>, VlessError> {
    let Some(hdr) = buf.get(..2) else {
        return Ok(None);
    };
    let b0 = *hdr.first().ok_or(VlessError::MalformedUdpPacket)?;
    let b1 = *hdr.get(1).ok_or(VlessError::MalformedUdpPacket)?;
    let pkt_len = usize::from(u16::from_be_bytes([b0, b1]));
    let total = 2usize
        .checked_add(pkt_len)
        .ok_or(VlessError::MalformedUdpPacket)?;
    let Some(payload) = buf.get(2..total) else {
        return Ok(None);
    };
    Ok(Some((payload.to_vec(), total)))
}

fn parse_addons_protobuf(data: &[u8]) -> Result<VlessFlow, VlessError> {
    let mut idx = 0usize;
    let mut flow = VlessFlow::None;

    while idx < data.len() {
        let (tag, next_idx) = read_varint(data, idx)?;
        idx = next_idx;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;

        match (field_num, wire_type) {
            (1, 2) => {
                let (str_len_u64, after_len) = read_varint(data, idx)?;
                let str_len =
                    usize::try_from(str_len_u64).map_err(|_| VlessError::MalformedAddons)?;
                let end = after_len
                    .checked_add(str_len)
                    .ok_or(VlessError::MalformedAddons)?;
                let flow_bytes = data
                    .get(after_len..end)
                    .ok_or(VlessError::MalformedAddons)?;
                let flow_str =
                    core::str::from_utf8(flow_bytes).map_err(|_| VlessError::MalformedAddons)?;
                flow = match flow_str {
                    "" => VlessFlow::None,
                    "xtls-rprx-vision" => VlessFlow::Vision {
                        allow_udp443: false,
                    },
                    "xtls-rprx-vision-udp443" => VlessFlow::Vision { allow_udp443: true },
                    _ => return Err(VlessError::UnsupportedFlow),
                };
                idx = end;
            }
            (2, 2) => {
                // Optional `bytes Seed = 2` (up to 4 uint32 seeds in Xray Addons)
                let (len_u64, after_len) = read_varint(data, idx)?;
                let len = usize::try_from(len_u64).map_err(|_| VlessError::MalformedAddons)?;
                let end = after_len
                    .checked_add(len)
                    .ok_or(VlessError::MalformedAddons)?;
                if data.get(after_len..end).is_none() {
                    return Err(VlessError::MalformedAddons);
                }
                idx = end;
            }
            _ => return Err(VlessError::MalformedAddons),
        }
    }

    Ok(flow)
}

fn read_varint(data: &[u8], start: usize) -> Result<(u64, usize), VlessError> {
    let mut val = 0u64;
    let mut shift = 0u32;
    let mut idx = start;

    for _ in 0..10 {
        let b = *data.get(idx).ok_or(VlessError::MalformedAddons)?;
        idx = idx.saturating_add(1);
        let low = u64::from(b & 0x7F);
        let shifted = low.checked_shl(shift).ok_or(VlessError::MalformedAddons)?;
        val |= shifted;
        if (b & 0x80) == 0 {
            return Ok((val, idx));
        }
        shift = shift.saturating_add(7);
    }

    Err(VlessError::MalformedAddons)
}

fn parse_port_then_address(buf: &[u8]) -> Result<Option<(VlessAddress, u16, usize)>, VlessError> {
    let Some(port_hdr) = buf.get(..3) else {
        return Ok(None);
    };
    let p0 = *port_hdr.first().ok_or(VlessError::MalformedAddress)?;
    let p1 = *port_hdr.get(1).ok_or(VlessError::MalformedAddress)?;
    let atyp = *port_hdr.get(2).ok_or(VlessError::MalformedAddress)?;
    let port = u16::from_be_bytes([p0, p1]);

    match atyp {
        0x01 => {
            let Some(ip_slice) = buf.get(3..7) else {
                return Ok(None);
            };
            let ip = Ipv4Addr::new(
                *ip_slice.first().ok_or(VlessError::MalformedAddress)?,
                *ip_slice.get(1).ok_or(VlessError::MalformedAddress)?,
                *ip_slice.get(2).ok_or(VlessError::MalformedAddress)?,
                *ip_slice.get(3).ok_or(VlessError::MalformedAddress)?,
            );
            Ok(Some((VlessAddress::Ipv4(ip), port, 7)))
        }
        0x02 => {
            let Some(&len_u8) = buf.get(3) else {
                return Ok(None);
            };
            let len = usize::from(len_u8);
            if len == 0 || len > MAX_DOMAIN_LEN {
                return Err(VlessError::MalformedAddress);
            }
            let total = 4usize
                .checked_add(len)
                .ok_or(VlessError::MalformedAddress)?;
            let Some(dom_bytes) = buf.get(4..total) else {
                return Ok(None);
            };
            let dom_str =
                core::str::from_utf8(dom_bytes).map_err(|_| VlessError::MalformedAddress)?;
            if !dom_str.bytes().all(|b| b.is_ascii_graphic() && b != b'\\') {
                return Err(VlessError::MalformedAddress);
            }
            Ok(Some((
                VlessAddress::Domain(dom_str.to_owned()),
                port,
                total,
            )))
        }
        0x03 => {
            let Some(ip_slice) = buf.get(3..19) else {
                return Ok(None);
            };
            let mut raw = [0u8; 16];
            raw.copy_from_slice(ip_slice);
            let ip = Ipv6Addr::from(raw);
            Ok(Some((VlessAddress::Ipv6(ip), port, 19)))
        }
        _ => Err(VlessError::MalformedAddress),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_vless_tcp_domain_packet(
        uuid: &[u8; 16],
        flow: &str,
        domain: &str,
        port: u16,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x00);
        out.extend_from_slice(uuid);
        if flow.is_empty() {
            out.push(0x00);
        } else {
            let flow_bytes = flow.as_bytes();
            let addons_len = 2usize.saturating_add(flow_bytes.len());
            out.push(addons_len as u8);
            out.push(0x0A);
            out.push(flow_bytes.len() as u8);
            out.extend_from_slice(flow_bytes);
        }
        out.push(0x01); // TCP
        out.extend_from_slice(&port.to_be_bytes());
        out.push(0x02); // Domain
        out.push(domain.len() as u8);
        out.extend_from_slice(domain.as_bytes());
        out.extend_from_slice(b"PAYLOAD");
        out
    }

    #[test]
    fn parses_vless_vision_request_and_wipes_header_bytes() {
        let Ok(uuid) = VlessUuid::from_str_hex("11223344-5566-7788-99aa-bbccddeeff00") else {
            return;
        };
        let mut pkt =
            build_vless_tcp_domain_packet(uuid.as_bytes(), "xtls-rprx-vision", "example.com", 443);

        // Partial slice -> NeedMoreData
        if let Some(prefix) = pkt.get_mut(..20) {
            assert!(matches!(
                parse_vless_request(prefix, core::slice::from_ref(&uuid)),
                VlessParseOutcome::NeedMoreData
            ));
        }

        let outcome = parse_vless_request(&mut pkt, &[uuid]);
        match outcome {
            VlessParseOutcome::Parsed(req) => {
                assert_eq!(req.command, VlessCommand::Tcp);
                assert_eq!(
                    req.flow,
                    VlessFlow::Vision {
                        allow_udp443: false
                    }
                );
                assert_eq!(req.address, VlessAddress::Domain("example.com".to_owned()));
                assert_eq!(req.port, 443);
                // Header bytes must be wiped from receive buffer; payload stays intact.
                assert_eq!(
                    pkt.get(..req.header_len),
                    Some(vec![0u8; req.header_len].as_slice())
                );
                assert_eq!(pkt.get(req.header_len..), Some(b"PAYLOAD".as_slice()));
            }
            other => {
                assert!(
                    matches!(other, VlessParseOutcome::Parsed(_)),
                    "unexpected {other:?}"
                );
            }
        }
    }

    #[test]
    fn rejects_unauthorized_uuid_and_non_443_udp_vision() {
        let Ok(allowed) = VlessUuid::from_str_hex("11223344-5566-7788-99aa-bbccddeeff00") else {
            return;
        };
        let mut bad = build_vless_tcp_domain_packet(&[0xFFu8; 16], "", "example.com", 443);
        assert!(matches!(
            parse_vless_request(&mut bad, core::slice::from_ref(&allowed)),
            VlessParseOutcome::Invalid(VlessError::UnauthorizedUuid)
        ));

        let mut udp_pkt = Vec::new();
        udp_pkt.push(0x00);
        udp_pkt.extend_from_slice(allowed.as_bytes());
        let flow = b"xtls-rprx-vision";
        udp_pkt.push((2usize.saturating_add(flow.len())) as u8);
        udp_pkt.push(0x0A);
        udp_pkt.push(flow.len() as u8);
        udp_pkt.extend_from_slice(flow);
        udp_pkt.push(0x02); // UDP
        udp_pkt.extend_from_slice(&53u16.to_be_bytes());
        udp_pkt.push(0x01);
        udp_pkt.extend_from_slice(&[1, 1, 1, 1]);

        assert!(matches!(
            parse_vless_request(&mut udp_pkt, &[allowed]),
            VlessParseOutcome::Invalid(VlessError::InvalidVisionUdp)
        ));
    }

    #[test]
    fn udp_packet_framing_roundtrip() {
        let Ok(encoded) = encode_udp_packet(b"dns-query") else {
            return;
        };
        let decoded = decode_udp_packet(&encoded);
        assert_eq!(decoded, Ok(Some((b"dns-query".to_vec(), encoded.len()))));
    }
}
