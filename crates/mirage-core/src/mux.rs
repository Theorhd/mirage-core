//! Pure Sans-I/O `Mux.Cool` (`v1.mux.cool`) and `XUDP` binary frame codec.
//!
//! Operates strictly over caller-supplied byte slices with bounded metadata
//! lengths, zero panics, zero indexing, and `Zeroizing` payload buffers.

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

use zeroize::{Zeroize, Zeroizing};

use crate::egress::is_valid_domain;
use crate::vless::VlessAddress;

/// Bitmask option flag indicating a 2-byte length-prefixed payload follows metadata.
pub const MUX_OPT_DATA: u8 = 0x01;
/// Bitmask option flag indicating the sub-session closed with an error.
pub const MUX_OPT_ERROR: u8 = 0x02;

/// Upper bound on encoded Mux metadata block length (bytes).
pub const MAX_MUX_METADATA_LEN: usize = 1024;

/// Maximum length of a domain string inside Mux metadata.
const MAX_MUX_DOMAIN_LEN: usize = 255;

/// Sub-session lifecycle status inside a `Mux.Cool` frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxStatus {
    /// Opens a new virtual sub-session (`0x01`).
    New,
    /// Carries stream/packet data or UDP destination update for an active session (`0x02`).
    Keep,
    /// Closes a virtual sub-session (`0x03`).
    End,
    /// Tunnel keep-alive / optional padding frame (`0x04`).
    KeepAlive,
}

impl MuxStatus {
    const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::New),
            0x02 => Some(Self::Keep),
            0x03 => Some(Self::End),
            0x04 => Some(Self::KeepAlive),
            _ => None,
        }
    }

    const fn to_u8(self) -> u8 {
        match self {
            Self::New => 0x01,
            Self::Keep => 0x02,
            Self::End => 0x03,
            Self::KeepAlive => 0x04,
        }
    }
}

/// Target transport network in `Mux.Cool` metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxNetwork {
    /// TCP sub-stream (`0x01`).
    Tcp,
    /// UDP datagram flow / XUDP (`0x02`).
    Udp,
}

impl MuxNetwork {
    const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::Tcp),
            0x02 => Some(Self::Udp),
            _ => None,
        }
    }

    const fn to_u8(self) -> u8 {
        match self {
            Self::Tcp => 0x01,
            Self::Udp => 0x02,
        }
    }
}

/// Target network, port, and address encoded inside `Mux.Cool` metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxTarget {
    /// Target transport protocol (`Tcp` or `Udp`).
    pub network: MuxNetwork,
    /// Target port (`1..=65535` on outbound dial; `0` allowed on metadata if peer omits).
    pub port: u16,
    /// Target address (`Ipv4`, `Domain`, or `Ipv6`).
    pub address: VlessAddress,
}

/// Decoded `Mux.Cool` / `XUDP` frame (redacted `Debug`).
#[derive(Clone, PartialEq, Eq)]
pub struct MuxFrame {
    /// Logical sub-session identifier (may be `0` in Single XUDP mode).
    pub id: u16,
    /// Session status (`New`, `Keep`, `End`, `KeepAlive`).
    pub status: MuxStatus,
    /// Whether `MUX_OPT_DATA` (`0x01`) is set.
    pub opt_data: bool,
    /// Whether `MUX_OPT_ERROR` (`0x02`) is set.
    pub opt_error: bool,
    /// Optional target routing metadata (`New`, or per-packet UDP `Keep` override).
    pub target: Option<MuxTarget>,
    /// Optional 8-byte XUDP `GlobalID` for Full-Cone NAT mapping.
    pub global_id: Option<[u8; 8]>,
    /// Zeroized frame payload (empty when `opt_data` is `false` or length is 0).
    pub payload: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for MuxFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MuxFrame")
            .field("id", &self.id)
            .field("status", &self.status)
            .field("opt_data", &self.opt_data)
            .field("opt_error", &self.opt_error)
            .field("target", &self.target)
            .field("has_global_id", &self.global_id.is_some())
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Errors emitted while decoding or encoding `Mux.Cool` / `XUDP` frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MuxError {
    /// Metadata length is `< 4`, exceeds `MAX_MUX_METADATA_LEN`, or does not match inner fields.
    InvalidMetadataLen,
    /// Unknown `SessionStatus` byte.
    InvalidStatus,
    /// Unknown `TargetNetwork` byte.
    InvalidNetwork,
    /// Malformed or non-ASCII domain / unsupported address type.
    InvalidAddress,
    /// Payload exceeds 65535 bytes.
    PayloadTooLarge,
    /// Reserved option bits set in Mux `opt` byte.
    InvalidOptions,
}

impl fmt::Display for MuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetadataLen => f.write_str("invalid Mux metadata length"),
            Self::InvalidStatus => f.write_str("invalid Mux session status byte"),
            Self::InvalidNetwork => f.write_str("invalid Mux target network"),
            Self::InvalidAddress => f.write_str("invalid Mux target address"),
            Self::PayloadTooLarge => f.write_str("Mux payload exceeds 65535 bytes"),
            Self::InvalidOptions => f.write_str("invalid reserved Mux option bits"),
        }
    }
}

impl core::error::Error for MuxError {}

/// Attempts to decode one complete `Mux.Cool` / `XUDP` frame from `buf`.
///
/// Returns `Ok(Some((frame, consumed_bytes)))`, `Ok(None)` when more input bytes
/// are required, or `Err(MuxError)` on structural error.
pub fn decode_mux_frame(buf: &[u8]) -> Result<Option<(MuxFrame, usize)>, MuxError> {
    let Some(len_hdr) = buf.get(..2) else {
        return Ok(None);
    };
    let l0 = *len_hdr.first().ok_or(MuxError::InvalidMetadataLen)?;
    let l1 = *len_hdr.get(1).ok_or(MuxError::InvalidMetadataLen)?;
    let meta_len = usize::from(u16::from_be_bytes([l0, l1]));

    if !(4..=MAX_MUX_METADATA_LEN).contains(&meta_len) {
        return Err(MuxError::InvalidMetadataLen);
    }

    let meta_end = 2usize
        .checked_add(meta_len)
        .ok_or(MuxError::InvalidMetadataLen)?;
    let Some(meta) = buf.get(2..meta_end) else {
        return Ok(None);
    };

    let id0 = *meta.first().ok_or(MuxError::InvalidMetadataLen)?;
    let id1 = *meta.get(1).ok_or(MuxError::InvalidMetadataLen)?;
    let id = u16::from_be_bytes([id0, id1]);
    let status = *meta.get(2).ok_or(MuxError::InvalidMetadataLen)?;
    let status = MuxStatus::from_u8(status).ok_or(MuxError::InvalidStatus)?;
    let opt = *meta.get(3).ok_or(MuxError::InvalidMetadataLen)?;
    if (opt & !(MUX_OPT_DATA | MUX_OPT_ERROR)) != 0 {
        return Err(MuxError::InvalidOptions);
    }

    let opt_data = (opt & MUX_OPT_DATA) != 0;
    let opt_error = (opt & MUX_OPT_ERROR) != 0;

    let mut target: Option<MuxTarget> = None;
    let mut global_id: Option<[u8; 8]> = None;

    match status {
        MuxStatus::New => {
            let (parsed_target, parsed_gid) = parse_target_and_gid(meta, 4, true)?;
            target = Some(parsed_target);
            global_id = parsed_gid;
        }
        MuxStatus::Keep if meta.len() > 4 => {
            let (parsed_target, parsed_gid) = parse_target_and_gid(meta, 4, false)?;
            target = Some(parsed_target);
            global_id = parsed_gid;
        }
        MuxStatus::Keep | MuxStatus::End | MuxStatus::KeepAlive => {
            if meta.len() != 4 {
                return Err(MuxError::InvalidMetadataLen);
            }
        }
    }

    if opt_data {
        let pay_hdr_end = meta_end
            .checked_add(2)
            .ok_or(MuxError::InvalidMetadataLen)?;
        let Some(pay_hdr) = buf.get(meta_end..pay_hdr_end) else {
            return Ok(None);
        };
        let p0 = *pay_hdr.first().ok_or(MuxError::PayloadTooLarge)?;
        let p1 = *pay_hdr.get(1).ok_or(MuxError::PayloadTooLarge)?;
        let pay_len = usize::from(u16::from_be_bytes([p0, p1]));
        let total_end = pay_hdr_end
            .checked_add(pay_len)
            .ok_or(MuxError::PayloadTooLarge)?;
        let Some(pay_slice) = buf.get(pay_hdr_end..total_end) else {
            return Ok(None);
        };
        Ok(Some((
            MuxFrame {
                id,
                status,
                opt_data,
                opt_error,
                target,
                global_id,
                payload: Zeroizing::new(pay_slice.to_vec()),
            },
            total_end,
        )))
    } else {
        Ok(Some((
            MuxFrame {
                id,
                status,
                opt_data,
                opt_error,
                target,
                global_id,
                payload: Zeroizing::new(Vec::new()),
            },
            meta_end,
        )))
    }
}

/// Encodes `frame` directly into `out`, validating all fields before mutating `out`
/// and clearing/zeroizing any previous contents while preserving existing capacity.
pub fn encode_mux_frame_into(frame: &MuxFrame, out: &mut Vec<u8>) -> Result<(), MuxError> {
    out.zeroize();
    out.clear();

    let has_data = frame.opt_data || !frame.payload.is_empty();
    let pay_len_u16 = u16::try_from(frame.payload.len()).map_err(|_| MuxError::PayloadTooLarge)?;

    // Validate all metadata and pre-calculate exact `meta_len` before writing into `out`.
    let mut meta_len = 4usize;
    if let Some(target) = &frame.target {
        if matches!(frame.status, MuxStatus::End | MuxStatus::KeepAlive) {
            return Err(MuxError::InvalidMetadataLen);
        }
        if frame.status == MuxStatus::Keep && target.network != MuxNetwork::Udp {
            return Err(MuxError::InvalidNetwork);
        }
        // network (1) + port (2) + atyp (1)
        meta_len = meta_len.saturating_add(4);
        match &target.address {
            VlessAddress::Ipv4(_) => meta_len = meta_len.saturating_add(4),
            VlessAddress::Domain(domain) => {
                if domain.len() > MAX_MUX_DOMAIN_LEN || !is_valid_domain(domain) {
                    return Err(MuxError::InvalidAddress);
                }
                meta_len = meta_len.saturating_add(1).saturating_add(domain.len());
            }
            VlessAddress::Ipv6(_) => meta_len = meta_len.saturating_add(16),
        }
        if frame.global_id.is_some() {
            if target.network != MuxNetwork::Udp {
                return Err(MuxError::InvalidMetadataLen);
            }
            meta_len = meta_len.saturating_add(8);
        }
    } else if frame.status == MuxStatus::New || frame.global_id.is_some() {
        return Err(MuxError::InvalidMetadataLen);
    }

    if meta_len > MAX_MUX_METADATA_LEN {
        return Err(MuxError::InvalidMetadataLen);
    }
    let meta_len_u16 = u16::try_from(meta_len).map_err(|_| MuxError::InvalidMetadataLen)?;

    let mut opt = 0u8;
    if has_data {
        opt |= MUX_OPT_DATA;
    }
    if frame.opt_error {
        opt |= MUX_OPT_ERROR;
    }

    let total_len = 2usize.saturating_add(meta_len).saturating_add(if has_data {
        2usize.saturating_add(frame.payload.len())
    } else {
        0
    });
    out.reserve(total_len);
    out.extend_from_slice(&meta_len_u16.to_be_bytes());
    out.extend_from_slice(&frame.id.to_be_bytes());
    out.push(frame.status.to_u8());
    out.push(opt);

    if let Some(target) = &frame.target {
        out.push(target.network.to_u8());
        out.extend_from_slice(&target.port.to_be_bytes());
        match &target.address {
            VlessAddress::Ipv4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            }
            VlessAddress::Domain(domain) => {
                let dlen = u8::try_from(domain.len()).map_err(|_| MuxError::InvalidAddress)?;
                out.push(0x02);
                out.push(dlen);
                out.extend_from_slice(domain.as_bytes());
            }
            VlessAddress::Ipv6(v6) => {
                out.push(0x03);
                out.extend_from_slice(&v6.octets());
            }
        }
        if let Some(gid) = frame.global_id {
            out.extend_from_slice(&gid);
        }
    }

    if has_data {
        out.extend_from_slice(&pay_len_u16.to_be_bytes());
        out.extend_from_slice(&frame.payload);
    }

    Ok(())
}

/// Encodes `frame` into a freshly allocated `Zeroizing<Vec<u8>>`.
pub fn encode_mux_frame(frame: &MuxFrame) -> Result<Zeroizing<Vec<u8>>, MuxError> {
    let mut out = Zeroizing::new(Vec::with_capacity(
        64usize.saturating_add(frame.payload.len()),
    ));
    encode_mux_frame_into(frame, &mut out)?;
    Ok(out)
}

fn parse_target_and_gid(
    meta: &[u8],
    start: usize,
    allow_tcp: bool,
) -> Result<(MuxTarget, Option<[u8; 8]>), MuxError> {
    let net_byte = *meta.get(start).ok_or(MuxError::InvalidMetadataLen)?;
    let network = MuxNetwork::from_u8(net_byte).ok_or(MuxError::InvalidNetwork)?;
    if !allow_tcp && network == MuxNetwork::Tcp {
        return Err(MuxError::InvalidNetwork);
    }

    let p_off = start.saturating_add(1);
    let p_end = p_off.saturating_add(2);
    let port_bytes = meta.get(p_off..p_end).ok_or(MuxError::InvalidMetadataLen)?;
    let pb0 = *port_bytes.first().ok_or(MuxError::InvalidMetadataLen)?;
    let pb1 = *port_bytes.get(1).ok_or(MuxError::InvalidMetadataLen)?;
    let port = u16::from_be_bytes([pb0, pb1]);

    let atyp = *meta.get(p_end).ok_or(MuxError::InvalidMetadataLen)?;
    let mut cursor = p_end.saturating_add(1);

    let address = match atyp {
        0x01 => {
            let end = cursor.saturating_add(4);
            let octs = meta.get(cursor..end).ok_or(MuxError::InvalidAddress)?;
            let a0 = *octs.first().ok_or(MuxError::InvalidAddress)?;
            let a1 = *octs.get(1).ok_or(MuxError::InvalidAddress)?;
            let a2 = *octs.get(2).ok_or(MuxError::InvalidAddress)?;
            let a3 = *octs.get(3).ok_or(MuxError::InvalidAddress)?;
            cursor = end;
            VlessAddress::Ipv4(Ipv4Addr::new(a0, a1, a2, a3))
        }
        0x02 => {
            let dlen = usize::from(*meta.get(cursor).ok_or(MuxError::InvalidAddress)?);
            if dlen == 0 || dlen > MAX_MUX_DOMAIN_LEN {
                return Err(MuxError::InvalidAddress);
            }
            cursor = cursor.saturating_add(1);
            let end = cursor.saturating_add(dlen);
            let dbytes = meta.get(cursor..end).ok_or(MuxError::InvalidAddress)?;
            let domain = core::str::from_utf8(dbytes).map_err(|_| MuxError::InvalidAddress)?;
            if !is_valid_domain(domain) {
                return Err(MuxError::InvalidAddress);
            }
            cursor = end;
            VlessAddress::Domain(domain.to_owned())
        }
        0x03 => {
            let end = cursor.saturating_add(16);
            let octs = meta.get(cursor..end).ok_or(MuxError::InvalidAddress)?;
            let mut raw = [0u8; 16];
            raw.copy_from_slice(octs);
            cursor = end;
            VlessAddress::Ipv6(Ipv6Addr::from(raw))
        }
        _ => return Err(MuxError::InvalidAddress),
    };

    let rem = meta.len().saturating_sub(cursor);
    let global_id = match (network, rem) {
        (_, 0) => None,
        (MuxNetwork::Udp, 8) => {
            let end = cursor.saturating_add(8);
            let gid_slice = meta.get(cursor..end).ok_or(MuxError::InvalidMetadataLen)?;
            let mut gid = [0u8; 8];
            gid.copy_from_slice(gid_slice);
            Some(gid)
        }
        _ => return Err(MuxError::InvalidMetadataLen),
    };

    Ok((
        MuxTarget {
            network,
            port,
            address,
        },
        global_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_mux_new_keep_end_keepalive_roundtrip() -> Result<(), MuxError> {
        let frames = [
            MuxFrame {
                id: 1,
                status: MuxStatus::New,
                opt_data: true,
                opt_error: false,
                target: Some(MuxTarget {
                    network: MuxNetwork::Tcp,
                    port: 443,
                    address: VlessAddress::Domain("example.com".to_owned()),
                }),
                global_id: None,
                payload: Zeroizing::new(b"GET / HTTP/1.1\r\n\r\n".to_vec()),
            },
            MuxFrame {
                id: 1,
                status: MuxStatus::Keep,
                opt_data: true,
                opt_error: false,
                target: None,
                global_id: None,
                payload: Zeroizing::new(b"more-data".to_vec()),
            },
            MuxFrame {
                id: 1,
                status: MuxStatus::End,
                opt_data: false,
                opt_error: false,
                target: None,
                global_id: None,
                payload: Zeroizing::new(Vec::new()),
            },
            MuxFrame {
                id: 0,
                status: MuxStatus::KeepAlive,
                opt_data: false,
                opt_error: false,
                target: None,
                global_id: None,
                payload: Zeroizing::new(Vec::new()),
            },
        ];

        let mut wire = Vec::new();
        for frame in &frames {
            let enc = encode_mux_frame(frame)?;
            wire.extend_from_slice(&enc);
        }

        // Verify partial prefix cleanly asks for more bytes.
        assert_eq!(decode_mux_frame(wire.get(..3).unwrap_or(&[])), Ok(None));

        let mut off = 0usize;
        for expected in &frames {
            let slice = wire.get(off..).unwrap_or(&[]);
            let (frame, used) = decode_mux_frame(slice)?.ok_or(MuxError::InvalidMetadataLen)?;
            assert_eq!(&frame, expected);
            off = off.saturating_add(used);
        }
        assert_eq!(off, wire.len());
        // Reserved option bit 0x04 must be rejected (SEC-36).
        assert_eq!(
            decode_mux_frame(&[0x00, 0x04, 0x00, 0x01, 0x04, 0x04]),
            Err(MuxError::InvalidOptions)
        );
        Ok(())
    }

    #[test]
    fn xudp_new_with_global_id_and_keep_target_override_roundtrip() {
        let gid = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let new_xudp = MuxFrame {
            id: 0,
            status: MuxStatus::New,
            opt_data: true,
            opt_error: false,
            target: Some(MuxTarget {
                network: MuxNetwork::Udp,
                port: 53,
                address: VlessAddress::Ipv4(Ipv4Addr::new(8, 8, 8, 8)),
            }),
            global_id: Some(gid),
            payload: Zeroizing::new(b"dns-packet-1".to_vec()),
        };
        let keep_override = MuxFrame {
            id: 0,
            status: MuxStatus::Keep,
            opt_data: true,
            opt_error: false,
            target: Some(MuxTarget {
                network: MuxNetwork::Udp,
                port: 443,
                address: VlessAddress::Ipv6(Ipv6Addr::new(
                    0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
                )),
            }),
            global_id: None,
            payload: Zeroizing::new(b"quic-initial".to_vec()),
        };

        let mut scratch = Vec::new();
        assert!(encode_mux_frame_into(&new_xudp, &mut scratch).is_ok());
        assert_eq!(
            decode_mux_frame(&scratch),
            Ok(Some((new_xudp, scratch.len())))
        );

        assert!(encode_mux_frame_into(&keep_override, &mut scratch).is_ok());
        assert_eq!(
            decode_mux_frame(&scratch),
            Ok(Some((keep_override, scratch.len())))
        );
    }

    #[test]
    fn rejects_invalid_mux_metadata_and_addresses() {
        // meta_len = 2 (< 4)
        assert_eq!(
            decode_mux_frame(&[0x00, 0x02, 0x00, 0x01]),
            Err(MuxError::InvalidMetadataLen)
        );
        // meta_len > MAX_MUX_METADATA_LEN
        assert_eq!(
            decode_mux_frame(&[0xFF, 0xFF, 0x00, 0x01]),
            Err(MuxError::InvalidMetadataLen)
        );
        // Unknown status 0x99
        assert_eq!(
            decode_mux_frame(&[0x00, 0x04, 0x00, 0x01, 0x99, 0x00]),
            Err(MuxError::InvalidStatus)
        );
        // Keep frame with TCP target override (0x01) is invalid (only UDP 0x02 allowed)
        assert_eq!(
            decode_mux_frame(&[
                0x00, 0x0C, 0x00, 0x01, 0x02, 0x00, 0x01, 0x01, 0xBB, 0x01, 1, 1, 1, 1
            ]),
            Err(MuxError::InvalidNetwork)
        );
        let invalid_keep_tcp = MuxFrame {
            id: 1,
            status: MuxStatus::Keep,
            opt_data: false,
            opt_error: false,
            target: Some(MuxTarget {
                network: MuxNetwork::Tcp,
                port: 443,
                address: VlessAddress::Ipv4(Ipv4Addr::new(1, 1, 1, 1)),
            }),
            global_id: None,
            payload: Zeroizing::new(Vec::new()),
        };
        assert_eq!(
            encode_mux_frame(&invalid_keep_tcp),
            Err(MuxError::InvalidNetwork)
        );
    }
}
