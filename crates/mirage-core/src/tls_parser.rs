//! Non-destructive TLS `ClientHello` inspection with multi-record fragment reassembly.
//!
//! Operates strictly on `&[u8]` without mutating or consuming the caller's
//! buffer so `miraged` can replay the exact initial TCP payload to `dest` on
//! fallback.

/// Default maximum number of bytes buffered for `ClientHello` inspection (16 KiB).
pub const DEFAULT_MAX_CLIENT_HELLO_BYTES: usize = 16 * 1024;

/// TLS record content type for Handshake messages.
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// TLS handshake message type for `ClientHello`.
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// Maximum TLS plaintext record fragment length per RFC 8446 §5.1.
const MAX_TLS_RECORD_FRAGMENT: usize = 16 * 1024;

/// TLS extension type: `server_name` (SNI).
const EXT_SERVER_NAME: u16 = 0x0000;

/// TLS extension type: `supported_versions`.
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// TLS extension type: `key_share`.
const EXT_KEY_SHARE: u16 = 0x0033;

/// NamedGroup: X25519 (`0x001d`).
const GROUP_X25519: u16 = 0x001d;

/// NamedGroup: X25519MLKEM768 hybrid post-quantum key exchange (`0x11ec`).
const GROUP_X25519_MLKEM768: u16 = 0x11ec;

/// Expected client key share length for X25519 (32 bytes).
const X25519_KEY_SHARE_LEN: usize = 32;

/// Expected client key share length for X25519MLKEM768 (1184-byte ML-KEM-768 + 32-byte X25519).
const X25519_MLKEM768_KEY_SHARE_LEN: usize = 1216;

/// TLS 1.3 protocol version wire value (`0x0304`).
const TLS_VERSION_1_3: u16 = 0x0304;

/// Minimum plausible `ClientHello` body length:
/// 2 (legacy_version) + 32 (random) + 1 (session_id_len) + 2 (cipher_suites_len) + 1 (comp_len).
const MIN_CLIENT_HELLO_BODY_LEN: usize = 38;

/// Reason a connection cannot be processed as a Reality `ClientHello` and must
/// fall back transparently to `dest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackReason {
    /// Initial bytes do not start with a valid TLS handshake record (`0x16 0x03 0x00..=0x04`).
    NotTlsHandshake,
    /// First handshake message is not a `ClientHello` (`0x01`).
    NotClientHello,
    /// Record or `ClientHello` exceeds the configured inspection byte budget.
    Oversize,
    /// Structurally invalid TLS record or `ClientHello` encoding.
    Malformed,
}

/// Result of non-destructive `ClientHello` inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectOutcome {
    /// More bytes are needed from the socket before a decision can be made.
    NeedMoreData,
    /// A complete `ClientHello` was parsed successfully.
    ClientHello(Box<ClientHelloInfo>),
    /// Input is non-TLS, malformed, or oversized; delegate transparently to `dest`.
    Fallback(FallbackReason),
}

/// Fixed-capacity buffer for a TLS Session ID (0..=32 bytes, zero heap allocation).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionId {
    bytes: [u8; 32],
    len: u8,
}

impl SessionId {
    /// Returns the Session ID bytes as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        let len = usize::from(self.len);
        self.bytes.get(..len).unwrap_or(&[])
    }

    /// Returns the length of the Session ID in bytes (`0..=32`).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `true` if the Session ID is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for SessionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionId").field("len", &self.len).finish()
    }
}

/// Fixed-capacity ASCII hostname extracted from the TLS `server_name` extension.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SniHost {
    bytes: [u8; 255],
    len: u8,
}

impl SniHost {
    /// Attempts to construct an `SniHost` from raw wire bytes.
    fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.is_empty() || raw.len() > 255 {
            return None;
        }
        if !raw.iter().all(|b| b.is_ascii_graphic() && *b != b'\\') {
            return None;
        }
        let len_u8 = u8::try_from(raw.len()).ok()?;
        let mut bytes = [0u8; 255];
        let dest = bytes.get_mut(..raw.len())?;
        dest.copy_from_slice(raw);
        Some(Self { bytes, len: len_u8 })
    }

    /// Returns the SNI hostname as a UTF-8 string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        let len = usize::from(self.len);
        let slice = self.bytes.get(..len).unwrap_or(&[]);
        core::str::from_utf8(slice).unwrap_or("")
    }

    /// Performs exact ASCII case-insensitive matching against an allowed server name.
    #[must_use]
    pub fn matches_ascii_case_insensitive(&self, allowed: &str) -> bool {
        self.as_str().eq_ignore_ascii_case(allowed)
    }
}

impl core::fmt::Debug for SniHost {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SniHost").field("len", &self.len).finish()
    }
}

/// Key shares extracted from the TLS `key_share` extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyShares {
    /// Classical X25519 ephemeral public key (`0x001d`), if offered.
    pub x25519: Option<[u8; 32]>,
    /// Whether the hybrid post-quantum group `X25519MLKEM768` (`0x11ec`) was offered.
    pub offers_x25519_mlkem768: bool,
}

/// Parsed fields of a TLS `ClientHello` required for SNI routing and Reality auth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// Legacy `ClientHello.client_version` field (typically `0x0303`).
    pub legacy_version: u16,
    /// 32-byte `ClientHello.random`.
    pub random: [u8; 32],
    /// Legacy `ClientHello.session_id` (carries the 32-byte Reality auth token).
    pub session_id: SessionId,
    /// Extracted SNI `host_name`, if present.
    pub sni: Option<SniHost>,
    /// Key shares offered in the `key_share` extension.
    pub key_shares: KeyShares,
    /// Whether `supported_versions` advertises TLS 1.3 (`0x0304`).
    pub offers_tls13: bool,
    /// Total TLS wire bytes consumed by the record(s) forming this `ClientHello`.
    pub wire_bytes_len: usize,
}

impl ClientHelloInfo {
    /// Returns `true` if the extracted SNI matches any entry in `server_names`
    /// using exact ASCII case-insensitive comparison.
    #[must_use]
    pub fn matches_any_server_name(&self, server_names: &[String]) -> bool {
        let Some(sni) = &self.sni else {
            return false;
        };
        server_names
            .iter()
            .any(|allowed| sni.matches_ascii_case_insensitive(allowed))
    }
}

/// Inspects a buffered prefix of an incoming TCP stream for a TLS `ClientHello`
/// without mutating `buf`.
///
/// Handles both single-record `ClientHello` messages (zero heap allocation)
/// and multi-record fragmented handshake messages up to `max_bytes`.
#[must_use]
pub fn inspect_client_hello(buf: &[u8], max_bytes: usize) -> InspectOutcome {
    if max_bytes == 0 {
        return InspectOutcome::Fallback(FallbackReason::Oversize);
    }
    if buf.is_empty() {
        return InspectOutcome::NeedMoreData;
    }

    // Fail fast on obvious non-TLS prefixes (e.g., HTTP, SSH, raw noise)
    // before waiting for a full 5-byte record header.
    if let Some(first_record_outcome) = precheck_record_prefix(buf, max_bytes) {
        return first_record_outcome;
    }

    let Some(first_header) = parse_record_header(buf) else {
        return InspectOutcome::NeedMoreData;
    };

    let Some(first_record_end) = 5usize.checked_add(first_header.fragment_len) else {
        return InspectOutcome::Fallback(FallbackReason::Oversize);
    };
    if first_record_end > max_bytes {
        return InspectOutcome::Fallback(FallbackReason::Oversize);
    }

    let Some(first_fragment) = buf.get(5..first_record_end) else {
        return if buf.len() >= max_bytes {
            InspectOutcome::Fallback(FallbackReason::Oversize)
        } else {
            InspectOutcome::NeedMoreData
        };
    };

    // Zero-copy fast path: entire ClientHello fits inside the first TLS record.
    if first_fragment.len() >= 4 {
        let Some(msg_type) = first_fragment.first().copied() else {
            return InspectOutcome::Fallback(FallbackReason::Malformed);
        };
        if msg_type != TLS_HANDSHAKE_CLIENT_HELLO {
            return InspectOutcome::Fallback(FallbackReason::NotClientHello);
        }
        let Some(hs_len) = read_u24_at(first_fragment, 1) else {
            return InspectOutcome::Fallback(FallbackReason::Malformed);
        };
        if hs_len < MIN_CLIENT_HELLO_BODY_LEN {
            return InspectOutcome::Fallback(FallbackReason::Malformed);
        }
        let Some(hs_total) = 4usize.checked_add(hs_len) else {
            return InspectOutcome::Fallback(FallbackReason::Oversize);
        };
        if hs_total > max_bytes {
            return InspectOutcome::Fallback(FallbackReason::Oversize);
        }

        if first_fragment.len() >= hs_total {
            let Some(body) = first_fragment.get(4..hs_total) else {
                return InspectOutcome::Fallback(FallbackReason::Malformed);
            };
            return match parse_client_hello_body(body, first_record_end) {
                Ok(info) => InspectOutcome::ClientHello(Box::new(info)),
                Err(reason) => InspectOutcome::Fallback(reason),
            };
        }
    }

    // Slow path: handshake message is fragmented across multiple TLS records.
    reassemble_and_parse(buf, max_bytes)
}

#[derive(Clone, Copy)]
struct RecordHeader {
    fragment_len: usize,
}

fn precheck_record_prefix(buf: &[u8], max_bytes: usize) -> Option<InspectOutcome> {
    if let Some(&ct) = buf.first() {
        if ct != TLS_CONTENT_TYPE_HANDSHAKE {
            return Some(InspectOutcome::Fallback(FallbackReason::NotTlsHandshake));
        }
    }
    if let Some(&major) = buf.get(1) {
        if major != 0x03 {
            return Some(InspectOutcome::Fallback(FallbackReason::NotTlsHandshake));
        }
    }
    if let Some(&minor) = buf.get(2) {
        if minor > 0x04 {
            return Some(InspectOutcome::Fallback(FallbackReason::NotTlsHandshake));
        }
    }
    if buf.len() > max_bytes {
        return Some(InspectOutcome::Fallback(FallbackReason::Oversize));
    }
    None
}

fn parse_record_header(buf: &[u8]) -> Option<RecordHeader> {
    let hdr = buf.get(..5)?;
    let b3 = *hdr.get(3)?;
    let b4 = *hdr.get(4)?;
    let fragment_len = usize::from(u16::from_be_bytes([b3, b4]));
    Some(RecordHeader { fragment_len })
}

fn validate_record_header(hdr: &[u8]) -> Result<RecordHeader, FallbackReason> {
    let ct = *hdr.first().ok_or(FallbackReason::Malformed)?;
    let major = *hdr.get(1).ok_or(FallbackReason::Malformed)?;
    let minor = *hdr.get(2).ok_or(FallbackReason::Malformed)?;
    let b3 = *hdr.get(3).ok_or(FallbackReason::Malformed)?;
    let b4 = *hdr.get(4).ok_or(FallbackReason::Malformed)?;

    if ct != TLS_CONTENT_TYPE_HANDSHAKE || major != 0x03 || minor > 0x04 {
        return Err(FallbackReason::NotTlsHandshake);
    }

    let fragment_len = usize::from(u16::from_be_bytes([b3, b4]));
    if fragment_len == 0 || fragment_len > MAX_TLS_RECORD_FRAGMENT {
        return Err(FallbackReason::Malformed);
    }

    Ok(RecordHeader { fragment_len })
}

fn reassemble_and_parse(buf: &[u8], max_bytes: usize) -> InspectOutcome {
    let mut offset = 0usize;
    let mut reassembled: Vec<u8> = Vec::with_capacity(buf.len().min(max_bytes));
    let mut expected_hs_total: Option<usize> = None;

    loop {
        let Some(remaining) = buf.get(offset..) else {
            return InspectOutcome::Fallback(FallbackReason::Malformed);
        };
        if remaining.is_empty() {
            return if buf.len() >= max_bytes {
                InspectOutcome::Fallback(FallbackReason::Oversize)
            } else {
                InspectOutcome::NeedMoreData
            };
        }

        if let Some(outcome) = precheck_record_prefix(remaining, max_bytes) {
            return outcome;
        }

        let Some(hdr_bytes) = remaining.get(..5) else {
            return if buf.len() >= max_bytes {
                InspectOutcome::Fallback(FallbackReason::Oversize)
            } else {
                InspectOutcome::NeedMoreData
            };
        };

        let hdr = match validate_record_header(hdr_bytes) {
            Ok(h) => h,
            Err(reason) => return InspectOutcome::Fallback(reason),
        };

        let Some(record_total) = 5usize.checked_add(hdr.fragment_len) else {
            return InspectOutcome::Fallback(FallbackReason::Oversize);
        };
        let Some(next_offset) = offset.checked_add(record_total) else {
            return InspectOutcome::Fallback(FallbackReason::Oversize);
        };
        if next_offset > max_bytes {
            return InspectOutcome::Fallback(FallbackReason::Oversize);
        }

        let Some(fragment) = remaining.get(5..record_total) else {
            return if buf.len() >= max_bytes {
                InspectOutcome::Fallback(FallbackReason::Oversize)
            } else {
                InspectOutcome::NeedMoreData
            };
        };

        let Some(new_reassembled_len) = reassembled.len().checked_add(fragment.len()) else {
            return InspectOutcome::Fallback(FallbackReason::Oversize);
        };
        if new_reassembled_len > max_bytes {
            return InspectOutcome::Fallback(FallbackReason::Oversize);
        }
        reassembled.extend_from_slice(fragment);
        offset = next_offset;

        if expected_hs_total.is_none() {
            if let Some(&msg_type) = reassembled.first() {
                if msg_type != TLS_HANDSHAKE_CLIENT_HELLO {
                    return InspectOutcome::Fallback(FallbackReason::NotClientHello);
                }
            }
            if reassembled.len() >= 4 {
                let Some(hs_len) = read_u24_at(&reassembled, 1) else {
                    return InspectOutcome::Fallback(FallbackReason::Malformed);
                };
                if hs_len < MIN_CLIENT_HELLO_BODY_LEN {
                    return InspectOutcome::Fallback(FallbackReason::Malformed);
                }
                let Some(hs_total) = 4usize.checked_add(hs_len) else {
                    return InspectOutcome::Fallback(FallbackReason::Oversize);
                };
                if hs_total > max_bytes {
                    return InspectOutcome::Fallback(FallbackReason::Oversize);
                }
                expected_hs_total = Some(hs_total);
            }
        }

        if let Some(hs_total) = expected_hs_total {
            if reassembled.len() >= hs_total {
                let Some(body) = reassembled.get(4..hs_total) else {
                    return InspectOutcome::Fallback(FallbackReason::Malformed);
                };
                return match parse_client_hello_body(body, offset) {
                    Ok(info) => InspectOutcome::ClientHello(Box::new(info)),
                    Err(reason) => InspectOutcome::Fallback(reason),
                };
            }
        }
    }
}

fn read_u24_at(buf: &[u8], start: usize) -> Option<usize> {
    let b0 = *buf.get(start)?;
    let b1 = *buf.get(start.checked_add(1)?)?;
    let b2 = *buf.get(start.checked_add(2)?)?;
    let val = u32::from_be_bytes([0, b0, b1, b2]);
    usize::try_from(val).ok()
}

fn parse_client_hello_body(
    body: &[u8],
    wire_bytes_len: usize,
) -> Result<ClientHelloInfo, FallbackReason> {
    let mut r = SliceReader::new(body);

    let legacy_version = r.read_u16()?;
    if (legacy_version >> 8) != 0x03 {
        return Err(FallbackReason::Malformed);
    }

    let random = r.read_array::<32>()?;

    let session_id_len = usize::from(r.read_u8()?);
    if session_id_len > 32 {
        return Err(FallbackReason::Malformed);
    }
    let session_id_raw = r.read_slice(session_id_len)?;
    let mut sid_bytes = [0u8; 32];
    if let Some(dst) = sid_bytes.get_mut(..session_id_len) {
        dst.copy_from_slice(session_id_raw);
    } else {
        return Err(FallbackReason::Malformed);
    }
    let sid_len_u8 = u8::try_from(session_id_len).map_err(|_| FallbackReason::Malformed)?;
    let session_id = SessionId {
        bytes: sid_bytes,
        len: sid_len_u8,
    };

    let cipher_suites_len = usize::from(r.read_u16()?);
    if cipher_suites_len < 2 || (cipher_suites_len % 2) != 0 {
        return Err(FallbackReason::Malformed);
    }
    let _ = r.read_slice(cipher_suites_len)?;

    let compression_len = usize::from(r.read_u8()?);
    if compression_len < 1 {
        return Err(FallbackReason::Malformed);
    }
    let _ = r.read_slice(compression_len)?;

    let mut sni = None;
    let mut key_shares = KeyShares::default();
    let mut offers_tls13 = false;

    if !r.is_empty() {
        let extensions_len = usize::from(r.read_u16()?);
        let extensions_slice = r.read_slice(extensions_len)?;
        if !r.is_empty() {
            return Err(FallbackReason::Malformed);
        }

        let mut ext_reader = SliceReader::new(extensions_slice);
        let mut seen_sni = false;
        let mut seen_key_share = false;
        let mut seen_supported_versions = false;

        while !ext_reader.is_empty() {
            let ext_type = ext_reader.read_u16()?;
            let ext_len = usize::from(ext_reader.read_u16()?);
            let ext_data = ext_reader.read_slice(ext_len)?;

            match ext_type {
                EXT_SERVER_NAME => {
                    if seen_sni {
                        return Err(FallbackReason::Malformed);
                    }
                    seen_sni = true;
                    sni = Some(parse_sni_extension(ext_data)?);
                }
                EXT_KEY_SHARE => {
                    if seen_key_share {
                        return Err(FallbackReason::Malformed);
                    }
                    seen_key_share = true;
                    key_shares = parse_key_share_extension(ext_data)?;
                }
                EXT_SUPPORTED_VERSIONS => {
                    if seen_supported_versions {
                        return Err(FallbackReason::Malformed);
                    }
                    seen_supported_versions = true;
                    offers_tls13 = parse_supported_versions_extension(ext_data)?;
                }
                _ => {}
            }
        }
    }

    Ok(ClientHelloInfo {
        legacy_version,
        random,
        session_id,
        sni,
        key_shares,
        offers_tls13,
        wire_bytes_len,
    })
}

fn parse_sni_extension(ext_data: &[u8]) -> Result<SniHost, FallbackReason> {
    let mut r = SliceReader::new(ext_data);
    let list_len = usize::from(r.read_u16()?);
    if list_len == 0 || list_len != r.remaining() {
        return Err(FallbackReason::Malformed);
    }

    let mut host: Option<SniHost> = None;
    while !r.is_empty() {
        let name_type = r.read_u8()?;
        let name_len = usize::from(r.read_u16()?);
        let name_bytes = r.read_slice(name_len)?;
        if name_type == 0x00 {
            if host.is_some() {
                return Err(FallbackReason::Malformed);
            }
            let parsed = SniHost::from_bytes(name_bytes).ok_or(FallbackReason::Malformed)?;
            host = Some(parsed);
        }
    }

    host.ok_or(FallbackReason::Malformed)
}

fn parse_key_share_extension(ext_data: &[u8]) -> Result<KeyShares, FallbackReason> {
    let mut r = SliceReader::new(ext_data);
    let shares_len = usize::from(r.read_u16()?);
    if shares_len != r.remaining() {
        return Err(FallbackReason::Malformed);
    }

    let mut shares = KeyShares::default();
    while !r.is_empty() {
        let group = r.read_u16()?;
        let key_len = usize::from(r.read_u16()?);
        let key_bytes = r.read_slice(key_len)?;

        if group == GROUP_X25519 {
            if shares.x25519.is_some() || key_bytes.len() != X25519_KEY_SHARE_LEN {
                return Err(FallbackReason::Malformed);
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(key_bytes);
            shares.x25519 = Some(key);
        } else if group == GROUP_X25519_MLKEM768 {
            if shares.offers_x25519_mlkem768 || key_bytes.len() != X25519_MLKEM768_KEY_SHARE_LEN {
                return Err(FallbackReason::Malformed);
            }
            shares.offers_x25519_mlkem768 = true;
        }
    }

    Ok(shares)
}

fn parse_supported_versions_extension(ext_data: &[u8]) -> Result<bool, FallbackReason> {
    let mut r = SliceReader::new(ext_data);
    let list_len = usize::from(r.read_u8()?);
    if list_len < 2 || (list_len % 2) != 0 || list_len != r.remaining() {
        return Err(FallbackReason::Malformed);
    }

    let mut has_tls13 = false;
    while !r.is_empty() {
        let version = r.read_u16()?;
        if version == TLS_VERSION_1_3 {
            has_tls13 = true;
        }
    }
    Ok(has_tls13)
}

struct SliceReader<'a> {
    buf: &'a [u8],
}

impl<'a> SliceReader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    const fn remaining(&self) -> usize {
        self.buf.len()
    }

    const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], FallbackReason> {
        let (head, tail) = self
            .buf
            .split_at_checked(len)
            .ok_or(FallbackReason::Malformed)?;
        self.buf = tail;
        Ok(head)
    }

    fn read_u8(&mut self) -> Result<u8, FallbackReason> {
        let slice = self.read_slice(1)?;
        slice.first().copied().ok_or(FallbackReason::Malformed)
    }

    fn read_u16(&mut self) -> Result<u16, FallbackReason> {
        let slice = self.read_slice(2)?;
        let b0 = *slice.first().ok_or(FallbackReason::Malformed)?;
        let b1 = *slice.get(1).ok_or(FallbackReason::Malformed)?;
        Ok(u16::from_be_bytes([b0, b1]))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], FallbackReason> {
        let slice = self.read_slice(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello_body(
        sni: Option<&str>,
        session_id: &[u8],
        x25519_key: Option<[u8; 32]>,
        include_mlkem768: bool,
        include_tls13: bool,
    ) -> Vec<u8> {
        let mut extensions = Vec::new();

        if let Some(host) = sni {
            let host_bytes = host.as_bytes();
            let entry_len = 1usize.saturating_add(2).saturating_add(host_bytes.len());
            let ext_len = 2usize.saturating_add(entry_len);
            extensions.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
            extensions.extend_from_slice(&(ext_len as u16).to_be_bytes());
            extensions.extend_from_slice(&(entry_len as u16).to_be_bytes());
            extensions.push(0x00);
            extensions.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
            extensions.extend_from_slice(host_bytes);
        }

        if include_tls13 {
            extensions.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
            extensions.extend_from_slice(&5u16.to_be_bytes());
            extensions.push(4);
            extensions.extend_from_slice(&0x0304u16.to_be_bytes());
            extensions.extend_from_slice(&0x0303u16.to_be_bytes());
        }

        if x25519_key.is_some() || include_mlkem768 {
            let mut shares = Vec::new();
            if include_mlkem768 {
                shares.extend_from_slice(&GROUP_X25519_MLKEM768.to_be_bytes());
                shares.extend_from_slice(&(X25519_MLKEM768_KEY_SHARE_LEN as u16).to_be_bytes());
                shares.extend(core::iter::repeat_n(0xAB, X25519_MLKEM768_KEY_SHARE_LEN));
            }
            if let Some(k) = x25519_key {
                shares.extend_from_slice(&GROUP_X25519.to_be_bytes());
                shares.extend_from_slice(&(X25519_KEY_SHARE_LEN as u16).to_be_bytes());
                shares.extend_from_slice(&k);
            }
            let ext_len = 2usize.saturating_add(shares.len());
            extensions.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
            extensions.extend_from_slice(&(ext_len as u16).to_be_bytes());
            extensions.extend_from_slice(&(shares.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&shares);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend([0x11u8; 32]);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.extend_from_slice(&0x1302u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        body
    }

    fn wrap_handshake_records(handshake_msg: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut wire = Vec::new();
        for chunk in handshake_msg.chunks(chunk_size) {
            wire.push(TLS_CONTENT_TYPE_HANDSHAKE);
            wire.extend_from_slice(&0x0301u16.to_be_bytes());
            wire.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            wire.extend_from_slice(chunk);
        }
        wire
    }

    fn build_handshake_msg(body: &[u8]) -> Vec<u8> {
        let len_bytes = (body.len() as u32).to_be_bytes();
        let mut msg = Vec::with_capacity(4usize.saturating_add(body.len()));
        msg.push(TLS_HANDSHAKE_CLIENT_HELLO);
        if let Some(tail) = len_bytes.get(1..4) {
            msg.extend_from_slice(tail);
        }
        msg.extend_from_slice(body);
        msg
    }

    #[test]
    fn parses_single_record_client_hello() {
        let sid = [0x42u8; 32];
        let x25519 = [0x99u8; 32];
        let body = build_client_hello_body(Some("Example.COM"), &sid, Some(x25519), false, true);
        let msg = build_handshake_msg(&body);
        let wire = wrap_handshake_records(&msg, msg.len());

        let outcome = inspect_client_hello(&wire, DEFAULT_MAX_CLIENT_HELLO_BYTES);
        match outcome {
            InspectOutcome::ClientHello(info) => {
                assert_eq!(info.legacy_version, 0x0303);
                assert_eq!(info.random, [0x11u8; 32]);
                assert_eq!(info.session_id.as_slice(), &sid);
                assert_eq!(info.sni.as_ref().map(SniHost::as_str), Some("Example.COM"));
                assert!(info.matches_any_server_name(&["example.com".to_owned()]));
                assert!(!info.matches_any_server_name(&["sub.example.com".to_owned()]));
                assert_eq!(info.key_shares.x25519, Some(x25519));
                assert!(!info.key_shares.offers_x25519_mlkem768);
                assert!(info.offers_tls13);
                assert_eq!(info.wire_bytes_len, wire.len());
            }
            other => {
                assert!(
                    matches!(other, InspectOutcome::ClientHello(_)),
                    "unexpected outcome: {other:?}"
                );
            }
        }
    }

    #[test]
    fn parses_fragmented_pq_client_hello_across_multiple_records() {
        let sid = [0x24u8; 32];
        let x25519 = [0x77u8; 32];
        let body = build_client_hello_body(Some("pq.example.org"), &sid, Some(x25519), true, true);
        let msg = build_handshake_msg(&body);
        // Fragment across small 17-byte TLS records to exercise multi-record reassembly
        // and header spanning multiple records.
        let wire = wrap_handshake_records(&msg, 17);

        // Partial prefixes must request more data without failing.
        for prefix_len in [1usize, 3, 5, 22, wire.len().saturating_sub(1)] {
            if let Some(prefix) = wire.get(..prefix_len) {
                assert_eq!(
                    inspect_client_hello(prefix, DEFAULT_MAX_CLIENT_HELLO_BYTES),
                    InspectOutcome::NeedMoreData
                );
            }
        }

        let outcome = inspect_client_hello(&wire, DEFAULT_MAX_CLIENT_HELLO_BYTES);
        match outcome {
            InspectOutcome::ClientHello(info) => {
                assert_eq!(
                    info.sni.as_ref().map(SniHost::as_str),
                    Some("pq.example.org")
                );
                assert_eq!(info.key_shares.x25519, Some(x25519));
                assert!(info.key_shares.offers_x25519_mlkem768);
                assert!(info.offers_tls13);
                assert_eq!(info.wire_bytes_len, wire.len());
            }
            other => {
                assert!(
                    matches!(other, InspectOutcome::ClientHello(_)),
                    "unexpected outcome: {other:?}"
                );
            }
        }
    }

    #[test]
    fn detects_non_tls_and_oversize_as_fallback() {
        assert_eq!(
            inspect_client_hello(b"GET / HTTP/1.1\r\n", DEFAULT_MAX_CLIENT_HELLO_BYTES),
            InspectOutcome::Fallback(FallbackReason::NotTlsHandshake)
        );
        assert_eq!(
            inspect_client_hello(b"SSH-2.0-OpenSSH_9.0\r\n", DEFAULT_MAX_CLIENT_HELLO_BYTES),
            InspectOutcome::Fallback(FallbackReason::NotTlsHandshake)
        );

        let oversized = vec![0x16, 0x03, 0x01, 0x40, 0x01];
        assert_eq!(
            inspect_client_hello(&oversized, DEFAULT_MAX_CLIENT_HELLO_BYTES),
            InspectOutcome::Fallback(FallbackReason::Oversize)
        );
    }

    #[test]
    fn rejects_malformed_session_id_and_duplicate_extensions() {
        let mut body = build_client_hello_body(Some("a.com"), &[1u8; 32], None, false, true);
        // Corrupt session_id_len (offset 34) to 33 (> 32).
        if let Some(slot) = body.get_mut(34) {
            *slot = 33;
        }
        let msg = build_handshake_msg(&body);
        let wire = wrap_handshake_records(&msg, msg.len());
        assert_eq!(
            inspect_client_hello(&wire, DEFAULT_MAX_CLIENT_HELLO_BYTES),
            InspectOutcome::Fallback(FallbackReason::Malformed)
        );
    }

    #[test]
    fn rejects_non_client_hello_handshake_even_when_fragmented() {
        // Single-byte TLS record carrying handshake type 0x02 (ServerHello).
        let wire = [0x16, 0x03, 0x01, 0x00, 0x01, 0x02];
        assert_eq!(
            inspect_client_hello(&wire, DEFAULT_MAX_CLIENT_HELLO_BYTES),
            InspectOutcome::Fallback(FallbackReason::NotClientHello)
        );
    }

    #[test]
    fn rejects_duplicate_x25519_key_share_entries() {
        let mut extensions = Vec::new();
        let mut shares = Vec::new();
        for _ in 0..2 {
            shares.extend_from_slice(&GROUP_X25519.to_be_bytes());
            shares.extend_from_slice(&(X25519_KEY_SHARE_LEN as u16).to_be_bytes());
            shares.extend([0x55u8; 32]);
        }
        let ext_len = 2usize.saturating_add(shares.len());
        extensions.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        extensions.extend_from_slice(&(ext_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(shares.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&shares);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend([0x11u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let msg = build_handshake_msg(&body);
        let wire = wrap_handshake_records(&msg, msg.len());
        assert_eq!(
            inspect_client_hello(&wire, DEFAULT_MAX_CLIENT_HELLO_BYTES),
            InspectOutcome::Fallback(FallbackReason::Malformed)
        );
    }
}
