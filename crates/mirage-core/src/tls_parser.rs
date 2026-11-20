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
pub const MAX_TLS_RECORD_FRAGMENT: usize = 16 * 1024;

/// Maximum TLS 1.3 encrypted record fragment length per RFC 8446 §5.4 (`2^14 + 256`).
pub const MAX_TLS_CIPHERTEXT_RECORD_LEN: usize = MAX_TLS_RECORD_FRAGMENT + 256;

/// TLS extension type: `server_name` (SNI).
const EXT_SERVER_NAME: u16 = 0x0000;

/// TLS extension type: `application_layer_protocol_negotiation` (ALPN).
const EXT_ALPN: u16 = 0x0010;

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

/// ML-KEM-768 encapsulation key prefix length inside `X25519MLKEM768` client share.
const MLKEM768_EK_LEN: usize = 1184;

/// Expected server key share length for `X25519MLKEM768` (1088-byte ciphertext + 32-byte X25519).
const X25519_MLKEM768_SERVER_SHARE_LEN: usize = 1120;

/// TLS record content type for ChangeCipherSpec.
const TLS_CONTENT_TYPE_CCS: u8 = 0x14;

/// TLS record content type for ApplicationData (encrypted TLS 1.3 records).
const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

/// TLS handshake message type for `ServerHello`.
const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;

/// TLS 1.3 `HelloRetryRequest` special random value (RFC 8446 §4.1.3).
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyShares {
    /// Classical X25519 ephemeral public key (`0x001d`), if offered.
    pub x25519: Option<[u8; 32]>,
    /// Full hybrid post-quantum share `X25519MLKEM768` (`0x11ec`), if offered.
    pub x25519_mlkem768: Option<Box<[u8; X25519_MLKEM768_KEY_SHARE_LEN]>>,
}

impl KeyShares {
    /// Returns `true` if `X25519MLKEM768` (`0x11ec`) was offered by the client.
    #[must_use]
    pub const fn offers_x25519_mlkem768(&self) -> bool {
        self.x25519_mlkem768.is_some()
    }

    /// Returns the 32-byte client X25519 public key used for Reality `AuthKey`
    /// derivation: prefers standalone `X25519` (`0x001d`), falling back to the
    /// X25519 tail of `X25519MLKEM768` (`[1184..1216]`).
    #[must_use]
    pub fn reality_auth_x25519_pubkey(&self) -> Option<[u8; 32]> {
        if let Some(pk) = self.x25519 {
            return Some(pk);
        }
        let hybrid = self.x25519_mlkem768.as_ref()?;
        let tail = hybrid.get(MLKEM768_EK_LEN..)?;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(tail);
        Some(pk)
    }
}

/// Preferred ALPN protocol offered by the client in extension `0x0010`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OfferedAlpn {
    /// Client offered `"h2"`.
    H2,
    /// Client offered `"http/1.1"` (without `"h2"`).
    Http11,
}

impl OfferedAlpn {
    /// Returns the wire protocol bytes (`b"h2"` or `b"http/1.1"`).
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::H2 => b"h2",
            Self::Http11 => b"http/1.1",
        }
    }
}

/// Parsed fields of a TLS `ClientHello` required for SNI routing and Reality auth.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// Legacy `ClientHello.client_version` field (typically `0x0303`).
    pub legacy_version: u16,
    /// 32-byte `ClientHello.random`.
    pub random: [u8; 32],
    /// Legacy `ClientHello.session_id` (carries the 32-byte Reality auth token).
    pub session_id: SessionId,
    /// Extracted SNI `host_name`, if present.
    pub sni: Option<SniHost>,
    /// Preferred ALPN protocol offered by the client (`h2` or `http/1.1`), if any.
    pub offered_alpn: Option<OfferedAlpn>,
    /// Key shares offered in the `key_share` extension.
    pub key_shares: KeyShares,
    /// Whether `supported_versions` advertises TLS 1.3 (`0x0304`).
    pub offers_tls13: bool,
    /// First recognized TLS 1.3 cipher suite offered by the client (for profile keying).
    pub preferred_tls13_cipher: Option<Tls13CipherSuiteId>,
    /// Bitmask of TLS 1.3 cipher suites offered by the client
    /// (bit 0 = AES_128_GCM_SHA256, bit 1 = AES_256_GCM_SHA384, bit 2 = CHACHA20_POLY1305_SHA256).
    pub offered_tls13_ciphers: u8,
    /// Total TLS wire bytes consumed by the record(s) forming this `ClientHello`.
    pub wire_bytes_len: usize,
    /// Reassembled TLS handshake message (`0x01 || u24_len || body`, without 5-byte record headers).
    pub handshake_raw: Vec<u8>,
}

impl core::fmt::Debug for ClientHelloInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientHelloInfo")
            .field("legacy_version", &self.legacy_version)
            .field("random", &"[REDACTED]")
            .field("session_id", &self.session_id)
            .field("sni", &self.sni)
            .field("offered_alpn", &self.offered_alpn)
            .field("offers_tls13", &self.offers_tls13)
            .field("preferred_tls13_cipher", &self.preferred_tls13_cipher)
            .field("offered_tls13_ciphers", &self.offered_tls13_ciphers)
            .field("wire_bytes_len", &self.wire_bytes_len)
            .field("handshake_raw_len", &self.handshake_raw.len())
            .finish()
    }
}

impl ClientHelloInfo {
    /// Returns `true` if the client offered the given TLS 1.3 cipher suite.
    #[must_use]
    pub const fn offers_cipher_suite(&self, suite: Tls13CipherSuiteId) -> bool {
        let bit = match suite {
            Tls13CipherSuiteId::Aes128GcmSha256 => 1 << 0,
            Tls13CipherSuiteId::Aes256GcmSha384 => 1 << 1,
            Tls13CipherSuiteId::ChaCha20Poly1305Sha256 => 1 << 2,
        };
        (self.offered_tls13_ciphers & bit) != 0
    }

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

    /// Builds the Reality AEAD Additional Authenticated Data (AAD) by cloning
    /// `handshake_raw` and zeroing the 32-byte `SessionId` field at bytes
    /// `39..71`. Returns `None` if `session_id.len() != 32` or the layout is
    /// shorter than 71 bytes.
    #[must_use]
    pub fn build_reality_aad(&self) -> Option<Vec<u8>> {
        if self.session_id.len() != 32 {
            return None;
        }
        // 1 (msg_type) + 3 (hs_len) + 2 (legacy_version) + 32 (random) + 1 (sid_len) = 39
        if self.handshake_raw.get(38) != Some(&32) {
            return None;
        }
        let mut aad = self.handshake_raw.clone();
        let sid_slot = aad.get_mut(39..71)?;
        sid_slot.fill(0);
        Some(aad)
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
    if first_header.fragment_len == 0 || first_header.fragment_len > MAX_TLS_RECORD_FRAGMENT {
        return InspectOutcome::Fallback(FallbackReason::Malformed);
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
            let Some(handshake_raw) = first_fragment.get(..hs_total) else {
                return InspectOutcome::Fallback(FallbackReason::Malformed);
            };
            let Some(body) = first_fragment.get(4..hs_total) else {
                return InspectOutcome::Fallback(FallbackReason::Malformed);
            };
            return match parse_client_hello_body(handshake_raw, body, first_record_end) {
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
                let Some(handshake_raw) = reassembled.get(..hs_total) else {
                    return InspectOutcome::Fallback(FallbackReason::Malformed);
                };
                let Some(body) = reassembled.get(4..hs_total) else {
                    return InspectOutcome::Fallback(FallbackReason::Malformed);
                };
                return match parse_client_hello_body(handshake_raw, body, offset) {
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
    handshake_raw: &[u8],
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
    let cipher_suites_raw = r.read_slice(cipher_suites_len)?;
    let mut offered_tls13_ciphers: u8 = 0;
    let mut preferred_tls13_cipher: Option<Tls13CipherSuiteId> = None;
    for pair in cipher_suites_raw.chunks_exact(2) {
        if let (Some(&b0), Some(&b1)) = (pair.first(), pair.get(1)) {
            let suite_u16 = u16::from_be_bytes([b0, b1]);
            if preferred_tls13_cipher.is_none() {
                preferred_tls13_cipher = Tls13CipherSuiteId::from_u16(suite_u16);
            }
            match suite_u16 {
                0x1301 => offered_tls13_ciphers |= 1 << 0,
                0x1302 => offered_tls13_ciphers |= 1 << 1,
                0x1303 => offered_tls13_ciphers |= 1 << 2,
                _ => {}
            }
        }
    }

    let compression_len = usize::from(r.read_u8()?);
    if compression_len < 1 {
        return Err(FallbackReason::Malformed);
    }
    let _ = r.read_slice(compression_len)?;

    let mut sni = None;
    let mut offered_alpn = None;
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
        let mut seen_alpn = false;
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
                EXT_ALPN => {
                    if seen_alpn {
                        return Err(FallbackReason::Malformed);
                    }
                    seen_alpn = true;
                    offered_alpn = parse_alpn_extension(ext_data)?;
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
        offered_alpn,
        key_shares,
        offers_tls13,
        preferred_tls13_cipher,
        offered_tls13_ciphers,
        wire_bytes_len,
        handshake_raw: handshake_raw.to_vec(),
    })
}

fn parse_alpn_extension(ext_data: &[u8]) -> Result<Option<OfferedAlpn>, FallbackReason> {
    let mut r = SliceReader::new(ext_data);
    let list_len = usize::from(r.read_u16()?);
    if list_len == 0 || list_len != r.remaining() {
        return Err(FallbackReason::Malformed);
    }

    let mut has_h2 = false;
    let mut has_http11 = false;
    while !r.is_empty() {
        let proto_len = usize::from(r.read_u8()?);
        if proto_len == 0 {
            return Err(FallbackReason::Malformed);
        }
        let proto = r.read_slice(proto_len)?;
        if proto == b"h2" {
            has_h2 = true;
        } else if proto == b"http/1.1" {
            has_http11 = true;
        }
    }

    Ok(if has_h2 {
        Some(OfferedAlpn::H2)
    } else if has_http11 {
        Some(OfferedAlpn::Http11)
    } else {
        None
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
            if shares.x25519_mlkem768.is_some() || key_bytes.len() != X25519_MLKEM768_KEY_SHARE_LEN
            {
                return Err(FallbackReason::Malformed);
            }
            let mut key = Box::new([0u8; X25519_MLKEM768_KEY_SHARE_LEN]);
            key.copy_from_slice(key_bytes);
            shares.x25519_mlkem768 = Some(key);
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

/// Supported TLS 1.3 cipher suites for Reality handshake mimicry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tls13CipherSuiteId {
    /// `TLS_AES_128_GCM_SHA256` (`0x1301`)
    Aes128GcmSha256,
    /// `TLS_AES_256_GCM_SHA384` (`0x1302`)
    Aes256GcmSha384,
    /// `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`)
    ChaCha20Poly1305Sha256,
}

impl Tls13CipherSuiteId {
    /// Parses a wire cipher suite identifier.
    #[must_use]
    pub const fn from_u16(raw: u16) -> Option<Self> {
        match raw {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }

    /// Returns the wire 16-bit cipher suite ID.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
            Self::ChaCha20Poly1305Sha256 => 0x1303,
        }
    }
}

/// Supported TLS 1.3 key-exchange groups selected by `dest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedGroup {
    /// Classical X25519 (`0x001d`, 32-byte server share).
    X25519,
    /// Post-quantum hybrid `X25519MLKEM768` (`0x11ec`, 1120-byte server share).
    X25519MlKem768,
}

/// Handshake profile learned from `dest`'s server flight for authenticated-path mimicry.
#[derive(Clone, PartialEq, Eq)]
pub struct DestServerProfile {
    /// Raw `ServerHello` handshake message (`0x02 || u24_len || body`) from `dest`.
    pub server_hello_raw: Vec<u8>,
    /// Byte offset inside `server_hello_raw` where the `key_exchange` bytes begin.
    pub key_exchange_offset: usize,
    /// Length of the `key_exchange` bytes inside `server_hello_raw` (32 or 1120).
    pub key_exchange_len: usize,
    /// Negotiated TLS 1.3 cipher suite.
    pub cipher_suite: Tls13CipherSuiteId,
    /// Negotiated key-exchange group.
    pub selected_group: SelectedGroup,
    /// Whether `dest` sent a middlebox-compatibility `ChangeCipherSpec` record.
    pub send_ccs: bool,
    /// Number of `0x17` encrypted records recorded in `encrypted_record_lens` (`0..=5`).
    pub encrypted_record_count: usize,
    /// Recorded encrypted handshake wire record lengths:
    /// `[EncryptedExtensions, Certificate, CertificateVerify, Finished, NewSessionTicket]`.
    pub encrypted_record_lens: [usize; 5],
}

impl core::fmt::Debug for DestServerProfile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DestServerProfile")
            .field("server_hello_raw_len", &self.server_hello_raw.len())
            .field("key_exchange_offset", &self.key_exchange_offset)
            .field("key_exchange_len", &self.key_exchange_len)
            .field("cipher_suite", &self.cipher_suite)
            .field("selected_group", &self.selected_group)
            .field("send_ccs", &self.send_ccs)
            .field("encrypted_record_count", &self.encrypted_record_count)
            .field("encrypted_record_lens", &self.encrypted_record_lens)
            .finish()
    }
}

impl DestServerProfile {
    /// Produces a per-connection clone of this cached `DestServerProfile` with a
    /// fresh 32-byte `ServerHello.random` and updated `legacy_session_id_echo`
    /// matching the authenticating client's `ClientHello.session_id`.
    ///
    /// Returns `None` if `server_hello_raw` is malformed or incompatible with
    /// the client's session ID length.
    #[must_use]
    pub fn adapt_for_client(&self, session_id: &[u8], mut fresh_random: [u8; 32]) -> Option<Self> {
        // Guard against colliding with the RFC 8446 HelloRetryRequest magic random.
        if fresh_random == HELLO_RETRY_REQUEST_RANDOM {
            fresh_random[0] ^= 0xFF;
        }
        // `server_hello_raw` layout:
        //   [0..4]   handshake header (0x02 || u24 len)
        //   [4..6]   legacy_version (0x03 0x03)
        //   [6..38]  ServerHello.random (32 bytes)
        //   [38]     legacy_session_id_echo length
        //   [39..39+sid_len] legacy_session_id_echo
        let sid_len = usize::from(*self.server_hello_raw.get(38)?);
        if sid_len != session_id.len() {
            return None;
        }
        let sid_end = 39usize.checked_add(sid_len)?;

        let mut adapted = self.clone();
        adapted
            .server_hello_raw
            .get_mut(6..38)?
            .copy_from_slice(&fresh_random);
        adapted
            .server_hello_raw
            .get_mut(39..sid_end)?
            .copy_from_slice(session_id);
        Some(adapted)
    }
}

/// Result of inspecting `dest`'s server flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerFlightStatus {
    /// More bytes are needed to finish parsing `ServerHello` or handshake records.
    NeedMoreData,
    /// `ServerHello` and at least one encrypted handshake record were parsed,
    /// though fewer than 4 separate `0x17` records have arrived so far.
    PartialWithProfile(Box<DestServerProfile>),
    /// `ServerHello` and all 4 encrypted handshake records (plus optional NST) arrived.
    Complete(Box<DestServerProfile>),
    /// `dest` returned non-TLS 1.3, `HelloRetryRequest`, unsupported suite/group, or malformed bytes.
    Invalid,
}

/// Parses `dest`'s server flight (`ServerHello` + optional `ChangeCipherSpec` +
/// encrypted TLS 1.3 handshake records) without mutating `buf`.
#[must_use]
pub fn parse_dest_server_flight(buf: &[u8]) -> ServerFlightStatus {
    if buf.len() < 5 {
        return ServerFlightStatus::NeedMoreData;
    }

    let Ok(sh_hdr) = validate_record_header(buf.get(..5).unwrap_or(&[])) else {
        return ServerFlightStatus::Invalid;
    };
    let Some(sh_rec_end) = 5usize.checked_add(sh_hdr.fragment_len) else {
        return ServerFlightStatus::Invalid;
    };
    let Some(sh_payload) = buf.get(5..sh_rec_end) else {
        return ServerFlightStatus::NeedMoreData;
    };
    if sh_payload.first() != Some(&TLS_HANDSHAKE_SERVER_HELLO) {
        return ServerFlightStatus::Invalid;
    }
    let Some(sh_hs_len) = read_u24_at(sh_payload, 1) else {
        return ServerFlightStatus::Invalid;
    };
    let Some(sh_hs_total) = 4usize.checked_add(sh_hs_len) else {
        return ServerFlightStatus::Invalid;
    };
    if sh_payload.len() != sh_hs_total {
        return ServerFlightStatus::Invalid;
    }
    let Some(sh_raw) = sh_payload.get(..sh_hs_total) else {
        return ServerFlightStatus::Invalid;
    };
    let Some(sh_body) = sh_payload.get(4..sh_hs_total) else {
        return ServerFlightStatus::Invalid;
    };

    let Ok(parsed_sh) = parse_server_hello_body(sh_body, sh_raw) else {
        return ServerFlightStatus::Invalid;
    };

    let mut offset = sh_rec_end;
    let mut send_ccs = false;
    let mut encrypted_record_lens = [0usize; 5];
    let mut enc_count = 0usize;

    while let Some(rem) = buf.get(offset..) {
        if rem.is_empty() {
            break;
        }
        let Some(hdr) = rem.get(..5) else {
            break;
        };
        let ct = *hdr.first().unwrap_or(&0);
        let major = *hdr.get(1).unwrap_or(&0);
        let minor = *hdr.get(2).unwrap_or(&0);
        let b3 = *hdr.get(3).unwrap_or(&0);
        let b4 = *hdr.get(4).unwrap_or(&0);
        if major != 0x03 || minor > 0x04 {
            return ServerFlightStatus::Invalid;
        }
        let frag_len = usize::from(u16::from_be_bytes([b3, b4]));
        if frag_len == 0 || frag_len > MAX_TLS_RECORD_FRAGMENT.saturating_add(256) {
            return ServerFlightStatus::Invalid;
        }
        let Some(rec_total) = 5usize.checked_add(frag_len) else {
            return ServerFlightStatus::Invalid;
        };
        if rem.len() < rec_total {
            break;
        }

        if ct == TLS_CONTENT_TYPE_CCS {
            if send_ccs || enc_count > 0 || rec_total != 6 {
                return ServerFlightStatus::Invalid;
            }
            send_ccs = true;
        } else if ct == TLS_CONTENT_TYPE_APPLICATION_DATA {
            if let Some(slot) = encrypted_record_lens.get_mut(enc_count) {
                *slot = rec_total;
                enc_count = enc_count.saturating_add(1);
            } else {
                break;
            }
        } else {
            return ServerFlightStatus::Invalid;
        }

        let Some(next_offset) = offset.checked_add(rec_total) else {
            break;
        };
        offset = next_offset;
        if enc_count >= 5 {
            break;
        }
    }

    let profile = DestServerProfile {
        server_hello_raw: sh_raw.to_vec(),
        key_exchange_offset: parsed_sh.key_exchange_offset,
        key_exchange_len: parsed_sh.key_exchange_len,
        cipher_suite: parsed_sh.cipher_suite,
        selected_group: parsed_sh.selected_group,
        send_ccs,
        encrypted_record_count: enc_count,
        encrypted_record_lens,
    };

    // Many production TLS 1.3 stacks (Cloudflare, BoringSSL, Nginx, Go) coalesce
    // EncryptedExtensions + Certificate + CertificateVerify + Finished into a
    // single 0x17 record (>= 350 bytes) optionally followed by 1..2 NewSessionTicket records.
    let is_coalesced_flight =
        (1..=3).contains(&enc_count) && encrypted_record_lens.first().copied().unwrap_or(0) >= 350;

    if enc_count >= 4 || is_coalesced_flight {
        ServerFlightStatus::Complete(Box::new(profile))
    } else if enc_count >= 1 {
        ServerFlightStatus::PartialWithProfile(Box::new(profile))
    } else {
        ServerFlightStatus::NeedMoreData
    }
}

struct ParsedServerHello {
    cipher_suite: Tls13CipherSuiteId,
    selected_group: SelectedGroup,
    key_exchange_offset: usize,
    key_exchange_len: usize,
}

fn parse_server_hello_body(
    body: &[u8],
    sh_raw: &[u8],
) -> Result<ParsedServerHello, FallbackReason> {
    let mut r = SliceReader::new(body);
    let legacy_version = r.read_u16()?;
    if legacy_version != 0x0303 {
        return Err(FallbackReason::Malformed);
    }

    let random = r.read_array::<32>()?;
    if random == HELLO_RETRY_REQUEST_RANDOM {
        return Err(FallbackReason::Malformed);
    }

    let sid_len = usize::from(r.read_u8()?);
    if sid_len > 32 {
        return Err(FallbackReason::Malformed);
    }
    let _ = r.read_slice(sid_len)?;

    let cs_raw = r.read_u16()?;
    let cipher_suite = Tls13CipherSuiteId::from_u16(cs_raw).ok_or(FallbackReason::Malformed)?;

    let comp = r.read_u8()?;
    if comp != 0 {
        return Err(FallbackReason::Malformed);
    }

    let ext_len = usize::from(r.read_u16()?);
    let ext_slice = r.read_slice(ext_len)?;
    if !r.is_empty() {
        return Err(FallbackReason::Malformed);
    }

    // Track exact start offset of `ext_slice` within `sh_raw` (4-byte handshake header + body prefix).
    let ext_base_in_body = body
        .len()
        .checked_sub(ext_len)
        .ok_or(FallbackReason::Malformed)?;
    let ext_base_in_sh = 4usize
        .checked_add(ext_base_in_body)
        .ok_or(FallbackReason::Malformed)?;

    let mut er = SliceReader::new(ext_slice);
    let mut is_tls13 = false;
    let mut key_share_info: Option<(SelectedGroup, usize, usize)> = None;

    while !er.is_empty() {
        let ext_type = er.read_u16()?;
        let data_len = usize::from(er.read_u16()?);
        let data_offset_in_ext = ext_slice
            .len()
            .checked_sub(er.remaining())
            .ok_or(FallbackReason::Malformed)?;
        let ext_data = er.read_slice(data_len)?;

        if ext_type == EXT_SUPPORTED_VERSIONS {
            if is_tls13 || ext_data.len() != 2 {
                return Err(FallbackReason::Malformed);
            }
            let b0 = *ext_data.first().ok_or(FallbackReason::Malformed)?;
            let b1 = *ext_data.get(1).ok_or(FallbackReason::Malformed)?;
            if u16::from_be_bytes([b0, b1]) != TLS_VERSION_1_3 {
                return Err(FallbackReason::Malformed);
            }
            is_tls13 = true;
        } else if ext_type == EXT_KEY_SHARE {
            if key_share_info.is_some() {
                return Err(FallbackReason::Malformed);
            }
            let mut kr = SliceReader::new(ext_data);
            let group_raw = kr.read_u16()?;
            let key_len = usize::from(kr.read_u16()?);
            let _ = kr.read_slice(key_len)?;
            if !kr.is_empty() {
                return Err(FallbackReason::Malformed);
            }

            let group = match (group_raw, key_len) {
                (GROUP_X25519, X25519_KEY_SHARE_LEN) => SelectedGroup::X25519,
                (GROUP_X25519_MLKEM768, X25519_MLKEM768_SERVER_SHARE_LEN) => {
                    SelectedGroup::X25519MlKem768
                }
                _ => return Err(FallbackReason::Malformed),
            };
            // Inside `key_share` ServerHello extension: 2 (group) + 2 (key_len) = 4 bytes before key bytes.
            let key_offset = ext_base_in_sh
                .checked_add(data_offset_in_ext)
                .and_then(|v| v.checked_add(4))
                .ok_or(FallbackReason::Malformed)?;
            let key_end = key_offset
                .checked_add(key_len)
                .ok_or(FallbackReason::Malformed)?;
            if sh_raw.get(key_offset..key_end).is_none() {
                return Err(FallbackReason::Malformed);
            }
            key_share_info = Some((group, key_offset, key_len));
        } else {
            // Reject pre_shared_key (0x0029) and any unexpected ServerHello extensions
            // so PSK-resumed flights can never poison DestProfileCache.
            return Err(FallbackReason::Malformed);
        }
    }

    if !is_tls13 {
        return Err(FallbackReason::Malformed);
    }
    let (selected_group, key_exchange_offset, key_exchange_len) =
        key_share_info.ok_or(FallbackReason::Malformed)?;

    Ok(ParsedServerHello {
        cipher_suite,
        selected_group,
        key_exchange_offset,
        key_exchange_len,
    })
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
                assert!(!info.key_shares.offers_x25519_mlkem768());
                assert!(info.offers_tls13);
                assert_eq!(info.wire_bytes_len, wire.len());
                let aad = info.build_reality_aad();
                assert!(aad.is_some());
                if let Some(a) = aad {
                    assert_eq!(a.get(39..71), Some([0u8; 32].as_slice()));
                }
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
                assert!(info.key_shares.offers_x25519_mlkem768());
                assert_eq!(info.key_shares.reality_auth_x25519_pubkey(), Some(x25519));
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

    #[test]
    fn dest_profile_adapt_for_client_patches_random_and_session_id() {
        let mut sh_raw = vec![0x02, 0x00, 0x00, 0x48];
        sh_raw.extend_from_slice(&[0x03, 0x03]);
        sh_raw.extend([0x11u8; 32]);
        sh_raw.push(32);
        sh_raw.extend([0x22u8; 32]);
        sh_raw.extend_from_slice(&[0x13, 0x01, 0x00, 0x00, 0x00]);

        let profile = DestServerProfile {
            server_hello_raw: sh_raw,
            key_exchange_offset: 71,
            key_exchange_len: 0,
            cipher_suite: Tls13CipherSuiteId::Aes128GcmSha256,
            selected_group: SelectedGroup::X25519,
            send_ccs: true,
            encrypted_record_count: 5,
            encrypted_record_lens: [80, 1100, 128, 96, 200],
        };

        let new_sid = [0x99u8; 32];
        let adapted = profile.adapt_for_client(&new_sid, HELLO_RETRY_REQUEST_RANDOM);
        assert!(adapted.is_some());
        if let Some(a) = adapted {
            assert_ne!(
                a.server_hello_raw.get(6..38),
                Some(HELLO_RETRY_REQUEST_RANDOM.as_slice())
            );
            assert_eq!(a.server_hello_raw.get(39..71), Some(new_sid.as_slice()));
            let dbg = format!("{a:?}");
            assert!(!dbg.contains("153"));
            assert!(dbg.contains("server_hello_raw_len"));
        }
    }

    #[test]
    fn parse_dest_server_flight_rejects_psk_and_classifies_coalesced_plus_nst() {
        let mut sh_exts = Vec::new();
        // supported_versions = 0x0304
        sh_exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        // key_share = X25519 (0x001d, 32 bytes)
        sh_exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
        sh_exts.extend([0xABu8; 32]);

        let mut sh_body = Vec::new();
        sh_body.extend_from_slice(&[0x03, 0x03]);
        sh_body.extend([0x12u8; 32]);
        sh_body.push(32);
        sh_body.extend([0x34u8; 32]);
        sh_body.extend_from_slice(&[0x13, 0x01, 0x00]);
        sh_body.extend_from_slice(&(sh_exts.len() as u16).to_be_bytes());
        sh_body.extend_from_slice(&sh_exts);

        let mut sh_hs = vec![0x02];
        let sh_len_bytes = (sh_body.len() as u32).to_be_bytes();
        if let Some(t) = sh_len_bytes.get(1..4) {
            sh_hs.extend_from_slice(t);
        }
        sh_hs.extend_from_slice(&sh_body);

        // Coalesced flight: 1 large 0x17 record (500 bytes) + 1 NST (250 bytes)
        let mut flight = Vec::new();
        flight.push(0x16);
        flight.extend_from_slice(&[0x03, 0x03]);
        flight.extend_from_slice(&(sh_hs.len() as u16).to_be_bytes());
        flight.extend_from_slice(&sh_hs);
        flight.extend_from_slice(&[0x17, 0x03, 0x03]);
        flight.extend_from_slice(&495u16.to_be_bytes());
        flight.extend(core::iter::repeat_n(0xAA, 495));
        flight.extend_from_slice(&[0x17, 0x03, 0x03]);
        flight.extend_from_slice(&245u16.to_be_bytes());
        flight.extend(core::iter::repeat_n(0xBB, 245));

        match parse_dest_server_flight(&flight) {
            ServerFlightStatus::Complete(p) => {
                assert_eq!(p.encrypted_record_count, 2);
                assert_eq!(p.encrypted_record_lens[0], 500);
                assert_eq!(p.encrypted_record_lens[1], 250);
            }
            other => assert!(
                matches!(other, ServerFlightStatus::Complete(_)),
                "unexpected: {other:?}"
            ),
        }

        // Now add pre_shared_key (0x0029) -> must return Invalid.
        let mut psk_exts = sh_exts;
        psk_exts.extend_from_slice(&[0x00, 0x29, 0x00, 0x02, 0x00, 0x00]);
        let mut psk_body = Vec::new();
        psk_body.extend_from_slice(&[0x03, 0x03]);
        psk_body.extend([0x12u8; 32]);
        psk_body.push(32);
        psk_body.extend([0x34u8; 32]);
        psk_body.extend_from_slice(&[0x13, 0x01, 0x00]);
        psk_body.extend_from_slice(&(psk_exts.len() as u16).to_be_bytes());
        psk_body.extend_from_slice(&psk_exts);
        let mut psk_hs = vec![0x02];
        let psk_len_bytes = (psk_body.len() as u32).to_be_bytes();
        if let Some(t) = psk_len_bytes.get(1..4) {
            psk_hs.extend_from_slice(t);
        }
        psk_hs.extend_from_slice(&psk_body);
        let mut psk_flight = vec![0x16, 0x03, 0x03];
        psk_flight.extend_from_slice(&(psk_hs.len() as u16).to_be_bytes());
        psk_flight.extend_from_slice(&psk_hs);
        psk_flight.extend_from_slice(&[0x17, 0x03, 0x03]);
        psk_flight.extend_from_slice(&495u16.to_be_bytes());
        psk_flight.extend(core::iter::repeat_n(0xAA, 495));

        assert_eq!(
            parse_dest_server_flight(&psk_flight),
            ServerFlightStatus::Invalid
        );
    }
}
