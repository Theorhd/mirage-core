//! CSPRNG credential generation utilities (`miraged keygen`).

use mirage_core::crypto::{encode_base64url, encode_hex, StaticPrivateKey};
use zeroize::Zeroizing;

use crate::error::DaemonError;

/// Generates a fresh X25519 Reality keypair, 8-byte ShortID, and RFC 4122
/// UUIDv4 using `getrandom`, printing ready-to-paste values to stdout.
pub fn run_keygen() -> Result<(), DaemonError> {
    let mut priv_raw = Zeroizing::new([0u8; 32]);
    getrandom::fill(priv_raw.as_mut_slice()).map_err(|_| DaemonError::HardeningFailed)?;
    // Apply X25519 scalar clamping so raw bytes match `xray x25519` conventions.
    if let Some(b0) = priv_raw.first_mut() {
        *b0 &= 248;
    }
    if let Some(b31) = priv_raw.get_mut(31) {
        *b31 &= 127;
        *b31 |= 64;
    }

    let priv_key = StaticPrivateKey::from_bytes(*priv_raw);
    let pub_key = priv_key.public_key();

    let priv_b64 = priv_key.to_base64url();
    let priv_hex = priv_key.to_hex();
    let pub_b64 = encode_base64url(&pub_key);
    let pub_hex = encode_hex(&pub_key);

    let mut short_id = [0u8; 8];
    getrandom::fill(&mut short_id).map_err(|_| DaemonError::HardeningFailed)?;
    let short_id_hex = encode_hex(&short_id);

    let mut uuid_bytes = [0u8; 16];
    getrandom::fill(&mut uuid_bytes).map_err(|_| DaemonError::HardeningFailed)?;
    if let Some(b6) = uuid_bytes.get_mut(6) {
        *b6 = (*b6 & 0x0F) | 0x40;
    }
    if let Some(b8) = uuid_bytes.get_mut(8) {
        *b8 = (*b8 & 0x3F) | 0x80;
    }
    let uuid_str = format_uuid_v4(&uuid_bytes);

    println!("PrivateKey (base64url): {}", *priv_b64);
    println!("PublicKey  (base64url): {pub_b64}");
    println!("PrivateKey (hex):       {}", *priv_hex);
    println!("PublicKey  (hex):       {pub_hex}");
    println!("ShortId    (hex):       {short_id_hex}");
    println!("UUIDv4:                 {uuid_str}");

    Ok(())
}

/// Formats 16 bytes into canonical lowercase hyphenated UUIDv4 text.
#[must_use]
pub fn format_uuid_v4(bytes: &[u8; 16]) -> String {
    let hex = encode_hex(bytes);
    let p1 = hex.get(0..8).unwrap_or("");
    let p2 = hex.get(8..12).unwrap_or("");
    let p3 = hex.get(12..16).unwrap_or("");
    let p4 = hex.get(16..20).unwrap_or("");
    let p5 = hex.get(20..32).unwrap_or("");
    format!("{p1}-{p2}-{p3}-{p4}-{p5}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_core::vless::VlessUuid;

    #[test]
    fn formats_valid_rfc4122_uuid_v4() {
        let mut bytes = [0xAAu8; 16];
        if let Some(b6) = bytes.get_mut(6) {
            *b6 = (*b6 & 0x0F) | 0x40;
        }
        if let Some(b8) = bytes.get_mut(8) {
            *b8 = (*b8 & 0x3F) | 0x80;
        }
        let s = format_uuid_v4(&bytes);
        assert_eq!(s.len(), 36);
        assert_eq!(s.as_bytes().get(14), Some(&b'4'));
        let parsed = VlessUuid::from_str_hex(&s);
        assert!(parsed.is_ok());
    }
}
