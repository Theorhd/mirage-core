//! Sans-I/O cryptographic primitives for XTLS-Reality and TLS 1.3.
//!
//! All secret-bearing types implement `ZeroizeOnDrop`, redact `Debug` output,
//! and compare secret identifiers in constant time (`subtle::ConstantTimeEq`).

use core::fmt;

use aes_gcm::{
    aead::{AeadInOut, KeyInit as AeadKeyInit, Nonce as AeadNonce},
    Aes128Gcm, Aes256Gcm,
};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as MacKeyInit, Mac};
use ml_kem::{ml_kem_768::EncapsulationKey as MlKem768Ek, Key as MlKemKey, B32};
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::tls_parser::{
    KeyShares, SelectedGroup, Tls13CipherSuiteId, MAX_TLS_CIPHERTEXT_RECORD_LEN,
    MAX_TLS_RECORD_FRAGMENT,
};

/// Errors produced by cryptographic primitives (no secrets embedded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid hexadecimal encoding or length.
    InvalidEncoding,
    /// Empty ShortID is rejected for production safety.
    EmptyShortIdNotAllowed,
    /// Non-contributory X25519 shared secret (all zeroes).
    NonContributorySharedSecret,
    /// HKDF expansion failed.
    KeyDerivationFailed,
    /// AEAD encryption or decryption failed.
    AeadFailed,
    /// Invalid ML-KEM-768 encapsulation key.
    InvalidMlKemKey,
    /// TLS 1.3 sequence number exhausted (`u64::MAX`).
    SequenceExhausted,
    /// TLS 1.3 record plaintext/ciphertext malformed.
    InvalidRecord,
    /// HMAC / Finished verify data mismatch.
    VerificationFailed,
}

/// Static X25519 server private key (`ZeroizeOnDrop`, redacted `Debug`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StaticPrivateKey {
    bytes: Box<[u8; 32]>,
    #[zeroize(skip)]
    secret: Box<X25519StaticSecret>,
}

impl StaticPrivateKey {
    /// Constructs a `StaticPrivateKey` from raw 32-byte scalar material.
    #[must_use]
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let secret = Box::new(X25519StaticSecret::from(bytes));
        let boxed_bytes = Box::new(bytes);
        bytes.zeroize();
        Self {
            bytes: boxed_bytes,
            secret,
        }
    }

    /// Parses a 64-character hexadecimal X25519 private key without leaving
    /// un-zeroized copies behind.
    pub fn from_hex(hex: &str) -> Result<Self, CryptoError> {
        let mut raw = Zeroizing::new([0u8; 32]);
        decode_hex_exact(hex, raw.as_mut_slice())?;
        Ok(Self::from_bytes(*raw))
    }

    /// Parses a 43-character unpadded (or 44-character `=`-padded) Base64url
    /// X25519 private key (standard Xray-core format) without leaving
    /// un-zeroized copies behind.
    pub fn from_base64url(b64: &str) -> Result<Self, CryptoError> {
        let mut raw = Zeroizing::new([0u8; 32]);
        decode_base64url_32(b64, &mut raw)?;
        Ok(Self::from_bytes(*raw))
    }

    /// Parses either 64-character hexadecimal or Base64url (Xray-core) encoding.
    pub fn from_encoded(encoded: &str) -> Result<Self, CryptoError> {
        let trimmed = encoded.trim();
        if trimmed.len() == 64 {
            Self::from_hex(trimmed)
        } else {
            Self::from_base64url(trimmed)
        }
    }

    /// Encodes the raw private key bytes as unpadded Base64url inside a
    /// `Zeroizing<String>` (for `keygen` CLI output).
    #[must_use]
    pub fn to_base64url(&self) -> Zeroizing<String> {
        Zeroizing::new(encode_base64url(self.bytes.as_slice()))
    }

    /// Encodes the raw private key bytes as lowercase hexadecimal inside a
    /// `Zeroizing<String>` (for `keygen` CLI output).
    #[must_use]
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(encode_hex(self.bytes.as_slice()))
    }

    /// Returns the corresponding 32-byte X25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        X25519PublicKey::from(&*self.secret).to_bytes()
    }

    /// Performs X25519 ECDH against a client's 32-byte ephemeral public key,
    /// rejecting non-contributory (all-zero) outputs.
    pub fn diffie_hellman(&self, peer_pub: &[u8; 32]) -> Result<SharedSecret, CryptoError> {
        let peer = X25519PublicKey::from(*peer_pub);
        let shared = self.secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(CryptoError::NonContributorySharedSecret);
        }
        Ok(SharedSecret {
            bytes: Box::new(shared.to_bytes()),
        })
    }
}

impl fmt::Debug for StaticPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StaticPrivateKey([REDACTED])")
    }
}

/// 32-byte X25519 shared secret (`ZeroizeOnDrop`, redacted `Debug`).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: Box<[u8; 32]>,
}

impl SharedSecret {
    /// Returns the shared secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret([REDACTED])")
    }
}

/// 32-byte Reality `AuthKey` derived via HKDF-SHA256 (`ZeroizeOnDrop`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AuthKey {
    bytes: Box<[u8; 32]>,
}

impl AuthKey {
    /// Returns the 32-byte key slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthKey([REDACTED])")
    }
}

/// 8-byte Reality `ShortId` (`ZeroizeOnDrop`, constant-time equality, redacted `Debug`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ShortId {
    bytes: Box<[u8; 8]>,
}

impl ShortId {
    /// Constructs a `ShortId` from 8 raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self {
            bytes: Box::new(bytes),
        }
    }

    /// Parses a hex ShortID (`2..=16` hex characters, even length), right-padded
    /// with zeros to 8 bytes. Empty ShortIDs (`""`) are rejected per security policy.
    pub fn from_hex(hex: &str) -> Result<Self, CryptoError> {
        let trimmed = hex.trim();
        if trimmed.is_empty() {
            return Err(CryptoError::EmptyShortIdNotAllowed);
        }
        let len = trimmed.len();
        if len > 16 || (len % 2) != 0 {
            return Err(CryptoError::InvalidEncoding);
        }
        let byte_len = len / 2;
        let mut out = Zeroizing::new([0u8; 8]);
        let dst = out
            .get_mut(..byte_len)
            .ok_or(CryptoError::InvalidEncoding)?;
        decode_hex_exact(trimmed, dst)?;
        Ok(Self::from_bytes(*out))
    }

    /// Constant-time comparison with another `ShortId`.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.bytes.as_slice().ct_eq(other.bytes.as_slice()))
    }
}

impl fmt::Debug for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShortId([REDACTED])")
    }
}

/// Decrypted 16-byte Reality `SessionId` payload.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RealityToken {
    /// Client Xray version `[major, minor, patch]`.
    pub client_version: [u8; 3],
    /// Reserved padding byte.
    pub padding: u8,
    /// Client Unix timestamp in seconds (big-endian `u32`).
    pub timestamp_secs: u32,
    /// Client ShortID (8 bytes).
    pub short_id: ShortId,
}

impl fmt::Debug for RealityToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityToken")
            .field("client_version", &self.client_version)
            .field("timestamp_secs", &self.timestamp_secs)
            .field("short_id", &"[REDACTED]")
            .finish()
    }
}

/// Derives the 32-byte Reality `AuthKey` from the ECDH shared secret and
/// `ClientHello.random[..20]` using `HKDF-SHA256` with info `"REALITY"`.
pub fn derive_reality_auth_key(
    shared_secret: &SharedSecret,
    client_random: &[u8; 32],
) -> Result<AuthKey, CryptoError> {
    let salt = client_random
        .get(..20)
        .ok_or(CryptoError::KeyDerivationFailed)?;
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret.as_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"REALITY", out.as_mut_slice())
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(AuthKey {
        bytes: Box::new(*out),
    })
}

/// Decrypts and authenticates the 32-byte Reality `ClientHello.SessionId`
/// using `AES-256-GCM(AuthKey, nonce = random[20..32], aad = zeroed_client_hello)`.
pub fn decrypt_reality_session_id(
    auth_key: &AuthKey,
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    aad_zeroed_ch: &[u8],
) -> Result<RealityToken, CryptoError> {
    let nonce_slice = client_random.get(20..32).ok_or(CryptoError::AeadFailed)?;
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce_slice);
    let nonce = AeadNonce::<Aes256Gcm>::from(nonce_arr);

    let cipher =
        Aes256Gcm::new_from_slice(auth_key.as_bytes()).map_err(|_| CryptoError::AeadFailed)?;

    let mut buf = Zeroizing::new(session_id.to_vec());
    cipher
        .decrypt_in_place(&nonce, aad_zeroed_ch, &mut *buf)
        .map_err(|_| CryptoError::AeadFailed)?;

    if buf.len() != 16 {
        return Err(CryptoError::AeadFailed);
    }

    let v0 = *buf.first().ok_or(CryptoError::AeadFailed)?;
    let v1 = *buf.get(1).ok_or(CryptoError::AeadFailed)?;
    let v2 = *buf.get(2).ok_or(CryptoError::AeadFailed)?;
    let padding = *buf.get(3).ok_or(CryptoError::AeadFailed)?;
    let t0 = *buf.get(4).ok_or(CryptoError::AeadFailed)?;
    let t1 = *buf.get(5).ok_or(CryptoError::AeadFailed)?;
    let t2 = *buf.get(6).ok_or(CryptoError::AeadFailed)?;
    let t3 = *buf.get(7).ok_or(CryptoError::AeadFailed)?;
    let sid_slice = buf.get(8..16).ok_or(CryptoError::AeadFailed)?;

    let mut sid_arr = [0u8; 8];
    sid_arr.copy_from_slice(sid_slice);

    Ok(RealityToken {
        client_version: [v0, v1, v2],
        padding,
        timestamp_secs: u32::from_be_bytes([t0, t1, t2, t3]),
        short_id: ShortId::from_bytes(sid_arr),
    })
}

/// Encrypts a 16-byte Reality token into a 32-byte `SessionId` (used for testing
/// wire-compatibility with XTLS-Reality clients).
pub fn encrypt_reality_session_id(
    auth_key: &AuthKey,
    client_random: &[u8; 32],
    token: &RealityToken,
    aad_zeroed_ch: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let nonce_slice = client_random.get(20..32).ok_or(CryptoError::AeadFailed)?;
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce_slice);
    let nonce = AeadNonce::<Aes256Gcm>::from(nonce_arr);

    let cipher =
        Aes256Gcm::new_from_slice(auth_key.as_bytes()).map_err(|_| CryptoError::AeadFailed)?;

    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&token.client_version);
    buf.push(token.padding);
    buf.extend_from_slice(&token.timestamp_secs.to_be_bytes());
    buf.extend_from_slice(token.short_id.bytes.as_slice());

    cipher
        .encrypt_in_place(&nonce, aad_zeroed_ch, &mut buf)
        .map_err(|_| CryptoError::AeadFailed)?;

    if buf.len() != 32 {
        return Err(CryptoError::AeadFailed);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf);
    Ok(out)
}

/// Computes a 16-byte keyed anti-replay cache tag using `HMAC-SHA256`
/// so raw `ClientHello.random` values are never retained in memory.
#[must_use]
pub fn keyed_replay_tag(hmac_key: &[u8; 32], client_random: &[u8; 32]) -> [u8; 16] {
    let mut tag = [0u8; 16];
    if let Ok(mut mac) = <Hmac<Sha256> as MacKeyInit>::new_from_slice(hmac_key) {
        mac.update(client_random);
        let full = mac.finalize().into_bytes();
        if let Some(prefix) = full.get(..16) {
            tag.copy_from_slice(prefix);
        }
    }
    tag
}

/// Ephemeral Ed25519 certificate template used by Reality to prove knowledge of
/// `AuthKey` via `HMAC-SHA512(AuthKey, ed25519_pubkey)` in the X.509 signature.
pub struct RealityCertTemplate {
    signing_key: SigningKey,
    verifying_key_bytes: [u8; 32],
    cert_der_template: Vec<u8>,
}

impl RealityCertTemplate {
    /// Builds a self-signed X.509 v3 Ed25519 DER certificate template from a
    /// 32-byte CSPRNG seed.
    #[must_use]
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let verifying_key_bytes = signing_key.verifying_key().to_bytes();
        let cert_der_template = build_ed25519_x509_template(&signing_key, &verifying_key_bytes);
        Self {
            signing_key,
            verifying_key_bytes,
            cert_der_template,
        }
    }

    /// Forges the session-specific Reality X.509 certificate by replacing the
    /// trailing 64-byte signature field with `HMAC-SHA512(auth_key, ed25519_pubkey)`.
    pub fn forge_cert_der(&self, auth_key: &AuthKey) -> Result<Vec<u8>, CryptoError> {
        let mut mac = <Hmac<Sha512> as MacKeyInit>::new_from_slice(auth_key.as_bytes())
            .map_err(|_| CryptoError::AeadFailed)?;
        mac.update(&self.verifying_key_bytes);
        let sig = mac.finalize().into_bytes();

        let mut cert = self.cert_der_template.clone();
        let sig_start = cert
            .len()
            .checked_sub(64)
            .ok_or(CryptoError::InvalidRecord)?;
        let dst = cert
            .get_mut(sig_start..)
            .ok_or(CryptoError::InvalidRecord)?;
        dst.copy_from_slice(sig.as_slice());
        Ok(cert)
    }

    /// Signs the TLS 1.3 `CertificateVerify` input with the template's Ed25519 private key.
    #[must_use]
    pub fn sign_certificate_verify(&self, transcript_hash: &[u8]) -> [u8; 64] {
        const CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify\x00";
        let mut msg = Vec::with_capacity(
            64usize
                .saturating_add(CONTEXT.len())
                .saturating_add(transcript_hash.len()),
        );
        msg.extend([0x20u8; 64]);
        msg.extend_from_slice(CONTEXT);
        msg.extend_from_slice(transcript_hash);
        self.signing_key.sign(&msg).to_bytes()
    }

    /// Returns the 32-byte Ed25519 public key embedded in the certificate.
    #[must_use]
    pub const fn public_key_bytes(&self) -> &[u8; 32] {
        &self.verifying_key_bytes
    }
}

impl fmt::Debug for RealityCertTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RealityCertTemplate([REDACTED])")
    }
}

fn build_ed25519_x509_template(signing_key: &SigningKey, pubkey: &[u8; 32]) -> Vec<u8> {
    // Ed25519 AlgorithmIdentifier: SEQUENCE { OID 1.3.101.112 (06 03 2B 65 70) }
    const ED25519_ALG_ID: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];
    // Version v3: [0] EXPLICIT INTEGER 2
    const VERSION_V3: &[u8] = &[0xA0, 0x03, 0x02, 0x01, 0x02];
    // SerialNumber: INTEGER 0
    const SERIAL_ZERO: &[u8] = &[0x02, 0x01, 0x00];
    // Empty Name: SEQUENCE {}
    const EMPTY_NAME: &[u8] = &[0x30, 0x00];
    // Validity: 2025-01-01 to 2035-01-01 (UTCTime)
    const VALIDITY: &[u8] = &[
        0x30, 0x1E, 0x17, 0x0D, b'2', b'5', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0',
        b'0', b'Z', 0x17, 0x0D, b'3', b'5', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0',
        b'0', b'Z',
    ];

    let mut spki_body = Vec::with_capacity(42);
    spki_body.extend_from_slice(ED25519_ALG_ID);
    spki_body.extend_from_slice(&[0x03, 0x21, 0x00]);
    spki_body.extend_from_slice(pubkey);
    let spki = der_sequence(&spki_body);

    let mut tbs_body = Vec::with_capacity(128);
    tbs_body.extend_from_slice(VERSION_V3);
    tbs_body.extend_from_slice(SERIAL_ZERO);
    tbs_body.extend_from_slice(ED25519_ALG_ID);
    tbs_body.extend_from_slice(EMPTY_NAME);
    tbs_body.extend_from_slice(VALIDITY);
    tbs_body.extend_from_slice(EMPTY_NAME);
    tbs_body.extend_from_slice(&spki);
    let tbs = der_sequence(&tbs_body);

    let sig = signing_key.sign(&tbs).to_bytes();

    let mut cert_body = Vec::with_capacity(tbs.len().saturating_add(80));
    cert_body.extend_from_slice(&tbs);
    cert_body.extend_from_slice(ED25519_ALG_ID);
    cert_body.extend_from_slice(&[0x03, 0x41, 0x00]);
    cert_body.extend_from_slice(&sig);
    der_sequence(&cert_body)
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = Vec::with_capacity(len.saturating_add(4));
    out.push(0x30);
    if len < 128 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else if len <= usize::from(u8::MAX) {
        out.push(0x81);
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        out.push(0x82);
        let len_u16 = u16::try_from(len).unwrap_or(u16::MAX);
        out.extend_from_slice(&len_u16.to_be_bytes());
    }
    out.extend_from_slice(content);
    out
}

/// Result of server-side TLS 1.3 key agreement (`X25519` or `X25519MLKEM768`).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Tls13KeyAgreementResult {
    /// Wire bytes to place into the server's `ServerHello.key_share` extension.
    #[zeroize(skip)]
    pub server_key_share: Vec<u8>,
    /// Shared secret (32 bytes for `X25519`, 64 bytes for `X25519MLKEM768`).
    pub shared_secret: Vec<u8>,
}

/// Computes the server's ephemeral TLS 1.3 key exchange for the group selected
/// by `dest` (`X25519` or hybrid `X25519MLKEM768`).
pub fn compute_tls13_server_key_exchange(
    selected_group: SelectedGroup,
    client_shares: &KeyShares,
    x25519_ephemeral_seed: [u8; 32],
    mlkem_randomness: [u8; 32],
) -> Result<Tls13KeyAgreementResult, CryptoError> {
    let eph_secret = X25519StaticSecret::from(x25519_ephemeral_seed);
    let eph_pub = X25519PublicKey::from(&eph_secret).to_bytes();

    match selected_group {
        SelectedGroup::X25519 => {
            let client_pub = client_shares
                .x25519
                .ok_or(CryptoError::NonContributorySharedSecret)?;
            let shared = eph_secret.diffie_hellman(&X25519PublicKey::from(client_pub));
            if !shared.was_contributory() {
                return Err(CryptoError::NonContributorySharedSecret);
            }
            Ok(Tls13KeyAgreementResult {
                server_key_share: eph_pub.to_vec(),
                shared_secret: shared.as_bytes().to_vec(),
            })
        }
        SelectedGroup::X25519MlKem768 => {
            let hybrid = client_shares
                .x25519_mlkem768
                .as_ref()
                .ok_or(CryptoError::InvalidMlKemKey)?;
            let ek_slice = hybrid.get(..1184).ok_or(CryptoError::InvalidMlKemKey)?;
            let x25519_tail = hybrid.get(1184..1216).ok_or(CryptoError::InvalidMlKemKey)?;

            let mut client_x25519 = [0u8; 32];
            client_x25519.copy_from_slice(x25519_tail);
            let ecdh_shared = eph_secret.diffie_hellman(&X25519PublicKey::from(client_x25519));
            if !ecdh_shared.was_contributory() {
                return Err(CryptoError::NonContributorySharedSecret);
            }

            let ek_arr = MlKemKey::<MlKem768Ek>::try_from(ek_slice)
                .map_err(|_| CryptoError::InvalidMlKemKey)?;
            let ek = MlKem768Ek::new(&ek_arr).map_err(|_| CryptoError::InvalidMlKemKey)?;
            let (ct, mlkem_shared) = ek.encapsulate_deterministic(&B32::from(mlkem_randomness));

            let mut server_share = Vec::with_capacity(1120);
            server_share.extend_from_slice(ct.as_slice());
            server_share.extend_from_slice(&eph_pub);

            let mut combined_secret = Vec::with_capacity(64);
            combined_secret.extend_from_slice(mlkem_shared.as_slice());
            combined_secret.extend_from_slice(ecdh_shared.as_bytes());

            Ok(Tls13KeyAgreementResult {
                server_key_share: server_share,
                shared_secret: combined_secret,
            })
        }
    }
}

/// Running TLS 1.3 handshake transcript hash (SHA-256 or SHA-384).
#[derive(Clone)]
pub enum TranscriptHash {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl TranscriptHash {
    /// Initializes a transcript hash matching the negotiated cipher suite.
    #[must_use]
    pub fn new(suite: Tls13CipherSuiteId) -> Self {
        match suite {
            Tls13CipherSuiteId::Aes128GcmSha256 | Tls13CipherSuiteId::ChaCha20Poly1305Sha256 => {
                Self::Sha256(Sha256::new())
            }
            Tls13CipherSuiteId::Aes256GcmSha384 => Self::Sha384(Sha384::new()),
        }
    }

    /// Feeds handshake message bytes (without 5-byte TLS record header) into the transcript.
    pub fn update(&mut self, msg: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(msg),
            Self::Sha384(h) => h.update(msg),
        }
    }

    /// Snapshots the current transcript digest (`32` or `48` bytes) without consuming state.
    #[must_use]
    pub fn current_hash(&self) -> Vec<u8> {
        match self {
            Self::Sha256(h) => h.clone().finalize().to_vec(),
            Self::Sha384(h) => h.clone().finalize().to_vec(),
        }
    }
}

/// TLS 1.3 key schedule helper matching RFC 8446 §7.1.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Tls13Secret {
    #[zeroize(skip)]
    suite: Tls13CipherSuiteId,
    bytes: Vec<u8>,
}

impl Tls13Secret {
    /// Derives the initial `early_secret = HKDF-Extract(0, 0)`.
    #[must_use]
    pub fn early_secret(suite: Tls13CipherSuiteId) -> Self {
        let len = suite_hash_len(suite);
        let zeros = vec![0u8; len];
        let prk = hkdf_extract(suite, Some(&zeros), &zeros);
        Self { suite, bytes: prk }
    }

    /// Advances from `early_secret` -> `derived` -> `handshake_secret = HKDF-Extract(derived, shared_key)`.
    pub fn derive_handshake_secret(&self, shared_key: &[u8]) -> Result<Self, CryptoError> {
        let empty_hash = empty_transcript_hash(self.suite);
        let derived = self.derive_secret(b"derived", &empty_hash)?;
        let prk = hkdf_extract(self.suite, Some(&derived.bytes), shared_key);
        Ok(Self {
            suite: self.suite,
            bytes: prk,
        })
    }

    /// Advances from `handshake_secret` -> `derived` -> `master_secret = HKDF-Extract(derived, 0)`.
    pub fn derive_master_secret(&self) -> Result<Self, CryptoError> {
        let empty_hash = empty_transcript_hash(self.suite);
        let derived = self.derive_secret(b"derived", &empty_hash)?;
        let zeros = vec![0u8; suite_hash_len(self.suite)];
        let prk = hkdf_extract(self.suite, Some(&derived.bytes), &zeros);
        Ok(Self {
            suite: self.suite,
            bytes: prk,
        })
    }

    /// `Derive-Secret(Secret, Label, TranscriptHash)` per RFC 8446 §7.1.
    pub fn derive_secret(&self, label: &[u8], transcript_hash: &[u8]) -> Result<Self, CryptoError> {
        let out_len = suite_hash_len(self.suite);
        let out = self.expand_label(label, transcript_hash, out_len)?;
        Ok(Self {
            suite: self.suite,
            bytes: out,
        })
    }

    /// `HKDF-Expand-Label(Secret, Label, Context, Length)` per RFC 8446 §7.1.
    pub fn expand_label(
        &self,
        label: &[u8],
        context: &[u8],
        out_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let len_u16 = u16::try_from(out_len).map_err(|_| CryptoError::KeyDerivationFailed)?;
        let full_label_len = 6usize
            .checked_add(label.len())
            .and_then(|v| u8::try_from(v).ok())
            .ok_or(CryptoError::KeyDerivationFailed)?;
        let ctx_len = u8::try_from(context.len()).map_err(|_| CryptoError::KeyDerivationFailed)?;

        let len_bytes = len_u16.to_be_bytes();
        let full_label_len_byte = [full_label_len];
        let ctx_len_byte = [ctx_len];
        let components: [&[u8]; 5] = [
            &len_bytes,
            &full_label_len_byte,
            b"tls13 ",
            label,
            &ctx_len_byte,
        ];
        // Note: `hkdf::expand_multi_info` accepts arbitrary slices; include `context` directly.
        let all_components: [&[u8]; 6] = [
            components[0],
            components[1],
            components[2],
            components[3],
            components[4],
            context,
        ];

        let mut out = vec![0u8; out_len];
        match self.suite {
            Tls13CipherSuiteId::Aes128GcmSha256 | Tls13CipherSuiteId::ChaCha20Poly1305Sha256 => {
                let hk = Hkdf::<Sha256>::from_prk(&self.bytes)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?;
                hk.expand_multi_info(&all_components, &mut out)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?;
            }
            Tls13CipherSuiteId::Aes256GcmSha384 => {
                let hk = Hkdf::<Sha384>::from_prk(&self.bytes)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?;
                hk.expand_multi_info(&all_components, &mut out)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?;
            }
        }
        Ok(out)
    }

    /// Computes TLS 1.3 `Finished` `verify_data = HMAC(finished_key, transcript_hash)`.
    pub fn compute_finished_verify_data(
        &self,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let hash_len = suite_hash_len(self.suite);
        let finished_key = Zeroizing::new(self.expand_label(b"finished", &[], hash_len)?);
        let mac_bytes = match self.suite {
            Tls13CipherSuiteId::Aes128GcmSha256 | Tls13CipherSuiteId::ChaCha20Poly1305Sha256 => {
                let mut mac = <Hmac<Sha256> as MacKeyInit>::new_from_slice(&finished_key)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?;
                mac.update(transcript_hash);
                mac.finalize().into_bytes().to_vec()
            }
            Tls13CipherSuiteId::Aes256GcmSha384 => {
                let mut mac = <Hmac<Sha384> as MacKeyInit>::new_from_slice(&finished_key)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?;
                mac.update(transcript_hash);
                mac.finalize().into_bytes().to_vec()
            }
        };
        Ok(mac_bytes)
    }

    /// Derives traffic encryption/decryption `Tls13RecordCipher` from this traffic secret.
    pub fn into_record_cipher(&self) -> Result<Tls13RecordCipher, CryptoError> {
        let key_len = match self.suite {
            Tls13CipherSuiteId::Aes128GcmSha256 => 16,
            Tls13CipherSuiteId::Aes256GcmSha384 | Tls13CipherSuiteId::ChaCha20Poly1305Sha256 => 32,
        };
        let key = Zeroizing::new(self.expand_label(b"key", &[], key_len)?);
        let iv_vec = Zeroizing::new(self.expand_label(b"iv", &[], 12)?);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_vec);

        let cipher = match self.suite {
            Tls13CipherSuiteId::Aes128GcmSha256 => CipherKind::Aes128(Box::new(
                Aes128Gcm::new_from_slice(&key).map_err(|_| CryptoError::KeyDerivationFailed)?,
            )),
            Tls13CipherSuiteId::Aes256GcmSha384 => CipherKind::Aes256(Box::new(
                Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::KeyDerivationFailed)?,
            )),
            Tls13CipherSuiteId::ChaCha20Poly1305Sha256 => CipherKind::ChaCha20(Box::new(
                ChaCha20Poly1305::new_from_slice(&key)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?,
            )),
        };

        Ok(Tls13RecordCipher {
            cipher,
            iv: Box::new(iv),
            seq: 0,
        })
    }
}

impl fmt::Debug for Tls13Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tls13Secret([REDACTED])")
    }
}

enum CipherKind {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha20(Box<ChaCha20Poly1305>),
}

/// Stateful TLS 1.3 AEAD record cipher (`ZeroizeOnDrop`, per-record nonce sequence).
pub struct Tls13RecordCipher {
    cipher: CipherKind,
    iv: Box<[u8; 12]>,
    seq: u64,
}

impl Drop for Tls13RecordCipher {
    fn drop(&mut self) {
        self.iv.zeroize();
        self.seq.zeroize();
    }
}

impl fmt::Debug for Tls13RecordCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls13RecordCipher")
            .field("seq", &self.seq)
            .finish()
    }
}

impl Tls13RecordCipher {
    /// Encrypts a TLS 1.3 record into a reusable buffer `record`, clearing any
    /// previous contents while preserving existing capacity.
    pub fn seal_record_into(
        &mut self,
        inner_content_type: u8,
        plaintext: &[u8],
        target_wire_len: Option<usize>,
        record: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        record.clear();
        if plaintext.len() > MAX_TLS_RECORD_FRAGMENT {
            return Err(CryptoError::InvalidRecord);
        }
        // Unpadded inner plaintext = plaintext.len() + 1 (content_type)
        // Overhead = 16 (GCM/Poly1305 tag), header = 5 bytes
        let unpadded_inner = plaintext
            .len()
            .checked_add(1)
            .ok_or(CryptoError::InvalidRecord)?;
        let unpadded_wire = 5usize
            .checked_add(unpadded_inner)
            .and_then(|v| v.checked_add(16))
            .ok_or(CryptoError::InvalidRecord)?;

        let zero_pad = match target_wire_len {
            Some(target) if target > unpadded_wire => target.saturating_sub(unpadded_wire),
            _ => 0,
        };

        let inner_len = unpadded_inner
            .checked_add(zero_pad)
            .ok_or(CryptoError::InvalidRecord)?;
        let ciphertext_len = inner_len
            .checked_add(16)
            .ok_or(CryptoError::InvalidRecord)?;
        if ciphertext_len > MAX_TLS_CIPHERTEXT_RECORD_LEN {
            return Err(CryptoError::InvalidRecord);
        }
        let ct_len_u16 = u16::try_from(ciphertext_len).map_err(|_| CryptoError::InvalidRecord)?;

        let [ct0, ct1] = ct_len_u16.to_be_bytes();
        let aad: [u8; 5] = [0x17, 0x03, 0x03, ct0, ct1];

        let total_wire_len = 5usize.saturating_add(ciphertext_len);
        if record.capacity() < total_wire_len {
            record.reserve(total_wire_len.saturating_sub(record.len()));
        }
        record.extend_from_slice(&aad);
        record.extend_from_slice(plaintext);
        record.push(inner_content_type);
        record.resize(5usize.saturating_add(inner_len), 0);

        let nonce = self.next_nonce()?;
        let body = record.get_mut(5..).ok_or(CryptoError::InvalidRecord)?;
        let tag = match &self.cipher {
            CipherKind::Aes128(c) => c
                .encrypt_inout_detached(&AeadNonce::<Aes128Gcm>::from(nonce), &aad, body.into())
                .map_err(|_| CryptoError::AeadFailed)?,
            CipherKind::Aes256(c) => c
                .encrypt_inout_detached(&AeadNonce::<Aes256Gcm>::from(nonce), &aad, body.into())
                .map_err(|_| CryptoError::AeadFailed)?,
            CipherKind::ChaCha20(c) => c
                .encrypt_inout_detached(
                    &AeadNonce::<ChaCha20Poly1305>::from(nonce),
                    &aad,
                    body.into(),
                )
                .map_err(|_| CryptoError::AeadFailed)?,
        };

        record.extend_from_slice(tag.as_slice());
        Ok(())
    }

    /// Encrypts a TLS 1.3 record, optionally zero-padding the inner plaintext so
    /// the resulting TLS wire record length equals `target_wire_len` (when `target_wire_len`
    /// is at least as large as the unpadded wire length).
    pub fn seal_record(
        &mut self,
        inner_content_type: u8,
        plaintext: &[u8],
        target_wire_len: Option<usize>,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut record =
            Vec::with_capacity(5usize.saturating_add(plaintext.len()).saturating_add(17));
        self.seal_record_into(inner_content_type, plaintext, target_wire_len, &mut record)?;
        Ok(record)
    }

    /// Decrypts a complete TLS 1.3 encrypted record (`0x17 0x03 0x03 <len> <ct>`),
    /// returning `(inner_content_type, plaintext)`.
    pub fn open_record(&mut self, wire_record: &[u8]) -> Result<(u8, Vec<u8>), CryptoError> {
        let mut buf = Vec::new();
        let ct = self.open_record_into(wire_record, &mut buf)?;
        Ok((ct, buf))
    }

    /// Decrypts a complete TLS 1.3 encrypted record (`0x17 0x03 0x03 <len> <ct>`)
    /// into a reusable buffer `out`, avoiding per-record heap allocations.
    ///
    /// Returns the inner TLS 1.3 content type on success. Scrubs and clears `out`
    /// on failure.
    pub fn open_record_into(
        &mut self,
        wire_record: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<u8, CryptoError> {
        let hdr = wire_record.get(..5).ok_or(CryptoError::InvalidRecord)?;
        if hdr.first() != Some(&0x17) || hdr.get(1) != Some(&0x03) || hdr.get(2) != Some(&0x03) {
            return Err(CryptoError::InvalidRecord);
        }
        let b3 = *hdr.get(3).ok_or(CryptoError::InvalidRecord)?;
        let b4 = *hdr.get(4).ok_or(CryptoError::InvalidRecord)?;
        let ct_len = usize::from(u16::from_be_bytes([b3, b4]));
        if !(17..=MAX_TLS_CIPHERTEXT_RECORD_LEN).contains(&ct_len) {
            return Err(CryptoError::InvalidRecord);
        }
        let total_len = 5usize
            .checked_add(ct_len)
            .ok_or(CryptoError::InvalidRecord)?;
        if wire_record.len() != total_len {
            return Err(CryptoError::InvalidRecord);
        }

        let ct_slice = wire_record.get(5..).ok_or(CryptoError::InvalidRecord)?;
        out.clear();
        out.extend_from_slice(ct_slice);

        let nonce = self.next_nonce()?;
        let decrypt_res = match &self.cipher {
            CipherKind::Aes128(c) => {
                c.decrypt_in_place(&AeadNonce::<Aes128Gcm>::from(nonce), hdr, out)
            }
            CipherKind::Aes256(c) => {
                c.decrypt_in_place(&AeadNonce::<Aes256Gcm>::from(nonce), hdr, out)
            }
            CipherKind::ChaCha20(c) => {
                c.decrypt_in_place(&AeadNonce::<ChaCha20Poly1305>::from(nonce), hdr, out)
            }
        };
        if decrypt_res.is_err() {
            out.zeroize();
            return Err(CryptoError::AeadFailed);
        }

        while out.last() == Some(&0) {
            out.pop();
        }
        let Some(content_type) = out.pop() else {
            out.zeroize();
            return Err(CryptoError::InvalidRecord);
        };
        if out.len() > MAX_TLS_RECORD_FRAGMENT {
            out.zeroize();
            return Err(CryptoError::InvalidRecord);
        }
        Ok(content_type)
    }

    fn next_nonce(&mut self) -> Result<[u8; 12], CryptoError> {
        let current_seq = self.seq;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(CryptoError::SequenceExhausted)?;

        let mut nonce = *self.iv;
        let seq_bytes = current_seq.to_be_bytes();
        for (idx, seq_b) in seq_bytes.iter().enumerate() {
            let offset = 4usize.saturating_add(idx);
            if let Some(slot) = nonce.get_mut(offset) {
                *slot ^= *seq_b;
            }
        }
        Ok(nonce)
    }
}

const fn suite_hash_len(suite: Tls13CipherSuiteId) -> usize {
    match suite {
        Tls13CipherSuiteId::Aes128GcmSha256 | Tls13CipherSuiteId::ChaCha20Poly1305Sha256 => 32,
        Tls13CipherSuiteId::Aes256GcmSha384 => 48,
    }
}

fn empty_transcript_hash(suite: Tls13CipherSuiteId) -> Vec<u8> {
    match suite {
        Tls13CipherSuiteId::Aes128GcmSha256 | Tls13CipherSuiteId::ChaCha20Poly1305Sha256 => {
            Sha256::digest([]).to_vec()
        }
        Tls13CipherSuiteId::Aes256GcmSha384 => Sha384::digest([]).to_vec(),
    }
}

fn hkdf_extract(suite: Tls13CipherSuiteId, salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
    match suite {
        Tls13CipherSuiteId::Aes128GcmSha256 | Tls13CipherSuiteId::ChaCha20Poly1305Sha256 => {
            let (prk, _) = Hkdf::<Sha256>::extract(salt, ikm);
            prk.to_vec()
        }
        Tls13CipherSuiteId::Aes256GcmSha384 => {
            let (prk, _) = Hkdf::<Sha384>::extract(salt, ikm);
            prk.to_vec()
        }
    }
}

fn decode_hex_exact(hex: &str, out: &mut [u8]) -> Result<(), CryptoError> {
    let trimmed = hex.trim();
    let expected_chars = out
        .len()
        .checked_mul(2)
        .ok_or(CryptoError::InvalidEncoding)?;
    if trimmed.len() != expected_chars {
        return Err(CryptoError::InvalidEncoding);
    }

    let bytes = trimmed.as_bytes();
    for (i, dst) in out.iter_mut().enumerate() {
        let hi_idx = i.checked_mul(2).ok_or(CryptoError::InvalidEncoding)?;
        let lo_idx = hi_idx.checked_add(1).ok_or(CryptoError::InvalidEncoding)?;
        let hi = hex_nibble(*bytes.get(hi_idx).ok_or(CryptoError::InvalidEncoding)?)?;
        let lo = hex_nibble(*bytes.get(lo_idx).ok_or(CryptoError::InvalidEncoding)?)?;
        *dst = (hi << 4) | lo;
    }
    Ok(())
}

const fn hex_nibble(b: u8) -> Result<u8, CryptoError> {
    match b {
        b'0'..=b'9' => Ok(b.saturating_sub(b'0')),
        b'a'..=b'f' => Ok(b.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Ok(b.saturating_sub(b'A').saturating_add(10)),
        _ => Err(CryptoError::InvalidEncoding),
    }
}

/// Encodes arbitrary bytes as lowercase hexadecimal.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        let hi = usize::from(b >> 4);
        let lo = usize::from(b & 0x0F);
        if let (Some(&hc), Some(&lc)) = (HEX.get(hi), HEX.get(lo)) {
            out.push(char::from(hc));
            out.push(char::from(lc));
        }
    }
    out
}

/// Encodes arbitrary bytes as unpadded Base64url (RFC 4648 §5, Xray-core format).
#[must_use]
pub fn encode_base64url(bytes: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b0 = *chunk.first().unwrap_or(&0);
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);

        let i0 = usize::from(b0 >> 2);
        let i1 = usize::from(((b0 & 0x03) << 4) | (b1 >> 4));
        let i2 = usize::from(((b1 & 0x0F) << 2) | (b2 >> 6));
        let i3 = usize::from(b2 & 0x3F);

        if let Some(&c0) = B64.get(i0) {
            out.push(char::from(c0));
        }
        if let Some(&c1) = B64.get(i1) {
            out.push(char::from(c1));
        }
        if chunk.len() >= 2 {
            if let Some(&c2) = B64.get(i2) {
                out.push(char::from(c2));
            }
        }
        if chunk.len() == 3 {
            if let Some(&c3) = B64.get(i3) {
                out.push(char::from(c3));
            }
        }
    }
    out
}

fn decode_base64url_32(input: &str, out: &mut [u8; 32]) -> Result<(), CryptoError> {
    let trimmed = input.trim();
    let unpadded = trimmed.strip_suffix('=').unwrap_or(trimmed);
    if unpadded.len() != 43 {
        return Err(CryptoError::InvalidEncoding);
    }

    let chars = unpadded.as_bytes();
    let mut dst_idx = 0usize;

    for block in chars.chunks_exact(4) {
        let v0 = b64url_val(*block.first().ok_or(CryptoError::InvalidEncoding)?)?;
        let v1 = b64url_val(*block.get(1).ok_or(CryptoError::InvalidEncoding)?)?;
        let v2 = b64url_val(*block.get(2).ok_or(CryptoError::InvalidEncoding)?)?;
        let v3 = b64url_val(*block.get(3).ok_or(CryptoError::InvalidEncoding)?)?;

        if let Some(s) = out.get_mut(dst_idx) {
            *s = (v0 << 2) | (v1 >> 4);
        }
        if let Some(s) = out.get_mut(dst_idx.saturating_add(1)) {
            *s = (v1 << 4) | (v2 >> 2);
        }
        if let Some(s) = out.get_mut(dst_idx.saturating_add(2)) {
            *s = (v2 << 6) | v3;
        }
        dst_idx = dst_idx.saturating_add(3);
    }

    // Trailing 3 chars (30..32 bytes: 18 bits -> 16 data bits + 2 zero padding bits)
    let rem = chars.get(40..43).ok_or(CryptoError::InvalidEncoding)?;
    let v0 = b64url_val(*rem.first().ok_or(CryptoError::InvalidEncoding)?)?;
    let v1 = b64url_val(*rem.get(1).ok_or(CryptoError::InvalidEncoding)?)?;
    let v2 = b64url_val(*rem.get(2).ok_or(CryptoError::InvalidEncoding)?)?;
    if (v2 & 0x03) != 0 {
        return Err(CryptoError::InvalidEncoding);
    }
    if let Some(s) = out.get_mut(30) {
        *s = (v0 << 2) | (v1 >> 4);
    }
    if let Some(s) = out.get_mut(31) {
        *s = (v1 << 4) | (v2 >> 2);
    }
    Ok(())
}

const fn b64url_val(b: u8) -> Result<u8, CryptoError> {
    match b {
        b'A'..=b'Z' => Ok(b.saturating_sub(b'A')),
        b'a'..=b'z' => Ok(b.saturating_sub(b'a').saturating_add(26)),
        b'0'..=b'9' => Ok(b.saturating_sub(b'0').saturating_add(52)),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(CryptoError::InvalidEncoding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_session_id_roundtrip_and_tampered_aad_fails() {
        let server_priv = StaticPrivateKey::from_bytes([0x1Au8; 32]);
        let server_pub = server_priv.public_key();

        let client_eph = StaticPrivateKey::from_bytes([0x2Bu8; 32]);
        let client_pub = client_eph.public_key();

        let client_shared = client_eph.diffie_hellman(&server_pub);
        assert!(client_shared.is_ok());
        let server_shared = server_priv.diffie_hellman(&client_pub);
        assert!(server_shared.is_ok());

        let Ok(cs) = client_shared else { return };
        let Ok(ss) = server_shared else { return };
        assert_eq!(cs.as_bytes(), ss.as_bytes());

        let client_random = [0x3Cu8; 32];
        let Ok(client_auth) = derive_reality_auth_key(&cs, &client_random) else {
            return;
        };
        let Ok(server_auth) = derive_reality_auth_key(&ss, &client_random) else {
            return;
        };

        let Ok(short_id) = ShortId::from_hex("0123abcd") else {
            return;
        };
        let token = RealityToken {
            client_version: [1, 8, 24],
            padding: 0,
            timestamp_secs: 1_763_444_000,
            short_id: short_id.clone(),
        };

        let aad = vec![0x01u8; 120];
        let Ok(sid_ct) = encrypt_reality_session_id(&client_auth, &client_random, &token, &aad)
        else {
            return;
        };

        let decoded = decrypt_reality_session_id(&server_auth, &client_random, &sid_ct, &aad);
        assert!(decoded.is_ok());
        if let Ok(tok) = decoded {
            assert_eq!(tok.client_version, [1, 8, 24]);
            assert_eq!(tok.timestamp_secs, 1_763_444_000);
            assert!(tok.short_id.ct_eq(&short_id));
        }

        let mut tampered_aad = aad;
        if let Some(b) = tampered_aad.get_mut(10) {
            *b ^= 0xFF;
        }
        assert_eq!(
            decrypt_reality_session_id(&server_auth, &client_random, &sid_ct, &tampered_aad).err(),
            Some(CryptoError::AeadFailed)
        );
    }

    #[test]
    fn cert_forge_replaces_last_64_bytes_with_hmac_sha512() {
        let tmpl = RealityCertTemplate::from_seed([0x44u8; 32]);
        let auth_key = AuthKey {
            bytes: Box::new([0x55u8; 32]),
        };
        let cert_res = tmpl.forge_cert_der(&auth_key);
        assert!(cert_res.is_ok());
        if let Ok(cert) = cert_res {
            let sig_slice = cert.get(cert.len().saturating_sub(64)..);
            let mut mac = <Hmac<Sha512> as MacKeyInit>::new_from_slice(auth_key.as_bytes()).ok();
            if let Some(ref mut m) = mac {
                m.update(tmpl.public_key_bytes());
                let expected = m.clone().finalize().into_bytes();
                assert_eq!(sig_slice, Some(expected.as_slice()));
            }
        }
    }

    #[test]
    fn rejects_empty_short_id_and_redacts_debug() {
        assert_eq!(
            ShortId::from_hex("").err(),
            Some(CryptoError::EmptyShortIdNotAllowed)
        );
        let key = StaticPrivateKey::from_bytes([0x11u8; 32]);
        assert_eq!(format!("{key:?}"), "StaticPrivateKey([REDACTED])");
    }

    #[test]
    fn tls13_record_seal_and_open_with_padding() {
        let secret = Tls13Secret {
            suite: Tls13CipherSuiteId::Aes128GcmSha256,
            bytes: vec![0x7Au8; 32],
        };
        let Ok(mut writer) = secret.into_record_cipher() else {
            return;
        };
        let Ok(mut reader) = secret.into_record_cipher() else {
            return;
        };

        let Ok(rec) = writer.seal_record(0x16, b"hello reality", Some(128)) else {
            return;
        };
        assert_eq!(rec.len(), 128);
        let opened = reader.open_record(&rec);
        assert_eq!(opened, Ok((0x16, b"hello reality".to_vec())));
    }

    #[test]
    fn base64url_and_hex_private_key_roundtrip() {
        let raw = [0x42u8; 32];
        let key = StaticPrivateKey::from_bytes(raw);
        let b64 = key.to_base64url();
        let hex = key.to_hex();
        assert_eq!(b64.len(), 43);
        assert_eq!(hex.len(), 64);

        let from_b64 = StaticPrivateKey::from_encoded(&b64);
        let from_hex = StaticPrivateKey::from_encoded(&hex);
        assert!(from_b64.is_ok());
        assert!(from_hex.is_ok());
        if let (Ok(k1), Ok(k2)) = (from_b64, from_hex) {
            assert_eq!(k1.public_key(), key.public_key());
            assert_eq!(k2.public_key(), key.public_key());
        }

        // Non-canonical trailing bits in 43rd Base64url char must be rejected.
        let mut bad_b64 = (*b64).clone();
        bad_b64.pop();
        bad_b64.push('B');
        assert_eq!(
            StaticPrivateKey::from_base64url(&bad_b64).err(),
            Some(CryptoError::InvalidEncoding)
        );
    }
}
