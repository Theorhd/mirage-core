//! Reality authentication state machine, bounded anti-replay cache, and
//! TLS 1.3 handshake completion mimicking `dest`.

use core::fmt;
use std::collections::{BTreeMap, HashSet};

use subtle::{Choice, ConstantTimeEq};

use crate::crypto::{
    compute_tls13_server_key_exchange, decrypt_reality_session_id, derive_reality_auth_key,
    keyed_replay_tag, AuthKey, CryptoError, RealityCertTemplate, ShortId, StaticPrivateKey,
    Tls13RecordCipher, Tls13Secret, TranscriptHash,
};
use crate::tls_parser::{ClientHelloInfo, DestServerProfile, Tls13CipherSuiteId};

/// Result of checking a `ClientHello.random` tag in the anti-replay cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// Fresh token accepted and atomically inserted into the active time bucket.
    Accepted,
    /// Token was already seen within the active window (replay attack).
    Replayed,
    /// Cache reached maximum capacity; fail-closed by delegating to `dest`.
    Saturated,
}

/// Bounded, fail-closed, time-bucketed anti-replay cache.
///
/// Stores only 16-byte `HMAC-SHA256(process_key, client_random)` tags so raw
/// `ClientHello.random` values are never retained. Expired buckets are pruned
/// wholesale; valid entries are never evicted early.
pub struct ReplayCache {
    hmac_key: [u8; 32],
    window_secs: u64,
    max_entries: usize,
    total_entries: usize,
    buckets: BTreeMap<u64, HashSet<[u8; 16]>>,
}

impl ReplayCache {
    /// Creates a new bounded anti-replay cache.
    #[must_use]
    pub fn new(hmac_key: [u8; 32], window_secs: u64, max_entries: usize) -> Self {
        Self {
            hmac_key,
            window_secs,
            max_entries,
            total_entries: 0,
            buckets: BTreeMap::new(),
        }
    }

    /// Atomically checks whether `client_random` was already seen and inserts it
    /// into the `now_unix_secs` bucket if accepted.
    ///
    /// Fails closed (`ReplayOutcome::Saturated`) when capacity is exhausted,
    /// never evicting valid entries early.
    pub fn check_and_insert(
        &mut self,
        client_random: &[u8; 32],
        now_unix_secs: u64,
    ) -> ReplayOutcome {
        self.prune_expired(now_unix_secs);

        let tag = keyed_replay_tag(&self.hmac_key, client_random);
        if self.buckets.values().any(|set| set.contains(&tag)) {
            return ReplayOutcome::Replayed;
        }

        if self.total_entries >= self.max_entries {
            return ReplayOutcome::Saturated;
        }

        let bucket = self.buckets.entry(now_unix_secs).or_default();
        if bucket.insert(tag) {
            self.total_entries = self.total_entries.saturating_add(1);
        }
        ReplayOutcome::Accepted
    }

    /// Returns the number of active entries currently tracked.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.total_entries
    }

    /// Returns `true` if the cache has no active entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total_entries == 0
    }

    fn prune_expired(&mut self, now_unix_secs: u64) {
        let cutoff = now_unix_secs.saturating_sub(self.window_secs);
        let retained = self.buckets.split_off(&cutoff);
        let expired = core::mem::replace(&mut self.buckets, retained);
        let removed_count: usize = expired.values().map(HashSet::len).sum();
        self.total_entries = self.total_entries.saturating_sub(removed_count);
    }
}

impl fmt::Debug for ReplayCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayCache")
            .field("window_secs", &self.window_secs)
            .field("max_entries", &self.max_entries)
            .field("total_entries", &self.total_entries)
            .finish()
    }
}

/// Reason a `ClientHello` fell back instead of opening a Reality session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFallbackReason {
    /// ClientHello did not offer TLS 1.3, 32-byte SessionId, or X25519 share.
    IncompatibleClientHello,
    /// AEAD authentication failed for all configured private keys.
    InvalidAuth,
    /// Client timestamp outside configured `max_time_diff_secs` window.
    TimestampExpired,
    /// Client version outside `[min_client_ver, max_client_ver]`.
    ClientVersionRejected,
    /// ShortID did not match any configured allowlist entry.
    InvalidShortId,
    /// `ClientHello.random` was already seen in the replay window.
    Replayed,
    /// Anti-replay cache is saturated (fail-closed).
    ReplayCacheSaturated,
}

/// Authenticated client metadata extracted from a valid Reality `ClientHello`.
#[derive(Clone)]
pub struct AuthenticatedClient {
    /// Derived 32-byte Reality `AuthKey`.
    pub auth_key: AuthKey,
    /// Client Xray version `[major, minor, patch]`.
    pub client_version: [u8; 3],
}

impl fmt::Debug for AuthenticatedClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedClient")
            .field("auth_key", &"[REDACTED]")
            .field("client_version", &self.client_version)
            .finish()
    }
}

/// Outcome of Reality authentication against a parsed `ClientHelloInfo`.
#[derive(Debug, Clone)]
pub enum AuthOutcome {
    /// Client is authenticated; proceed to `dest` mimicry & TLS 1.3 completion.
    Authenticated(Box<AuthenticatedClient>),
    /// Authentication failed or replay/saturation detected; delegate to `dest`.
    Fallback(AuthFallbackReason),
}

/// Server-side Reality verifier parameters.
#[derive(Clone)]
pub struct RealityAuthParams<'a> {
    /// Active server private keys (e.g., `[current, previous]` during rotation).
    pub private_keys: &'a [StaticPrivateKey],
    /// Allowed non-empty ShortIDs.
    pub short_ids: &'a [ShortId],
    /// Maximum allowed clock skew between client timestamp and server Unix time (seconds).
    pub max_time_diff_secs: u64,
    /// Optional inclusive minimum client version `[major, minor, patch]`.
    pub min_client_ver: Option<[u8; 3]>,
    /// Optional inclusive maximum client version `[major, minor, patch]`.
    pub max_client_ver: Option<[u8; 3]>,
}

/// Verifies a parsed `ClientHelloInfo` against Reality credentials and updates
/// `replay_cache` only after cryptographic and ShortID validation succeed.
#[must_use]
pub fn authenticate_client_hello(
    client_hello: &ClientHelloInfo,
    params: &RealityAuthParams<'_>,
    replay_cache: &mut ReplayCache,
    now_unix_secs: u64,
) -> AuthOutcome {
    if !client_hello.offers_tls13 || params.max_time_diff_secs == 0 {
        return AuthOutcome::Fallback(AuthFallbackReason::IncompatibleClientHello);
    }

    let sid_slice = client_hello.session_id.as_slice();
    if sid_slice.len() != 32 {
        return AuthOutcome::Fallback(AuthFallbackReason::IncompatibleClientHello);
    }
    let mut sid_arr = [0u8; 32];
    sid_arr.copy_from_slice(sid_slice);

    let Some(aad) = client_hello.build_reality_aad() else {
        return AuthOutcome::Fallback(AuthFallbackReason::IncompatibleClientHello);
    };
    let Some(peer_x25519) = client_hello.key_shares.reality_auth_x25519_pubkey() else {
        return AuthOutcome::Fallback(AuthFallbackReason::IncompatibleClientHello);
    };

    let mut decrypted: Option<(AuthKey, crate::crypto::RealityToken)> = None;
    for priv_key in params.private_keys {
        let Ok(shared) = priv_key.diffie_hellman(&peer_x25519) else {
            continue;
        };
        let Ok(auth_key) = derive_reality_auth_key(&shared, &client_hello.random) else {
            continue;
        };
        if let Ok(token) =
            decrypt_reality_session_id(&auth_key, &client_hello.random, &sid_arr, &aad)
        {
            decrypted = Some((auth_key, token));
            break;
        }
    }

    let Some((auth_key, token)) = decrypted else {
        return AuthOutcome::Fallback(AuthFallbackReason::InvalidAuth);
    };

    let age_secs = now_unix_secs.abs_diff(u64::from(token.timestamp_secs));
    if age_secs > params.max_time_diff_secs {
        return AuthOutcome::Fallback(AuthFallbackReason::TimestampExpired);
    }

    if let Some(min_ver) = params.min_client_ver {
        if token.client_version < min_ver {
            return AuthOutcome::Fallback(AuthFallbackReason::ClientVersionRejected);
        }
    }
    if let Some(max_ver) = params.max_client_ver {
        if token.client_version > max_ver {
            return AuthOutcome::Fallback(AuthFallbackReason::ClientVersionRejected);
        }
    }

    // Iterate ALL short_ids without early exit to avoid leaking ShortID count/index via timing.
    let mut matched = Choice::from(0u8);
    for allowed in params.short_ids {
        let is_eq = Choice::from(u8::from(token.short_id.ct_eq(allowed)));
        matched |= is_eq;
    }
    if !bool::from(matched) {
        return AuthOutcome::Fallback(AuthFallbackReason::InvalidShortId);
    }

    match replay_cache.check_and_insert(&client_hello.random, now_unix_secs) {
        ReplayOutcome::Accepted => AuthOutcome::Authenticated(Box::new(AuthenticatedClient {
            auth_key,
            client_version: token.client_version,
        })),
        ReplayOutcome::Replayed => AuthOutcome::Fallback(AuthFallbackReason::Replayed),
        ReplayOutcome::Saturated => AuthOutcome::Fallback(AuthFallbackReason::ReplayCacheSaturated),
    }
}

/// Result of feeding client flight bytes into `RealityPendingHandshake`.
#[derive(Debug)]
pub enum ClientFlightStatus {
    /// More bytes are needed from the client socket.
    NeedMoreData,
    /// Client `Finished` verified; TLS 1.3 session is established.
    Complete {
        session: Box<RealityTlsSession>,
        /// Any decrypted TLS 1.3 Application Data bytes that arrived right after `Finished`.
        initial_app_data: Vec<u8>,
    },
    /// Client sent invalid CCS/Finished/record bytes; abort session cleanly.
    Failed,
}

/// Active, authenticated TLS 1.3 record stream after Reality handshake completion.
pub struct RealityTlsSession {
    server_app: Tls13RecordCipher,
    client_app: Tls13RecordCipher,
    cipher_suite: Tls13CipherSuiteId,
    read_buf: Vec<u8>,
}

impl fmt::Debug for RealityTlsSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityTlsSession")
            .field("cipher_suite", &self.cipher_suite)
            .finish()
    }
}

/// Independent read half of an active `RealityTlsSession`.
pub struct RealityTlsReader {
    client_app: Tls13RecordCipher,
    read_buf: Vec<u8>,
}

impl RealityTlsReader {
    /// Appends raw incoming wire bytes to the read buffer.
    pub fn push_wire_bytes(&mut self, incoming: &[u8]) {
        self.read_buf.extend_from_slice(incoming);
    }

    /// Consumes and decrypts at most ONE complete outer TLS 1.3 record.
    pub fn next_record(&mut self) -> Result<Option<(u8, Vec<u8>)>, CryptoError> {
        if self.read_buf.len() < 5 {
            return Ok(None);
        }
        let ct = *self.read_buf.first().ok_or(CryptoError::InvalidRecord)?;
        if ct != 0x17 {
            return Err(CryptoError::InvalidRecord);
        }
        let b3 = *self.read_buf.get(3).ok_or(CryptoError::InvalidRecord)?;
        let b4 = *self.read_buf.get(4).ok_or(CryptoError::InvalidRecord)?;
        let frag_len = usize::from(u16::from_be_bytes([b3, b4]));
        let rec_total = 5usize
            .checked_add(frag_len)
            .ok_or(CryptoError::InvalidRecord)?;
        let Some(rec) = self.read_buf.get(..rec_total) else {
            return Ok(None);
        };
        let (inner_ct, payload) = self.client_app.open_record(rec)?;
        self.read_buf.drain(..rec_total);
        Ok(Some((inner_ct, payload)))
    }

    /// Consumes the reader and returns any unparsed raw wire bytes (for Vision direct switch).
    #[must_use]
    pub fn into_remaining_wire_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.read_buf)
    }
}

/// Independent write half of an active `RealityTlsSession`.
pub struct RealityTlsWriter {
    server_app: Tls13RecordCipher,
}

impl RealityTlsWriter {
    /// Encrypts application data into a TLS 1.3 `0x17` record.
    pub fn seal_app_data(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.server_app.seal_record(0x17, plaintext, None)
    }
}

impl RealityTlsSession {
    /// Splits this session into independent read and write halves for concurrent
    /// lock-free uplink/downlink relaying.
    #[must_use]
    pub fn into_split(self) -> (RealityTlsReader, RealityTlsWriter) {
        (
            RealityTlsReader {
                client_app: self.client_app,
                read_buf: self.read_buf,
            },
            RealityTlsWriter {
                server_app: self.server_app,
            },
        )
    }

    /// Encrypts application data into a TLS 1.3 `0x17` record.
    pub fn seal_app_data(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.server_app.seal_record(0x17, plaintext, None)
    }

    /// Appends raw incoming wire bytes to the session read buffer.
    pub fn push_wire_bytes(&mut self, incoming: &[u8]) {
        self.read_buf.extend_from_slice(incoming);
    }

    /// Consumes and decrypts at most ONE complete outer TLS 1.3 record from the
    /// read buffer, leaving any subsequent raw/encrypted bytes intact.
    ///
    /// Returns `Ok(Some((inner_content_type, plaintext)))` or `Ok(None)` if
    /// more wire bytes are needed.
    pub fn next_record(&mut self) -> Result<Option<(u8, Vec<u8>)>, CryptoError> {
        if self.read_buf.len() < 5 {
            return Ok(None);
        }
        let ct = *self.read_buf.first().ok_or(CryptoError::InvalidRecord)?;
        if ct != 0x17 {
            return Err(CryptoError::InvalidRecord);
        }
        let b3 = *self.read_buf.get(3).ok_or(CryptoError::InvalidRecord)?;
        let b4 = *self.read_buf.get(4).ok_or(CryptoError::InvalidRecord)?;
        let frag_len = usize::from(u16::from_be_bytes([b3, b4]));
        let rec_total = 5usize
            .checked_add(frag_len)
            .ok_or(CryptoError::InvalidRecord)?;
        let Some(rec) = self.read_buf.get(..rec_total) else {
            return Ok(None);
        };
        let (inner_ct, payload) = self.client_app.open_record(rec)?;
        self.read_buf.drain(..rec_total);
        Ok(Some((inner_ct, payload)))
    }

    /// Consumes the session and returns any remaining unparsed raw wire bytes
    /// (used when XTLS-Vision switches uplink to `DirectCopy`).
    #[must_use]
    pub fn into_remaining_wire_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.read_buf)
    }

    /// Feeds raw incoming TLS wire bytes and extracts all complete decrypted
    /// records currently buffered.
    /// Returns `(application_data_chunks, peer_close_notify)`.
    pub fn feed_wire_bytes(&mut self, incoming: &[u8]) -> Result<(Vec<u8>, bool), CryptoError> {
        self.push_wire_bytes(incoming);
        let mut app_out = Vec::new();
        let mut close_notify = false;

        while let Some((inner_ct, payload)) = self.next_record()? {
            match inner_ct {
                0x17 => app_out.extend_from_slice(&payload),
                0x15 => {
                    if payload.get(1) == Some(&0) {
                        close_notify = true;
                    }
                }
                0x16 => {}
                _ => return Err(CryptoError::InvalidRecord),
            }
        }

        Ok((app_out, close_notify))
    }
}

/// Pending Reality TLS 1.3 handshake awaiting client `Finished`.
pub struct RealityPendingHandshake {
    client_hs_cipher: Tls13RecordCipher,
    expected_client_finished: Vec<u8>,
    server_app_cipher: Option<Tls13RecordCipher>,
    client_app_cipher: Option<Tls13RecordCipher>,
    cipher_suite: Tls13CipherSuiteId,
    incoming_buf: Vec<u8>,
    seen_ccs: bool,
}

impl fmt::Debug for RealityPendingHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityPendingHandshake")
            .field("cipher_suite", &self.cipher_suite)
            .finish()
    }
}

/// Output of preparing the Reality server TLS 1.3 flight.
pub struct PreparedServerFlight {
    /// Complete wire bytes (`ServerHello` + optional `ChangeCipherSpec` + encrypted handshake records)
    /// to write directly to the authenticated client socket.
    pub wire_bytes: Vec<u8>,
    /// State machine waiting for the client's `Finished` record.
    pub pending: RealityPendingHandshake,
}

/// Builds the complete Reality server TLS 1.3 flight mimicking `dest_profile`.
pub fn prepare_server_flight(
    client_hello: &ClientHelloInfo,
    auth: &AuthenticatedClient,
    dest_profile: &DestServerProfile,
    cert_template: &RealityCertTemplate,
    x25519_ephemeral_seed: [u8; 32],
    mlkem_randomness: [u8; 32],
) -> Result<PreparedServerFlight, CryptoError> {
    let key_exchange = compute_tls13_server_key_exchange(
        dest_profile.selected_group,
        &client_hello.key_shares,
        x25519_ephemeral_seed,
        mlkem_randomness,
    )?;

    if key_exchange.server_key_share.len() != dest_profile.key_exchange_len {
        return Err(CryptoError::InvalidRecord);
    }

    let mut server_hello_raw = dest_profile.server_hello_raw.clone();
    let ke_end = dest_profile
        .key_exchange_offset
        .checked_add(dest_profile.key_exchange_len)
        .ok_or(CryptoError::InvalidRecord)?;
    let ke_slot = server_hello_raw
        .get_mut(dest_profile.key_exchange_offset..ke_end)
        .ok_or(CryptoError::InvalidRecord)?;
    ke_slot.copy_from_slice(&key_exchange.server_key_share);

    let suite = dest_profile.cipher_suite;
    let mut transcript = TranscriptHash::new(suite);
    transcript.update(&client_hello.handshake_raw);
    transcript.update(&server_hello_raw);

    let early = Tls13Secret::early_secret(suite);
    let handshake_secret = early.derive_handshake_secret(&key_exchange.shared_secret)?;
    let ch_sh_hash = transcript.current_hash();
    let s_hs_secret = handshake_secret.derive_secret(b"s hs traffic", &ch_sh_hash)?;
    let c_hs_secret = handshake_secret.derive_secret(b"c hs traffic", &ch_sh_hash)?;

    let mut server_hs_cipher = s_hs_secret.into_record_cipher()?;
    let client_hs_cipher = c_hs_secret.into_record_cipher()?;

    let mut wire_bytes = Vec::with_capacity(4096);

    // 1. ServerHello plaintext TLS record (0x16 0x03 0x03 <len>)
    let sh_len_u16 =
        u16::try_from(server_hello_raw.len()).map_err(|_| CryptoError::InvalidRecord)?;
    wire_bytes.extend_from_slice(&[0x16, 0x03, 0x03]);
    wire_bytes.extend_from_slice(&sh_len_u16.to_be_bytes());
    wire_bytes.extend_from_slice(&server_hello_raw);

    // 2. Optional middlebox-compatibility ChangeCipherSpec matching `dest`
    if dest_profile.send_ccs {
        wire_bytes.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    }

    // 3. EncryptedExtensions
    let ee_msg = build_encrypted_extensions_msg(client_hello.sni.is_some());
    transcript.update(&ee_msg);
    let ee_rec = server_hs_cipher.seal_record(
        0x16,
        &ee_msg,
        nonzero_target(dest_profile.encrypted_record_lens.first().copied()),
    )?;
    wire_bytes.extend_from_slice(&ee_rec);

    // 4. Certificate (forged with HMAC-SHA512(AuthKey, ed25519_pub))
    let forged_cert_der = cert_template.forge_cert_der(&auth.auth_key)?;
    let cert_msg = build_certificate_msg(&forged_cert_der)?;
    transcript.update(&cert_msg);
    let cert_rec = server_hs_cipher.seal_record(
        0x16,
        &cert_msg,
        nonzero_target(dest_profile.encrypted_record_lens.get(1).copied()),
    )?;
    wire_bytes.extend_from_slice(&cert_rec);

    // 5. CertificateVerify (Ed25519 signature 0x0807)
    let cert_verify_sig = cert_template.sign_certificate_verify(&transcript.current_hash());
    let cv_msg = build_certificate_verify_msg(&cert_verify_sig);
    transcript.update(&cv_msg);
    let cv_rec = server_hs_cipher.seal_record(
        0x16,
        &cv_msg,
        nonzero_target(dest_profile.encrypted_record_lens.get(2).copied()),
    )?;
    wire_bytes.extend_from_slice(&cv_rec);

    // 6. Server Finished
    let server_finished_vd =
        s_hs_secret.compute_finished_verify_data(&transcript.current_hash())?;
    let fin_msg = build_finished_msg(&server_finished_vd)?;
    transcript.update(&fin_msg);
    let fin_rec = server_hs_cipher.seal_record(
        0x16,
        &fin_msg,
        nonzero_target(dest_profile.encrypted_record_lens.get(3).copied()),
    )?;
    wire_bytes.extend_from_slice(&fin_rec);

    // 7. Derive Application traffic secrets & expected Client Finished
    let sf_hash = transcript.current_hash();
    let master = handshake_secret.derive_master_secret()?;
    let s_app_secret = master.derive_secret(b"s ap traffic", &sf_hash)?;
    let c_app_secret = master.derive_secret(b"c ap traffic", &sf_hash)?;

    let mut server_app_cipher = s_app_secret.into_record_cipher()?;
    let client_app_cipher = c_app_secret.into_record_cipher()?;
    let expected_client_finished = c_hs_secret.compute_finished_verify_data(&sf_hash)?;

    // 8. Optional padded dummy record matching `dest`'s 5th encrypted record (NewSessionTicket)
    if let Some(nst_len) = nonzero_target(dest_profile.encrypted_record_lens.get(4).copied()) {
        if nst_len >= 22 {
            let nst_pad = server_app_cipher.seal_record(0x17, &[], Some(nst_len))?;
            wire_bytes.extend_from_slice(&nst_pad);
        }
    }

    Ok(PreparedServerFlight {
        wire_bytes,
        pending: RealityPendingHandshake {
            client_hs_cipher,
            expected_client_finished,
            server_app_cipher: Some(server_app_cipher),
            client_app_cipher: Some(client_app_cipher),
            cipher_suite: suite,
            incoming_buf: Vec::new(),
            seen_ccs: false,
        },
    })
}

impl RealityPendingHandshake {
    /// Feeds bytes from the client socket until optional `ChangeCipherSpec` and
    /// encrypted client `Finished` have been verified.
    pub fn feed_client_bytes(&mut self, data: &[u8]) -> ClientFlightStatus {
        self.incoming_buf.extend_from_slice(data);
        let mut offset = 0usize;

        while let Some(rem) = self.incoming_buf.get(offset..) {
            if rem.len() < 5 {
                break;
            }
            let ct = *rem.first().unwrap_or(&0);
            let major = *rem.get(1).unwrap_or(&0);
            let minor = *rem.get(2).unwrap_or(&0);
            let b3 = *rem.get(3).unwrap_or(&0);
            let b4 = *rem.get(4).unwrap_or(&0);
            if major != 0x03 || minor > 0x04 {
                return ClientFlightStatus::Failed;
            }
            let frag_len = usize::from(u16::from_be_bytes([b3, b4]));
            let Some(rec_total) = 5usize.checked_add(frag_len) else {
                return ClientFlightStatus::Failed;
            };
            let Some(rec) = rem.get(..rec_total) else {
                break;
            };

            if ct == 0x14 {
                if self.seen_ccs || rec_total != 6 || rec.get(5) != Some(&0x01) {
                    return ClientFlightStatus::Failed;
                }
                self.seen_ccs = true;
                offset = offset.saturating_add(rec_total);
                continue;
            }

            if ct != 0x17 {
                return ClientFlightStatus::Failed;
            }

            let Ok((inner_ct, plaintext)) = self.client_hs_cipher.open_record(rec) else {
                return ClientFlightStatus::Failed;
            };
            if inner_ct != 0x16 {
                return ClientFlightStatus::Failed;
            }
            // Expect Handshake Finished: 0x14 || u24_len || verify_data
            if plaintext.first() != Some(&0x14) {
                return ClientFlightStatus::Failed;
            }
            let Some(vd) = plaintext.get(4..) else {
                return ClientFlightStatus::Failed;
            };
            let b1 = *plaintext.get(1).unwrap_or(&0);
            let b2 = *plaintext.get(2).unwrap_or(&0);
            let b3 = *plaintext.get(3).unwrap_or(&0);
            let expected_len = usize::from(u16::from_be_bytes([b2, b3]));
            if b1 != 0
                || vd.len() != expected_len
                || vd.len() != self.expected_client_finished.len()
            {
                return ClientFlightStatus::Failed;
            }
            if !bool::from(vd.ct_eq(&self.expected_client_finished)) {
                return ClientFlightStatus::Failed;
            }

            offset = offset.saturating_add(rec_total);
            let trailing = self.incoming_buf.get(offset..).unwrap_or(&[]).to_vec();

            // Construct active TLS 1.3 session and feed any trailing encrypted AppData records.
            let Some(server_app) = self.server_app_cipher.take() else {
                return ClientFlightStatus::Failed;
            };
            let Some(client_app) = self.client_app_cipher.take() else {
                return ClientFlightStatus::Failed;
            };
            let mut session = RealityTlsSession {
                server_app,
                client_app,
                cipher_suite: self.cipher_suite,
                read_buf: trailing,
            };
            let initial_app_data = Vec::new();
            let _ = &mut session;

            return ClientFlightStatus::Complete {
                session: Box::new(session),
                initial_app_data,
            };
        }

        if offset > 0 {
            self.incoming_buf.drain(..offset);
        }
        ClientFlightStatus::NeedMoreData
    }
}

const fn nonzero_target(val: Option<usize>) -> Option<usize> {
    match val {
        Some(v) if v > 0 => Some(v),
        _ => None,
    }
}

fn build_encrypted_extensions_msg(ack_sni: bool) -> Vec<u8> {
    if ack_sni {
        // 0x08 (EncryptedExtensions) || u24_len(6) || u16 ext_len(4) || 0x0000 (SNI) || 0x0000
        vec![0x08, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]
    } else {
        vec![0x08, 0x00, 0x00, 0x02, 0x00, 0x00]
    }
}

fn build_certificate_msg(cert_der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cert_len_u32 = u32::try_from(cert_der.len()).map_err(|_| CryptoError::InvalidRecord)?;
    // entry = u24(cert_len) + cert_der + u16(0 extensions)
    let list_len = 3usize
        .checked_add(cert_der.len())
        .and_then(|v| v.checked_add(2))
        .ok_or(CryptoError::InvalidRecord)?;
    let list_len_u32 = u32::try_from(list_len).map_err(|_| CryptoError::InvalidRecord)?;
    // body = u8(0 request_context_len) + u24(list_len) + entry
    let body_len = 1usize
        .checked_add(3)
        .and_then(|v| v.checked_add(list_len))
        .ok_or(CryptoError::InvalidRecord)?;
    let body_len_u32 = u32::try_from(body_len).map_err(|_| CryptoError::InvalidRecord)?;

    let mut out = Vec::with_capacity(4usize.saturating_add(body_len));
    out.push(0x0B);
    push_u24(&mut out, body_len_u32);
    out.push(0x00);
    push_u24(&mut out, list_len_u32);
    push_u24(&mut out, cert_len_u32);
    out.extend_from_slice(cert_der);
    out.extend_from_slice(&[0x00, 0x00]);
    Ok(out)
}

fn build_certificate_verify_msg(sig: &[u8; 64]) -> Vec<u8> {
    // 0x0F || u24(68) || 0x0807 (Ed25519) || u16(64) || sig
    let mut out = Vec::with_capacity(72);
    out.extend_from_slice(&[0x0F, 0x00, 0x00, 0x44, 0x08, 0x07, 0x00, 0x40]);
    out.extend_from_slice(sig);
    out
}

fn build_finished_msg(verify_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let vd_len = u32::try_from(verify_data.len()).map_err(|_| CryptoError::InvalidRecord)?;
    let mut out = Vec::with_capacity(4usize.saturating_add(verify_data.len()));
    out.push(0x14);
    push_u24(&mut out, vd_len);
    out.extend_from_slice(verify_data);
    Ok(out)
}

fn push_u24(buf: &mut Vec<u8>, val: u32) {
    let bytes = val.to_be_bytes();
    if let Some(tail) = bytes.get(1..4) {
        buf.extend_from_slice(tail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encrypt_reality_session_id, RealityToken};
    use crate::tls_parser::{inspect_client_hello, InspectOutcome, DEFAULT_MAX_CLIENT_HELLO_BYTES};

    fn make_client_hello(
        server_pub: &[u8; 32],
        client_priv_seed: [u8; 32],
        client_random: [u8; 32],
        timestamp_secs: u32,
        short_id: &ShortId,
    ) -> Option<ClientHelloInfo> {
        let client_priv = StaticPrivateKey::from_bytes(client_priv_seed);
        let client_pub = client_priv.public_key();
        let shared = client_priv.diffie_hellman(server_pub).ok()?;
        let auth_key = derive_reality_auth_key(&shared, &client_random).ok()?;

        let sni = b"example.com";
        let mut extensions = Vec::new();
        // SNI
        let entry_len = 3usize.saturating_add(sni.len());
        let sni_ext_len = 2usize.saturating_add(entry_len);
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(entry_len as u16).to_be_bytes());
        extensions.push(0x00);
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(sni);
        // supported_versions (TLS 1.3)
        extensions.extend_from_slice(&0x002bu16.to_be_bytes());
        extensions.extend_from_slice(&3u16.to_be_bytes());
        extensions.push(2);
        extensions.extend_from_slice(&0x0304u16.to_be_bytes());
        // key_share (X25519)
        extensions.extend_from_slice(&0x0033u16.to_be_bytes());
        extensions.extend_from_slice(&38u16.to_be_bytes());
        extensions.extend_from_slice(&36u16.to_be_bytes());
        extensions.extend_from_slice(&0x001du16.to_be_bytes());
        extensions.extend_from_slice(&32u16.to_be_bytes());
        extensions.extend_from_slice(&client_pub);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&client_random);
        body.push(32);
        body.extend([0u8; 32]); // zeroed SessionId for AAD
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let len_bytes = (body.len() as u32).to_be_bytes();
        let mut hs = Vec::new();
        hs.push(0x01);
        hs.extend_from_slice(len_bytes.get(1..4)?);
        hs.extend_from_slice(&body);

        let token = RealityToken {
            client_version: [1, 8, 24],
            padding: 0,
            timestamp_secs,
            short_id: short_id.clone(),
        };
        let sealed_sid = encrypt_reality_session_id(&auth_key, &client_random, &token, &hs).ok()?;
        let sid_slot = hs.get_mut(39..71)?;
        sid_slot.copy_from_slice(&sealed_sid);

        let mut wire = Vec::new();
        wire.push(0x16);
        wire.extend_from_slice(&0x0301u16.to_be_bytes());
        wire.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        wire.extend_from_slice(&hs);

        match inspect_client_hello(&wire, DEFAULT_MAX_CLIENT_HELLO_BYTES) {
            InspectOutcome::ClientHello(info) => Some(*info),
            _ => None,
        }
    }

    #[test]
    fn replay_cache_rejects_replays_and_fails_closed_on_saturation() {
        let mut cache = ReplayCache::new([0x99u8; 32], 60, 2);
        let r1 = [0x01u8; 32];
        let r2 = [0x02u8; 32];
        let r3 = [0x03u8; 32];

        assert_eq!(cache.check_and_insert(&r1, 1000), ReplayOutcome::Accepted);
        assert_eq!(cache.check_and_insert(&r1, 1010), ReplayOutcome::Replayed);
        assert_eq!(cache.check_and_insert(&r2, 1020), ReplayOutcome::Accepted);
        // Cache is saturated (2/2): must fail closed and NOT evict r1/r2 early!
        assert_eq!(cache.check_and_insert(&r3, 1030), ReplayOutcome::Saturated);
        assert_eq!(cache.check_and_insert(&r1, 1030), ReplayOutcome::Replayed);

        // Advance time past window (1000 < 1070 - 60 = 1010): r1 expires wholesale!
        assert_eq!(cache.check_and_insert(&r3, 1070), ReplayOutcome::Accepted);
    }

    #[test]
    fn authenticates_valid_reality_client_and_blocks_replay_and_wrong_short_id() {
        let server_priv = StaticPrivateKey::from_bytes([0x41u8; 32]);
        let server_pub = server_priv.public_key();
        let Ok(sid_ok) = ShortId::from_hex("aabbccdd") else {
            return;
        };
        let Ok(sid_bad) = ShortId::from_hex("11223344") else {
            return;
        };

        let Some(ch) = make_client_hello(
            &server_pub,
            [0x51u8; 32],
            [0x61u8; 32],
            1_760_000_000,
            &sid_ok,
        ) else {
            return;
        };

        let keys = [server_priv];
        let sids = [sid_ok.clone()];
        let params = RealityAuthParams {
            private_keys: &keys,
            short_ids: &sids,
            max_time_diff_secs: 60,
            min_client_ver: Some([1, 8, 0]),
            max_client_ver: None,
        };
        let mut cache = ReplayCache::new([0x77u8; 32], 60, 100);

        // Wrong timestamp -> TimestampExpired
        let res_old = authenticate_client_hello(&ch, &params, &mut cache, 1_760_000_200);
        assert!(matches!(
            res_old,
            AuthOutcome::Fallback(AuthFallbackReason::TimestampExpired)
        ));
        assert!(cache.is_empty());

        // Valid timestamp -> Authenticated
        let res_ok = authenticate_client_hello(&ch, &params, &mut cache, 1_760_000_010);
        assert!(matches!(res_ok, AuthOutcome::Authenticated(_)));
        assert_eq!(cache.len(), 1);

        // Immediate replay -> Replayed
        let res_rep = authenticate_client_hello(&ch, &params, &mut cache, 1_760_000_015);
        assert!(matches!(
            res_rep,
            AuthOutcome::Fallback(AuthFallbackReason::Replayed)
        ));

        // Wrong ShortID -> InvalidShortId (not inserted into cache)
        let Some(ch_bad_sid) = make_client_hello(
            &server_pub,
            [0x52u8; 32],
            [0x62u8; 32],
            1_760_000_010,
            &sid_bad,
        ) else {
            return;
        };
        let res_bad_sid =
            authenticate_client_hello(&ch_bad_sid, &params, &mut cache, 1_760_000_010);
        assert!(matches!(
            res_bad_sid,
            AuthOutcome::Fallback(AuthFallbackReason::InvalidShortId)
        ));
        assert_eq!(cache.len(), 1);
    }
}
