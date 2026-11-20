#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use mirage_core::crypto::{
    decrypt_reality_session_id, derive_reality_auth_key, AuthKey, RealityCertTemplate, ShortId,
    StaticPrivateKey,
};
use mirage_core::reality::{
    prepare_server_flight, verify_client_hello_credentials, AuthenticatedClient, RealityAuthParams,
    ReplayCache,
};
use mirage_core::tls_parser::{
    inspect_client_hello, parse_dest_server_flight, ClientHelloInfo, InspectOutcome,
    ServerFlightStatus, DEFAULT_MAX_CLIENT_HELLO_BYTES,
};

fn dummy_client_hello() -> Option<ClientHelloInfo> {
    let mut rec = vec![0u8; 5];
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x11; 32]);
    body.push(32);
    body.extend_from_slice(&[0x22; 32]);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);
    let exts = [
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, // supported_versions: 1.3
        0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
    ];
    let mut full_exts = Vec::from(exts);
    full_exts.extend_from_slice(&[0x33; 32]);
    body.extend_from_slice(&u16::try_from(full_exts.len()).ok()?.to_be_bytes());
    body.extend_from_slice(&full_exts);

    let hs_len = body.len();
    let mut hs = vec![0x01, 0x00];
    hs.extend_from_slice(&u16::try_from(hs_len).ok()?.to_be_bytes());
    hs.extend_from_slice(&body);

    rec[0] = 0x16;
    rec[1] = 0x03;
    rec[2] = 0x01;
    let rec_len = u16::try_from(hs.len()).ok()?.to_be_bytes();
    rec[3] = rec_len[0];
    rec[4] = rec_len[1];
    rec.extend_from_slice(&hs);

    if let InspectOutcome::ClientHello(ch) =
        inspect_client_hello(&rec, DEFAULT_MAX_CLIENT_HELLO_BYTES)
    {
        Some(*ch)
    } else {
        None
    }
}

fn minimal_dest_profile_bytes() -> Vec<u8> {
    let mut sh_body = Vec::new();
    sh_body.extend_from_slice(&[0x03, 0x03]);
    sh_body.extend_from_slice(&[0x44; 32]);
    sh_body.push(32);
    sh_body.extend_from_slice(&[0x22; 32]);
    sh_body.extend_from_slice(&[0x13, 0x01]);
    sh_body.push(0x00);
    let mut exts = Vec::new();
    exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    exts.extend_from_slice(&[0x55; 32]);
    let exts_len = u16::try_from(exts.len()).unwrap_or(0).to_be_bytes();
    sh_body.extend_from_slice(&exts_len);
    sh_body.extend_from_slice(&exts);

    let sh_len = u16::try_from(sh_body.len()).unwrap_or(0).to_be_bytes();
    let mut sh_hs = vec![0x02, 0x00, sh_len[0], sh_len[1]];
    sh_hs.extend_from_slice(&sh_body);

    let rec_len = u16::try_from(sh_hs.len()).unwrap_or(0).to_be_bytes();
    let mut flight = vec![0x16, 0x03, 0x03, rec_len[0], rec_len[1]];
    flight.extend_from_slice(&sh_hs);
    flight.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x12]);
    flight.extend_from_slice(&[0x00; 18]);
    flight
}

fuzz_target!(|data: &[u8]| {
    let key = StaticPrivateKey::from_bytes([0x41u8; 32]);
    let peer_pub = StaticPrivateKey::from_bytes([0x51u8; 32]).public_key();
    let sid = ShortId::from_bytes([0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0]);
    let keys = [key.clone()];
    let sids = [sid];
    let params = RealityAuthParams {
        private_keys: &keys,
        short_ids: &sids,
        max_time_diff_secs: 120,
        min_client_ver: None,
        max_client_ver: None,
    };

    if let InspectOutcome::ClientHello(ch) =
        inspect_client_hello(data, DEFAULT_MAX_CLIENT_HELLO_BYTES)
    {
        let mut cache = ReplayCache::new([0x77; 32], 240, 16);
        if let Ok(verified) = verify_client_hello_credentials(&ch, &params, 1_760_000_000) {
            let _ = cache.check_and_insert_with_expiry(
                &ch.random,
                1_760_000_000,
                verified.replay_expires_at,
            );
        }
    }

    let Ok(shared) = key.diffie_hellman(&peer_pub) else {
        return;
    };
    let Ok(auth_key) = derive_reality_auth_key(&shared, &[0x22; 32]) else {
        return;
    };
    let _check_type: &AuthKey = &auth_key;

    if data.len() >= 32 {
        let mut sid_arr = [0u8; 32];
        sid_arr.copy_from_slice(&data[..32]);
        let _ = decrypt_reality_session_id(&auth_key, &[0x22; 32], &sid_arr, &data[32..]);
    }

    if let (
        Some(ch),
        ServerFlightStatus::PartialWithProfile(profile) | ServerFlightStatus::Complete(profile),
    ) = (
        dummy_client_hello(),
        parse_dest_server_flight(&minimal_dest_profile_bytes()),
    ) {
        let cert_tpl = RealityCertTemplate::from_seed([0x99; 32]);
        let auth = AuthenticatedClient {
            auth_key,
            client_version: [1, 8, 0],
        };
        if let Ok(mut prepared) =
            prepare_server_flight(&ch, &auth, &profile, &cert_tpl, &[0x12; 32], &[0x34; 32])
        {
            let mid = data.len() / 2;
            let _ = prepared.pending.feed_client_bytes(&data[..mid]);
            let _ = prepared.pending.feed_client_bytes(&data[mid..]);
        }
    }
});
