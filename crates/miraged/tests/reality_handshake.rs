//! End-to-end integration tests for Milestone 2 (Reality authentication,
//! `dest` handshake profile mimicry, hybrid `X25519MLKEM768`, Ed25519 +
//! HMAC-SHA512 certificate verification, anti-replay fallback, key rotation,
//! and Zero-PII logging).

use core::time::Duration;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use mirage_core::crypto::{
    derive_reality_auth_key, encrypt_reality_session_id, RealityToken, ShortId, StaticPrivateKey,
    Tls13Secret, TranscriptHash,
};
use mirage_core::tls_parser::Tls13CipherSuiteId;
use miraged::config::{Config, RealityConfig};
use miraged::metrics::Metrics;
use miraged::proxy;
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::ml_kem_768::{Ciphertext as MlKem768Ct, DecapsulationKey as MlKem768Dk};
use ml_kem::Seed as MlKemSeed;
use sha2::Sha512;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tracing_subscriber::fmt::MakeWriter;
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Sec};

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl LogBuffer {
    fn contents(&self) -> String {
        let guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(&guard).into_owned()
    }
}

struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogBuffer {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter(Arc::clone(&self.0))
    }
}

/// Builds a mock TLS 1.3 `ServerHello` + `CCS` + 4 encrypted handshake records
/// + `NewSessionTicket` matching the requested cipher suite & key share group.
fn build_mock_dest_flight(suite: u16, use_pq_group: bool) -> (Vec<u8>, [usize; 5]) {
    let mut sh_ext = Vec::new();
    // supported_versions (0x002b) -> 0x0304
    sh_ext.extend_from_slice(&0x002bu16.to_be_bytes());
    sh_ext.extend_from_slice(&2u16.to_be_bytes());
    sh_ext.extend_from_slice(&0x0304u16.to_be_bytes());

    // key_share (0x0033)
    let (group_id, share_len) = if use_pq_group {
        (0x11ecu16, 1120usize)
    } else {
        (0x001du16, 32usize)
    };
    let ext_data_len = 4usize.saturating_add(share_len);
    sh_ext.extend_from_slice(&0x0033u16.to_be_bytes());
    sh_ext.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
    sh_ext.extend_from_slice(&group_id.to_be_bytes());
    sh_ext.extend_from_slice(&(share_len as u16).to_be_bytes());
    sh_ext.extend(core::iter::repeat_n(0xDE, share_len));

    let mut sh_body = Vec::new();
    sh_body.extend_from_slice(&0x0303u16.to_be_bytes());
    sh_body.extend([0xABu8; 32]);
    sh_body.push(32);
    sh_body.extend([0xCDu8; 32]);
    sh_body.extend_from_slice(&suite.to_be_bytes());
    sh_body.push(0);
    sh_body.extend_from_slice(&(sh_ext.len() as u16).to_be_bytes());
    sh_body.extend_from_slice(&sh_ext);

    let sh_len_bytes = (sh_body.len() as u32).to_be_bytes();
    let mut sh_hs = Vec::new();
    sh_hs.push(0x02);
    if let Some(tail) = sh_len_bytes.get(1..4) {
        sh_hs.extend_from_slice(tail);
    }
    sh_hs.extend_from_slice(&sh_body);

    let mut wire = Vec::new();
    wire.extend_from_slice(&[0x16, 0x03, 0x03]);
    wire.extend_from_slice(&(sh_hs.len() as u16).to_be_bytes());
    wire.extend_from_slice(&sh_hs);

    // ChangeCipherSpec
    wire.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);

    // 4 encrypted handshake records + 1 NewSessionTicket (realistic sizes >= unpadded)
    let record_lens = [80usize, 1180, 128, 96, 210];
    for len in record_lens {
        let payload_len = len.saturating_sub(5);
        wire.extend_from_slice(&[0x17, 0x03, 0x03]);
        wire.extend_from_slice(&(payload_len as u16).to_be_bytes());
        wire.extend(core::iter::repeat_n(0xEE, payload_len));
    }

    (wire, record_lens)
}

async fn spawn_mock_tls13_dest(
    suite: u16,
    use_pq_group: bool,
) -> Option<(SocketAddr, [usize; 5], oneshot::Sender<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
    let addr = listener.local_addr().ok()?;
    let (tx, mut rx) = oneshot::channel::<()>();
    let (flight_bytes, record_lens) = build_mock_dest_flight(suite, use_pq_group);

    tokio::spawn(async move {
        loop {
            let accept = tokio::select! {
                _ = &mut rx => break,
                res = listener.accept() => res,
            };
            let Ok((mut sock, _)) = accept else {
                break;
            };
            let flight = flight_bytes.clone();
            tokio::spawn(async move {
                let mut ch = [0u8; 4096];
                let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_secs(1), sock.read(&mut ch)).await
                else {
                    return;
                };
                if n == 0 {
                    return;
                }
                let _ = sock.write_all(&flight).await;
                let _ = sock.write_all(b"DEST_FALLBACK").await;
                let _ = sock.shutdown().await;
            });
        }
    });

    Some((addr, record_lens, tx))
}

fn build_reality_client_hello(
    server_pub: &[u8; 32],
    short_id: &ShortId,
    sni: &str,
    client_x25519_seed: [u8; 32],
    mlkem_dk: Option<&MlKem768Dk>,
    client_random: [u8; 32],
    timestamp_secs: u32,
) -> Option<(Vec<u8>, Vec<u8>, X25519Sec)> {
    let client_x25519 = X25519Sec::from(client_x25519_seed);
    let client_x25519_pub = X25519Pub::from(&client_x25519).to_bytes();

    let priv_wrapper = StaticPrivateKey::from_bytes(client_x25519_seed);
    let shared = priv_wrapper.diffie_hellman(server_pub).ok()?;
    let auth_key = derive_reality_auth_key(&shared, &client_random).ok()?;

    let mut extensions = Vec::new();
    // SNI
    let host = sni.as_bytes();
    let entry_len = 3usize.saturating_add(host.len());
    let sni_ext_len = 2usize.saturating_add(entry_len);
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
    extensions.extend_from_slice(&(entry_len as u16).to_be_bytes());
    extensions.push(0x00);
    extensions.extend_from_slice(&(host.len() as u16).to_be_bytes());
    extensions.extend_from_slice(host);

    // supported_versions (TLS 1.3)
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&3u16.to_be_bytes());
    extensions.push(2);
    extensions.extend_from_slice(&0x0304u16.to_be_bytes());

    // key_share
    let mut shares = Vec::new();
    if let Some(dk) = mlkem_dk {
        let ek_bytes = dk.encapsulation_key().to_bytes();
        let hybrid_len = ek_bytes.len().saturating_add(32);
        shares.extend_from_slice(&0x11ecu16.to_be_bytes());
        shares.extend_from_slice(&(hybrid_len as u16).to_be_bytes());
        shares.extend_from_slice(ek_bytes.as_slice());
        shares.extend_from_slice(&client_x25519_pub);
    }
    shares.extend_from_slice(&0x001du16.to_be_bytes());
    shares.extend_from_slice(&32u16.to_be_bytes());
    shares.extend_from_slice(&client_x25519_pub);

    let ks_ext_len = 2usize.saturating_add(shares.len());
    extensions.extend_from_slice(&0x0033u16.to_be_bytes());
    extensions.extend_from_slice(&(ks_ext_len as u16).to_be_bytes());
    extensions.extend_from_slice(&(shares.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&shares);

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&client_random);
    body.push(32);
    body.extend([0u8; 32]);
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&0x1302u16.to_be_bytes());
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

    Some((wire, hs, client_x25519))
}

async fn read_tls_record(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut hdr))
        .await
        .ok()?
        .ok()?;
    let b3 = *hdr.get(3)?;
    let b4 = *hdr.get(4)?;
    let len = usize::from(u16::from_be_bytes([b3, b4]));
    let mut rec = Vec::with_capacity(5usize.saturating_add(len));
    rec.extend_from_slice(&hdr);
    rec.resize(5usize.saturating_add(len), 0);
    let body = rec.get_mut(5..)?;
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(body))
        .await
        .ok()?
        .ok()?;
    Some(rec)
}

fn extract_ed25519_pubkey_from_x509(cert_der: &[u8]) -> Option<[u8; 32]> {
    // Locate the SPKI Ed25519 BIT STRING marker: OID 1.3.101.112 + 0x03 0x21 0x00 + 32 bytes
    const MARKER: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00];
    let pos = cert_der.windows(MARKER.len()).position(|w| w == MARKER)?;
    let start = pos.checked_add(MARKER.len())?;
    let end = start.checked_add(32)?;
    let slice = cert_der.get(start..end)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Some(out)
}

async fn perform_client_reality_handshake(
    proxy_addr: SocketAddr,
    server_pub: &[u8; 32],
    short_id: &ShortId,
    sni: &str,
    expected_record_lens: [usize; 5],
    use_pq_group: bool,
    client_random: [u8; 32],
) -> Option<()> {
    let mlkem_dk = if use_pq_group {
        Some(MlKem768Dk::from_seed(MlKemSeed::from([0x7Au8; 64])))
    } else {
        None
    };

    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let now_u32 = u32::try_from(now_secs).ok()?;

    let (ch_wire, ch_hs, client_x25519) = build_reality_client_hello(
        server_pub,
        short_id,
        sni,
        [0x33u8; 32],
        mlkem_dk.as_ref(),
        client_random,
        now_u32,
    )?;

    let auth_shared = StaticPrivateKey::from_bytes([0x33u8; 32])
        .diffie_hellman(server_pub)
        .ok()?;
    let auth_key = derive_reality_auth_key(&auth_shared, &client_random).ok()?;

    let mut stream = TcpStream::connect(proxy_addr).await.ok()?;
    stream.write_all(&ch_wire).await.ok()?;

    // 1. ServerHello
    let sh_rec = read_tls_record(&mut stream).await?;
    assert_eq!(sh_rec.first(), Some(&0x16));
    let sh_hs = sh_rec.get(5..)?;

    let suite = if use_pq_group {
        Tls13CipherSuiteId::Aes256GcmSha384
    } else {
        Tls13CipherSuiteId::Aes128GcmSha256
    };

    // Extract server key_share tail (32-byte X25519) and optional ML-KEM ciphertext (1088 bytes)
    let sh_key_len = if use_pq_group { 1120usize } else { 32usize };
    let server_share_slice = sh_hs.get(sh_hs.len().checked_sub(sh_key_len)?..)?;
    let shared_secret = if let Some(dk) = &mlkem_dk {
        let ct_slice = server_share_slice.get(..1088)?;
        let ct = MlKem768Ct::try_from(ct_slice).ok()?;
        let mlkem_ss = dk.decapsulate(&ct);
        let x_slice = server_share_slice.get(1088..1120)?;
        let mut srv_x = [0u8; 32];
        srv_x.copy_from_slice(x_slice);
        let x_ss = client_x25519.diffie_hellman(&X25519Pub::from(srv_x));
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(mlkem_ss.as_slice());
        combined.extend_from_slice(x_ss.as_bytes());
        combined
    } else {
        let mut srv_x = [0u8; 32];
        srv_x.copy_from_slice(server_share_slice);
        client_x25519
            .diffie_hellman(&X25519Pub::from(srv_x))
            .as_bytes()
            .to_vec()
    };

    // 2. ChangeCipherSpec
    let ccs_rec = read_tls_record(&mut stream).await?;
    assert_eq!(ccs_rec.as_slice(), &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);

    // Derive TLS 1.3 handshake secrets
    let mut transcript = TranscriptHash::new(suite);
    transcript.update(&ch_hs);
    transcript.update(sh_hs);

    let early = Tls13Secret::early_secret(suite);
    let hs_secret = early.derive_handshake_secret(&shared_secret).ok()?;
    let ch_sh_hash = transcript.current_hash();
    let s_hs = hs_secret.derive_secret(b"s hs traffic", &ch_sh_hash).ok()?;
    let c_hs = hs_secret.derive_secret(b"c hs traffic", &ch_sh_hash).ok()?;

    let mut s_hs_cipher = s_hs.into_record_cipher().ok()?;
    let mut c_hs_cipher = c_hs.into_record_cipher().ok()?;

    // 3. EncryptedExtensions (record length must mimic dest!)
    let ee_rec = read_tls_record(&mut stream).await?;
    assert_eq!(ee_rec.len(), *expected_record_lens.first()?);
    let (ee_ct, ee_msg) = s_hs_cipher.open_record(&ee_rec).ok()?;
    assert_eq!(ee_ct, 0x16);
    assert_eq!(ee_msg.first(), Some(&0x08));
    transcript.update(&ee_msg);

    // 4. Certificate (verify HMAC-SHA512(AuthKey, ed25519_pub) == cert signature)
    let cert_rec = read_tls_record(&mut stream).await?;
    assert_eq!(cert_rec.len(), *expected_record_lens.get(1)?);
    let (cert_ct, cert_msg) = s_hs_cipher.open_record(&cert_rec).ok()?;
    assert_eq!(cert_ct, 0x16);
    assert_eq!(cert_msg.first(), Some(&0x0B));
    let cert_der = cert_msg.get(11..cert_msg.len().checked_sub(2)?)?;
    let ed_pub = extract_ed25519_pubkey_from_x509(cert_der)?;
    let cert_sig = cert_der.get(cert_der.len().checked_sub(64)?..)?;
    let mut hmac = <Hmac<Sha512> as KeyInit>::new_from_slice(auth_key.as_bytes()).ok()?;
    hmac.update(&ed_pub);
    let expected_hmac = hmac.finalize().into_bytes();
    assert!(bool::from(cert_sig.ct_eq(expected_hmac.as_slice())));
    transcript.update(&cert_msg);

    // 5. CertificateVerify (verify Ed25519 signature!)
    let cv_rec = read_tls_record(&mut stream).await?;
    assert_eq!(cv_rec.len(), *expected_record_lens.get(2)?);
    let (cv_ct, cv_msg) = s_hs_cipher.open_record(&cv_rec).ok()?;
    assert_eq!(cv_ct, 0x16);
    assert_eq!(cv_msg.get(4..8), Some([0x08, 0x07, 0x00, 0x40].as_slice()));
    let cv_sig_bytes = cv_msg.get(8..72)?;
    let cv_sig = Signature::from_slice(cv_sig_bytes).ok()?;
    let vk = VerifyingKey::from_bytes(&ed_pub).ok()?;
    let mut signed_msg = Vec::new();
    signed_msg.extend([0x20u8; 64]);
    signed_msg.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
    signed_msg.extend_from_slice(&transcript.current_hash());
    assert!(vk.verify(&signed_msg, &cv_sig).is_ok());
    transcript.update(&cv_msg);

    // 6. Server Finished
    let sf_rec = read_tls_record(&mut stream).await?;
    assert_eq!(sf_rec.len(), *expected_record_lens.get(3)?);
    let (sf_ct, sf_msg) = s_hs_cipher.open_record(&sf_rec).ok()?;
    assert_eq!(sf_ct, 0x16);
    assert_eq!(sf_msg.first(), Some(&0x14));
    let expected_sf_vd = s_hs
        .compute_finished_verify_data(&transcript.current_hash())
        .ok()?;
    assert!(bool::from(
        sf_msg.get(4..)?.ct_eq(expected_sf_vd.as_slice())
    ));
    transcript.update(&sf_msg);

    // 7. Padded NewSessionTicket mimic record (record 5)
    let nst_rec = read_tls_record(&mut stream).await?;
    assert_eq!(nst_rec.len(), *expected_record_lens.get(4)?);

    // 8. Derive client Finished & Application traffic ciphers, send ClientFinished + AppData + close_notify
    let sf_hash = transcript.current_hash();
    let master = hs_secret.derive_master_secret().ok()?;
    let c_app = master.derive_secret(b"c ap traffic", &sf_hash).ok()?;
    let mut c_app_cipher = c_app.into_record_cipher().ok()?;

    let cf_vd = c_hs.compute_finished_verify_data(&sf_hash).ok()?;
    let mut cf_msg = Vec::with_capacity(4usize.saturating_add(cf_vd.len()));
    let vd_len_u32 = u32::try_from(cf_vd.len()).ok()?;
    cf_msg.push(0x14);
    cf_msg.extend_from_slice(vd_len_u32.to_be_bytes().get(1..4)?);
    cf_msg.extend_from_slice(&cf_vd);
    let cf_rec = c_hs_cipher.seal_record(0x16, &cf_msg, None).ok()?;

    let app_rec = c_app_cipher.seal_record(0x17, b"VLESS_READY", None).ok()?;
    let close_rec = c_app_cipher.seal_record(0x15, &[0x01, 0x00], None).ok()?;

    stream
        .write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
        .await
        .ok()?;
    stream.write_all(&cf_rec).await.ok()?;
    stream.write_all(&app_rec).await.ok()?;
    stream.write_all(&close_rec).await.ok()?;
    let _ = stream.shutdown().await;

    Some(())
}

#[tokio::test]
async fn reality_pq_and_x25519_handshakes_anti_replay_and_rotation() {
    let log_buf = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log_buf.clone())
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let key_current = StaticPrivateKey::from_bytes([0x11u8; 32]);
    let key_previous = StaticPrivateKey::from_bytes([0x22u8; 32]);
    let pub_current = key_current.public_key();
    let pub_previous = key_previous.public_key();

    let Ok(short_id) = ShortId::from_hex("0123abcd") else {
        return;
    };

    // Case A: Hybrid Post-Quantum X25519MLKEM768 + TLS_AES_256_GCM_SHA384
    let Some((dest_pq_addr, pq_lens, dest_pq_stop)) = spawn_mock_tls13_dest(0x1302, true).await
    else {
        return;
    };
    let Ok(listener_pq) = TcpListener::bind("127.0.0.1:0").await else {
        return;
    };
    let Ok(proxy_pq_addr) = listener_pq.local_addr() else {
        return;
    };

    let Ok(rc_pq) = RealityConfig::new(
        vec![key_current.clone(), key_previous.clone()],
        vec![short_id.clone()],
        60,
        1024,
        Some([1, 8, 0]),
        None,
    ) else {
        return;
    };
    let Ok(cfg_pq) = Config::new(
        proxy_pq_addr,
        dest_pq_addr,
        vec!["reality-test.example.com".to_owned()],
        16 * 1024,
        1_000,
        64,
        false,
    )
    .and_then(|c| c.with_reality(rc_pq)) else {
        return;
    };

    let metrics_pq = Arc::new(Metrics::new());
    let (stop_pq_tx, stop_pq_rx) = oneshot::channel::<()>();
    let srv_pq = tokio::spawn(proxy::run_server(
        listener_pq,
        Arc::new(cfg_pq),
        Arc::clone(&metrics_pq),
        async move {
            let _ = stop_pq_rx.await;
        },
    ));

    let res_pq = perform_client_reality_handshake(
        proxy_pq_addr,
        &pub_current,
        &short_id,
        "reality-test.example.com",
        pq_lens,
        true,
        [0x88u8; 32],
    )
    .await;
    assert!(res_pq.is_some(), "PQ Reality handshake must succeed");
    // Give server task a brief moment to process close_notify and finish counter increment.
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(metrics_pq.reality_authenticated(), 1);
    assert_eq!(metrics_pq.reality_handshake_completed(), 1);

    // Key rotation: client authenticating with `key_previous` during grace period also succeeds!
    let res_rot = perform_client_reality_handshake(
        proxy_pq_addr,
        &pub_previous,
        &short_id,
        "reality-test.example.com",
        pq_lens,
        true,
        [0x8Au8; 32],
    )
    .await;
    assert!(
        res_rot.is_some(),
        "grace-period rotated key handshake must succeed"
    );
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(metrics_pq.reality_authenticated(), 2);
    assert_eq!(metrics_pq.reality_handshake_completed(), 2);

    // Case B: Classical X25519 + TLS_AES_128_GCM_SHA256 + Replay fallback to dest
    let Some((dest_x_addr, x_lens, dest_x_stop)) = spawn_mock_tls13_dest(0x1301, false).await
    else {
        return;
    };
    let Ok(listener_x) = TcpListener::bind("127.0.0.1:0").await else {
        return;
    };
    let Ok(proxy_x_addr) = listener_x.local_addr() else {
        return;
    };
    let Ok(rc_x) = RealityConfig::new(
        vec![key_current],
        vec![short_id.clone()],
        60,
        1024,
        None,
        None,
    ) else {
        return;
    };
    let Ok(cfg_x) = Config::new(
        proxy_x_addr,
        dest_x_addr,
        vec!["reality-test.example.com".to_owned()],
        16 * 1024,
        1_000,
        64,
        false,
    )
    .and_then(|c| c.with_reality(rc_x)) else {
        return;
    };

    let metrics_x = Arc::new(Metrics::new());
    let (stop_x_tx, stop_x_rx) = oneshot::channel::<()>();
    let srv_x = tokio::spawn(proxy::run_server(
        listener_x,
        Arc::new(cfg_x),
        Arc::clone(&metrics_x),
        async move {
            let _ = stop_x_rx.await;
        },
    ));

    let res_x = perform_client_reality_handshake(
        proxy_x_addr,
        &pub_current,
        &short_id,
        "reality-test.example.com",
        x_lens,
        false,
        [0x99u8; 32],
    )
    .await;
    assert!(res_x.is_some(), "X25519 Reality handshake must succeed");

    // Replay the EXACT same ClientHello bytes -> must be rejected and fall back to dest!
    let now_u32 = u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(0);
    let Some((replay_wire, _, _)) = build_reality_client_hello(
        &pub_current,
        &short_id,
        "reality-test.example.com",
        [0x34u8; 32],
        None,
        [0x55u8; 32],
        now_u32,
    ) else {
        return;
    };

    // First send succeeds; second send with identical wire bytes falls back to `dest`.
    if let Ok(mut s1) = TcpStream::connect(proxy_x_addr).await {
        let _ = s1.write_all(&replay_wire).await;
        let _ = read_tls_record(&mut s1).await;
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    if let Ok(mut s2) = TcpStream::connect(proxy_x_addr).await {
        let _ = s2.write_all(&replay_wire).await;
        let _ = s2.shutdown().await;
        let mut resp = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(1), s2.read_to_end(&mut resp)).await;
        assert!(resp.ends_with(b"DEST_FALLBACK"));
    }
    assert_eq!(metrics_x.reality_replayed_or_saturated(), 1);

    // Zero-PII log verification
    let logs = log_buf.contents();
    assert!(!logs.contains("127.0.0.1"));
    assert!(!logs.contains("reality-test.example.com"));
    assert!(!logs.contains("0123abcd"));

    let _ = stop_pq_tx.send(());
    let _ = dest_pq_stop.send(());
    let _ = stop_x_tx.send(());
    let _ = dest_x_stop.send(());
    let _ = srv_pq.await;
    let _ = srv_x.await;
}
