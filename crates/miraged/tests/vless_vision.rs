//! End-to-end integration tests for Milestone 3:
//! - Reality + VLESS TCP (`xtls-rprx-vision` -> `CommandPaddingDirect` switch)
//! - Reality + VLESS TCP (non-TLS fallback to `CommandPaddingEnd` keeping outer TLS)
//! - Reality + VLESS UDP packet framing
//! - Private RFC 1035 DNS + Anti-SSRF egress blocking (loopback, metadata, SMTP/25, DNS->private IP)
//! - Unauthorized VLESS UUID rejection & Zero-PII logging

use core::time::Duration;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use mirage_core::crypto::{
    derive_reality_auth_key, encrypt_reality_session_id, RealityToken, ShortId, StaticPrivateKey,
    Tls13RecordCipher, Tls13Secret, TranscriptHash,
};
use mirage_core::tls_parser::Tls13CipherSuiteId;
use mirage_core::vision::{UnpadMode, VisionPadder, VisionTlsFilter, VisionUnpadder};
use mirage_core::vless::{decode_udp_packet, encode_udp_packet, VlessUuid};
use miraged::config::{Config, RealityConfig, VlessConfig};
use miraged::dns::parse_dns_response;
use miraged::metrics::Metrics;
use miraged::proxy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
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

fn build_mock_dest_flight(suite: u16) -> Vec<u8> {
    let mut sh_ext = Vec::new();
    sh_ext.extend_from_slice(&0x002bu16.to_be_bytes());
    sh_ext.extend_from_slice(&2u16.to_be_bytes());
    sh_ext.extend_from_slice(&0x0304u16.to_be_bytes());
    sh_ext.extend_from_slice(&0x0033u16.to_be_bytes());
    sh_ext.extend_from_slice(&36u16.to_be_bytes());
    sh_ext.extend_from_slice(&0x001du16.to_be_bytes());
    sh_ext.extend_from_slice(&32u16.to_be_bytes());
    sh_ext.extend([0xDEu8; 32]);

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
    wire.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);

    for len in [80usize, 1180, 128, 96] {
        let payload_len = len.saturating_sub(5);
        wire.extend_from_slice(&[0x17, 0x03, 0x03]);
        wire.extend_from_slice(&(payload_len as u16).to_be_bytes());
        wire.extend(core::iter::repeat_n(0xEE, payload_len));
    }
    wire
}

async fn spawn_mock_tls13_dest() -> Option<(SocketAddr, oneshot::Sender<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
    let addr = listener.local_addr().ok()?;
    let (tx, mut rx) = oneshot::channel::<()>();
    let flight = build_mock_dest_flight(0x1301);

    tokio::spawn(async move {
        loop {
            let accept = tokio::select! {
                _ = &mut rx => break,
                res = listener.accept() => res,
            };
            let Ok((mut sock, _)) = accept else { break };
            let f = flight.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_secs(1), sock.read(&mut buf)).await
                {
                    if n > 0 {
                        let _ = sock.write_all(&f).await;
                    }
                }
                let _ = sock.shutdown().await;
            });
        }
    });

    Some((addr, tx))
}

async fn spawn_mock_dns_server(mapped_ip: Ipv4Addr) -> Option<(SocketAddr, oneshot::Sender<()>)> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let addr = sock.local_addr().ok()?;
    let (tx, mut rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            let recv_res = tokio::select! {
                _ = &mut rx => break,
                res = sock.recv_from(&mut buf) => res,
            };
            let Ok((n, peer)) = recv_res else { break };
            let Some(query) = buf.get(..n) else { continue };
            if query.len() < 12 {
                continue;
            }
            // Build minimal A-record response with compression pointer 0xC00C.
            let mut resp = query.to_vec();
            if let Some(flags) = resp.get_mut(2..4) {
                flags.copy_from_slice(&0x8180u16.to_be_bytes());
            }
            if let Some(ancount) = resp.get_mut(6..8) {
                ancount.copy_from_slice(&1u16.to_be_bytes());
            }
            resp.extend_from_slice(&[0xC0, 0x0C]);
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&60u32.to_be_bytes());
            resp.extend_from_slice(&4u16.to_be_bytes());
            resp.extend_from_slice(&mapped_ip.octets());
            let _ = parse_dns_response(
                &resp,
                u16::from_be_bytes([*query.first().unwrap_or(&0), *query.get(1).unwrap_or(&0)]),
            );
            let _ = sock.send_to(&resp, peer).await;
        }
    });

    Some((addr, tx))
}

async fn read_tls_record(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut hdr))
        .await
        .ok()?
        .ok()?;
    let len = usize::from(u16::from_be_bytes([*hdr.get(3)?, *hdr.get(4)?]));
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

async fn open_reality_tunnel(
    proxy_addr: SocketAddr,
    server_pub: &[u8; 32],
    short_id: &ShortId,
    sni: &str,
    client_random: [u8; 32],
) -> Option<(TcpStream, Tls13RecordCipher, Tls13RecordCipher)> {
    let client_x25519 = X25519Sec::from([0x33u8; 32]);
    let client_pub = X25519Pub::from(&client_x25519).to_bytes();

    let shared = StaticPrivateKey::from_bytes([0x33u8; 32])
        .diffie_hellman(server_pub)
        .ok()?;
    let auth_key = derive_reality_auth_key(&shared, &client_random).ok()?;

    let mut extensions = Vec::new();
    let host = sni.as_bytes();
    let entry_len = 3usize.saturating_add(host.len());
    let sni_ext_len = 2usize.saturating_add(entry_len);
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
    extensions.extend_from_slice(&(entry_len as u16).to_be_bytes());
    extensions.push(0x00);
    extensions.extend_from_slice(&(host.len() as u16).to_be_bytes());
    extensions.extend_from_slice(host);

    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&3u16.to_be_bytes());
    extensions.push(2);
    extensions.extend_from_slice(&0x0304u16.to_be_bytes());

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
    body.extend([0u8; 32]);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let len_bytes = (body.len() as u32).to_be_bytes();
    let mut ch_hs = Vec::new();
    ch_hs.push(0x01);
    ch_hs.extend_from_slice(len_bytes.get(1..4)?);
    ch_hs.extend_from_slice(&body);

    let now_u32 =
        u32::try_from(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()?;
    let token = RealityToken {
        client_version: [1, 8, 24],
        padding: 0,
        timestamp_secs: now_u32,
        short_id: short_id.clone(),
    };
    let sealed_sid = encrypt_reality_session_id(&auth_key, &client_random, &token, &ch_hs).ok()?;
    ch_hs.get_mut(39..71)?.copy_from_slice(&sealed_sid);

    let mut ch_wire = Vec::new();
    ch_wire.push(0x16);
    ch_wire.extend_from_slice(&0x0301u16.to_be_bytes());
    ch_wire.extend_from_slice(&(ch_hs.len() as u16).to_be_bytes());
    ch_wire.extend_from_slice(&ch_hs);

    let mut stream = TcpStream::connect(proxy_addr).await.ok()?;
    stream.write_all(&ch_wire).await.ok()?;

    let sh_rec = read_tls_record(&mut stream).await?;
    let sh_hs = sh_rec.get(5..)?;
    let srv_x_slice = sh_hs.get(sh_hs.len().checked_sub(32)?..)?;
    let mut srv_x = [0u8; 32];
    srv_x.copy_from_slice(srv_x_slice);
    let shared_secret = client_x25519.diffie_hellman(&X25519Pub::from(srv_x));

    let _ccs = read_tls_record(&mut stream).await?;

    let suite = Tls13CipherSuiteId::Aes128GcmSha256;
    let mut transcript = TranscriptHash::new(suite);
    transcript.update(&ch_hs);
    transcript.update(sh_hs);

    let early = Tls13Secret::early_secret(suite);
    let hs_secret = early
        .derive_handshake_secret(shared_secret.as_bytes())
        .ok()?;
    let ch_sh_hash = transcript.current_hash();
    let s_hs = hs_secret.derive_secret(b"s hs traffic", &ch_sh_hash).ok()?;
    let c_hs = hs_secret.derive_secret(b"c hs traffic", &ch_sh_hash).ok()?;

    let mut s_hs_cipher = s_hs.into_record_cipher().ok()?;
    let mut c_hs_cipher = c_hs.into_record_cipher().ok()?;

    for _ in 0..4 {
        let rec = read_tls_record(&mut stream).await?;
        let (_, msg) = s_hs_cipher.open_record(&rec).ok()?;
        transcript.update(&msg);
    }

    let sf_hash = transcript.current_hash();
    let master = hs_secret.derive_master_secret().ok()?;
    let s_app = master
        .derive_secret(b"s ap traffic", &sf_hash)
        .ok()?
        .into_record_cipher()
        .ok()?;
    let c_app = master
        .derive_secret(b"c ap traffic", &sf_hash)
        .ok()?
        .into_record_cipher()
        .ok()?;

    let cf_vd = c_hs.compute_finished_verify_data(&sf_hash).ok()?;
    let vd_len_u32 = u32::try_from(cf_vd.len()).ok()?;
    let mut cf_msg = Vec::new();
    cf_msg.push(0x14);
    cf_msg.extend_from_slice(vd_len_u32.to_be_bytes().get(1..4)?);
    cf_msg.extend_from_slice(&cf_vd);
    let cf_rec = c_hs_cipher.seal_record(0x16, &cf_msg, None).ok()?;

    stream
        .write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
        .await
        .ok()?;
    stream.write_all(&cf_rec).await.ok()?;

    Some((stream, c_app, s_app))
}

fn build_vless_header(uuid: &VlessUuid, flow: &str, cmd: u8, ip: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x00);
    out.extend_from_slice(uuid.as_bytes());
    if flow.is_empty() {
        out.push(0x00);
    } else {
        let fb = flow.as_bytes();
        out.push((2usize.saturating_add(fb.len())) as u8);
        out.push(0x0A);
        out.push(fb.len() as u8);
        out.extend_from_slice(fb);
    }
    out.push(cmd);
    out.extend_from_slice(&port.to_be_bytes());
    out.push(0x01);
    out.extend_from_slice(&ip.octets());
    out
}

fn build_vless_domain_header(uuid: &VlessUuid, cmd: u8, domain: &str, port: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x00);
    out.extend_from_slice(uuid.as_bytes());
    out.push(0x00);
    out.push(cmd);
    out.extend_from_slice(&port.to_be_bytes());
    out.push(0x02);
    out.push(domain.len() as u8);
    out.extend_from_slice(domain.as_bytes());
    out
}

fn build_inner_tls13_server_hello() -> Vec<u8> {
    let mut sh = vec![0x16, 0x03, 0x03, 0x00, 0x55, 0x02, 0x00, 0x00, 0x51];
    sh.resize(43, 0x11);
    sh.push(32);
    sh.extend([0x22u8; 32]);
    sh.extend_from_slice(&0x1301u16.to_be_bytes());
    sh.push(0);
    sh.extend_from_slice(&6u16.to_be_bytes());
    sh.extend_from_slice(&[0x00, 0x2B, 0x00, 0x02, 0x03, 0x04]);
    let rec_len = sh.len().saturating_sub(5);
    if let Some(s) = sh.get_mut(3..5) {
        s.copy_from_slice(&(rec_len as u16).to_be_bytes());
    }
    sh
}

#[tokio::test]
async fn vless_vision_direct_copy_udp_dns_and_ssrf_blocking() {
    let log_buf = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log_buf.clone())
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let server_priv = StaticPrivateKey::from_bytes([0x41u8; 32]);
    let server_pub = server_priv.public_key();
    let Ok(short_id) = ShortId::from_hex("cafebabe") else {
        return;
    };
    let Ok(uuid) = VlessUuid::from_str_hex("11223344-5566-7788-99aa-bbccddeeff00") else {
        return;
    };

    let Some((dest_addr, dest_stop)) = spawn_mock_tls13_dest().await else {
        return;
    };
    // Mock private DNS server that returns private IP 10.20.30.40 (tests DNS->SSRF block!)
    let Some((dns_addr, dns_stop)) = spawn_mock_dns_server(Ipv4Addr::new(10, 20, 30, 40)).await
    else {
        return;
    };

    // Server A: allow_private_egress = true (for localhost upstream TCP/UDP tests)
    let Ok(l_allow) = TcpListener::bind("127.0.0.1:0").await else {
        return;
    };
    let Ok(addr_allow) = l_allow.local_addr() else {
        return;
    };
    let Ok(rc_a) = RealityConfig::new(
        vec![server_priv.clone()],
        vec![short_id.clone()],
        60,
        1024,
        None,
        None,
    ) else {
        return;
    };
    let Ok(vc_a) = VlessConfig::new(vec![uuid.clone()], true, false, dns_addr, false) else {
        return;
    };
    let Ok(cfg_a) = Config::new(
        addr_allow,
        dest_addr,
        vec!["vless-test.example.com".to_owned()],
        16 * 1024,
        1_000,
        64,
        false,
    )
    .and_then(|c| c.with_reality(rc_a))
    .and_then(|c| c.with_vless(vc_a)) else {
        return;
    };

    let metrics_a = Arc::new(Metrics::new());
    let (stop_a_tx, stop_a_rx) = oneshot::channel::<()>();
    let srv_a = tokio::spawn(proxy::run_server(
        l_allow,
        Arc::new(cfg_a),
        Arc::clone(&metrics_a),
        async move {
            let _ = stop_a_rx.await;
        },
    ));

    // 1. Vision TCP with inner TLS 1.3 -> must transition to CommandPaddingDirect raw TCP copy!
    let Ok(up_tls_listener) = TcpListener::bind("127.0.0.1:0").await else {
        return;
    };
    let Ok(up_tls_addr) = up_tls_listener.local_addr() else {
        return;
    };
    tokio::spawn(async move {
        if let Ok((mut s, _)) = up_tls_listener.accept().await {
            let mut buf = [0u8; 512];
            let Ok(n) = s.read(&mut buf).await else {
                return;
            };
            assert!(n > 0);
            let _ = s.write_all(&build_inner_tls13_server_hello()).await;
            let mut app = vec![0x17, 0x03, 0x03, 0x00, 0x0B];
            app.extend_from_slice(b"VISION_INIT");
            let _ = s.write_all(&app).await;
            // After direct copy starts, echo raw bytes verbatim across arbitrary TCP splits!
            let mut raw = [0u8; 64];
            loop {
                match tokio::time::timeout(Duration::from_millis(500), s.read(&mut raw)).await {
                    Ok(Ok(0) | Err(_)) | Err(_) => break,
                    Ok(Ok(m)) => {
                        if let Some(r) = raw.get(..m) {
                            if s.write_all(r).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
            let _ = s.shutdown().await;
        }
    });

    if let Some((mut stream, mut c_app, mut s_app)) = open_reality_tunnel(
        addr_allow,
        &server_pub,
        &short_id,
        "vless-test.example.com",
        [0x10u8; 32],
    )
    .await
    {
        let mut req = build_vless_header(
            &uuid,
            "xtls-rprx-vision",
            0x01,
            Ipv4Addr::LOCALHOST,
            up_tls_addr.port(),
        );
        let mut client_padder = VisionPadder::new(uuid.clone());
        let mut client_filter = VisionTlsFilter::new();

        // Inner TLS ClientHello (0x16 0x03 0x01 ... 0x01)
        let inner_ch = vec![
            0x16, 0x03, 0x01, 0x00, 0x06, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00,
        ];
        client_filter.inspect(&inner_ch);
        let padded_ch = client_padder.wrap_outbound(&inner_ch, &client_filter, 7);
        req.extend_from_slice(&padded_ch);

        let Ok(sealed_req) = c_app.seal_record(0x17, &req, None) else {
            return;
        };
        let _ = stream.write_all(&sealed_req).await;

        // Read VLESS response [0x00, 0x00]
        let Some(r0) = read_tls_record(&mut stream).await else {
            return;
        };
        assert_eq!(s_app.open_record(&r0).ok(), Some((0x17, vec![0x00, 0x00])));

        // Read Vision-padded ServerHello + Vision-padded AppData (CommandPaddingDirect!)
        let mut client_unpadder = VisionUnpadder::new(uuid.clone());
        let mut seen_init = false;
        while client_unpadder.mode() != UnpadMode::DirectCopy {
            let Some(rec) = read_tls_record(&mut stream).await else {
                break;
            };
            let Ok((_, dec)) = s_app.open_record(&rec) else {
                break;
            };
            let out = client_unpadder.feed(&dec);
            client_filter.inspect(&out.payload);
            if out.payload.ends_with(b"VISION_INIT") {
                seen_init = true;
            }
        }
        assert!(
            seen_init,
            "expected inner TLS 1.3 ServerHello + VISION_INIT"
        );
        assert_eq!(client_unpadder.mode(), UnpadMode::DirectCopy);

        // Client now sends inner TLS 1.3 ApplicationData triggering uplink DirectCopy,
        // immediately followed by raw unencrypted direct bytes!
        let mut inner_app = vec![0x17, 0x03, 0x03, 0x00, 0x04];
        inner_app.extend_from_slice(b"PING");
        let padded_direct = client_padder.wrap_outbound(&inner_app, &client_filter, 9);
        assert!(client_padder.direct_copy_active());
        let Ok(sealed_direct) = c_app.seal_record(0x17, &padded_direct, None) else {
            return;
        };
        let _ = stream.write_all(&sealed_direct).await;
        let _ = stream.write_all(b"DIRECT_RAW_ECHO").await;

        let mut got = Vec::new();
        let mut echoed = [0u8; 64];
        while !got
            .windows(b"DIRECT_RAW_ECHO".len())
            .any(|w| w == b"DIRECT_RAW_ECHO")
        {
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut echoed)).await {
                Ok(Ok(0) | Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    if let Some(chunk) = echoed.get(..n) {
                        got.extend_from_slice(chunk);
                    }
                }
            }
        }
        assert!(got
            .windows(b"DIRECT_RAW_ECHO".len())
            .any(|w| w == b"DIRECT_RAW_ECHO"));
    }
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(metrics_a.vless_tcp_sessions(), 1);
    assert_eq!(metrics_a.vision_direct_switches(), 1);

    // 2. VLESS UDP relay over Reality TLS 1.3
    let Ok(udp_echo) = UdpSocket::bind("127.0.0.1:0").await else {
        return;
    };
    let Ok(udp_addr) = udp_echo.local_addr() else {
        return;
    };
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        if let Ok((n, peer)) = udp_echo.recv_from(&mut buf).await {
            if let Some(s) = buf.get(..n) {
                let mut out = b"UDP_OK:".to_vec();
                out.extend_from_slice(s);
                let _ = udp_echo.send_to(&out, peer).await;
            }
        }
    });

    if let Some((mut stream, mut c_app, mut s_app)) = open_reality_tunnel(
        addr_allow,
        &server_pub,
        &short_id,
        "vless-test.example.com",
        [0x12u8; 32],
    )
    .await
    {
        let mut hdr = build_vless_header(&uuid, "", 0x02, Ipv4Addr::LOCALHOST, udp_addr.port());
        let Ok(pkt) = encode_udp_packet(b"HELLO_UDP") else {
            return;
        };
        hdr.extend_from_slice(&pkt);
        let Ok(sealed) = c_app.seal_record(0x17, &hdr, None) else {
            return;
        };
        let _ = stream.write_all(&sealed).await;

        let Some(r0) = read_tls_record(&mut stream).await else {
            return;
        };
        assert_eq!(s_app.open_record(&r0).ok(), Some((0x17, vec![0x00, 0x00])));

        let Some(r1) = read_tls_record(&mut stream).await else {
            return;
        };
        let Ok((_, dec1)) = s_app.open_record(&r1) else {
            return;
        };
        assert_eq!(
            decode_udp_packet(&dec1),
            Ok(Some((b"UDP_OK:HELLO_UDP".to_vec(), dec1.len())))
        );
    }
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(metrics_a.vless_udp_sessions(), 1);

    // 3. Unauthorized VLESS UUID -> rejected cleanly
    if let Some((mut stream, mut c_app, _s_app)) = open_reality_tunnel(
        addr_allow,
        &server_pub,
        &short_id,
        "vless-test.example.com",
        [0x13u8; 32],
    )
    .await
    {
        let bad_uuid = VlessUuid::from_bytes([0xFFu8; 16]);
        let hdr = build_vless_header(&bad_uuid, "", 0x01, Ipv4Addr::LOCALHOST, 443);
        let Ok(sealed) = c_app.seal_record(0x17, &hdr, None) else {
            return;
        };
        let _ = stream.write_all(&sealed).await;
        let mut sink = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut sink)).await;
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(metrics_a.vless_auth_failed(), 1);

    // Server B: Production SSRF policy (allow_private_egress = false, allow_smtp_port_25 = false)
    let Ok(l_strict) = TcpListener::bind("127.0.0.1:0").await else {
        return;
    };
    let Ok(addr_strict) = l_strict.local_addr() else {
        return;
    };
    let Ok(rc_b) = RealityConfig::new(
        vec![server_priv],
        vec![short_id.clone()],
        60,
        1024,
        None,
        None,
    ) else {
        return;
    };
    let Ok(vc_b) = VlessConfig::new(vec![uuid.clone()], false, false, dns_addr, false) else {
        return;
    };
    let Ok(cfg_b) = Config::new(
        addr_strict,
        dest_addr,
        vec!["vless-test.example.com".to_owned()],
        16 * 1024,
        1_000,
        64,
        false,
    )
    .and_then(|c| c.with_reality(rc_b))
    .and_then(|c| c.with_vless(vc_b)) else {
        return;
    };

    let metrics_b = Arc::new(Metrics::new());
    let (stop_b_tx, stop_b_rx) = oneshot::channel::<()>();
    let srv_b = tokio::spawn(proxy::run_server(
        l_strict,
        Arc::new(cfg_b),
        Arc::clone(&metrics_b),
        async move {
            let _ = stop_b_rx.await;
        },
    ));

    // 4. SSRF tests: loopback 127.0.0.1, metadata 169.254.169.254, SMTP port 25, and DNS -> 10.20.30.40
    let ssrf_targets = [
        build_vless_header(&uuid, "", 0x01, Ipv4Addr::LOCALHOST, 80),
        build_vless_header(&uuid, "", 0x01, Ipv4Addr::new(169, 254, 169, 254), 80),
        build_vless_header(&uuid, "", 0x01, Ipv4Addr::new(1, 1, 1, 1), 25),
        build_vless_domain_header(&uuid, 0x01, "internal.corp.example", 443),
    ];

    for (idx, req_bytes) in ssrf_targets.into_iter().enumerate() {
        let mut rnd = [0x20u8; 32];
        if let Some(first) = rnd.first_mut() {
            *first = u8::try_from(idx.saturating_add(1)).unwrap_or(1);
        }
        if let Some((mut stream, mut c_app, _s_app)) = open_reality_tunnel(
            addr_strict,
            &server_pub,
            &short_id,
            "vless-test.example.com",
            rnd,
        )
        .await
        {
            if let Ok(sealed) = c_app.seal_record(0x17, &req_bytes, None) {
                let _ = stream.write_all(&sealed).await;
                let mut sink = [0u8; 64];
                let _ =
                    tokio::time::timeout(Duration::from_millis(300), stream.read(&mut sink)).await;
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(metrics_b.egress_blocked(), 4);

    // Zero-PII log check
    let logs = log_buf.contents();
    assert!(!logs.contains("127.0.0.1"));
    assert!(!logs.contains("169.254.169.254"));
    assert!(!logs.contains("internal.corp.example"));
    assert!(!logs.contains("vless-test.example.com"));
    assert!(!logs.contains("11223344"));

    let _ = stop_a_tx.send(());
    let _ = stop_b_tx.send(());
    let _ = dns_stop.send(());
    let _ = dest_stop.send(());
    let _ = srv_a.await;
    let _ = srv_b.await;
}
