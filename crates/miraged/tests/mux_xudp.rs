//! End-to-end integration tests for `Mux.Cool`, `XUDP` Full-Cone NAT,
//! anti-SSRF on per-frame overrides, and Happy Eyeballs multi-IP dialing.

use core::time::Duration;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mirage_core::crypto::{
    derive_reality_auth_key, encrypt_reality_session_id, RealityToken, ShortId, StaticPrivateKey,
    Tls13RecordCipher, Tls13Secret, TranscriptHash,
};
use mirage_core::mux::{
    decode_mux_frame, encode_mux_frame, MuxFrame, MuxNetwork, MuxStatus, MuxTarget,
};
use mirage_core::tls_parser::Tls13CipherSuiteId;
use mirage_core::vless::{VlessAddress, VlessUuid};
use miraged::config::{Config, RealityConfig, VlessConfig};
use miraged::metrics::Metrics;
use miraged::outbound::connect_happy_eyeballs;
use miraged::proxy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Sec};
use zeroize::Zeroizing;

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
    let client_x25519 = X25519Sec::from([0x35u8; 32]);
    let client_pub = X25519Pub::from(&client_x25519).to_bytes();

    let shared = StaticPrivateKey::from_bytes([0x35u8; 32])
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

fn build_vless_mux_header(uuid: &VlessUuid) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x00);
    out.extend_from_slice(uuid.as_bytes());
    out.push(0x00); // empty addons
    out.push(0x03); // VlessCommand::Mux
    out
}

async fn read_next_mux_frame(
    stream: &mut TcpStream,
    s_app: &mut Tls13RecordCipher,
    plain_buf: &mut Vec<u8>,
) -> Option<MuxFrame> {
    loop {
        if let Ok(Some((frame, used))) = decode_mux_frame(plain_buf) {
            plain_buf.drain(..used);
            return Some(frame);
        }
        let rec = read_tls_record(stream).await?;
        let (ct, pt) = s_app.open_record(&rec).ok()?;
        if ct == 0x17 {
            plain_buf.extend_from_slice(&pt);
        } else {
            return None;
        }
    }
}

#[tokio::test]
async fn mux_tcp_xudp_full_cone_anti_ssrf_and_happy_eyeballs() -> Result<(), &'static str> {
    let server_priv = StaticPrivateKey::from_bytes([0x51u8; 32]);
    let server_pub = server_priv.public_key();
    let short_id = ShortId::from_hex("01234567").map_err(|_| "short id")?;
    let uuid =
        VlessUuid::from_str_hex("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").map_err(|_| "uuid")?;

    let (dest_addr, dest_stop) = spawn_mock_tls13_dest().await.ok_or("spawn dest")?;

    // Server A: allow_private_egress = true for localhost Mux TCP & XUDP tests.
    let l_allow = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "bind allow")?;
    let proxy_allow_addr = l_allow.local_addr().map_err(|_| "allow addr")?;
    let cfg_allow = Config::new(
        proxy_allow_addr,
        dest_addr,
        vec!["example.com".to_owned()],
        16 * 1024,
        2000,
        64,
        false,
    )
    .and_then(|c| {
        c.with_reality(RealityConfig::new(
            vec![server_priv.clone()],
            vec![short_id.clone()],
            60,
            256,
            None,
            None,
        )?)?
        .with_vless(VlessConfig::new(
            vec![uuid.clone()],
            true,
            false,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5353)),
            false,
        )?)
    })
    .map_err(|_| "cfg_allow")?;
    let metrics_allow = Arc::new(Metrics::new());
    let (stop_allow_tx, stop_allow_rx) = oneshot::channel::<()>();
    tokio::spawn({
        let m = Arc::clone(&metrics_allow);
        async move {
            let _ = proxy::run_server(l_allow, Arc::new(cfg_allow), m, async {
                let _ = stop_allow_rx.await;
            })
            .await;
        }
    });

    // Spawn 2 distinct TCP echo servers with distinct prefixes ("T1:", "T2:").
    let up_tcp1 = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "bind tcp1")?;
    let up_tcp1_addr = up_tcp1.local_addr().map_err(|_| "addr tcp1")?;
    tokio::spawn(async move {
        if let Ok((mut s, _)) = up_tcp1.accept().await {
            let mut b = [0u8; 256];
            if let Ok(n) = s.read(&mut b).await {
                if let Some(slice) = b.get(..n) {
                    let mut out = b"T1:".to_vec();
                    out.extend_from_slice(slice);
                    let _ = s.write_all(&out).await;
                }
            }
            let _ = s.shutdown().await;
        }
    });

    let up_tcp2 = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "bind tcp2")?;
    let up_tcp2_addr = up_tcp2.local_addr().map_err(|_| "addr tcp2")?;
    tokio::spawn(async move {
        if let Ok((mut s, _)) = up_tcp2.accept().await {
            let mut b = [0u8; 256];
            if let Ok(n) = s.read(&mut b).await {
                if let Some(slice) = b.get(..n) {
                    let mut out = b"T2:".to_vec();
                    out.extend_from_slice(slice);
                    let _ = s.write_all(&out).await;
                }
            }
            let _ = s.shutdown().await;
        }
    });

    // Spawn 2 distinct UDP responders capturing source port (verifies Full-Cone NAT).
    let up_udp1 = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|_| "bind udp1")?;
    let up_udp1_addr = up_udp1.local_addr().map_err(|_| "addr udp1")?;
    let (u1_port_tx, u1_port_rx) = oneshot::channel::<u16>();
    tokio::spawn(async move {
        let mut b = [0u8; 256];
        if let Ok((n, peer)) = up_udp1.recv_from(&mut b).await {
            let _ = u1_port_tx.send(peer.port());
            if let Some(slice) = b.get(..n) {
                let mut out = b"U1:".to_vec();
                out.extend_from_slice(slice);
                let _ = up_udp1.send_to(&out, peer).await;
            }
        }
    });

    let up_udp2 = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|_| "bind udp2")?;
    let up_udp2_addr = up_udp2.local_addr().map_err(|_| "addr udp2")?;
    let (u2_port_tx, u2_port_rx) = oneshot::channel::<u16>();
    tokio::spawn(async move {
        let mut b = [0u8; 256];
        if let Ok((n, peer)) = up_udp2.recv_from(&mut b).await {
            let _ = u2_port_tx.send(peer.port());
            if let Some(slice) = b.get(..n) {
                let mut out = b"U2:".to_vec();
                out.extend_from_slice(slice);
                let _ = up_udp2.send_to(&out, peer).await;
            }
        }
    });

    // Open single Reality + VLESS Mux tunnel carrying both TCP streams AND XUDP!
    let (mut stream, mut c_app, mut s_app) = open_reality_tunnel(
        proxy_allow_addr,
        &server_pub,
        &short_id,
        "example.com",
        [0x81; 32],
    )
    .await
    .ok_or("reality handshake 1")?;

    let mut init = build_vless_mux_header(&uuid);
    let tcp1_frame = MuxFrame {
        id: 1,
        status: MuxStatus::New,
        opt_data: true,
        opt_error: false,
        target: Some(MuxTarget {
            network: MuxNetwork::Tcp,
            port: up_tcp1_addr.port(),
            address: VlessAddress::Ipv4(Ipv4Addr::LOCALHOST),
        }),
        global_id: None,
        payload: Zeroizing::new(b"alpha".to_vec()),
    };
    let tcp2_frame = MuxFrame {
        id: 2,
        status: MuxStatus::New,
        opt_data: true,
        opt_error: false,
        target: Some(MuxTarget {
            network: MuxNetwork::Tcp,
            port: up_tcp2_addr.port(),
            address: VlessAddress::Ipv4(Ipv4Addr::LOCALHOST),
        }),
        global_id: None,
        payload: Zeroizing::new(b"beta".to_vec()),
    };
    let gid = [0x99u8; 8];
    let xudp1_frame = MuxFrame {
        id: 0,
        status: MuxStatus::New,
        opt_data: true,
        opt_error: false,
        target: Some(MuxTarget {
            network: MuxNetwork::Udp,
            port: up_udp1_addr.port(),
            address: VlessAddress::Ipv4(Ipv4Addr::LOCALHOST),
        }),
        global_id: Some(gid),
        payload: Zeroizing::new(b"ping1".to_vec()),
    };
    let xudp2_frame = MuxFrame {
        id: 0,
        status: MuxStatus::Keep,
        opt_data: true,
        opt_error: false,
        target: Some(MuxTarget {
            network: MuxNetwork::Udp,
            port: up_udp2_addr.port(),
            address: VlessAddress::Ipv4(Ipv4Addr::LOCALHOST),
        }),
        global_id: None,
        payload: Zeroizing::new(b"ping2".to_vec()),
    };

    for f in [&tcp1_frame, &tcp2_frame, &xudp1_frame, &xudp2_frame] {
        let enc = encode_mux_frame(f).map_err(|_| "encode mux")?;
        init.extend_from_slice(&enc);
    }

    let sealed_init = c_app
        .seal_record(0x17, &init, None)
        .map_err(|_| "seal init")?;
    assert!(stream.write_all(&sealed_init).await.is_ok());

    // First outer TLS record starts with 2-byte VLESS response header [0x00, 0x00].
    let mut plain_buf = Vec::new();
    let first_rec = read_tls_record(&mut stream).await.ok_or("first rec")?;
    let (ct, pt) = s_app.open_record(&first_rec).map_err(|_| "open rec")?;
    assert_eq!(ct, 0x17);
    assert_eq!(pt.get(..2), Some(&[0x00, 0x00][..]));
    if let Some(rest) = pt.get(2..) {
        plain_buf.extend_from_slice(rest);
    }

    let mut got_t1 = false;
    let mut got_t2 = false;
    let mut got_u1 = false;
    let mut got_u2 = false;

    for _ in 0..10 {
        if got_t1 && got_t2 && got_u1 && got_u2 {
            break;
        }
        let Some(frame) = read_next_mux_frame(&mut stream, &mut s_app, &mut plain_buf).await else {
            break;
        };
        if frame.status == MuxStatus::Keep && frame.opt_data {
            if frame.id == 1 && frame.payload.as_slice() == b"T1:alpha" {
                got_t1 = true;
            } else if frame.id == 2 && frame.payload.as_slice() == b"T2:beta" {
                got_t2 = true;
            } else if frame.id == 0 && frame.payload.as_slice() == b"U1:ping1" {
                assert_eq!(
                    frame.target.as_ref().map(|t| t.port),
                    Some(up_udp1_addr.port())
                );
                got_u1 = true;
            } else if frame.id == 0 && frame.payload.as_slice() == b"U2:ping2" {
                assert_eq!(
                    frame.target.as_ref().map(|t| t.port),
                    Some(up_udp2_addr.port())
                );
                got_u2 = true;
            }
        }
    }

    assert!(got_t1, "mux TCP substream 1 response missing");
    assert!(got_t2, "mux TCP substream 2 response missing");
    assert!(got_u1, "XUDP response 1 missing");
    assert!(got_u2, "XUDP response 2 missing");

    // Verify Full-Cone NAT: both UDP peers observed the exact same NAT source port!
    let nat_port1 = tokio::time::timeout(Duration::from_secs(1), u1_port_rx)
        .await
        .map_err(|_| "u1 timeout")?;
    let nat_port2 = tokio::time::timeout(Duration::from_secs(1), u2_port_rx)
        .await
        .map_err(|_| "u2 timeout")?;
    assert!(nat_port1.is_ok() && nat_port1 == nat_port2);
    assert_eq!(metrics_allow.vless_mux_sessions(), 1);
    assert!(metrics_allow.xudp_packets() >= 2);

    // Server B: allow_private_egress = false -> XUDP to loopback must be blocked!
    let l_deny = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "bind deny")?;
    let proxy_deny_addr = l_deny.local_addr().map_err(|_| "addr deny")?;
    let cfg_deny = Config::new(
        proxy_deny_addr,
        dest_addr,
        vec!["example.com".to_owned()],
        16 * 1024,
        2000,
        64,
        false,
    )
    .and_then(|c| {
        c.with_reality(RealityConfig::new(
            vec![server_priv],
            vec![short_id.clone()],
            60,
            256,
            None,
            None,
        )?)?
        .with_vless(VlessConfig::new(
            vec![uuid.clone()],
            false,
            false,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5353)),
            false,
        )?)
    })
    .map_err(|_| "cfg_deny")?;
    let metrics_deny = Arc::new(Metrics::new());
    let (stop_deny_tx, stop_deny_rx) = oneshot::channel::<()>();
    tokio::spawn({
        let m = Arc::clone(&metrics_deny);
        async move {
            let _ = proxy::run_server(l_deny, Arc::new(cfg_deny), m, async {
                let _ = stop_deny_rx.await;
            })
            .await;
        }
    });

    let (mut s_deny, mut c_app2, mut s_app2) = open_reality_tunnel(
        proxy_deny_addr,
        &server_pub,
        &short_id,
        "example.com",
        [0x82; 32],
    )
    .await
    .ok_or("reality handshake 2")?;
    let mut ssrf_init = build_vless_mux_header(&uuid);
    let ssrf_xudp = MuxFrame {
        id: 0,
        status: MuxStatus::New,
        opt_data: true,
        opt_error: false,
        target: Some(MuxTarget {
            network: MuxNetwork::Udp,
            port: 5353,
            address: VlessAddress::Ipv4(Ipv4Addr::LOCALHOST),
        }),
        global_id: Some([0x77; 8]),
        payload: Zeroizing::new(b"ssrf-probe".to_vec()),
    };
    let enc = encode_mux_frame(&ssrf_xudp).map_err(|_| "encode ssrf")?;
    ssrf_init.extend_from_slice(&enc);
    let sealed = c_app2
        .seal_record(0x17, &ssrf_init, None)
        .map_err(|_| "seal ssrf")?;
    assert!(s_deny.write_all(&sealed).await.is_ok());
    let rec = read_tls_record(&mut s_deny).await.ok_or("read ssrf resp")?;
    assert!(s_app2.open_record(&rec).is_ok());
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(metrics_deny.egress_blocked() >= 1);

    // Happy Eyeballs multi-IP fallback test: closed port first, live listener second.
    let closed_l = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "bind closed")?;
    let dead_addr = closed_l.local_addr().map_err(|_| "dead addr")?;
    drop(closed_l);

    let live_l = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "bind live")?;
    let live_addr = live_l.local_addr().map_err(|_| "live addr")?;
    tokio::spawn(async move {
        let _ = live_l.accept().await;
    });

    let connected = connect_happy_eyeballs(&[dead_addr, live_addr]).await;
    assert!(connected.is_some());

    let _ = stop_allow_tx.send(());
    let _ = stop_deny_tx.send(());
    let _ = dest_stop.send(());
    Ok(())
}
