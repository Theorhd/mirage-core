//! Differential probing and Zero-PII log verification tests for `miraged`.
//!
//! Each probe suite is executed identically against a direct mock `dest`
//! server and against `miraged` fronting that `dest`, verifying byte-for-byte
//! parity, faithful EOF/half-close propagation, timeout delegation, and
//! absence of PII in `tracing` output.

use core::time::Duration;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use miraged::config::Config;
use miraged::metrics::Metrics;
use miraged::proxy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tracing_subscriber::fmt::MakeWriter;

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

/// Starts a mock `dest` server that:
/// - If the client sends nothing within 250ms, writes `b"DEST_IDLE_BANNER\n"` and closes.
/// - Otherwise reads until EOF (or up to 32 KiB) and echoes back `b"DEST_ECHO:"` + received bytes.
async fn spawn_mock_dest() -> Option<(SocketAddr, oneshot::Sender<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
    let addr = listener.local_addr().ok()?;
    let (tx, mut rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            let accept = tokio::select! {
                _ = &mut rx => break,
                res = listener.accept() => res,
            };
            let Ok((mut sock, _)) = accept else {
                break;
            };
            tokio::spawn(async move {
                let mut first = [0u8; 4096];
                let first_read =
                    tokio::time::timeout(Duration::from_millis(250), sock.read(&mut first)).await;

                match first_read {
                    Err(_) => {
                        let _ = sock.write_all(b"DEST_IDLE_BANNER\n").await;
                        let _ = sock.shutdown().await;
                    }
                    Ok(Ok(0)) => {
                        let _ = sock.write_all(b"DEST_EMPTY_EOF\n").await;
                        let _ = sock.shutdown().await;
                    }
                    Ok(Ok(n)) => {
                        let mut acc = Vec::new();
                        if let Some(s) = first.get(..n) {
                            acc.extend_from_slice(s);
                        }
                        while let Ok(Ok(m)) =
                            tokio::time::timeout(Duration::from_millis(100), sock.read(&mut first))
                                .await
                        {
                            if m == 0 {
                                break;
                            }
                            if let Some(s) = first.get(..m) {
                                acc.extend_from_slice(s);
                            }
                            if acc.len() >= 32 * 1024 {
                                break;
                            }
                        }
                        let _ = sock.write_all(b"DEST_ECHO:").await;
                        let _ = sock.write_all(&acc).await;
                        let _ = sock.shutdown().await;
                    }
                    Ok(Err(_)) => {}
                }
            });
        }
    });

    Some((addr, tx))
}

async fn run_probe(addr: SocketAddr, payload: Option<&[u8]>, half_close: bool) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await.ok()?;
    if let Some(bytes) = payload {
        stream.write_all(bytes).await.ok()?;
        if half_close {
            stream.shutdown().await.ok()?;
        }
    }
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut out)).await;
    Some(out)
}

fn build_fragmented_pq_client_hello(sni: &str) -> Vec<u8> {
    let host_bytes = sni.as_bytes();
    let mut extensions = Vec::new();

    // server_name
    let entry_len = 1usize.saturating_add(2).saturating_add(host_bytes.len());
    let sni_ext_len = 2usize.saturating_add(entry_len);
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
    extensions.extend_from_slice(&(entry_len as u16).to_be_bytes());
    extensions.push(0x00);
    extensions.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    extensions.extend_from_slice(host_bytes);

    // supported_versions (TLS 1.3)
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&3u16.to_be_bytes());
    extensions.push(2);
    extensions.extend_from_slice(&0x0304u16.to_be_bytes());

    // key_share (X25519MLKEM768 + X25519)
    let mut shares = Vec::new();
    shares.extend_from_slice(&0x11ecu16.to_be_bytes());
    shares.extend_from_slice(&1216u16.to_be_bytes());
    shares.extend(core::iter::repeat_n(0x5A, 1216));
    shares.extend_from_slice(&0x001du16.to_be_bytes());
    shares.extend_from_slice(&32u16.to_be_bytes());
    shares.extend([0x77u8; 32]);

    let ks_ext_len = 2usize.saturating_add(shares.len());
    extensions.extend_from_slice(&0x0033u16.to_be_bytes());
    extensions.extend_from_slice(&(ks_ext_len as u16).to_be_bytes());
    extensions.extend_from_slice(&(shares.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&shares);

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend([0x11u8; 32]);
    body.push(32);
    body.extend([0x22u8; 32]);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let len_bytes = (body.len() as u32).to_be_bytes();
    let mut hs_msg = Vec::new();
    hs_msg.push(0x01);
    if let Some(tail) = len_bytes.get(1..4) {
        hs_msg.extend_from_slice(tail);
    }
    hs_msg.extend_from_slice(&body);

    let mut wire = Vec::new();
    for chunk in hs_msg.chunks(256) {
        wire.push(0x16);
        wire.extend_from_slice(&0x0301u16.to_be_bytes());
        wire.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        wire.extend_from_slice(chunk);
    }
    wire
}

#[tokio::test]
async fn differential_probing_and_zero_pii_logs() {
    let log_buf = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log_buf.clone())
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let mock_dest = spawn_mock_dest().await;
    assert!(mock_dest.is_some(), "failed to bind mock dest");
    let Some((dest_addr, dest_stop)) = mock_dest else {
        return;
    };

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| std::process::abort());
    let proxy_addr = listener
        .local_addr()
        .unwrap_or_else(|_| std::process::abort());

    let cfg_res = Config::new(
        proxy_addr,
        dest_addr,
        vec!["secret-probe.example.org".to_owned()],
        16 * 1024,
        120,
        64,
        false,
    );
    assert!(cfg_res.is_ok(), "test config should be valid");
    let Ok(cfg) = cfg_res else {
        return;
    };
    let cfg = Arc::new(cfg);
    let metrics = Arc::new(Metrics::new());
    let (proxy_stop_tx, proxy_stop_rx) = oneshot::channel::<()>();

    let server_handle = tokio::spawn(proxy::run_server(
        listener,
        cfg,
        Arc::clone(&metrics),
        async move {
            let _ = proxy_stop_rx.await;
        },
    ));

    // 1. Silent connection: miraged must delegate on initial timeout, not close.
    let direct_silent = run_probe(dest_addr, None, false).await;
    let proxy_silent = run_probe(proxy_addr, None, false).await;
    assert_eq!(
        proxy_silent.as_deref(),
        Some(b"DEST_IDLE_BANNER\n".as_slice())
    );
    assert_eq!(proxy_silent, direct_silent);
    assert_eq!(metrics.timeout_delegated(), 1);

    // 2. Non-TLS HTTP request: byte-for-byte parity.
    let http_probe = b"GET / HTTP/1.1\r\nHost: secret-probe.example.org\r\n\r\n";
    let direct_http = run_probe(dest_addr, Some(http_probe), true).await;
    let proxy_http = run_probe(proxy_addr, Some(http_probe), true).await;
    assert_eq!(proxy_http, direct_http);

    // 3. Partial/truncated ClientHello followed by EOF: faithful replay + half-close.
    let partial_ch = &[0x16, 0x03, 0x01, 0x00, 0x40, 0x01, 0x00, 0x00];
    let direct_partial = run_probe(dest_addr, Some(partial_ch), true).await;
    let proxy_partial = run_probe(proxy_addr, Some(partial_ch), true).await;
    assert_eq!(proxy_partial, direct_partial);

    // 4. Oversized stream (> 16 KiB): falls back at cap and streams everything verbatim.
    let mut oversized = vec![0x16, 0x03, 0x01, 0x40, 0x00];
    oversized.resize(20 * 1024, 0xCD);
    let direct_over = run_probe(dest_addr, Some(&oversized), true).await;
    let proxy_over = run_probe(proxy_addr, Some(&oversized), true).await;
    assert_eq!(proxy_over, direct_over);
    assert!(metrics.oversize_delegated() >= 1);

    // 5. Fragmented PQ ClientHello matching allowed SNI -> increments sni_matched and delegates.
    let pq_matched = build_fragmented_pq_client_hello("secret-probe.example.org");
    let direct_pq = run_probe(dest_addr, Some(&pq_matched), true).await;
    let proxy_pq = run_probe(proxy_addr, Some(&pq_matched), true).await;
    assert_eq!(proxy_pq, direct_pq);
    assert_eq!(metrics.sni_matched(), 1);

    // 6. Unknown SNI ClientHello -> relayed transparently without matching SNI.
    let pq_unknown = build_fragmented_pq_client_hello("other.example.net");
    let direct_unknown = run_probe(dest_addr, Some(&pq_unknown), true).await;
    let proxy_unknown = run_probe(proxy_addr, Some(&pq_unknown), true).await;
    assert_eq!(proxy_unknown, direct_unknown);
    assert_eq!(metrics.sni_matched(), 1);

    // 7. Immediate empty EOF -> half-close delegated faithfully to dest.
    let direct_empty = run_probe(dest_addr, Some(b""), true).await;
    let proxy_empty = run_probe(proxy_addr, Some(b""), true).await;
    assert_eq!(proxy_empty.as_deref(), Some(b"DEST_EMPTY_EOF\n".as_slice()));
    assert_eq!(proxy_empty, direct_empty);

    // Verify Zero-PII logging: no IPs, SNIs, or hostnames in captured log output.
    let logs = log_buf.contents();
    assert!(!logs.contains("127.0.0.1"));
    assert!(!logs.contains("secret-probe.example.org"));
    assert!(!logs.contains("other.example.net"));

    let _ = proxy_stop_tx.send(());
    let _ = dest_stop.send(());
    let _ = server_handle.await;
}
