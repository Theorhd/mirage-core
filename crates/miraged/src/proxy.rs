//! Async TCP listener, non-destructive `ClientHello` buffering, and
//! transparent "never close, always delegate" fallback relay to `dest`.

use core::future::Future;
use core::time::Duration;
use std::sync::Arc;

use bytes::BytesMut;
use mirage_core::tls_parser::{inspect_client_hello, FallbackReason, InspectOutcome};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::Config;
use crate::error::DaemonError;
use crate::metrics::Metrics;

/// Brief backoff if `accept()` encounters a transient OS resource error.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Initial `BytesMut` capacity reserved for reading a `ClientHello`.
const INITIAL_BUFFER_CAPACITY: usize = 2048;

/// Chunk size for bounded socket reads into `BytesMut`.
const READ_CHUNK_SIZE: usize = 2048;

/// Runs the TCP accept loop until `shutdown` resolves.
///
/// Enforces global connection budgets via **accept-side backpressure**: a
/// semaphore permit is acquired *before* calling `accept()`, so saturated
/// servers never accept-then-close sockets.
pub async fn run_server<F>(
    listener: TcpListener,
    config: Arc<Config>,
    metrics: Arc<Metrics>,
    shutdown: F,
) -> Result<(), DaemonError>
where
    F: Future<Output = ()>,
{
    let semaphore = Arc::new(Semaphore::new(config.max_connections()));
    tokio::pin!(shutdown);

    loop {
        let permit = tokio::select! {
            biased;
            () = &mut shutdown => break,
            res = Arc::clone(&semaphore).acquire_owned() => {
                match res {
                    Ok(p) => p,
                    Err(_) => break,
                }
            }
        };

        let accept_res = tokio::select! {
            biased;
            () = &mut shutdown => break,
            res = listener.accept() => res,
        };

        match accept_res {
            Ok((stream, _peer_addr)) => {
                metrics.inc_accepted();
                tokio::spawn(handle_connection(
                    stream,
                    Arc::clone(&config),
                    Arc::clone(&metrics),
                    permit,
                ));
            }
            Err(_) => {
                drop(permit);
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
            }
        }
    }

    Ok(())
}

async fn handle_connection(
    mut client: TcpStream,
    config: Arc<Config>,
    metrics: Arc<Metrics>,
    _permit: OwnedSemaphorePermit,
) {
    let _ = client.set_nodelay(true);

    let mut buf = BytesMut::with_capacity(INITIAL_BUFFER_CAPACITY);
    let mut client_eof = false;
    let mut client_io_err = false;

    let read_result = tokio::time::timeout(
        config.initial_read_timeout(),
        read_until_decision(
            &mut client,
            &mut buf,
            &mut client_eof,
            &mut client_io_err,
            &config,
            &metrics,
        ),
    )
    .await;

    if read_result.is_err() {
        metrics.inc_timeout_delegated();
    } else if client_io_err && buf.is_empty() {
        return;
    }

    // Milestone 1: all connections (including matched SNI, timeout, oversize,
    // malformed, non-TLS, or partial EOF) delegate transparently to `dest`.
    // Milestone 2 will branch matched SNI + valid Reality auth before fallback.
    metrics.inc_delegated_fallback();
    delegate_to_dest(client, buf, client_eof, config.dest_addr(), &metrics).await;
}

async fn read_until_decision(
    client: &mut TcpStream,
    buf: &mut BytesMut,
    client_eof: &mut bool,
    client_io_err: &mut bool,
    config: &Config,
    metrics: &Metrics,
) {
    let mut chunk = [0u8; READ_CHUNK_SIZE];

    loop {
        let remaining = config.max_client_hello_bytes().saturating_sub(buf.len());
        if remaining == 0 {
            metrics.inc_oversize_delegated();
            return;
        }

        let to_read = remaining.min(chunk.len());
        let Some(slice) = chunk.get_mut(..to_read) else {
            return;
        };

        match client.read(slice).await {
            Ok(0) => {
                *client_eof = true;
                return;
            }
            Ok(n) => {
                let Some(read_bytes) = slice.get(..n) else {
                    return;
                };
                buf.extend_from_slice(read_bytes);

                match inspect_client_hello(buf, config.max_client_hello_bytes()) {
                    InspectOutcome::NeedMoreData => {
                        if buf.len() >= config.max_client_hello_bytes() {
                            metrics.inc_oversize_delegated();
                            return;
                        }
                    }
                    InspectOutcome::ClientHello(info) => {
                        if info.matches_any_server_name(config.server_names()) {
                            metrics.inc_sni_matched();
                        }
                        return;
                    }
                    InspectOutcome::Fallback(FallbackReason::Oversize) => {
                        metrics.inc_oversize_delegated();
                        return;
                    }
                    InspectOutcome::Fallback(_) => {
                        return;
                    }
                }
            }
            Err(_) => {
                *client_io_err = true;
                return;
            }
        }
    }
}

async fn delegate_to_dest(
    mut client: TcpStream,
    buffered: BytesMut,
    client_eof: bool,
    dest_addr: std::net::SocketAddr,
    metrics: &Metrics,
) {
    let Ok(mut dest) = TcpStream::connect(dest_addr).await else {
        metrics.inc_dial_dest_failed();
        return;
    };
    let _ = dest.set_nodelay(true);

    if !buffered.is_empty() && dest.write_all(&buffered).await.is_err() {
        return;
    }

    if client_eof {
        let _ = dest.shutdown().await;
        let _ = tokio::io::copy(&mut dest, &mut client).await;
        let _ = client.shutdown().await;
        return;
    }

    let _ = tokio::io::copy_bidirectional(&mut client, &mut dest).await;
}
