//! Async TCP listener, non-destructive `ClientHello` buffering, Reality
//! authentication + TLS 1.3 handshake completion, and transparent "never close,
//! always delegate" fallback relay to `dest`.

use core::future::Future;
use core::time::Duration;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use mirage_core::crypto::RealityCertTemplate;
use mirage_core::reality::{
    authenticate_client_hello, prepare_server_flight, AuthFallbackReason, AuthOutcome,
    AuthenticatedClient, ClientFlightStatus, RealityAuthParams, RealityTlsSession, ReplayCache,
};
use mirage_core::tls_parser::{
    inspect_client_hello, parse_dest_server_flight, ClientHelloInfo, DestServerProfile,
    FallbackReason, InspectOutcome, ServerFlightStatus,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::error::DaemonError;
use crate::metrics::Metrics;

/// Brief backoff if `accept()` encounters a transient OS resource error.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Initial `BytesMut` capacity reserved for reading a `ClientHello`.
const INITIAL_BUFFER_CAPACITY: usize = 2048;

/// Chunk size for bounded socket reads into `BytesMut`.
const READ_CHUNK_SIZE: usize = 2048;

/// Maximum bytes buffered while inspecting `dest`'s TLS 1.3 server flight.
const MAX_DEST_FLIGHT_BYTES: usize = 32 * 1024;

/// Brief grace window to gather trailing `dest` encrypted records when
/// `ServerHello` has already arrived.
const DEST_TRAILING_RECORD_WAIT: Duration = Duration::from_millis(40);

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
    let mut hmac_key = Zeroizing::new([0u8; 32]);
    let mut cert_seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(hmac_key.as_mut_slice()).map_err(|_| DaemonError::HardeningFailed)?;
    getrandom::fill(cert_seed.as_mut_slice()).map_err(|_| DaemonError::HardeningFailed)?;

    let cert_template = Arc::new(RealityCertTemplate::from_seed(*cert_seed));
    let replay_cache = config.reality().map(|rc| {
        Arc::new(Mutex::new(ReplayCache::new(
            *hmac_key,
            rc.max_time_diff_secs(),
            rc.replay_cache_capacity(),
        )))
    });

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
                    Arc::clone(&cert_template),
                    replay_cache.as_ref().map(Arc::clone),
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
    cert_template: Arc<RealityCertTemplate>,
    replay_cache: Option<Arc<Mutex<ReplayCache>>>,
    _permit: OwnedSemaphorePermit,
) {
    let _ = client.set_nodelay(true);

    let mut buf = BytesMut::with_capacity(INITIAL_BUFFER_CAPACITY);
    let mut client_eof = false;
    let mut client_io_err = false;
    let mut matched_hello: Option<Box<ClientHelloInfo>> = None;

    let read_result = tokio::time::timeout(
        config.initial_read_timeout(),
        read_until_decision(
            &mut client,
            &mut buf,
            &mut client_eof,
            &mut client_io_err,
            &mut matched_hello,
            &config,
            &metrics,
        ),
    )
    .await;

    if read_result.is_err() {
        metrics.inc_timeout_delegated();
    } else if client_io_err && buf.is_empty() {
        return;
    } else if !client_eof {
        if let (Some(ch), Some(rc), Some(cache)) =
            (matched_hello, config.reality(), replay_cache.as_ref())
        {
            let now_unix_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let params = RealityAuthParams {
                private_keys: rc.private_keys(),
                short_ids: rc.short_ids(),
                max_time_diff_secs: rc.max_time_diff_secs(),
                min_client_ver: rc.min_client_ver(),
                max_client_ver: rc.max_client_ver(),
            };
            let auth_outcome = {
                let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
                authenticate_client_hello(&ch, &params, &mut guard, now_unix_secs)
            };

            match auth_outcome {
                AuthOutcome::Authenticated(auth) => {
                    metrics.inc_reality_authenticated();
                    complete_reality_handshake(
                        client,
                        buf,
                        *ch,
                        *auth,
                        &config,
                        &cert_template,
                        &metrics,
                    )
                    .await;
                    return;
                }
                AuthOutcome::Fallback(
                    AuthFallbackReason::Replayed | AuthFallbackReason::ReplayCacheSaturated,
                ) => {
                    metrics.inc_reality_replayed_or_saturated();
                }
                AuthOutcome::Fallback(_) => {
                    metrics.inc_reality_auth_failed();
                }
            }
        }
    }

    metrics.inc_delegated_fallback();
    delegate_to_dest(client, buf, client_eof, config.dest_addr(), &metrics).await;
}

async fn read_until_decision(
    client: &mut TcpStream,
    buf: &mut BytesMut,
    client_eof: &mut bool,
    client_io_err: &mut bool,
    matched_hello: &mut Option<Box<ClientHelloInfo>>,
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
                            *matched_hello = Some(info);
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

async fn complete_reality_handshake(
    mut client: TcpStream,
    buffered_ch: BytesMut,
    client_hello: ClientHelloInfo,
    auth: AuthenticatedClient,
    config: &Config,
    cert_template: &RealityCertTemplate,
    metrics: &Metrics,
) {
    let Ok(mut dest) = TcpStream::connect(config.dest_addr()).await else {
        metrics.inc_dial_dest_failed();
        return;
    };
    let _ = dest.set_nodelay(true);

    if dest.write_all(&buffered_ch).await.is_err() {
        metrics.inc_reality_dest_profile_fallback();
        return;
    }

    let mut dest_buf = BytesMut::with_capacity(4096);
    let profile = read_dest_profile(&mut dest, &mut dest_buf, config.initial_read_timeout()).await;

    let Some(dest_profile) = profile else {
        // Fallback seamlessly if `dest` returned invalid/incomplete ServerHello.
        metrics.inc_reality_dest_profile_fallback();
        if !dest_buf.is_empty() && client.write_all(&dest_buf).await.is_err() {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut dest).await;
        return;
    };

    // Learned `dest`'s exact handshake profile; drop `dest` before replying as Reality.
    drop(dest);

    let mut x25519_seed = Zeroizing::new([0u8; 32]);
    let mut mlkem_seed = Zeroizing::new([0u8; 32]);
    if getrandom::fill(x25519_seed.as_mut_slice()).is_err()
        || getrandom::fill(mlkem_seed.as_mut_slice()).is_err()
    {
        return;
    }

    let Ok(mut prepared) = prepare_server_flight(
        &client_hello,
        &auth,
        &dest_profile,
        cert_template,
        *x25519_seed,
        *mlkem_seed,
    ) else {
        return;
    };

    if client.write_all(&prepared.wire_bytes).await.is_err() {
        return;
    }

    let mut buf = [0u8; READ_CHUNK_SIZE];
    let handshake_res = tokio::time::timeout(config.initial_read_timeout(), async {
        loop {
            let n = client.read(&mut buf).await.ok()?;
            if n == 0 {
                return None;
            }
            let slice = buf.get(..n)?;
            match prepared.pending.feed_client_bytes(slice) {
                ClientFlightStatus::NeedMoreData => continue,
                ClientFlightStatus::Complete {
                    session,
                    initial_app_data,
                } => return Some((session, initial_app_data)),
                ClientFlightStatus::Failed => return None,
            }
        }
    })
    .await;

    let Ok(Some((session, initial_app_data))) = handshake_res else {
        return;
    };

    metrics.inc_reality_handshake_completed();
    drive_authenticated_session(client, *session, initial_app_data).await;
}

async fn read_dest_profile(
    dest: &mut TcpStream,
    dest_buf: &mut BytesMut,
    timeout_dur: Duration,
) -> Option<DestServerProfile> {
    let mut partial_profile: Option<DestServerProfile> = None;
    let mut chunk = [0u8; 4096];

    let _ = tokio::time::timeout(timeout_dur, async {
        loop {
            let remaining = MAX_DEST_FLIGHT_BYTES.saturating_sub(dest_buf.len());
            if remaining == 0 {
                break;
            }
            let to_read = remaining.min(chunk.len());
            let Some(slice) = chunk.get_mut(..to_read) else {
                break;
            };
            let read_fut = dest.read(slice);
            let n = if partial_profile.is_some() {
                match tokio::time::timeout(DEST_TRAILING_RECORD_WAIT, read_fut).await {
                    Ok(Ok(n)) => n,
                    _ => break,
                }
            } else {
                match read_fut.await {
                    Ok(n) => n,
                    Err(_) => break,
                }
            };
            if n == 0 {
                break;
            }
            let Some(read_bytes) = slice.get(..n) else {
                break;
            };
            dest_buf.extend_from_slice(read_bytes);

            match parse_dest_server_flight(dest_buf) {
                ServerFlightStatus::NeedMoreData => continue,
                ServerFlightStatus::PartialWithProfile(profile) => {
                    partial_profile = Some(*profile);
                }
                ServerFlightStatus::Complete(profile) => {
                    partial_profile = Some(*profile);
                    break;
                }
                ServerFlightStatus::Invalid => {
                    partial_profile = None;
                    break;
                }
            }
        }
    })
    .await;

    partial_profile
}

async fn drive_authenticated_session(
    mut client: TcpStream,
    mut session: RealityTlsSession,
    _initial_app_data: Vec<u8>,
) {
    // Milestone 2: authenticated TLS 1.3 record stream is established and ready.
    // Milestone 3 will decode VLESS headers & XTLS-Vision framing from `initial_app_data`
    // and subsequent decrypted `feed_wire_bytes` slices.
    let mut buf = [0u8; 4096];
    loop {
        match client.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let Some(slice) = buf.get(..n) else {
                    break;
                };
                match session.feed_wire_bytes(slice) {
                    Ok((_app_data, true)) => {
                        if let Ok(alert) = session.seal_app_data(&[]) {
                            let _ = client.write_all(&alert).await;
                        }
                        let _ = client.shutdown().await;
                        break;
                    }
                    Ok((_app_data, false)) => continue,
                    Err(_) => break,
                }
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
