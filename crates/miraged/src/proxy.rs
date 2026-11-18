//! Async TCP listener, non-destructive `ClientHello` buffering, Reality
//! authentication + TLS 1.3 handshake completion, VLESS/XTLS-Vision proxying
//! with anti-SSRF egress enforcement, and transparent fallback relay to `dest`.

use core::future::Future;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use mirage_core::crypto::RealityCertTemplate;
use mirage_core::egress::EgressPolicy;
use mirage_core::reality::{
    authenticate_client_hello, prepare_server_flight, AuthFallbackReason, AuthOutcome,
    AuthenticatedClient, ClientFlightStatus, RealityAuthParams, RealityTlsReader,
    RealityTlsSession, RealityTlsWriter, ReplayCache,
};
use mirage_core::tls_parser::{
    inspect_client_hello, parse_dest_server_flight, ClientHelloInfo, DestServerProfile,
    FallbackReason, InspectOutcome, ServerFlightStatus,
};
use mirage_core::vision::{UnpadMode, VisionPadder, VisionTlsFilter, VisionUnpadder};
use mirage_core::vless::{
    decode_udp_packet, encode_udp_packet, encode_vless_response_header, parse_vless_request,
    VlessAddress, VlessCommand, VlessFlow, VlessParseOutcome, VlessRequest,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::{Zeroize, Zeroizing};

use crate::config::{Config, VlessConfig};
use crate::dns::DnsResolver;
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

/// Maximum bytes buffered while decoding the initial VLESS request header.
const MAX_VLESS_HEADER_BYTES: usize = 4096;

/// Outbound/upstream read chunk size kept safely below TLS 1.3 16 KiB limit
/// (even with Vision framing & padding overhead).
const RELAY_CHUNK_SIZE: usize = 8192;

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
    let dns_resolver = config
        .vless()
        .map(|vc| Arc::new(DnsResolver::new(vc.dns_resolver(), vc.allow_system_dns())));

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
                    dns_resolver.as_ref().map(Arc::clone),
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
    dns_resolver: Option<Arc<DnsResolver>>,
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
                        dns_resolver.as_deref(),
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

#[allow(clippy::too_many_arguments)]
async fn complete_reality_handshake(
    mut client: TcpStream,
    buffered_ch: BytesMut,
    client_hello: ClientHelloInfo,
    auth: AuthenticatedClient,
    config: &Config,
    cert_template: &RealityCertTemplate,
    dns_resolver: Option<&DnsResolver>,
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
        metrics.inc_reality_dest_profile_fallback();
        if !dest_buf.is_empty() && client.write_all(&dest_buf).await.is_err() {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut dest).await;
        return;
    };

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
                    initial_app_data: _,
                } => return Some(session),
                ClientFlightStatus::Failed => return None,
            }
        }
    })
    .await;

    let Ok(Some(session)) = handshake_res else {
        return;
    };

    metrics.inc_reality_handshake_completed();
    drive_authenticated_session(client, *session, config, dns_resolver, metrics).await;
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
    config: &Config,
    dns_resolver: Option<&DnsResolver>,
    metrics: &Metrics,
) {
    let Some(vless_cfg) = config.vless() else {
        // Milestone 2 mode (no [vless] configured): drain encrypted TLS 1.3 records cleanly.
        let mut buf = [0u8; 4096];
        loop {
            match client.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let Some(slice) = buf.get(..n) else {
                        break;
                    };
                    match session.feed_wire_bytes(slice) {
                        Ok((_, true)) => {
                            if let Ok(alert) = session.seal_app_data(&[]) {
                                let _ = client.write_all(&alert).await;
                            }
                            let _ = client.shutdown().await;
                            break;
                        }
                        Ok((_, false)) => continue,
                        Err(_) => break,
                    }
                }
            }
        }
        return;
    };

    let (mut tls_reader, tls_writer) = session.into_split();
    let Some((req, trailing_app_data)) = read_vless_header(
        &mut client,
        &mut tls_reader,
        vless_cfg,
        config.initial_read_timeout(),
        metrics,
    )
    .await
    else {
        return;
    };

    let Some(target_addr) =
        resolve_and_validate_egress(&req, config, vless_cfg, dns_resolver, metrics).await
    else {
        return;
    };

    match req.command {
        VlessCommand::Tcp => {
            metrics.inc_vless_tcp_sessions();
            relay_vless_tcp(
                client,
                tls_reader,
                tls_writer,
                req,
                trailing_app_data,
                target_addr,
                metrics,
            )
            .await;
        }
        VlessCommand::Udp => {
            metrics.inc_vless_udp_sessions();
            relay_vless_udp(
                client,
                tls_reader,
                tls_writer,
                trailing_app_data,
                target_addr,
            )
            .await;
        }
        VlessCommand::Mux => {}
    }
}

async fn read_vless_header(
    client: &mut TcpStream,
    tls_reader: &mut RealityTlsReader,
    vless_cfg: &VlessConfig,
    timeout_dur: Duration,
    metrics: &Metrics,
) -> Option<(Box<VlessRequest>, Zeroizing<Vec<u8>>)> {
    let mut app_buf = Zeroizing::new(Vec::with_capacity(512));
    let mut wire_chunk = [0u8; READ_CHUNK_SIZE];

    let parsed = tokio::time::timeout(timeout_dur, async {
        loop {
            while let Ok(Some((inner_ct, payload))) = tls_reader.next_record() {
                if inner_ct == 0x15 {
                    return None;
                }
                if inner_ct == 0x17 {
                    let new_len = app_buf.len().saturating_add(payload.len());
                    if new_len > MAX_VLESS_HEADER_BYTES {
                        return None;
                    }
                    app_buf.extend_from_slice(&payload);

                    match parse_vless_request(&mut app_buf, vless_cfg.uuids()) {
                        VlessParseOutcome::NeedMoreData => continue,
                        VlessParseOutcome::Parsed(req) => {
                            let trailing = Zeroizing::new(
                                app_buf.get(req.header_len..).unwrap_or(&[]).to_vec(),
                            );
                            app_buf.zeroize();
                            return Some((req, trailing));
                        }
                        VlessParseOutcome::Invalid(_) => {
                            metrics.inc_vless_auth_failed();
                            app_buf.zeroize();
                            return None;
                        }
                    }
                }
            }

            let n = client.read(&mut wire_chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            let slice = wire_chunk.get(..n)?;
            tls_reader.push_wire_bytes(slice);
        }
    })
    .await;

    match parsed {
        Ok(Some(res)) => Some(res),
        _ => None,
    }
}

async fn resolve_and_validate_egress(
    req: &VlessRequest,
    config: &Config,
    vless_cfg: &VlessConfig,
    dns_resolver: Option<&DnsResolver>,
    metrics: &Metrics,
) -> Option<SocketAddr> {
    let is_tcp = req.command == VlessCommand::Tcp;
    let policy = EgressPolicy {
        allow_private_egress: vless_cfg.allow_private_egress(),
        allow_smtp_port_25: vless_cfg.allow_smtp_port_25(),
        blocked_ips: vec![config.listen_addr().ip(), config.dest_addr().ip()],
    };

    let candidate_ips: Vec<IpAddr> = match &req.address {
        VlessAddress::Ipv4(v4) => vec![IpAddr::V4(*v4)],
        VlessAddress::Ipv6(v6) => vec![IpAddr::V6(*v6)],
        VlessAddress::Domain(domain) => dns_resolver?.resolve(domain).await?,
    };

    for ip in candidate_ips {
        if let Ok(validated) = policy.validate_target(ip, req.port, is_tcp) {
            return Some(validated);
        }
    }

    metrics.inc_egress_blocked();
    None
}

async fn relay_vless_tcp(
    client: TcpStream,
    mut tls_reader: RealityTlsReader,
    mut tls_writer: RealityTlsWriter,
    req: Box<VlessRequest>,
    mut trailing_app_data: Zeroizing<Vec<u8>>,
    target_addr: SocketAddr,
    metrics: &Metrics,
) {
    let Ok(upstream) = TcpStream::connect(target_addr).await else {
        return;
    };
    let _ = upstream.set_nodelay(true);

    let (mut client_read, mut client_write) = client.into_split();
    let (mut up_read, mut up_write) = upstream.into_split();

    let resp_hdr = encode_vless_response_header();
    let Ok(sealed_hdr) = tls_writer.seal_app_data(&resp_hdr) else {
        return;
    };
    if client_write.write_all(&sealed_hdr).await.is_err() {
        return;
    }

    match req.flow {
        VlessFlow::None => {
            if !trailing_app_data.is_empty()
                && up_write.write_all(&trailing_app_data).await.is_err()
            {
                return;
            }
            trailing_app_data.zeroize();

            let up_fut = relay_plain_uplink(&mut client_read, &mut tls_reader, &mut up_write);
            let down_fut = relay_plain_downlink(&mut up_read, &mut tls_writer, &mut client_write);
            let _ = tokio::join!(up_fut, down_fut);
        }
        VlessFlow::Vision { .. } => {
            let tls_filter = Arc::new(Mutex::new(VisionTlsFilter::new()));
            let uuid = req.uuid.clone();
            let up_fut = relay_vision_uplink(
                &mut client_read,
                tls_reader,
                &mut up_write,
                uuid.clone(),
                trailing_app_data,
                Arc::clone(&tls_filter),
            );
            let down_fut = relay_vision_downlink(
                &mut up_read,
                tls_writer,
                &mut client_write,
                uuid,
                tls_filter,
                metrics,
            );
            let _ = tokio::join!(up_fut, down_fut);
        }
    }
}

async fn relay_plain_uplink(
    client_read: &mut OwnedReadHalf,
    tls_reader: &mut RealityTlsReader,
    up_write: &mut OwnedWriteHalf,
) {
    let mut wire = [0u8; RELAY_CHUNK_SIZE];
    loop {
        match tls_reader.next_record() {
            Ok(Some((0x17, payload))) => {
                if !payload.is_empty() && up_write.write_all(&payload).await.is_err() {
                    break;
                }
                continue;
            }
            Ok(Some((0x15, _))) => {
                let _ = up_write.shutdown().await;
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => {}
            Err(_) => break,
        }

        match client_read.read(&mut wire).await {
            Ok(0) | Err(_) => {
                let _ = up_write.shutdown().await;
                break;
            }
            Ok(n) => {
                if let Some(s) = wire.get(..n) {
                    tls_reader.push_wire_bytes(s);
                }
            }
        }
    }
}

async fn relay_plain_downlink(
    up_read: &mut OwnedReadHalf,
    tls_writer: &mut RealityTlsWriter,
    client_write: &mut OwnedWriteHalf,
) {
    let mut buf = [0u8; RELAY_CHUNK_SIZE];
    loop {
        match up_read.read(&mut buf).await {
            Ok(0) => {
                if let Ok(alert) = tls_writer.seal_app_data(&[]) {
                    let _ = client_write.write_all(&alert).await;
                }
                let _ = client_write.shutdown().await;
                break;
            }
            Ok(n) => {
                let Some(slice) = buf.get(..n) else {
                    break;
                };
                let Ok(sealed) = tls_writer.seal_app_data(slice) else {
                    break;
                };
                if client_write.write_all(&sealed).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

async fn relay_vision_uplink(
    client_read: &mut OwnedReadHalf,
    mut tls_reader: RealityTlsReader,
    up_write: &mut OwnedWriteHalf,
    uuid: mirage_core::vless::VlessUuid,
    mut trailing_app_data: Zeroizing<Vec<u8>>,
    tls_filter: Arc<Mutex<VisionTlsFilter>>,
) {
    let mut unpadder = VisionUnpadder::new(uuid);

    if !trailing_app_data.is_empty() {
        let out = unpadder.feed(&trailing_app_data);
        trailing_app_data.zeroize();
        if !out.payload.is_empty() {
            {
                let mut f = tls_filter.lock().unwrap_or_else(|e| e.into_inner());
                f.inspect(&out.payload);
            }
            if up_write.write_all(&out.payload).await.is_err() {
                return;
            }
        }
        if out.mode == UnpadMode::DirectCopy {
            if !out.direct_trailing.is_empty()
                && up_write.write_all(&out.direct_trailing).await.is_err()
            {
                return;
            }
            let rem_raw = tls_reader.into_remaining_wire_bytes();
            if !rem_raw.is_empty() && up_write.write_all(&rem_raw).await.is_err() {
                return;
            }
            let _ = tokio::io::copy(client_read, up_write).await;
            let _ = up_write.shutdown().await;
            return;
        }
    }

    let mut wire = [0u8; RELAY_CHUNK_SIZE];
    loop {
        loop {
            match tls_reader.next_record() {
                Ok(Some((0x17, payload))) => {
                    let out = unpadder.feed(&payload);
                    if !out.payload.is_empty() {
                        {
                            let mut f = tls_filter.lock().unwrap_or_else(|e| e.into_inner());
                            f.inspect(&out.payload);
                        }
                        if up_write.write_all(&out.payload).await.is_err() {
                            return;
                        }
                    }
                    if out.mode == UnpadMode::DirectCopy {
                        if !out.direct_trailing.is_empty()
                            && up_write.write_all(&out.direct_trailing).await.is_err()
                        {
                            return;
                        }
                        let rem_raw = tls_reader.into_remaining_wire_bytes();
                        if !rem_raw.is_empty() && up_write.write_all(&rem_raw).await.is_err() {
                            return;
                        }
                        let _ = tokio::io::copy(client_read, up_write).await;
                        let _ = up_write.shutdown().await;
                        return;
                    }
                }
                Ok(Some((0x15, _))) => {
                    let _ = up_write.shutdown().await;
                    return;
                }
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(_) => return,
            }
        }

        match client_read.read(&mut wire).await {
            Ok(0) | Err(_) => {
                let _ = up_write.shutdown().await;
                return;
            }
            Ok(n) => {
                if let Some(s) = wire.get(..n) {
                    tls_reader.push_wire_bytes(s);
                }
            }
        }
    }
}

async fn relay_vision_downlink(
    up_read: &mut OwnedReadHalf,
    mut tls_writer: RealityTlsWriter,
    client_write: &mut OwnedWriteHalf,
    uuid: mirage_core::vless::VlessUuid,
    tls_filter: Arc<Mutex<VisionTlsFilter>>,
    metrics: &Metrics,
) {
    let mut padder = VisionPadder::new(uuid);
    let mut buf = [0u8; RELAY_CHUNK_SIZE];

    loop {
        match up_read.read(&mut buf).await {
            Ok(0) => {
                let _ = client_write.shutdown().await;
                return;
            }
            Ok(n) => {
                let Some(slice) = buf.get(..n) else {
                    return;
                };
                let filter_snapshot = {
                    let mut f = tls_filter.lock().unwrap_or_else(|e| e.into_inner());
                    f.inspect(slice);
                    f.clone()
                };
                let mut rand_bytes = [0u8; 4];
                if getrandom::fill(&mut rand_bytes).is_err() {
                    return;
                }
                let rand_u32 = u32::from_be_bytes(rand_bytes);
                let out_bytes = padder.wrap_outbound(slice, &filter_snapshot, rand_u32);
                let Ok(sealed) = tls_writer.seal_app_data(&out_bytes) else {
                    return;
                };
                if client_write.write_all(&sealed).await.is_err() {
                    return;
                }
                if padder.direct_copy_active() {
                    metrics.inc_vision_direct_switches();
                    let _ = tokio::io::copy(up_read, client_write).await;
                    let _ = client_write.shutdown().await;
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

async fn relay_vless_udp(
    client: TcpStream,
    mut tls_reader: RealityTlsReader,
    mut tls_writer: RealityTlsWriter,
    mut trailing_app_data: Zeroizing<Vec<u8>>,
    target_addr: SocketAddr,
) {
    let bind_addr = if target_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let Ok(udp_sock) = UdpSocket::bind(bind_addr).await else {
        return;
    };
    if udp_sock.connect(target_addr).await.is_err() {
        return;
    }
    let udp_send = Arc::new(udp_sock);
    let udp_recv = Arc::clone(&udp_send);

    let (mut client_read, mut client_write) = client.into_split();

    let resp_hdr = encode_vless_response_header();
    let Ok(sealed_hdr) = tls_writer.seal_app_data(&resp_hdr) else {
        return;
    };
    if client_write.write_all(&sealed_hdr).await.is_err() {
        return;
    }

    let up_fut = async {
        let mut pkt_buf = Vec::from(trailing_app_data.as_slice());
        trailing_app_data.zeroize();
        let mut wire = [0u8; RELAY_CHUNK_SIZE];

        loop {
            while let Ok(Some((pkt, consumed))) = decode_udp_packet(&pkt_buf) {
                pkt_buf.drain(..consumed);
                if udp_send.send(&pkt).await.is_err() {
                    return;
                }
            }

            loop {
                match tls_reader.next_record() {
                    Ok(Some((0x17, payload))) => {
                        pkt_buf.extend_from_slice(&payload);
                        while let Ok(Some((pkt, consumed))) = decode_udp_packet(&pkt_buf) {
                            pkt_buf.drain(..consumed);
                            if udp_send.send(&pkt).await.is_err() {
                                return;
                            }
                        }
                    }
                    Ok(Some((0x15, _))) => return,
                    Ok(Some(_)) => continue,
                    Ok(None) => break,
                    Err(_) => return,
                }
            }

            match client_read.read(&mut wire).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if let Some(s) = wire.get(..n) {
                        tls_reader.push_wire_bytes(s);
                    }
                }
            }
        }
    };

    let down_fut = async {
        let mut ubuf = [0u8; RELAY_CHUNK_SIZE];
        loop {
            match udp_recv.recv(&mut ubuf).await {
                Ok(n) => {
                    let Some(slice) = ubuf.get(..n) else {
                        return;
                    };
                    let Ok(framed) = encode_udp_packet(slice) else {
                        return;
                    };
                    let Ok(sealed) = tls_writer.seal_app_data(&framed) else {
                        return;
                    };
                    if client_write.write_all(&sealed).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    };

    tokio::select! {
        () = up_fut => {}
        () = down_fut => {}
    }
}

async fn delegate_to_dest(
    mut client: TcpStream,
    buffered: BytesMut,
    client_eof: bool,
    dest_addr: SocketAddr,
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
