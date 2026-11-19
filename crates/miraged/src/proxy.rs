//! Async TCP listener, non-destructive `ClientHello` buffering, Reality
//! authentication + TLS 1.3 handshake completion, VLESS/XTLS-Vision proxying
//! with anti-SSRF egress enforcement, and transparent fallback relay to `dest`.

use core::future::Future;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use mirage_core::crypto::RealityCertTemplate;
use mirage_core::reality::{
    authenticate_client_hello, prepare_server_flight, AuthFallbackReason, AuthOutcome,
    AuthenticatedClient, ClientFlightStatus, RealityAuthParams, RealityTlsReader,
    RealityTlsSession, RealityTlsWriter, ReplayCache,
};
use mirage_core::tls_parser::{
    inspect_client_hello, parse_dest_server_flight, ClientHelloInfo, DestServerProfile,
    FallbackReason, InspectOutcome, OfferedAlpn, ServerFlightStatus,
};
use mirage_core::vision::{UnpadMode, VisionPadder, VisionTlsFilter, VisionUnpadder};
use mirage_core::vless::{
    decode_udp_packet, encode_udp_packet_into, encode_vless_response_header, parse_vless_request,
    VlessCommand, VlessFlow, VlessParseOutcome, VlessRequest,
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
use crate::mux::{relay_vless_mux, GlobalUdpTable};
use crate::net_opt::{
    relay_direct_copy, timeout_with_half_close, tune_tcp_stream, tune_udp_socket, HalfCloseSignal,
    UDP_SOCKET_BUFFER_BYTES,
};
use crate::outbound::{connect_happy_eyeballs_with_options, EgressContext};

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

/// Outbound/upstream read chunk size for padded Vision streams (fits safely below
/// the TLS 1.3 16 KiB limit after adding Vision command & padding overhead).
const RELAY_CHUNK_SIZE: usize = 8192;

/// Outbound/upstream read chunk size for unpadded streams (matches max TLS 1.3 fragment).
const PLAIN_RELAY_CHUNK_SIZE: usize = 16 * 1024;

/// Maximum buffered bytes in the VLESS-over-UDP reassembly buffer (max 64 KiB UDP datagram + 16 KiB TLS record).
const MAX_UDP_STREAM_BUFFER: usize = 65_537 + 16_384;

/// Brief grace window to gather trailing `dest` encrypted records when
/// `ServerHello` has already arrived.
const DEST_TRAILING_RECORD_WAIT: Duration = Duration::from_millis(40);

/// Maximum distinct client capability variants cached per `dest_addr`.
const MAX_DEST_PROFILE_CACHE_ENTRIES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DestProfileKey {
    has_mlkem: bool,
    has_x25519: bool,
    offered_tls13_ciphers: u8,
    offered_alpn: Option<OfferedAlpn>,
}

impl DestProfileKey {
    fn from_client_hello(ch: &ClientHelloInfo) -> Self {
        Self {
            has_mlkem: ch.key_shares.x25519_mlkem768.is_some(),
            has_x25519: ch.key_shares.x25519.is_some(),
            offered_tls13_ciphers: ch.offered_tls13_ciphers,
            offered_alpn: ch.offered_alpn,
        }
    }
}

struct CachedDestProfile {
    profile: DestServerProfile,
    expires_at: Instant,
}

/// Bounded RAM-only cache of learned `dest` TLS 1.3 profiles, avoiding a
/// per-connection TCP round-trip + 40 ms wait to `dest_addr` on authenticated handshakes.
#[derive(Default)]
struct DestProfileCache {
    entries: HashMap<DestProfileKey, CachedDestProfile>,
}

impl DestProfileCache {
    fn get_adapted(
        &mut self,
        key: DestProfileKey,
        session_id: &[u8],
        fresh_random: [u8; 32],
    ) -> Option<DestServerProfile> {
        let now = Instant::now();
        let entry = self.entries.get(&key)?;
        if entry.expires_at <= now {
            self.entries.remove(&key);
            return None;
        }
        entry.profile.adapt_for_client(session_id, fresh_random)
    }

    fn insert(&mut self, key: DestProfileKey, profile: DestServerProfile, ttl: Duration) {
        if ttl.is_zero() {
            return;
        }
        let now = Instant::now();
        let Some(expires_at) = now.checked_add(ttl) else {
            return;
        };
        if self.entries.len() >= MAX_DEST_PROFILE_CACHE_ENTRIES {
            self.entries.retain(|_, v| v.expires_at > now);
            if self.entries.len() >= MAX_DEST_PROFILE_CACHE_ENTRIES {
                if let Some(oldest_key) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, v)| v.expires_at)
                    .map(|(k, _)| *k)
                {
                    self.entries.remove(&oldest_key);
                }
            }
        }
        self.entries.insert(
            key,
            CachedDestProfile {
                profile,
                expires_at,
            },
        );
    }
}

/// Snapshot of reloadable runtime configuration and RAM-only caches.
pub struct ReloadableState {
    config: Config,
    replay_cache: Option<Arc<Mutex<ReplayCache>>>,
    dns_resolver: Option<Arc<DnsResolver>>,
    dest_profile_cache: Arc<Mutex<DestProfileCache>>,
}

/// Thread-safe, hot-reloadable runtime state swapped atomically on `SIGHUP`.
///
/// Existing connections keep their already-acquired `Config`/`ReplayCache`/`DnsResolver`
/// handles without interruption while rotated-out secrets are dropped and zeroized.
pub struct SharedRuntime {
    hmac_key: Zeroizing<[u8; 32]>,
    udp_table: Arc<GlobalUdpTable>,
    state: RwLock<Arc<ReloadableState>>,
}

impl SharedRuntime {
    /// Initializes reloadable state from an initial validated `Config`.
    pub fn new(config: Config) -> Result<Arc<Self>, DaemonError> {
        let mut hmac_key = Zeroizing::new([0u8; 32]);
        getrandom::fill(hmac_key.as_mut_slice()).map_err(|_| DaemonError::HardeningFailed)?;

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

        Ok(Arc::new(Self {
            hmac_key,
            udp_table: Arc::new(GlobalUdpTable::new()),
            state: RwLock::new(Arc::new(ReloadableState {
                config,
                replay_cache,
                dns_resolver,
                dest_profile_cache: Arc::new(Mutex::new(DestProfileCache::default())),
            })),
        }))
    }

    /// Returns a cheap `Arc` snapshot of the current active configuration and caches.
    #[must_use]
    pub fn snapshot(&self) -> Arc<ReloadableState> {
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        Arc::clone(&guard)
    }

    /// Atomically swaps in a newly validated `Config` (zeroizing dropped secrets).
    ///
    /// Preserves the active `ReplayCache` when `max_time_diff_secs` and
    /// `replay_cache_capacity` are unchanged so key rotation never clears replay history.
    pub fn reload(&self, new_config: Config) -> Result<(), DaemonError> {
        let old = self.snapshot();
        if new_config.listen_addr() != old.config.listen_addr() {
            return Err(DaemonError::ConfigInvalid);
        }

        let replay_cache = match (
            new_config.reality(),
            old.config.reality(),
            &old.replay_cache,
        ) {
            (Some(new_rc), Some(old_rc), Some(existing))
                if new_rc.max_time_diff_secs() == old_rc.max_time_diff_secs()
                    && new_rc.replay_cache_capacity() == old_rc.replay_cache_capacity() =>
            {
                Some(Arc::clone(existing))
            }
            (Some(new_rc), _, _) => Some(Arc::new(Mutex::new(ReplayCache::new(
                *self.hmac_key,
                new_rc.max_time_diff_secs(),
                new_rc.replay_cache_capacity(),
            )))),
            (None, _, _) => None,
        };

        let dns_resolver = match (new_config.vless(), old.config.vless(), &old.dns_resolver) {
            (Some(new_vc), Some(old_vc), Some(existing))
                if new_vc.dns_resolver() == old_vc.dns_resolver()
                    && new_vc.allow_system_dns() == old_vc.allow_system_dns() =>
            {
                Some(Arc::clone(existing))
            }
            (Some(new_vc), _, _) => Some(Arc::new(DnsResolver::new(
                new_vc.dns_resolver(),
                new_vc.allow_system_dns(),
            ))),
            (None, _, _) => None,
        };

        let dest_profile_cache = if !new_config.dest_profile_cache_ttl().is_zero()
            && new_config.dest_addr() == old.config.dest_addr()
            && new_config.server_names() == old.config.server_names()
        {
            Arc::clone(&old.dest_profile_cache)
        } else {
            Arc::new(Mutex::new(DestProfileCache::default()))
        };

        let next_state = Arc::new(ReloadableState {
            config: new_config,
            replay_cache,
            dns_resolver,
            dest_profile_cache,
        });

        let previous = {
            let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
            core::mem::replace(&mut *guard, next_state)
        };
        drop(previous);
        Ok(())
    }
}

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
    let runtime = SharedRuntime::new((*config).clone())?;
    run_server_with_reload(listener, runtime, metrics, shutdown).await
}

/// Runs the TCP accept loop backed by a hot-reloadable [`SharedRuntime`].
pub async fn run_server_with_reload<F>(
    listener: TcpListener,
    runtime: Arc<SharedRuntime>,
    metrics: Arc<Metrics>,
    shutdown: F,
) -> Result<(), DaemonError>
where
    F: Future<Output = ()>,
{
    let mut cert_seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(cert_seed.as_mut_slice()).map_err(|_| DaemonError::HardeningFailed)?;

    let cert_template = Arc::new(RealityCertTemplate::from_seed(*cert_seed));
    let initial_max_conns = runtime.snapshot().config.max_connections();
    let semaphore = Arc::new(Semaphore::new(initial_max_conns));
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
                let snap = runtime.snapshot();
                tokio::spawn(handle_connection_state(
                    stream,
                    snap,
                    Arc::clone(&metrics),
                    Arc::clone(&cert_template),
                    Arc::clone(&runtime.udp_table),
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

async fn handle_connection_state(
    client: TcpStream,
    state: Arc<ReloadableState>,
    metrics: Arc<Metrics>,
    cert_template: Arc<RealityCertTemplate>,
    udp_table: Arc<GlobalUdpTable>,
    permit: OwnedSemaphorePermit,
) {
    handle_connection(
        client,
        &state.config,
        metrics,
        cert_template,
        state.replay_cache.as_ref().map(Arc::clone),
        state.dns_resolver.as_ref().map(Arc::clone),
        Arc::clone(&state.dest_profile_cache),
        udp_table,
        permit,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut client: TcpStream,
    config: &Config,
    metrics: Arc<Metrics>,
    cert_template: Arc<RealityCertTemplate>,
    replay_cache: Option<Arc<Mutex<ReplayCache>>>,
    dns_resolver: Option<Arc<DnsResolver>>,
    dest_profile_cache: Arc<Mutex<DestProfileCache>>,
    udp_table: Arc<GlobalUdpTable>,
    _permit: OwnedSemaphorePermit,
) {
    tune_tcp_stream(&client, config.tcp_keepalive());

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
            config,
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
                        config,
                        &cert_template,
                        dns_resolver,
                        dest_profile_cache,
                        udp_table,
                        metrics,
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
    dns_resolver: Option<Arc<DnsResolver>>,
    dest_profile_cache: Arc<Mutex<DestProfileCache>>,
    udp_table: Arc<GlobalUdpTable>,
    metrics: Arc<Metrics>,
) {
    let ch_only = buffered_ch
        .get(..client_hello.wire_bytes_len)
        .unwrap_or(&buffered_ch);
    let pipelined_after_ch = buffered_ch
        .get(client_hello.wire_bytes_len..)
        .unwrap_or(&[]);

    let cache_ttl = config.dest_profile_cache_ttl();
    let profile_key = DestProfileKey::from_client_hello(&client_hello);
    let cached_profile = if !cache_ttl.is_zero() {
        let mut fresh_random = [0u8; 32];
        if getrandom::fill(&mut fresh_random).is_ok() {
            let mut guard = dest_profile_cache.lock().unwrap_or_else(|e| e.into_inner());
            guard.get_adapted(
                profile_key,
                client_hello.session_id.as_slice(),
                fresh_random,
            )
        } else {
            None
        }
    } else {
        None
    };

    let dest_profile = if let Some(cached) = cached_profile {
        metrics.inc_dest_profile_cache_hits();
        cached
    } else {
        let Ok(mut dest) = TcpStream::connect(config.dest_addr()).await else {
            metrics.inc_dial_dest_failed();
            return;
        };
        let _ = dest.set_nodelay(true);

        if dest.write_all(ch_only).await.is_err() {
            metrics.inc_reality_dest_profile_fallback();
            return;
        }

        let mut dest_buf = BytesMut::with_capacity(4096);
        let profile =
            read_dest_profile(&mut dest, &mut dest_buf, config.initial_read_timeout()).await;

        let Some(fresh_profile) = profile else {
            metrics.inc_reality_dest_profile_fallback();
            if !pipelined_after_ch.is_empty() && dest.write_all(pipelined_after_ch).await.is_err() {
                return;
            }
            if !dest_buf.is_empty() && client.write_all(&dest_buf).await.is_err() {
                return;
            }
            let _ = tokio::io::copy_bidirectional(&mut client, &mut dest).await;
            return;
        };

        drop(dest);

        if !cache_ttl.is_zero() {
            let mut guard = dest_profile_cache.lock().unwrap_or_else(|e| e.into_inner());
            guard.insert(profile_key, fresh_profile.clone(), cache_ttl);
        }
        fresh_profile
    };

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

    let pre_session = if !pipelined_after_ch.is_empty() {
        match prepared.pending.feed_client_bytes(pipelined_after_ch) {
            ClientFlightStatus::NeedMoreData => None,
            ClientFlightStatus::Complete {
                session,
                initial_app_data: _,
            } => Some(session),
            ClientFlightStatus::Failed => return,
        }
    } else {
        None
    };

    let session = if let Some(s) = pre_session {
        s
    } else {
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

        let Ok(Some(s)) = handshake_res else {
            return;
        };
        s
    };

    metrics.inc_reality_handshake_completed();
    drive_authenticated_session(client, *session, config, dns_resolver, udp_table, metrics).await;
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
    dns_resolver: Option<Arc<DnsResolver>>,
    udp_table: Arc<GlobalUdpTable>,
    metrics: Arc<Metrics>,
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
        &metrics,
    )
    .await
    else {
        return;
    };

    let local_socket_ip = client.local_addr().ok().map(|a| a.ip());
    let egress_ctx = EgressContext::from_config(config, vless_cfg, local_socket_ip);

    if req.command == VlessCommand::Mux {
        // XTLS-Vision flow is defined for raw TCP/UDP streams, not inner Mux framing.
        if req.flow != VlessFlow::None {
            return;
        }
        metrics.inc_vless_mux_sessions();
        relay_vless_mux(
            client,
            tls_reader,
            tls_writer,
            req.uuid.clone(),
            trailing_app_data,
            egress_ctx,
            dns_resolver,
            udp_table,
            metrics,
        )
        .await;
        return;
    }

    let targets = egress_ctx
        .resolve_and_validate(
            &req.address,
            req.port,
            req.command == VlessCommand::Tcp,
            dns_resolver.as_deref(),
            &metrics,
        )
        .await;
    if targets.is_empty() {
        return;
    }

    match req.command {
        VlessCommand::Tcp => {
            metrics.inc_vless_tcp_sessions();
            relay_vless_tcp(
                client,
                tls_reader,
                tls_writer,
                req,
                trailing_app_data,
                &targets,
                config,
                &metrics,
            )
            .await;
        }
        VlessCommand::Udp => {
            let Some(&target_addr) = targets.first() else {
                return;
            };
            metrics.inc_vless_udp_sessions();
            relay_vless_udp(
                client,
                tls_reader,
                tls_writer,
                trailing_app_data,
                target_addr,
                config.udp_idle_timeout(),
                &metrics,
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
            while let Ok(Some((inner_ct, mut payload))) = tls_reader.next_record() {
                if inner_ct == 0x15 {
                    payload.zeroize();
                    return None;
                }
                if inner_ct == 0x17 {
                    let new_len = app_buf.len().saturating_add(payload.len());
                    if new_len > MAX_VLESS_HEADER_BYTES {
                        payload.zeroize();
                        return None;
                    }
                    app_buf.extend_from_slice(&payload);
                    payload.zeroize();

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
                payload.zeroize();
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

#[derive(Clone, Copy)]
struct RelayTimeouts {
    idle: Duration,
    half_close: Duration,
}

#[allow(clippy::too_many_arguments)]
async fn relay_vless_tcp(
    client: TcpStream,
    mut tls_reader: RealityTlsReader,
    mut tls_writer: RealityTlsWriter,
    req: Box<VlessRequest>,
    mut trailing_app_data: Zeroizing<Vec<u8>>,
    targets: &[SocketAddr],
    config: &Config,
    metrics: &Metrics,
) {
    let Some(upstream) = connect_happy_eyeballs_with_options(
        targets,
        config.happy_eyeballs_delay(),
        config.tcp_keepalive(),
    )
    .await
    else {
        return;
    };

    let (mut client_read, mut client_write) = client.into_split();
    let (mut up_read, mut up_write) = upstream.into_split();

    let resp_hdr = encode_vless_response_header();
    let Ok(sealed_hdr) = tls_writer.seal_app_data(&resp_hdr) else {
        return;
    };
    if client_write.write_all(&sealed_hdr).await.is_err() {
        return;
    }

    let timeouts = RelayTimeouts {
        idle: config.tcp_idle_timeout(),
        half_close: config.half_close_timeout(),
    };
    let peer_closed = HalfCloseSignal::new();

    match req.flow {
        VlessFlow::None => {
            if !trailing_app_data.is_empty()
                && up_write.write_all(&trailing_app_data).await.is_err()
            {
                return;
            }
            trailing_app_data.zeroize();

            let up_fut = relay_plain_uplink(
                &mut client_read,
                &mut tls_reader,
                &mut up_write,
                timeouts,
                &peer_closed,
                metrics,
            );
            let down_fut = relay_plain_downlink(
                &mut up_read,
                &mut tls_writer,
                &mut client_write,
                timeouts,
                &peer_closed,
                metrics,
            );
            let _ = tokio::join!(up_fut, down_fut);
        }
        VlessFlow::Vision { .. } => {
            let tls_filter = Arc::new(Mutex::new(VisionTlsFilter::new()));
            let filter_done = Arc::new(AtomicBool::new(false));
            let uuid = req.uuid.clone();
            let up_fut = relay_vision_uplink(
                &mut client_read,
                tls_reader,
                &mut up_write,
                uuid.clone(),
                trailing_app_data,
                Arc::clone(&tls_filter),
                Arc::clone(&filter_done),
                timeouts,
                &peer_closed,
                metrics,
            );
            let down_fut = relay_vision_downlink(
                &mut up_read,
                tls_writer,
                &mut client_write,
                uuid,
                tls_filter,
                filter_done,
                timeouts,
                &peer_closed,
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
    timeouts: RelayTimeouts,
    peer_closed: &HalfCloseSignal,
    metrics: &Metrics,
) {
    let mut wire = [0u8; PLAIN_RELAY_CHUNK_SIZE];
    let mut payload = Zeroizing::new(Vec::with_capacity(PLAIN_RELAY_CHUNK_SIZE + 32));
    loop {
        match tls_reader.next_record_into(&mut payload) {
            Ok(Some(0x17)) => {
                let write_err = !payload.is_empty() && up_write.write_all(&payload).await.is_err();
                payload.zeroize();
                if write_err {
                    break;
                }
                continue;
            }
            Ok(Some(0x15)) => {
                payload.zeroize();
                let _ = up_write.shutdown().await;
                break;
            }
            Ok(Some(_)) => {
                payload.zeroize();
                continue;
            }
            Ok(None) => {}
            Err(_) => break,
        }

        match timeout_with_half_close(
            timeouts.idle,
            timeouts.half_close,
            peer_closed,
            client_read.read(&mut wire),
        )
        .await
        {
            Ok(Ok(0) | Err(_)) => {
                let _ = up_write.shutdown().await;
                break;
            }
            Err(_) => {
                metrics.inc_idle_timeouts();
                let _ = up_write.shutdown().await;
                break;
            }
            Ok(Ok(n)) => {
                if let Some(s) = wire.get(..n) {
                    tls_reader.push_wire_bytes(s);
                }
            }
        }
    }
    peer_closed.mark_closed();
}

async fn relay_plain_downlink(
    up_read: &mut OwnedReadHalf,
    tls_writer: &mut RealityTlsWriter,
    client_write: &mut OwnedWriteHalf,
    timeouts: RelayTimeouts,
    peer_closed: &HalfCloseSignal,
    metrics: &Metrics,
) {
    let mut buf = [0u8; PLAIN_RELAY_CHUNK_SIZE];
    let mut record_buf = Zeroizing::new(Vec::with_capacity(PLAIN_RELAY_CHUNK_SIZE + 32));
    loop {
        match timeout_with_half_close(
            timeouts.idle,
            timeouts.half_close,
            peer_closed,
            up_read.read(&mut buf),
        )
        .await
        {
            Ok(Ok(0)) => {
                if tls_writer.seal_app_data_into(&[], &mut record_buf).is_ok() {
                    let _ = client_write.write_all(&record_buf).await;
                }
                let _ = client_write.shutdown().await;
                break;
            }
            Ok(Ok(n)) => {
                let Some(slice) = buf.get(..n) else {
                    break;
                };
                if tls_writer
                    .seal_app_data_into(slice, &mut record_buf)
                    .is_err()
                {
                    break;
                }
                if client_write.write_all(&record_buf).await.is_err() {
                    break;
                }
            }
            Err(_) => {
                metrics.inc_idle_timeouts();
                break;
            }
            Ok(Err(_)) => break,
        }
    }
    peer_closed.mark_closed();
}

fn inspect_vision_filter(
    payload: &[u8],
    tls_filter: &Mutex<VisionTlsFilter>,
    filter_done: &AtomicBool,
) {
    if filter_done.load(Ordering::Acquire) {
        return;
    }
    let mut f = tls_filter.lock().unwrap_or_else(|e| e.into_inner());
    f.inspect(payload);
    if f.is_finished() {
        filter_done.store(true, Ordering::Release);
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_vision_uplink(
    client_read: &mut OwnedReadHalf,
    mut tls_reader: RealityTlsReader,
    up_write: &mut OwnedWriteHalf,
    uuid: mirage_core::vless::VlessUuid,
    mut trailing_app_data: Zeroizing<Vec<u8>>,
    tls_filter: Arc<Mutex<VisionTlsFilter>>,
    filter_done: Arc<AtomicBool>,
    timeouts: RelayTimeouts,
    peer_closed: &HalfCloseSignal,
    metrics: &Metrics,
) {
    let mut unpadder = VisionUnpadder::new(uuid);

    if !trailing_app_data.is_empty() {
        let out = unpadder.feed(&trailing_app_data);
        trailing_app_data.zeroize();
        if !out.payload.is_empty() {
            inspect_vision_filter(&out.payload, &tls_filter, &filter_done);
            if up_write.write_all(&out.payload).await.is_err() {
                peer_closed.mark_closed();
                return;
            }
        }
        if out.mode == UnpadMode::DirectCopy {
            if !out.direct_trailing.is_empty()
                && up_write.write_all(&out.direct_trailing).await.is_err()
            {
                peer_closed.mark_closed();
                return;
            }
            let rem_raw = tls_reader.into_remaining_wire_bytes();
            if !rem_raw.is_empty() && up_write.write_all(&rem_raw).await.is_err() {
                peer_closed.mark_closed();
                return;
            }
            let _ = relay_direct_copy(
                client_read,
                up_write,
                timeouts.idle,
                timeouts.half_close,
                peer_closed,
                metrics,
            )
            .await;
            let _ = up_write.shutdown().await;
            peer_closed.mark_closed();
            return;
        }
    }

    let mut wire = [0u8; RELAY_CHUNK_SIZE];
    let mut payload = Zeroizing::new(Vec::with_capacity(PLAIN_RELAY_CHUNK_SIZE + 32));
    loop {
        loop {
            match tls_reader.next_record_into(&mut payload) {
                Ok(Some(0x17)) => {
                    let mut out = unpadder.feed(&payload);
                    payload.zeroize();
                    if !out.payload.is_empty() {
                        inspect_vision_filter(&out.payload, &tls_filter, &filter_done);
                        let err = up_write.write_all(&out.payload).await.is_err();
                        out.payload.zeroize();
                        if err {
                            out.direct_trailing.zeroize();
                            peer_closed.mark_closed();
                            return;
                        }
                    }
                    if out.mode == UnpadMode::DirectCopy {
                        if !out.direct_trailing.is_empty() {
                            let err = up_write.write_all(&out.direct_trailing).await.is_err();
                            out.direct_trailing.zeroize();
                            if err {
                                peer_closed.mark_closed();
                                return;
                            }
                        }
                        let rem_raw = tls_reader.into_remaining_wire_bytes();
                        if !rem_raw.is_empty() && up_write.write_all(&rem_raw).await.is_err() {
                            peer_closed.mark_closed();
                            return;
                        }
                        let _ = relay_direct_copy(
                            client_read,
                            up_write,
                            timeouts.idle,
                            timeouts.half_close,
                            peer_closed,
                            metrics,
                        )
                        .await;
                        let _ = up_write.shutdown().await;
                        peer_closed.mark_closed();
                        return;
                    }
                }
                Ok(Some(0x15)) => {
                    payload.zeroize();
                    let _ = up_write.shutdown().await;
                    peer_closed.mark_closed();
                    return;
                }
                Ok(Some(_)) => {
                    payload.zeroize();
                    continue;
                }
                Ok(None) => break,
                Err(_) => {
                    peer_closed.mark_closed();
                    return;
                }
            }
        }

        match timeout_with_half_close(
            timeouts.idle,
            timeouts.half_close,
            peer_closed,
            client_read.read(&mut wire),
        )
        .await
        {
            Ok(Ok(0) | Err(_)) => {
                let _ = up_write.shutdown().await;
                peer_closed.mark_closed();
                return;
            }
            Err(_) => {
                metrics.inc_idle_timeouts();
                let _ = up_write.shutdown().await;
                peer_closed.mark_closed();
                return;
            }
            Ok(Ok(n)) => {
                if let Some(s) = wire.get(..n) {
                    tls_reader.push_wire_bytes(s);
                }
            }
        }
    }
}

fn split_leading_tls_record_len(buf: &[u8]) -> Option<usize> {
    let hdr = buf.get(..5)?;
    let ct = *hdr.first()?;
    let ver_maj = *hdr.get(1)?;
    let ver_min = *hdr.get(2)?;
    if !matches!(ct, 0x14..=0x17) || ver_maj != 0x03 || !matches!(ver_min, 0x00..=0x04) {
        return None;
    }
    let rec_len = usize::from(u16::from_be_bytes([*hdr.get(3)?, *hdr.get(4)?]));
    let total = 5usize.checked_add(rec_len)?;
    if rec_len == 0 || total >= buf.len() {
        return None;
    }
    Some(total)
}

#[allow(clippy::too_many_arguments)]
async fn relay_vision_downlink(
    up_read: &mut OwnedReadHalf,
    mut tls_writer: RealityTlsWriter,
    client_write: &mut OwnedWriteHalf,
    uuid: mirage_core::vless::VlessUuid,
    tls_filter: Arc<Mutex<VisionTlsFilter>>,
    filter_done: Arc<AtomicBool>,
    timeouts: RelayTimeouts,
    peer_closed: &HalfCloseSignal,
    metrics: &Metrics,
) {
    let mut padder = VisionPadder::new(uuid);
    let mut buf = [0u8; RELAY_CHUNK_SIZE];
    let mut big_buf = [0u8; PLAIN_RELAY_CHUNK_SIZE];
    let mut record_buf = Zeroizing::new(Vec::with_capacity(PLAIN_RELAY_CHUNK_SIZE + 32));

    loop {
        let target_buf = if padder.is_padding() {
            &mut buf[..]
        } else {
            &mut big_buf[..]
        };

        match timeout_with_half_close(
            timeouts.idle,
            timeouts.half_close,
            peer_closed,
            up_read.read(target_buf),
        )
        .await
        {
            Ok(Ok(0)) => {
                let _ = client_write.shutdown().await;
                peer_closed.mark_closed();
                return;
            }
            Ok(Ok(n)) => {
                let Some(slice) = target_buf.get(..n) else {
                    peer_closed.mark_closed();
                    return;
                };
                if padder.is_padding() {
                    let mut rem = slice;
                    while !rem.is_empty() && padder.is_padding() {
                        // Split coalesced non-ApplicationData TLS records (e.g. ServerHello
                        // followed immediately by 0x17 encrypted flight) so Vision detects
                        // inner TLS 1.3 `0x17` boundaries cleanly.
                        let piece_len = if rem.first() != Some(&0x17) {
                            split_leading_tls_record_len(rem).unwrap_or(rem.len())
                        } else {
                            rem.len()
                        };
                        let Some(piece) = rem.get(..piece_len) else {
                            peer_closed.mark_closed();
                            return;
                        };
                        rem = rem.get(piece_len..).unwrap_or(&[]);

                        let filter_snapshot = {
                            let mut f = tls_filter.lock().unwrap_or_else(|e| e.into_inner());
                            f.inspect(piece);
                            if f.is_finished() {
                                filter_done.store(true, Ordering::Release);
                            }
                            f.clone()
                        };
                        let mut rand_bytes = [0u8; 4];
                        if getrandom::fill(&mut rand_bytes).is_err() {
                            peer_closed.mark_closed();
                            return;
                        }
                        let rand_u32 = u32::from_be_bytes(rand_bytes);
                        let wrapped = padder.wrap_outbound(piece, &filter_snapshot, rand_u32);
                        let switched_direct = padder.direct_copy_active();
                        if tls_writer
                            .seal_app_data_into(&wrapped, &mut record_buf)
                            .is_err()
                        {
                            peer_closed.mark_closed();
                            return;
                        }
                        if client_write.write_all(&record_buf).await.is_err() {
                            peer_closed.mark_closed();
                            return;
                        }
                        if switched_direct {
                            metrics.inc_vision_direct_switches();
                            if !rem.is_empty() && client_write.write_all(rem).await.is_err() {
                                peer_closed.mark_closed();
                                return;
                            }
                            let _ = relay_direct_copy(
                                up_read,
                                client_write,
                                timeouts.idle,
                                timeouts.half_close,
                                peer_closed,
                                metrics,
                            )
                            .await;
                            let _ = client_write.shutdown().await;
                            peer_closed.mark_closed();
                            return;
                        }
                    }
                    if !rem.is_empty() {
                        if tls_writer.seal_app_data_into(rem, &mut record_buf).is_err() {
                            peer_closed.mark_closed();
                            return;
                        }
                        if client_write.write_all(&record_buf).await.is_err() {
                            peer_closed.mark_closed();
                            return;
                        }
                    }
                } else {
                    if tls_writer
                        .seal_app_data_into(slice, &mut record_buf)
                        .is_err()
                    {
                        peer_closed.mark_closed();
                        return;
                    }
                    if client_write.write_all(&record_buf).await.is_err() {
                        peer_closed.mark_closed();
                        return;
                    }
                }
            }
            Err(_) => {
                metrics.inc_idle_timeouts();
                peer_closed.mark_closed();
                return;
            }
            Ok(Err(_)) => {
                peer_closed.mark_closed();
                return;
            }
        }
    }
}

async fn relay_vless_udp(
    client: TcpStream,
    mut tls_reader: RealityTlsReader,
    mut tls_writer: RealityTlsWriter,
    mut trailing_app_data: Zeroizing<Vec<u8>>,
    target_addr: SocketAddr,
    udp_idle_timeout: Duration,
    metrics: &Metrics,
) {
    let bind_addr = if target_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let Ok(udp_sock) = UdpSocket::bind(bind_addr).await else {
        return;
    };
    tune_udp_socket(&udp_sock, UDP_SOCKET_BUFFER_BYTES);
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
        let mut pkt_buf = Zeroizing::new(Vec::from(trailing_app_data.as_slice()));
        let mut pkt_offset = 0usize;
        trailing_app_data.zeroize();
        let mut wire = [0u8; RELAY_CHUNK_SIZE];
        let mut payload = Zeroizing::new(Vec::with_capacity(PLAIN_RELAY_CHUNK_SIZE + 32));

        loop {
            while let Some(avail) = pkt_buf.get(pkt_offset..) {
                match decode_udp_packet(avail) {
                    Ok(Some((pkt, consumed))) => {
                        pkt_offset = pkt_offset.saturating_add(consumed);
                        if udp_send.send(&pkt).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return,
                }
            }
            if pkt_offset >= pkt_buf.len() {
                pkt_buf.clear();
                pkt_offset = 0;
            } else if pkt_offset >= 16_384 {
                pkt_buf.drain(..pkt_offset);
                pkt_offset = 0;
            }

            loop {
                match tls_reader.next_record_into(&mut payload) {
                    Ok(Some(0x17)) => {
                        let unread_len = pkt_buf.len().saturating_sub(pkt_offset);
                        if unread_len.saturating_add(payload.len()) > MAX_UDP_STREAM_BUFFER {
                            payload.zeroize();
                            return;
                        }
                        pkt_buf.extend_from_slice(&payload);
                        payload.zeroize();
                        while let Some(avail) = pkt_buf.get(pkt_offset..) {
                            match decode_udp_packet(avail) {
                                Ok(Some((mut pkt, consumed))) => {
                                    pkt_offset = pkt_offset.saturating_add(consumed);
                                    let send_err = udp_send.send(&pkt).await.is_err();
                                    pkt.zeroize();
                                    if send_err {
                                        return;
                                    }
                                }
                                Ok(None) => break,
                                Err(_) => return,
                            }
                        }
                        if pkt_offset >= pkt_buf.len() {
                            pkt_buf.clear();
                            pkt_offset = 0;
                        } else if pkt_offset >= 16_384 {
                            pkt_buf.drain(..pkt_offset);
                            pkt_offset = 0;
                        }
                    }
                    Ok(Some(0x15)) => {
                        payload.zeroize();
                        return;
                    }
                    Ok(Some(_)) => {
                        payload.zeroize();
                        continue;
                    }
                    Ok(None) => break,
                    Err(_) => return,
                }
            }

            match tokio::time::timeout(udp_idle_timeout, client_read.read(&mut wire)).await {
                Ok(Ok(0) | Err(_)) => return,
                Err(_) => {
                    metrics.inc_idle_timeouts();
                    return;
                }
                Ok(Ok(n)) => {
                    if let Some(s) = wire.get(..n) {
                        tls_reader.push_wire_bytes(s);
                    }
                }
            }
        }
    };

    let down_fut = async {
        let mut ubuf = [0u8; PLAIN_RELAY_CHUNK_SIZE - 2];
        let mut framed = Zeroizing::new(Vec::with_capacity(PLAIN_RELAY_CHUNK_SIZE));
        let mut batch_buf = Zeroizing::new(Vec::with_capacity(PLAIN_RELAY_CHUNK_SIZE));
        let mut record_buf = Zeroizing::new(Vec::with_capacity(PLAIN_RELAY_CHUNK_SIZE + 64));
        loop {
            match tokio::time::timeout(udp_idle_timeout, udp_recv.recv(&mut ubuf)).await {
                Ok(Ok(n)) => {
                    let Some(slice) = ubuf.get(..n) else {
                        return;
                    };
                    if encode_udp_packet_into(slice, &mut framed).is_err() {
                        return;
                    }
                    batch_buf.clear();
                    batch_buf.extend_from_slice(&framed);

                    // Coalesce additional already-queued UDP datagrams into the same
                    // 16 KiB TLS 1.3 record to cut AEAD and syscall overhead under burst load.
                    while batch_buf.len() < PLAIN_RELAY_CHUNK_SIZE {
                        match udp_recv.try_recv(&mut ubuf) {
                            Ok(next_n) => {
                                let Some(next_slice) = ubuf.get(..next_n) else {
                                    return;
                                };
                                let next_framed_len = next_n.saturating_add(2);
                                if batch_buf.len().saturating_add(next_framed_len)
                                    > PLAIN_RELAY_CHUNK_SIZE
                                {
                                    if tls_writer
                                        .seal_app_data_into(&batch_buf, &mut record_buf)
                                        .is_err()
                                    {
                                        return;
                                    }
                                    if client_write.write_all(&record_buf).await.is_err() {
                                        return;
                                    }
                                    batch_buf.clear();
                                }
                                if encode_udp_packet_into(next_slice, &mut framed).is_err() {
                                    return;
                                }
                                batch_buf.extend_from_slice(&framed);
                            }
                            Err(_) => break,
                        }
                    }

                    if !batch_buf.is_empty() {
                        if tls_writer
                            .seal_app_data_into(&batch_buf, &mut record_buf)
                            .is_err()
                        {
                            return;
                        }
                        if client_write.write_all(&record_buf).await.is_err() {
                            return;
                        }
                    }
                }
                Err(_) => {
                    metrics.inc_idle_timeouts();
                    return;
                }
                Ok(Err(_)) => return,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RealityConfig;
    use mirage_core::crypto::{ShortId, StaticPrivateKey};
    use std::net::{IpAddr, Ipv4Addr};

    fn test_config(
        listen_port: u16,
        key_seed: u8,
        short_id_seed: u8,
        max_time_diff_secs: u64,
        replay_cache_capacity: usize,
    ) -> Result<Config, DaemonError> {
        let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let cfg = Config::new(
            listen,
            dest,
            vec!["example.com".to_owned()],
            16 * 1024,
            5000,
            64,
            false,
        )?;
        let key = StaticPrivateKey::from_bytes([key_seed; 32]);
        let short_id = ShortId::from_bytes([short_id_seed; 8]);
        let reality = RealityConfig::new(
            vec![key],
            vec![short_id],
            max_time_diff_secs,
            replay_cache_capacity,
            None,
            None,
        )?;
        cfg.with_reality(reality)
    }

    #[test]
    fn shared_runtime_hot_reload_swaps_keys_and_preserves_replay_cache() -> Result<(), DaemonError>
    {
        let initial = test_config(8443, 0x11, 0xAA, 120, 1024)?;
        let runtime = SharedRuntime::new(initial)?;
        let snap1 = runtime.snapshot();
        let cache1 = snap1
            .replay_cache
            .as_ref()
            .ok_or(DaemonError::ConfigInvalid)?;

        // Rotate private key & short_id while keeping replay window/capacity identical.
        let rotated = test_config(8443, 0x22, 0xBB, 120, 1024)?;
        runtime.reload(rotated)?;

        let snap2 = runtime.snapshot();
        let cache2 = snap2
            .replay_cache
            .as_ref()
            .ok_or(DaemonError::ConfigInvalid)?;

        assert!(Arc::ptr_eq(cache1, cache2));
        let key2 = snap2
            .config
            .reality()
            .and_then(|r| r.private_keys().first())
            .ok_or(DaemonError::ConfigInvalid)?;
        assert_eq!(
            key2.to_hex(),
            StaticPrivateKey::from_bytes([0x22; 32]).to_hex()
        );

        // Changing replay cache window/capacity allocates a fresh cache.
        let resized = test_config(8443, 0x33, 0xCC, 180, 2048)?;
        runtime.reload(resized)?;
        let snap3 = runtime.snapshot();
        let cache3 = snap3
            .replay_cache
            .as_ref()
            .ok_or(DaemonError::ConfigInvalid)?;
        assert!(!Arc::ptr_eq(cache2, cache3));

        // Changing listen_addr at runtime must fail-closed and keep snap3 intact.
        let changed_listen = test_config(9443, 0x44, 0xDD, 180, 2048)?;
        assert!(runtime.reload(changed_listen).is_err());
        assert_eq!(runtime.snapshot().config.listen_addr().port(), 8443);

        Ok(())
    }
}
