//! Async TCP listener, non-destructive `ClientHello` buffering, Reality
//! authentication + TLS 1.3 handshake completion, VLESS/XTLS-Vision proxying
//! with anti-SSRF egress enforcement, and transparent fallback relay to `dest`.

use core::future::Future;
use core::net::{IpAddr, SocketAddr};
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use mirage_core::crypto::RealityCertTemplate;
use mirage_core::egress::TransportProtocol;
use mirage_core::reality::{
    prepare_server_flight, verify_client_hello_credentials, AuthFallbackReason, AuthOutcome,
    AuthenticatedClient, ClientFlightStatus, RealityAuthParams, RealityTlsReader,
    RealityTlsSession, RealityTlsWriter, ReplayCache, ReplayOutcome,
};
use mirage_core::tls_parser::{
    inspect_client_hello, parse_dest_server_flight, ClientHelloInfo, DestServerProfile,
    FallbackReason, InspectOutcome, OfferedAlpn, ServerFlightStatus, Tls13CipherSuiteId,
};
use mirage_core::vision::{UnpadMode, VisionPadder, VisionTlsFilter, VisionUnpadder};
use mirage_core::vless::{
    decode_udp_packet, encode_udp_packet_into, encode_vless_response_header, parse_vless_request,
    VlessCommand, VlessFlow, VlessParseOutcome, VlessRequest, VlessUuid,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use zeroize::{Zeroize, Zeroizing};

use crate::config::{Config, VlessConfig};
use crate::dns::DnsResolver;
use crate::error::DaemonError;
use crate::metrics::Metrics;
use crate::mux::{relay_vless_mux, GlobalUdpTable, MuxTunnelArgs};
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

/// Maximum plaintext bytes allowed in a single sealed TLS 1.3 ApplicationData record.
const MAX_TLS_RECORD_FRAGMENT: usize = 16_384;

/// Maximum single UDP datagram payload bytes (`65_507`).
const MAX_UDP_DATAGRAM_BYTES: usize = 65_507;

/// Maximum buffered bytes in the VLESS-over-UDP reassembly buffer (max 64 KiB UDP datagram + 16 KiB TLS record).
const MAX_UDP_STREAM_BUFFER: usize = 65_537 + 16_384;

/// Grace window to gather trailing `dest` encrypted records (EncryptedExtensions, Cert,
/// CertificateVerify, Finished, NewSessionTicket) after `ServerHello` has arrived.
const DEST_TRAILING_RECORD_WAIT: Duration = Duration::from_millis(200);

/// Connect timeout when dialing `dest_addr` for profile learning or fallback delegation.
const OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Write timeout applied to client/upstream socket writes so stalled peers cannot wedge tasks.
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum concurrent connections permitted per canonicalized source IP address.
const MAX_CONNS_PER_IP: usize = 256;

/// Maximum time spent draining active connections during graceful shutdown.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum distinct client capability variants cached per `dest_addr`.
const MAX_DEST_PROFILE_CACHE_ENTRIES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DestProfileKey {
    sni: String,
    has_mlkem: bool,
    has_x25519: bool,
    offered_tls13_ciphers: u8,
    preferred_tls13_cipher: Option<Tls13CipherSuiteId>,
    offered_alpn: Option<OfferedAlpn>,
}

impl DestProfileKey {
    fn from_client_hello(ch: &ClientHelloInfo) -> Self {
        Self {
            sni: ch
                .sni
                .as_ref()
                .map_or("", |s| s.as_str())
                .to_ascii_lowercase(),
            has_mlkem: ch.key_shares.x25519_mlkem768.is_some(),
            has_x25519: ch.key_shares.x25519.is_some(),
            offered_tls13_ciphers: ch.offered_tls13_ciphers,
            preferred_tls13_cipher: ch.preferred_tls13_cipher,
            offered_alpn: ch.offered_alpn,
        }
    }
}

struct CachedDestProfile {
    profile: DestServerProfile,
    expires_at: Instant,
}

/// Bounded RAM-only cache of learned `dest` TLS 1.3 profiles, avoiding a
/// per-connection TCP round-trip + wait to `dest_addr` on authenticated handshakes.
#[derive(Default)]
struct DestProfileCache {
    entries: HashMap<DestProfileKey, CachedDestProfile>,
}

impl DestProfileCache {
    fn get_adapted(
        &mut self,
        key: &DestProfileKey,
        session_id: &[u8],
        fresh_random: [u8; 32],
    ) -> Option<DestServerProfile> {
        let now = Instant::now();
        let entry = self.entries.get(key)?;
        if entry.expires_at <= now {
            self.entries.remove(key);
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
        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_DEST_PROFILE_CACHE_ENTRIES
        {
            self.entries.retain(|_, v| v.expires_at > now);
            if self.entries.len() >= MAX_DEST_PROFILE_CACHE_ENTRIES {
                if let Some(oldest_key) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, v)| v.expires_at)
                    .map(|(k, _)| k.clone())
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
        getrandom::fill(hmac_key.as_mut_slice()).map_err(|_| DaemonError::EntropyFailed)?;

        let replay_cache = config.reality().map(|rc| {
            Arc::new(Mutex::new(ReplayCache::new(
                *hmac_key,
                rc.max_time_diff_secs().saturating_mul(2),
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
    /// Rejects changes to listener/process-wide parameters that cannot be altered
    /// without restarting the listener, and preserves/migrates active `ReplayCache`
    /// entries so key rotation or window resizing never clears replay history.
    pub fn reload(&self, new_config: Config) -> Result<(), DaemonError> {
        let old = self.snapshot();
        if new_config.listen_addr() != old.config.listen_addr()
            || new_config.max_connections() != old.config.max_connections()
            || new_config.listen_backlog() != old.config.listen_backlog()
            || new_config.unsafe_debug_logging() != old.config.unsafe_debug_logging()
        {
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
            (Some(new_rc), _, Some(existing)) => {
                let mut next_cache = ReplayCache::new(
                    *self.hmac_key,
                    new_rc.max_time_diff_secs().saturating_mul(2),
                    new_rc.replay_cache_capacity(),
                );
                let now_unix_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                {
                    let mut old_guard = existing.lock().unwrap_or_else(|e| e.into_inner());
                    old_guard.migrate_non_expired_into(&mut next_cache, now_unix_secs);
                }
                Some(Arc::new(Mutex::new(next_cache)))
            }
            (Some(new_rc), _, None) => Some(Arc::new(Mutex::new(ReplayCache::new(
                *self.hmac_key,
                new_rc.max_time_diff_secs().saturating_mul(2),
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

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

#[derive(Default)]
struct PerIpConnectionLimiter {
    counts: Mutex<HashMap<IpAddr, usize>>,
}

impl PerIpConnectionLimiter {
    fn try_acquire(self: &Arc<Self>, peer_ip: IpAddr, limit: usize) -> Option<IpPermit> {
        let key = canonical_ip(peer_ip);
        let mut guard = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let current = guard.get(&key).copied().unwrap_or(0);
        if current >= limit {
            return None;
        }
        guard.insert(key, current.saturating_add(1));
        Some(IpPermit {
            limiter: Arc::clone(self),
            key,
        })
    }
}

struct IpPermit {
    limiter: Arc<PerIpConnectionLimiter>,
    key: IpAddr,
}

impl Drop for IpPermit {
    fn drop(&mut self) {
        let mut guard = self
            .limiter
            .counts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(cnt) = guard.get_mut(&self.key) {
            *cnt = cnt.saturating_sub(1);
            if *cnt == 0 {
                guard.remove(&self.key);
            }
        }
    }
}

struct ConnectionContext {
    state: Arc<ReloadableState>,
    metrics: Arc<Metrics>,
    cert_template: Arc<RealityCertTemplate>,
    udp_table: Arc<GlobalUdpTable>,
}

async fn write_all_with_timeout(
    writer: &mut OwnedWriteHalf,
    data: &[u8],
    timeout_dur: Duration,
) -> bool {
    matches!(
        tokio::time::timeout(timeout_dur, writer.write_all(data)).await,
        Ok(Ok(()))
    )
}

async fn write_stream_with_timeout(
    stream: &mut TcpStream,
    data: &[u8],
    timeout_dur: Duration,
) -> bool {
    matches!(
        tokio::time::timeout(timeout_dur, stream.write_all(data)).await,
        Ok(Ok(()))
    )
}

async fn seal_and_write_chunked(
    tls_writer: &mut RealityTlsWriter,
    client_write: &mut OwnedWriteHalf,
    data: &[u8],
    record_buf: &mut Zeroizing<Vec<u8>>,
) -> bool {
    for chunk in data.chunks(MAX_TLS_RECORD_FRAGMENT) {
        if tls_writer.seal_app_data_into(chunk, record_buf).is_err() {
            record_buf.zeroize();
            return false;
        }
        let ok = write_all_with_timeout(client_write, record_buf, CLIENT_WRITE_TIMEOUT).await;
        record_buf.zeroize();
        if !ok {
            return false;
        }
    }
    true
}

async fn relay_tcp_pair_with_timeouts(
    client: TcpStream,
    dest: TcpStream,
    timeouts: RelayTimeouts,
    metrics: &Metrics,
) {
    let (mut cr, mut cw) = client.into_split();
    let (mut dr, mut dw) = dest.into_split();
    let peer_closed = HalfCloseSignal::new();

    let c2d = async {
        let _ = relay_direct_copy(
            &mut cr,
            &mut dw,
            timeouts.idle,
            timeouts.half_close,
            &peer_closed,
            metrics,
        )
        .await;
        let _ = tokio::time::timeout(timeouts.half_close, dw.shutdown()).await;
        peer_closed.mark_closed();
    };
    let d2c = async {
        let _ = relay_direct_copy(
            &mut dr,
            &mut cw,
            timeouts.idle,
            timeouts.half_close,
            &peer_closed,
            metrics,
        )
        .await;
        let _ = tokio::time::timeout(timeouts.half_close, cw.shutdown()).await;
        peer_closed.mark_closed();
    };
    let _ = tokio::join!(c2d, d2c);
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
    getrandom::fill(cert_seed.as_mut_slice()).map_err(|_| DaemonError::EntropyFailed)?;

    let cert_template = Arc::new(RealityCertTemplate::from_seed(*cert_seed));
    let initial_max_conns = runtime.snapshot().config.max_connections();
    let per_ip_limit = (initial_max_conns >> 2)
        .clamp(64, MAX_CONNS_PER_IP)
        .min(initial_max_conns);
    let semaphore = Arc::new(Semaphore::new(initial_max_conns));
    let ip_limiter = Arc::new(PerIpConnectionLimiter::default());
    let mut conns = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        while conns.try_join_next().is_some() {}

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
            () = &mut shutdown => {
                drop(permit);
                break;
            }
            res = listener.accept() => res,
        };

        match accept_res {
            Ok((stream, peer_addr)) => {
                let Some(ip_permit) = ip_limiter.try_acquire(peer_addr.ip(), per_ip_limit) else {
                    drop(permit);
                    drop(stream);
                    continue;
                };
                metrics.inc_accepted();
                let ctx = ConnectionContext {
                    state: runtime.snapshot(),
                    metrics: Arc::clone(&metrics),
                    cert_template: Arc::clone(&cert_template),
                    udp_table: Arc::clone(&runtime.udp_table),
                };
                conns.spawn(handle_connection(stream, ctx, permit, ip_permit));
            }
            Err(_) => {
                drop(permit);
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
            }
        }
    }

    let _ = tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, async {
        while conns.join_next().await.is_some() {}
    })
    .await;
    conns.abort_all();

    Ok(())
}

async fn handle_connection(
    mut client: TcpStream,
    ctx: ConnectionContext,
    _permit: OwnedSemaphorePermit,
    _ip_permit: IpPermit,
) {
    let config = &ctx.state.config;
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
            &ctx.metrics,
        ),
    )
    .await;

    if read_result.is_err() {
        ctx.metrics.inc_timeout_delegated();
    } else if client_io_err {
        return;
    } else if !client_eof {
        if let (Some(ch), Some(rc), Some(cache)) = (
            matched_hello,
            config.reality(),
            ctx.state.replay_cache.as_ref(),
        ) {
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
            // Verify HMAC/X25519 credentials completely lock-free BEFORE acquiring
            // the ReplayCache mutex so unauthenticated floods never contend on it.
            let auth_outcome = match verify_client_hello_credentials(&ch, &params, now_unix_secs) {
                Ok(verified) => {
                    let outcome = {
                        let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
                        guard.check_and_insert_with_expiry(
                            &ch.random,
                            now_unix_secs,
                            verified.replay_expires_at,
                        )
                    };
                    match outcome {
                        ReplayOutcome::Accepted => {
                            AuthOutcome::Authenticated(Box::new(verified.client))
                        }
                        ReplayOutcome::Replayed => {
                            AuthOutcome::Fallback(AuthFallbackReason::Replayed)
                        }
                        ReplayOutcome::Saturated => {
                            AuthOutcome::Fallback(AuthFallbackReason::ReplayCacheSaturated)
                        }
                    }
                }
                Err(reason) => AuthOutcome::Fallback(reason),
            };

            match auth_outcome {
                AuthOutcome::Authenticated(auth) => {
                    ctx.metrics.inc_reality_authenticated();
                    complete_reality_handshake(client, buf, *ch, *auth, ctx).await;
                    return;
                }
                AuthOutcome::Fallback(
                    AuthFallbackReason::Replayed | AuthFallbackReason::ReplayCacheSaturated,
                ) => {
                    ctx.metrics.inc_reality_replayed_or_saturated();
                }
                AuthOutcome::Fallback(_) => {
                    ctx.metrics.inc_reality_auth_failed();
                }
            }
        }
    }

    ctx.metrics.inc_delegated_fallback();
    let timeouts = RelayTimeouts {
        idle: config.tcp_idle_timeout(),
        half_close: config.half_close_timeout(),
    };
    delegate_to_dest(
        client,
        buf,
        client_eof,
        config.dest_addr(),
        config.tcp_keepalive(),
        timeouts,
        &ctx.metrics,
    )
    .await;
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
    ctx: ConnectionContext,
) {
    let config = &ctx.state.config;
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
            let mut guard = ctx
                .state
                .dest_profile_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            guard.get_adapted(
                &profile_key,
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
        ctx.metrics.inc_dest_profile_cache_hits();
        cached
    } else {
        let Ok(Ok(mut dest)) = tokio::time::timeout(
            OUTBOUND_CONNECT_TIMEOUT,
            TcpStream::connect(config.dest_addr()),
        )
        .await
        else {
            ctx.metrics.inc_dial_dest_failed();
            return;
        };
        tune_tcp_stream(&dest, config.tcp_keepalive());

        if !write_stream_with_timeout(&mut dest, ch_only, CLIENT_WRITE_TIMEOUT).await {
            ctx.metrics.inc_reality_dest_profile_fallback();
            return;
        }

        let mut dest_buf = BytesMut::with_capacity(4096);
        let (profile, is_complete) =
            read_dest_profile(&mut dest, &mut dest_buf, config.initial_read_timeout()).await;

        let Some(fresh_profile) = profile else {
            ctx.metrics.inc_reality_dest_profile_fallback();
            if !pipelined_after_ch.is_empty()
                && !write_stream_with_timeout(&mut dest, pipelined_after_ch, CLIENT_WRITE_TIMEOUT)
                    .await
            {
                return;
            }
            if !dest_buf.is_empty()
                && !write_stream_with_timeout(&mut client, &dest_buf, CLIENT_WRITE_TIMEOUT).await
            {
                return;
            }
            let timeouts = RelayTimeouts {
                idle: config.tcp_idle_timeout(),
                half_close: config.half_close_timeout(),
            };
            relay_tcp_pair_with_timeouts(client, dest, timeouts, &ctx.metrics).await;
            return;
        };

        drop(dest);

        if is_complete && !cache_ttl.is_zero() {
            let mut guard = ctx
                .state
                .dest_profile_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
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
        &ctx.cert_template,
        &x25519_seed,
        &mlkem_seed,
    ) else {
        return;
    };

    if !write_stream_with_timeout(&mut client, &prepared.wire_bytes, CLIENT_WRITE_TIMEOUT).await {
        return;
    }

    let pre_session = if !pipelined_after_ch.is_empty() {
        match prepared.pending.feed_client_bytes(pipelined_after_ch) {
            ClientFlightStatus::NeedMoreData => None,
            ClientFlightStatus::Complete(session) => Some(session),
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
                    ClientFlightStatus::Complete(session) => return Some(session),
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

    ctx.metrics.inc_reality_handshake_completed();
    drive_authenticated_session(
        client,
        *session,
        &ctx.state.config,
        ctx.state.dns_resolver.clone(),
        ctx.udp_table,
        ctx.metrics,
    )
    .await;
}

async fn read_dest_profile(
    dest: &mut TcpStream,
    dest_buf: &mut BytesMut,
    timeout_dur: Duration,
) -> (Option<DestServerProfile>, bool) {
    let mut partial_profile: Option<DestServerProfile> = None;
    let mut is_complete = false;
    let mut chunk = Zeroizing::new(vec![0u8; 4096]);

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
                    is_complete = true;
                    break;
                }
                ServerFlightStatus::Invalid => {
                    partial_profile = None;
                    is_complete = false;
                    break;
                }
            }
        }
    })
    .await;

    (partial_profile, is_complete)
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
        let mut buf = Zeroizing::new(vec![0u8; 4096]);
        let idle = config.tcp_idle_timeout();
        loop {
            match tokio::time::timeout(idle, client.read(&mut buf)).await {
                Ok(Ok(0) | Err(_)) => break,
                Err(_) => {
                    metrics.inc_idle_timeouts();
                    break;
                }
                Ok(Ok(n)) => {
                    let Some(slice) = buf.get(..n) else {
                        break;
                    };
                    match session.feed_wire_bytes(slice) {
                        Ok((_, true)) => {
                            if let Ok(alert) = session.seal_close_notify() {
                                let _ = write_stream_with_timeout(
                                    &mut client,
                                    &alert,
                                    CLIENT_WRITE_TIMEOUT,
                                )
                                .await;
                            }
                            let _ = tokio::time::timeout(
                                config.half_close_timeout(),
                                client.shutdown(),
                            )
                            .await;
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
        if req.flow != VlessFlow::None {
            return;
        }
        metrics.inc_vless_mux_sessions();
        relay_vless_mux(MuxTunnelArgs {
            client,
            tls_reader,
            tls_writer,
            uuid: req.uuid.clone(),
            trailing_app_data,
            egress_ctx,
            dns_resolver,
            udp_table,
            metrics,
        })
        .await;
        return;
    }

    let proto = match req.command {
        VlessCommand::Tcp => TransportProtocol::Tcp,
        VlessCommand::Udp => TransportProtocol::Udp,
        VlessCommand::Mux => return,
    };

    let targets = egress_ctx
        .resolve_and_validate(
            &req.address,
            req.port,
            proto,
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
            relay_vless_tcp(VlessTcpArgs {
                client,
                tls_reader,
                tls_writer,
                req,
                trailing_app_data,
                targets: &targets,
                config,
                metrics: Arc::clone(&metrics),
            })
            .await;
        }
        VlessCommand::Udp => {
            metrics.inc_vless_udp_sessions();
            relay_vless_udp(
                client,
                tls_reader,
                tls_writer,
                trailing_app_data,
                &targets,
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
    let mut wire_chunk = Zeroizing::new(vec![0u8; READ_CHUNK_SIZE]);

    let parsed = tokio::time::timeout(timeout_dur, async {
        loop {
            loop {
                match tls_reader.next_record() {
                    Ok(Some((inner_ct, mut payload))) => {
                        if inner_ct == 0x15 {
                            payload.zeroize();
                            app_buf.zeroize();
                            return None;
                        }
                        if inner_ct == 0x17 {
                            let new_len = app_buf.len().saturating_add(payload.len());
                            if new_len > MAX_VLESS_HEADER_BYTES {
                                payload.zeroize();
                                app_buf.zeroize();
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
                    Ok(None) => break,
                    Err(_) => {
                        app_buf.zeroize();
                        return None;
                    }
                }
            }

            let n = client.read(&mut wire_chunk).await.ok()?;
            if n == 0 {
                app_buf.zeroize();
                return None;
            }
            let slice = wire_chunk.get(..n)?;
            if tls_reader.push_wire_bytes(slice).is_err() {
                app_buf.zeroize();
                return None;
            }
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

struct VlessTcpArgs<'a> {
    client: TcpStream,
    tls_reader: RealityTlsReader,
    tls_writer: RealityTlsWriter,
    req: Box<VlessRequest>,
    trailing_app_data: Zeroizing<Vec<u8>>,
    targets: &'a [SocketAddr],
    config: &'a Config,
    metrics: Arc<Metrics>,
}

async fn relay_vless_tcp(args: VlessTcpArgs<'_>) {
    let VlessTcpArgs {
        client,
        tls_reader,
        mut tls_writer,
        req,
        mut trailing_app_data,
        targets,
        config,
        metrics,
    } = args;

    let Some(upstream) = connect_happy_eyeballs_with_options(
        targets,
        config.happy_eyeballs_delay(),
        config.tcp_keepalive(),
    )
    .await
    else {
        trailing_app_data.zeroize();
        return;
    };

    let (mut client_read, mut client_write) = client.into_split();
    let (mut up_read, mut up_write) = upstream.into_split();

    let resp_hdr = encode_vless_response_header();
    let timeouts = RelayTimeouts {
        idle: config.tcp_idle_timeout(),
        half_close: config.half_close_timeout(),
    };
    let peer_closed = HalfCloseSignal::new();

    match req.flow {
        VlessFlow::None => {
            let Ok(sealed_hdr) = tls_writer.seal_app_data(&resp_hdr) else {
                trailing_app_data.zeroize();
                return;
            };
            if !write_all_with_timeout(&mut client_write, &sealed_hdr, CLIENT_WRITE_TIMEOUT).await {
                trailing_app_data.zeroize();
                return;
            }
            if !trailing_app_data.is_empty()
                && !write_all_with_timeout(&mut up_write, &trailing_app_data, CLIENT_WRITE_TIMEOUT)
                    .await
            {
                trailing_app_data.zeroize();
                return;
            }
            trailing_app_data.zeroize();

            let up_fut = relay_plain_uplink(
                &mut client_read,
                tls_reader,
                &mut up_write,
                timeouts,
                &peer_closed,
                &metrics,
            );
            let down_fut = relay_plain_downlink(
                &mut up_read,
                tls_writer,
                &mut client_write,
                timeouts,
                &peer_closed,
                &metrics,
            );
            let _ = tokio::join!(up_fut, down_fut);
        }
        VlessFlow::Vision { .. } => {
            let mut padder = VisionPadder::new(req.uuid.clone());
            let mut rand_bytes = [0u8; 4];
            if getrandom::fill(&mut rand_bytes).is_err() {
                trailing_app_data.zeroize();
                return;
            }
            // Mask the 2-byte VLESS response header inside the initial Vision padded block so
            // no distinct tiny `[0x00, 0x00]` record leaks on the wire (`SEC-16`).
            let init_pad =
                padder.wrap_outbound(&[], &VisionTlsFilter::new(), u32::from_be_bytes(rand_bytes));
            let mut first_msg = Zeroizing::new(Vec::with_capacity(
                resp_hdr.len().saturating_add(init_pad.len()),
            ));
            first_msg.extend_from_slice(&resp_hdr);
            first_msg.extend_from_slice(&init_pad);
            let mut record_buf =
                Zeroizing::new(Vec::with_capacity(first_msg.len().saturating_add(64)));
            let init_ok = seal_and_write_chunked(
                &mut tls_writer,
                &mut client_write,
                &first_msg,
                &mut record_buf,
            )
            .await;
            first_msg.zeroize();
            if !init_ok {
                trailing_app_data.zeroize();
                return;
            }

            let shared = VisionRelayShared {
                uuid: req.uuid.clone(),
                tls_filter: Mutex::new(VisionTlsFilter::new()),
                timeouts,
                peer_closed,
                metrics: Arc::clone(&metrics),
            };
            let up_fut = relay_vision_uplink(
                &mut client_read,
                tls_reader,
                &mut up_write,
                trailing_app_data,
                &shared,
            );
            let down_fut =
                relay_vision_downlink(&mut up_read, tls_writer, &mut client_write, padder, &shared);
            let _ = tokio::join!(up_fut, down_fut);
        }
    }
}

async fn relay_plain_uplink(
    client_read: &mut OwnedReadHalf,
    mut tls_reader: RealityTlsReader,
    up_write: &mut OwnedWriteHalf,
    timeouts: RelayTimeouts,
    peer_closed: &HalfCloseSignal,
    metrics: &Metrics,
) {
    let mut wire = Zeroizing::new(vec![0u8; PLAIN_RELAY_CHUNK_SIZE]);
    let mut payload = Zeroizing::new(Vec::with_capacity(PLAIN_RELAY_CHUNK_SIZE + 32));
    loop {
        match tls_reader.next_record_into(&mut payload) {
            Ok(Some(0x17)) => {
                let write_err = !payload.is_empty()
                    && !write_all_with_timeout(up_write, &payload, CLIENT_WRITE_TIMEOUT).await;
                payload.zeroize();
                if write_err {
                    break;
                }
                continue;
            }
            Ok(Some(0x15)) => {
                payload.zeroize();
                let _ = tokio::time::timeout(timeouts.half_close, up_write.shutdown()).await;
                break;
            }
            Ok(Some(_)) => {
                payload.zeroize();
                continue;
            }
            Ok(None) => {}
            Err(_) => {
                payload.zeroize();
                break;
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
                let _ = tokio::time::timeout(timeouts.half_close, up_write.shutdown()).await;
                break;
            }
            Err(_) => {
                metrics.inc_idle_timeouts();
                let _ = tokio::time::timeout(timeouts.half_close, up_write.shutdown()).await;
                break;
            }
            Ok(Ok(n)) => {
                let Some(s) = wire.get(..n) else {
                    break;
                };
                if tls_reader.push_wire_bytes(s).is_err() {
                    break;
                }
            }
        }
    }
    peer_closed.mark_closed();
}

async fn relay_plain_downlink(
    up_read: &mut OwnedReadHalf,
    mut tls_writer: RealityTlsWriter,
    client_write: &mut OwnedWriteHalf,
    timeouts: RelayTimeouts,
    peer_closed: &HalfCloseSignal,
    metrics: &Metrics,
) {
    let mut buf = Zeroizing::new(vec![0u8; PLAIN_RELAY_CHUNK_SIZE]);
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
                if tls_writer.seal_close_notify_into(&mut record_buf).is_ok() {
                    let _ = write_all_with_timeout(client_write, &record_buf, CLIENT_WRITE_TIMEOUT)
                        .await;
                    record_buf.zeroize();
                }
                let _ = tokio::time::timeout(timeouts.half_close, client_write.shutdown()).await;
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
                    record_buf.zeroize();
                    break;
                }
                let ok =
                    write_all_with_timeout(client_write, &record_buf, CLIENT_WRITE_TIMEOUT).await;
                record_buf.zeroize();
                if !ok {
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

struct VisionRelayShared {
    uuid: VlessUuid,
    tls_filter: Mutex<VisionTlsFilter>,
    timeouts: RelayTimeouts,
    peer_closed: HalfCloseSignal,
    metrics: Arc<Metrics>,
}

fn inspect_vision_uplink(
    payload: &[u8],
    tls_filter: &Mutex<VisionTlsFilter>,
    filter_done: &mut bool,
) {
    if *filter_done {
        return;
    }
    let mut f = tls_filter.lock().unwrap_or_else(|e| e.into_inner());
    f.inspect_uplink(payload);
    if f.is_uplink_finished() {
        *filter_done = true;
    }
}

async fn switch_uplink_direct_copy(
    client_read: &mut OwnedReadHalf,
    tls_reader: RealityTlsReader,
    up_write: &mut OwnedWriteHalf,
    mut direct_trailing: Zeroizing<Vec<u8>>,
    shared: &VisionRelayShared,
) {
    if !direct_trailing.is_empty() {
        let ok = write_all_with_timeout(up_write, &direct_trailing, CLIENT_WRITE_TIMEOUT).await;
        direct_trailing.zeroize();
        if !ok {
            shared.peer_closed.mark_closed();
            return;
        }
    }
    let rem_raw = Zeroizing::new(tls_reader.into_remaining_wire_bytes());
    if !rem_raw.is_empty()
        && !write_all_with_timeout(up_write, &rem_raw, CLIENT_WRITE_TIMEOUT).await
    {
        shared.peer_closed.mark_closed();
        return;
    }
    let _ = relay_direct_copy(
        client_read,
        up_write,
        shared.timeouts.idle,
        shared.timeouts.half_close,
        &shared.peer_closed,
        &shared.metrics,
    )
    .await;
    let _ = tokio::time::timeout(shared.timeouts.half_close, up_write.shutdown()).await;
    shared.peer_closed.mark_closed();
}

async fn relay_vision_uplink(
    client_read: &mut OwnedReadHalf,
    mut tls_reader: RealityTlsReader,
    up_write: &mut OwnedWriteHalf,
    mut trailing_app_data: Zeroizing<Vec<u8>>,
    shared: &VisionRelayShared,
) {
    let mut unpadder = VisionUnpadder::new(shared.uuid.clone());
    let mut uplink_filter_done = false;

    if !trailing_app_data.is_empty() {
        let Ok(mut out) = unpadder.feed(&trailing_app_data) else {
            trailing_app_data.zeroize();
            shared.peer_closed.mark_closed();
            return;
        };
        trailing_app_data.zeroize();
        if !out.payload.is_empty() {
            inspect_vision_uplink(&out.payload, &shared.tls_filter, &mut uplink_filter_done);
            let ok = write_all_with_timeout(up_write, &out.payload, CLIENT_WRITE_TIMEOUT).await;
            out.payload.zeroize();
            if !ok {
                out.direct_trailing.zeroize();
                shared.peer_closed.mark_closed();
                return;
            }
        }
        if out.mode == UnpadMode::DirectCopy {
            switch_uplink_direct_copy(
                client_read,
                tls_reader,
                up_write,
                out.direct_trailing,
                shared,
            )
            .await;
            return;
        }
    }

    let mut wire = Zeroizing::new(vec![0u8; RELAY_CHUNK_SIZE]);
    let mut payload = Zeroizing::new(Vec::with_capacity(PLAIN_RELAY_CHUNK_SIZE + 32));
    loop {
        loop {
            match tls_reader.next_record_into(&mut payload) {
                Ok(Some(0x17)) => {
                    let feed_res = unpadder.feed(&payload);
                    payload.zeroize();
                    let Ok(mut out) = feed_res else {
                        shared.peer_closed.mark_closed();
                        return;
                    };
                    if !out.payload.is_empty() {
                        inspect_vision_uplink(
                            &out.payload,
                            &shared.tls_filter,
                            &mut uplink_filter_done,
                        );
                        let ok =
                            write_all_with_timeout(up_write, &out.payload, CLIENT_WRITE_TIMEOUT)
                                .await;
                        out.payload.zeroize();
                        if !ok {
                            out.direct_trailing.zeroize();
                            shared.peer_closed.mark_closed();
                            return;
                        }
                    }
                    if out.mode == UnpadMode::DirectCopy {
                        switch_uplink_direct_copy(
                            client_read,
                            tls_reader,
                            up_write,
                            out.direct_trailing,
                            shared,
                        )
                        .await;
                        return;
                    }
                }
                Ok(Some(0x15)) => {
                    payload.zeroize();
                    let _ =
                        tokio::time::timeout(shared.timeouts.half_close, up_write.shutdown()).await;
                    shared.peer_closed.mark_closed();
                    return;
                }
                Ok(Some(_)) => {
                    payload.zeroize();
                    continue;
                }
                Ok(None) => break,
                Err(_) => {
                    payload.zeroize();
                    shared.peer_closed.mark_closed();
                    return;
                }
            }
        }

        match timeout_with_half_close(
            shared.timeouts.idle,
            shared.timeouts.half_close,
            &shared.peer_closed,
            client_read.read(&mut wire),
        )
        .await
        {
            Ok(Ok(0) | Err(_)) => {
                let _ = tokio::time::timeout(shared.timeouts.half_close, up_write.shutdown()).await;
                shared.peer_closed.mark_closed();
                return;
            }
            Err(_) => {
                shared.metrics.inc_idle_timeouts();
                let _ = tokio::time::timeout(shared.timeouts.half_close, up_write.shutdown()).await;
                shared.peer_closed.mark_closed();
                return;
            }
            Ok(Ok(n)) => {
                let Some(s) = wire.get(..n) else {
                    shared.peer_closed.mark_closed();
                    return;
                };
                if tls_reader.push_wire_bytes(s).is_err() {
                    shared.peer_closed.mark_closed();
                    return;
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

async fn relay_vision_downlink(
    up_read: &mut OwnedReadHalf,
    mut tls_writer: RealityTlsWriter,
    client_write: &mut OwnedWriteHalf,
    mut padder: VisionPadder,
    shared: &VisionRelayShared,
) {
    let mut buf = Zeroizing::new(vec![0u8; PLAIN_RELAY_CHUNK_SIZE]);
    let mut record_buf = Zeroizing::new(Vec::with_capacity(PLAIN_RELAY_CHUNK_SIZE + 64));
    let mut downlink_filter_done = false;

    loop {
        let max_read = if padder.is_padding() {
            RELAY_CHUNK_SIZE
        } else {
            PLAIN_RELAY_CHUNK_SIZE
        };
        let Some(target_buf) = buf.get_mut(..max_read) else {
            shared.peer_closed.mark_closed();
            return;
        };

        match timeout_with_half_close(
            shared.timeouts.idle,
            shared.timeouts.half_close,
            &shared.peer_closed,
            up_read.read(target_buf),
        )
        .await
        {
            Ok(Ok(0)) => {
                if !padder.direct_copy_active()
                    && tls_writer.seal_close_notify_into(&mut record_buf).is_ok()
                {
                    let _ = write_all_with_timeout(client_write, &record_buf, CLIENT_WRITE_TIMEOUT)
                        .await;
                    record_buf.zeroize();
                }
                let _ =
                    tokio::time::timeout(shared.timeouts.half_close, client_write.shutdown()).await;
                shared.peer_closed.mark_closed();
                return;
            }
            Ok(Ok(n)) => {
                let Some(slice) = target_buf.get(..n) else {
                    shared.peer_closed.mark_closed();
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
                            shared.peer_closed.mark_closed();
                            return;
                        };
                        rem = rem.get(piece_len..).unwrap_or(&[]);

                        let filter_snapshot = {
                            let mut f = shared.tls_filter.lock().unwrap_or_else(|e| e.into_inner());
                            if !downlink_filter_done {
                                f.inspect_downlink(piece);
                                if f.is_downlink_finished() {
                                    downlink_filter_done = true;
                                }
                            }
                            f.clone()
                        };
                        let mut rand_bytes = [0u8; 4];
                        if getrandom::fill(&mut rand_bytes).is_err() {
                            shared.peer_closed.mark_closed();
                            return;
                        }
                        let rand_u32 = u32::from_be_bytes(rand_bytes);
                        let wrapped = padder.wrap_outbound(piece, &filter_snapshot, rand_u32);
                        let switched_direct = padder.direct_copy_active();
                        if !seal_and_write_chunked(
                            &mut tls_writer,
                            client_write,
                            &wrapped,
                            &mut record_buf,
                        )
                        .await
                        {
                            shared.peer_closed.mark_closed();
                            return;
                        }
                        if switched_direct {
                            shared.metrics.inc_vision_direct_switches();
                            if !rem.is_empty()
                                && !write_all_with_timeout(client_write, rem, CLIENT_WRITE_TIMEOUT)
                                    .await
                            {
                                shared.peer_closed.mark_closed();
                                return;
                            }
                            let _ = relay_direct_copy(
                                up_read,
                                client_write,
                                shared.timeouts.idle,
                                shared.timeouts.half_close,
                                &shared.peer_closed,
                                &shared.metrics,
                            )
                            .await;
                            let _ = tokio::time::timeout(
                                shared.timeouts.half_close,
                                client_write.shutdown(),
                            )
                            .await;
                            shared.peer_closed.mark_closed();
                            return;
                        }
                    }
                    if !rem.is_empty()
                        && !seal_and_write_chunked(
                            &mut tls_writer,
                            client_write,
                            rem,
                            &mut record_buf,
                        )
                        .await
                    {
                        shared.peer_closed.mark_closed();
                        return;
                    }
                } else if !seal_and_write_chunked(
                    &mut tls_writer,
                    client_write,
                    slice,
                    &mut record_buf,
                )
                .await
                {
                    shared.peer_closed.mark_closed();
                    return;
                }
            }
            Err(_) => {
                shared.metrics.inc_idle_timeouts();
                shared.peer_closed.mark_closed();
                return;
            }
            Ok(Err(_)) => {
                shared.peer_closed.mark_closed();
                return;
            }
        }
    }
}

async fn bind_and_connect_udp(targets: &[SocketAddr]) -> Option<UdpSocket> {
    for &target in targets {
        let bind_addr = if target.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let Ok(sock) = UdpSocket::bind(bind_addr).await else {
            continue;
        };
        tune_udp_socket(&sock, UDP_SOCKET_BUFFER_BYTES);
        if sock.connect(target).await.is_ok() {
            return Some(sock);
        }
    }
    None
}

fn touch_activity(last_activity_ms: &AtomicU64, start: Instant) {
    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    last_activity_ms.store(elapsed_ms, Ordering::Relaxed);
}

fn udp_idle_remaining(
    last_activity_ms: &AtomicU64,
    start: Instant,
    idle_timeout: Duration,
) -> Option<Duration> {
    let now_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let last_ms = last_activity_ms.load(Ordering::Relaxed);
    let since_active = Duration::from_millis(now_ms.saturating_sub(last_ms));
    idle_timeout
        .checked_sub(since_active)
        .filter(|d| !d.is_zero())
}

async fn send_udp_datagram(sock: &UdpSocket, pkt: &[u8]) -> bool {
    match sock.send(pkt).await {
        Ok(_) => true,
        // Connected UDP sockets may report a delayed ICMP Port Unreachable error
        // as `ConnectionRefused` on one subsequent syscall; do not kill the relay on it.
        Err(ref err) if err.kind() == ErrorKind::ConnectionRefused => sock.send(pkt).await.is_ok(),
        Err(_) => false,
    }
}

async fn relay_vless_udp(
    client: TcpStream,
    mut tls_reader: RealityTlsReader,
    mut tls_writer: RealityTlsWriter,
    mut trailing_app_data: Zeroizing<Vec<u8>>,
    targets: &[SocketAddr],
    udp_idle_timeout: Duration,
    metrics: &Metrics,
) {
    let Some(udp_sock) = bind_and_connect_udp(targets).await else {
        trailing_app_data.zeroize();
        return;
    };
    let udp_send = Arc::new(udp_sock);
    let udp_recv = Arc::clone(&udp_send);

    let (mut client_read, mut client_write) = client.into_split();

    let resp_hdr = encode_vless_response_header();
    let Ok(sealed_hdr) = tls_writer.seal_app_data(&resp_hdr) else {
        trailing_app_data.zeroize();
        return;
    };
    if !write_all_with_timeout(&mut client_write, &sealed_hdr, CLIENT_WRITE_TIMEOUT).await {
        trailing_app_data.zeroize();
        return;
    }

    let start = Instant::now();
    let last_activity_ms = Arc::new(AtomicU64::new(0));
    let up_activity = Arc::clone(&last_activity_ms);
    let down_activity = Arc::clone(&last_activity_ms);

    let up_fut = async {
        let mut pkt_buf = Zeroizing::new(Vec::from(trailing_app_data.as_slice()));
        let mut pkt_offset = 0usize;
        trailing_app_data.zeroize();
        let mut wire = Zeroizing::new(vec![0u8; RELAY_CHUNK_SIZE]);
        let mut payload = Zeroizing::new(Vec::with_capacity(PLAIN_RELAY_CHUNK_SIZE + 32));
        let mut wait_budget = udp_idle_timeout;

        loop {
            while let Some(avail) = pkt_buf.get(pkt_offset..) {
                match decode_udp_packet(avail) {
                    Ok(Some((mut pkt, consumed))) => {
                        pkt_offset = pkt_offset.saturating_add(consumed);
                        let ok = send_udp_datagram(&udp_send, &pkt).await;
                        pkt.zeroize();
                        if !ok {
                            pkt_buf.zeroize();
                            return;
                        }
                        touch_activity(&up_activity, start);
                        wait_budget = udp_idle_timeout;
                    }
                    Ok(None) => break,
                    Err(_) => {
                        pkt_buf.zeroize();
                        return;
                    }
                }
            }
            if pkt_offset >= pkt_buf.len() {
                pkt_buf.zeroize();
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
                            pkt_buf.zeroize();
                            return;
                        }
                        pkt_buf.extend_from_slice(&payload);
                        payload.zeroize();
                        while let Some(avail) = pkt_buf.get(pkt_offset..) {
                            match decode_udp_packet(avail) {
                                Ok(Some((mut pkt, consumed))) => {
                                    pkt_offset = pkt_offset.saturating_add(consumed);
                                    let ok = send_udp_datagram(&udp_send, &pkt).await;
                                    pkt.zeroize();
                                    if !ok {
                                        pkt_buf.zeroize();
                                        return;
                                    }
                                    touch_activity(&up_activity, start);
                                    wait_budget = udp_idle_timeout;
                                }
                                Ok(None) => break,
                                Err(_) => {
                                    pkt_buf.zeroize();
                                    return;
                                }
                            }
                        }
                        if pkt_offset >= pkt_buf.len() {
                            pkt_buf.zeroize();
                            pkt_buf.clear();
                            pkt_offset = 0;
                        } else if pkt_offset >= 16_384 {
                            pkt_buf.drain(..pkt_offset);
                            pkt_offset = 0;
                        }
                    }
                    Ok(Some(0x15)) => {
                        payload.zeroize();
                        pkt_buf.zeroize();
                        return;
                    }
                    Ok(Some(_)) => {
                        payload.zeroize();
                        continue;
                    }
                    Ok(None) => break,
                    Err(_) => {
                        payload.zeroize();
                        pkt_buf.zeroize();
                        return;
                    }
                }
            }

            match tokio::time::timeout(wait_budget, client_read.read(&mut wire)).await {
                Ok(Ok(0) | Err(_)) => {
                    pkt_buf.zeroize();
                    return;
                }
                Err(_) => {
                    if let Some(rem) = udp_idle_remaining(&up_activity, start, udp_idle_timeout) {
                        wait_budget = rem;
                        continue;
                    }
                    metrics.inc_idle_timeouts();
                    pkt_buf.zeroize();
                    return;
                }
                Ok(Ok(n)) => {
                    wait_budget = udp_idle_timeout;
                    let Some(s) = wire.get(..n) else {
                        pkt_buf.zeroize();
                        return;
                    };
                    if tls_reader.push_wire_bytes(s).is_err() {
                        pkt_buf.zeroize();
                        return;
                    }
                }
            }
        }
    };

    let down_fut = async {
        let mut ubuf = Zeroizing::new(vec![0u8; MAX_UDP_DATAGRAM_BYTES]);
        let mut framed = Zeroizing::new(Vec::with_capacity(PLAIN_RELAY_CHUNK_SIZE));
        let mut batch_buf = Zeroizing::new(Vec::with_capacity(PLAIN_RELAY_CHUNK_SIZE));
        let mut record_buf = Zeroizing::new(Vec::with_capacity(PLAIN_RELAY_CHUNK_SIZE + 64));
        let mut wait_budget = udp_idle_timeout;

        loop {
            match tokio::time::timeout(wait_budget, udp_recv.recv(&mut ubuf)).await {
                Ok(Ok(n)) => {
                    wait_budget = udp_idle_timeout;
                    touch_activity(&down_activity, start);
                    let Some(slice) = ubuf.get(..n) else {
                        return;
                    };
                    if encode_udp_packet_into(slice, &mut framed).is_err() {
                        return;
                    }
                    batch_buf.zeroize();
                    batch_buf.clear();
                    batch_buf.extend_from_slice(&framed);

                    // Coalesce additional already-queued small UDP datagrams into a single
                    // <= 16 KiB TLS 1.3 record to cut AEAD and syscall overhead under burst load.
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
                                    if !seal_and_write_chunked(
                                        &mut tls_writer,
                                        &mut client_write,
                                        &batch_buf,
                                        &mut record_buf,
                                    )
                                    .await
                                    {
                                        return;
                                    }
                                    batch_buf.zeroize();
                                    batch_buf.clear();
                                }
                                if encode_udp_packet_into(next_slice, &mut framed).is_err() {
                                    return;
                                }
                                batch_buf.extend_from_slice(&framed);
                            }
                            Err(ref e) if e.kind() == ErrorKind::ConnectionRefused => continue,
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }

                    if !batch_buf.is_empty() {
                        let ok = seal_and_write_chunked(
                            &mut tls_writer,
                            &mut client_write,
                            &batch_buf,
                            &mut record_buf,
                        )
                        .await;
                        batch_buf.zeroize();
                        if !ok {
                            return;
                        }
                    }
                }
                Ok(Err(ref err)) if err.kind() == ErrorKind::ConnectionRefused => continue,
                Err(_) => {
                    if let Some(rem) = udp_idle_remaining(&down_activity, start, udp_idle_timeout) {
                        wait_budget = rem;
                        continue;
                    }
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
    client: TcpStream,
    buffered: BytesMut,
    client_eof: bool,
    dest_addr: SocketAddr,
    tcp_keepalive: Duration,
    timeouts: RelayTimeouts,
    metrics: &Metrics,
) {
    let Ok(Ok(mut dest)) =
        tokio::time::timeout(OUTBOUND_CONNECT_TIMEOUT, TcpStream::connect(dest_addr)).await
    else {
        metrics.inc_dial_dest_failed();
        return;
    };
    tune_tcp_stream(&dest, tcp_keepalive);

    if !buffered.is_empty()
        && !write_stream_with_timeout(&mut dest, &buffered, CLIENT_WRITE_TIMEOUT).await
    {
        return;
    }

    if client_eof {
        let _ = tokio::time::timeout(timeouts.half_close, dest.shutdown()).await;
        let (_cr, mut cw) = client.into_split();
        let (mut dr, _dw) = dest.into_split();
        let peer_closed = HalfCloseSignal::new();
        let _ = relay_direct_copy(
            &mut dr,
            &mut cw,
            timeouts.half_close,
            timeouts.half_close,
            &peer_closed,
            metrics,
        )
        .await;
        let _ = tokio::time::timeout(timeouts.half_close, cw.shutdown()).await;
        return;
    }

    relay_tcp_pair_with_timeouts(client, dest, timeouts, metrics).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RealityConfig;
    use mirage_core::crypto::{ShortId, StaticPrivateKey};
    use mirage_core::reality::ReplayOutcome;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_config(
        listen_port: u16,
        key_seed: u8,
        short_id_seed: u8,
        max_time_diff_secs: u64,
        replay_cache_capacity: usize,
        max_connections: usize,
    ) -> Result<Config, DaemonError> {
        let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let cfg = Config::new(
            listen,
            dest,
            vec!["example.com".to_owned()],
            16 * 1024,
            5000,
            max_connections,
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
        let initial = test_config(8443, 0x11, 0xAA, 120, 1024, 64)?;
        let runtime = SharedRuntime::new(initial)?;
        let snap1 = runtime.snapshot();
        let cache1 = snap1
            .replay_cache
            .as_ref()
            .ok_or(DaemonError::ConfigInvalid)?;

        let seen_random = [0x5Au8; 32];
        {
            let mut guard = cache1.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(
                guard.check_and_insert(&seen_random, 1_700_000_000),
                ReplayOutcome::Accepted
            );
        }

        // Rotate private key & short_id while keeping replay window/capacity identical.
        let rotated = test_config(8443, 0x22, 0xBB, 120, 1024, 64)?;
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

        // Changing replay cache window/capacity allocates a fresh cache and migrates entries.
        let resized = test_config(8443, 0x33, 0xCC, 180, 2048, 64)?;
        runtime.reload(resized)?;
        let snap3 = runtime.snapshot();
        let cache3 = snap3
            .replay_cache
            .as_ref()
            .ok_or(DaemonError::ConfigInvalid)?;
        assert!(!Arc::ptr_eq(cache2, cache3));
        {
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let mut guard = cache3.lock().unwrap_or_else(|e| e.into_inner());
            // Insert another fresh entry tied to current wall clock and verify migration
            // of active entries across reload.
            let active_random = [0x6Bu8; 32];
            assert_eq!(
                guard.check_and_insert(&active_random, now_unix),
                ReplayOutcome::Accepted
            );
            let resized_again = test_config(8443, 0x34, 0xCD, 240, 2048, 64)?;
            drop(guard);
            runtime.reload(resized_again)?;
            let snap4 = runtime.snapshot();
            let cache4 = snap4
                .replay_cache
                .as_ref()
                .ok_or(DaemonError::ConfigInvalid)?;
            let mut guard4 = cache4.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(
                guard4.check_and_insert(&active_random, now_unix),
                ReplayOutcome::Replayed
            );
        }

        // Changing non-reloadable listen_addr or max_connections must fail-closed.
        let changed_listen = test_config(9443, 0x44, 0xDD, 180, 2048, 64)?;
        assert!(runtime.reload(changed_listen).is_err());
        let changed_max_conns = test_config(8443, 0x44, 0xDD, 180, 2048, 128)?;
        assert!(runtime.reload(changed_max_conns).is_err());
        assert_eq!(runtime.snapshot().config.listen_addr().port(), 8443);

        Ok(())
    }
}
