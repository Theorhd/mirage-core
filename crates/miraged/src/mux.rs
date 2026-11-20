//! `Mux.Cool` (`v1.mux.cool`) sub-stream multiplexer and `XUDP` Full-Cone NAT.
//!
//! Supports concurrent multiplexed TCP streams and connectionless Full-Cone
//! UDP NAT sessions keyed by `(VlessUuid, GlobalID)` (or ephemeral local ID),
//! with strict `EgressPolicy` validation on every initial, per-packet override,
//! and incoming Full-Cone UDP peer datagram.

use core::net::{IpAddr, SocketAddr};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use mirage_core::egress::TransportProtocol;
use mirage_core::mux::{
    decode_mux_frame, encode_mux_frame_into, MuxFrame, MuxNetwork, MuxStatus, MuxTarget,
};
use mirage_core::reality::{RealityTlsReader, RealityTlsWriter};
use mirage_core::tls_parser::MAX_TLS_RECORD_FRAGMENT;
use mirage_core::vless::{encode_vless_response_header, VlessAddress, VlessUuid};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::{AbortHandle, JoinHandle, JoinSet};
use zeroize::{Zeroize, Zeroizing};

use crate::dns::DnsResolver;
use crate::metrics::Metrics;
use crate::net_opt::{timeout_with_half_close, tune_udp_socket, HalfCloseSignal, RelayElapsed};
use crate::outbound::{connect_happy_eyeballs_with_options, EgressContext};

/// Maximum buffered undecoded Mux stream bytes per connection (`256 KiB`).
const MAX_MUX_STREAM_BUFFER: usize = 256 * 1024;

/// Maximum concurrent multiplexed sub-sessions (TCP + UDP) allowed per tunnel.
const MAX_MUX_SUBSESSIONS: usize = 256;

/// Maximum total bytes queued across all TCP substream uplink channels in one tunnel (`4 MiB`).
const MAX_MUX_TUNNEL_BUFFERED_BYTES: usize = 4 * 1024 * 1024;

/// Maximum distinct Full-Cone XUDP sessions referenced by a single tunnel or UUID.
const MAX_PER_UUID_XUDP_SESSIONS: usize = 128;

/// Maximum concurrent Full-Cone XUDP/UDP NAT mappings retained globally in RAM.
const MAX_GLOBAL_UDP_SESSIONS: usize = 1024;

/// Maximum outbound Mux frames queued per client tunnel before backpressure.
const MUX_OUTBOUND_CHANNEL_CAPACITY: usize = 256;

/// Maximum queued uplink chunks per Mux TCP sub-session.
const MUX_SUBSTREAM_CHANNEL_CAPACITY: usize = 32;

/// Maximum time the Mux reader loop waits for a stalled TCP sub-stream or byte budget
/// before terminating that sub-stream to avoid Head-of-Line blocking.
const MUX_SUBSTREAM_SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum time allowed for a single encrypted client socket write before disconnecting slow peers.
const MUX_CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum concurrent background DNS resolutions spawned for Mux UDP cache misses per tunnel.
const MAX_MUX_ASYNC_UDP_DNS_TASKS: usize = 32;

/// Read chunk size for TCP sub-streams and TLS record framing (`16 KiB` matches max TLS 1.3 fragment).
const MUX_RELAY_CHUNK_SIZE: usize = 16 * 1024;

/// Idle timeout for Mux tunnel & TCP sub-streams.
const MUX_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Idle timeout for Full-Cone XUDP NAT sockets.
const XUDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Per-socket kernel buffer size for XUDP Full-Cone sockets (`512 KiB`).
const XUDP_UDP_SOCKET_BUFFER_BYTES: usize = 512 * 1024;

/// Maximum UDP datagram payload accepted by XUDP NAT receivers.
const MAX_UDP_DATAGRAM_BYTES: usize = 65_507;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum UdpNatKey {
    Xudp { uuid: [u8; 16], global_id: [u8; 8] },
    Local { tunnel_id: u64, session_id: u16 },
}

struct UdpNatEntry {
    closed: AtomicBool,
    v4_sock: tokio::sync::Mutex<Option<Arc<UdpSocket>>>,
    v6_sock: tokio::sync::Mutex<Option<Arc<UdpSocket>>>,
    v4_reader: Mutex<Option<AbortHandle>>,
    v6_reader: Mutex<Option<AbortHandle>>,
    active_sink: Mutex<Option<(u16, mpsc::Sender<MuxFrame>)>>,
    last_active_ms: AtomicU64,
}

impl UdpNatEntry {
    fn new(now_ms: u64, session_id: u16, tx: mpsc::Sender<MuxFrame>) -> Self {
        Self {
            closed: AtomicBool::new(false),
            v4_sock: tokio::sync::Mutex::new(None),
            v6_sock: tokio::sync::Mutex::new(None),
            v4_reader: Mutex::new(None),
            v6_reader: Mutex::new(None),
            active_sink: Mutex::new(Some((session_id, tx))),
            last_active_ms: AtomicU64::new(now_ms),
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn touch(&self, now_ms: u64, session_id: u16, tx: &mpsc::Sender<MuxFrame>) {
        self.last_active_ms.store(now_ms, Ordering::Relaxed);
        let mut guard = self.active_sink.lock().unwrap_or_else(|e| e.into_inner());
        let replace = match &*guard {
            Some((cur_id, cur_tx)) => *cur_id != session_id || !cur_tx.same_channel(tx),
            None => true,
        };
        if replace {
            *guard = Some((session_id, tx.clone()));
        }
    }

    fn clear_sink_if_same(&self, tx: &mpsc::Sender<MuxFrame>) {
        let mut guard = self.active_sink.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, cur_tx)) = &*guard {
            if cur_tx.same_channel(tx) {
                *guard = None;
            }
        }
    }

    fn clear_sink_if_session(&self, session_id: u16, tx: &mpsc::Sender<MuxFrame>) {
        let mut guard = self.active_sink.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((cur_id, cur_tx)) = &*guard {
            if *cur_id == session_id && cur_tx.same_channel(tx) {
                *guard = None;
            }
        }
    }

    fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        *self.active_sink.lock().unwrap_or_else(|e| e.into_inner()) = None;
        if let Some(h) = self
            .v4_reader
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            h.abort();
        }
        if let Some(h) = self
            .v6_reader
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            h.abort();
        }
    }
}

#[derive(Default)]
struct UdpTableState {
    entries: HashMap<UdpNatKey, Arc<UdpNatEntry>>,
    xudp_counts: HashMap<[u8; 16], usize>,
}

impl UdpTableState {
    fn remove_entry(&mut self, key: &UdpNatKey) -> Option<Arc<UdpNatEntry>> {
        let removed = self.entries.remove(key)?;
        if let UdpNatKey::Xudp { uuid, .. } = key {
            if let Some(cnt) = self.xudp_counts.get_mut(uuid) {
                *cnt = cnt.saturating_sub(1);
                if *cnt == 0 {
                    self.xudp_counts.remove(uuid);
                }
            }
        }
        Some(removed)
    }

    fn prune_idle(&mut self, now_ms: u64, idle_ms: u64) {
        let mut expired = Vec::new();
        for (&key, entry) in &self.entries {
            if now_ms.saturating_sub(entry.last_active_ms.load(Ordering::Relaxed)) >= idle_ms {
                expired.push(key);
            }
        }
        for key in expired {
            if let Some(entry) = self.remove_entry(&key) {
                entry.shutdown();
            }
        }
    }
}

/// Shared RAM-only Full-Cone UDP NAT table keyed by `(VlessUuid, GlobalID)`
/// for XUDP and `(tunnel_id, session_id)` for standard Mux UDP.
///
/// Enforces strict per-UUID XUDP quotas and never evicts another user's active session.
pub struct GlobalUdpTable {
    started_at: Instant,
    next_tunnel_id: AtomicU64,
    state: Mutex<UdpTableState>,
}

impl Default for GlobalUdpTable {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalUdpTable {
    /// Creates an empty Full-Cone UDP NAT table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            next_tunnel_id: AtomicU64::new(1),
            state: Mutex::new(UdpTableState::default()),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn alloc_tunnel_id(&self) -> u64 {
        self.next_tunnel_id.fetch_add(1, Ordering::Relaxed)
    }

    fn get_or_insert(
        &self,
        key: UdpNatKey,
        session_id: u16,
        tx: &mpsc::Sender<MuxFrame>,
    ) -> Option<Arc<UdpNatEntry>> {
        let now_ms = self.now_ms();
        let idle_ms = u64::try_from(XUDP_IDLE_TIMEOUT.as_millis()).unwrap_or(120_000);

        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = guard.entries.get(&key) {
            if !existing.is_closed() {
                existing.touch(now_ms, session_id, tx);
                return Some(Arc::clone(existing));
            }
            if let Some(removed) = guard.remove_entry(&key) {
                removed.shutdown();
            }
        }

        if let UdpNatKey::Xudp { uuid, .. } = key {
            let cur_count = guard.xudp_counts.get(&uuid).copied().unwrap_or(0);
            if cur_count >= MAX_PER_UUID_XUDP_SESSIONS {
                guard.prune_idle(now_ms, idle_ms);
                let after_prune = guard.xudp_counts.get(&uuid).copied().unwrap_or(0);
                if after_prune >= MAX_PER_UUID_XUDP_SESSIONS {
                    return None;
                }
            }
        }

        if guard.entries.len() >= MAX_GLOBAL_UDP_SESSIONS {
            guard.prune_idle(now_ms, idle_ms);
            if guard.entries.len() >= MAX_GLOBAL_UDP_SESSIONS {
                // Fail closed instead of evicting other users' active NAT sessions (SEC-09).
                return None;
            }
        }

        let entry = Arc::new(UdpNatEntry::new(now_ms, session_id, tx.clone()));
        guard.entries.insert(key, Arc::clone(&entry));
        if let UdpNatKey::Xudp { uuid, .. } = key {
            let count = guard.xudp_counts.entry(uuid).or_insert(0);
            *count = count.saturating_add(1);
        }
        Some(entry)
    }

    fn remove_local_session(&self, tunnel_id: u64, session_id: u16) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(removed) = guard.remove_entry(&UdpNatKey::Local {
            tunnel_id,
            session_id,
        }) {
            removed.shutdown();
        }
    }

    fn cleanup_tunnel_locals(&self, tunnel_id: u64) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let to_remove: Vec<UdpNatKey> = guard
            .entries
            .keys()
            .copied()
            .filter(|k| matches!(k, UdpNatKey::Local { tunnel_id: tid, .. } if *tid == tunnel_id))
            .collect();
        for key in to_remove {
            if let Some(removed) = guard.remove_entry(&key) {
                removed.shutdown();
            }
        }
    }

    fn remove_if_idle(&self, key: UdpNatKey, idle_ms: u64) {
        let now_ms = self.now_ms();
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let is_idle = guard.entries.get(&key).is_some_and(|entry| {
            now_ms.saturating_sub(entry.last_active_ms.load(Ordering::Relaxed)) >= idle_ms
        });
        if is_idle {
            if let Some(removed) = guard.remove_entry(&key) {
                removed.shutdown();
            }
        }
    }
}

struct QueuedMuxPayload {
    data: Zeroizing<Vec<u8>>,
    _byte_permit: OwnedSemaphorePermit,
}

type TcpSubstreamEntry = (mpsc::Sender<QueuedMuxPayload>, JoinHandle<()>);
type SharedResolvedUdpTarget = Arc<Mutex<Option<(VlessAddress, u16, SocketAddr)>>>;

struct UdpSessionHandle {
    key: UdpNatKey,
    default_target: Option<MuxTarget>,
    resolved_cache: SharedResolvedUdpTarget,
}

enum MuxSubsession {
    Tcp(TcpSubstreamEntry),
    Udp(UdpSessionHandle),
}

/// Parameters required to run a `Mux.Cool` + `XUDP` multiplexed tunnel.
pub struct MuxTunnelArgs {
    pub client: tokio::net::TcpStream,
    pub tls_reader: RealityTlsReader,
    pub tls_writer: RealityTlsWriter,
    pub uuid: VlessUuid,
    pub trailing_app_data: Zeroizing<Vec<u8>>,
    pub egress_ctx: EgressContext,
    pub dns_resolver: Option<Arc<DnsResolver>>,
    pub udp_table: Arc<GlobalUdpTable>,
    pub metrics: Arc<Metrics>,
}

struct MuxLoopState {
    tunnel_id: u64,
    uuid_bytes: [u8; 16],
    egress_ctx: EgressContext,
    dns_resolver: Option<Arc<DnsResolver>>,
    udp_table: Arc<GlobalUdpTable>,
    mux_tx: mpsc::Sender<MuxFrame>,
    subs: HashMap<u16, MuxSubsession>,
    active_xudp_entries: HashMap<UdpNatKey, Weak<UdpNatEntry>>,
    udp_dns_sem: Arc<Semaphore>,
    udp_dns_tasks: JoinSet<()>,
    tunnel_byte_budget: Arc<Semaphore>,
    metrics: Arc<Metrics>,
}

/// Runs a `Mux.Cool` + `XUDP` multiplexed tunnel over Reality TLS 1.3.
pub async fn relay_vless_mux(args: MuxTunnelArgs) {
    let MuxTunnelArgs {
        mut client,
        mut tls_reader,
        mut tls_writer,
        uuid,
        mut trailing_app_data,
        egress_ctx,
        dns_resolver,
        udp_table,
        metrics,
    } = args;

    let resp_hdr = encode_vless_response_header();
    let Ok(sealed_hdr) = tls_writer.seal_app_data(&resp_hdr) else {
        return;
    };
    if !matches!(
        tokio::time::timeout(MUX_CLIENT_WRITE_TIMEOUT, client.write_all(&sealed_hdr)).await,
        Ok(Ok(()))
    ) {
        return;
    }

    let tunnel_id = udp_table.alloc_tunnel_id();
    let uuid_bytes = *uuid.as_bytes();
    let (mut client_read, client_write) = client.into_split();

    let (mux_tx, mux_rx) = mpsc::channel::<MuxFrame>(MUX_OUTBOUND_CHANNEL_CAPACITY);
    let writer_handle = tokio::spawn(run_mux_writer(mux_rx, tls_writer, client_write));

    let mut state = MuxLoopState {
        tunnel_id,
        uuid_bytes,
        egress_ctx,
        dns_resolver,
        udp_table: Arc::clone(&udp_table),
        mux_tx: mux_tx.clone(),
        subs: HashMap::new(),
        active_xudp_entries: HashMap::new(),
        udp_dns_sem: Arc::new(Semaphore::new(MAX_MUX_ASYNC_UDP_DNS_TASKS)),
        udp_dns_tasks: JoinSet::new(),
        tunnel_byte_budget: Arc::new(Semaphore::new(MAX_MUX_TUNNEL_BUFFERED_BYTES)),
        metrics: Arc::clone(&metrics),
    };

    let mut mux_buf = Zeroizing::new(Vec::with_capacity(8192));
    let mut mux_off = 0usize;
    mux_buf.extend_from_slice(&trailing_app_data);
    trailing_app_data.zeroize();

    let mut wire = Zeroizing::new(vec![0u8; MUX_RELAY_CHUNK_SIZE]);
    let mut record_payload = Zeroizing::new(Vec::with_capacity(MAX_TLS_RECORD_FRAGMENT + 32));

    'outer: loop {
        loop {
            let Some(avail) = mux_buf.get(mux_off..) else {
                mux_buf.zeroize();
                mux_buf.clear();
                mux_off = 0;
                break;
            };
            match decode_mux_frame(avail) {
                Ok(Some((frame, consumed))) => {
                    mux_off = mux_off.saturating_add(consumed);
                    handle_decoded_mux_frame(frame, &mut state).await;
                }
                Ok(None) => break,
                Err(_) => break 'outer,
            }
        }

        if mux_off >= mux_buf.len() {
            mux_buf.zeroize();
            mux_buf.clear();
            mux_off = 0;
        } else if mux_off >= 16 * 1024 {
            if let Some(consumed) = mux_buf.get_mut(..mux_off) {
                consumed.zeroize();
            }
            mux_buf.drain(..mux_off);
            mux_off = 0;
        }

        // Reap finished TCP sub-session tasks and completed background UDP DNS tasks.
        state
            .subs
            .retain(|_, sub| !matches!(sub, MuxSubsession::Tcp((_, h)) if h.is_finished()));
        while state.udp_dns_tasks.try_join_next().is_some() {}

        let mut drained_record = false;
        loop {
            match tls_reader.next_record_into(&mut record_payload) {
                Ok(Some(0x17)) => {
                    let unread = mux_buf.len().saturating_sub(mux_off);
                    if unread.saturating_add(record_payload.len()) > MAX_MUX_STREAM_BUFFER {
                        record_payload.zeroize();
                        break 'outer;
                    }
                    mux_buf.extend_from_slice(&record_payload);
                    record_payload.zeroize();
                    drained_record = true;
                }
                Ok(Some(0x15)) => {
                    if record_payload.len() != 2 || record_payload.first() == Some(&2) {
                        record_payload.zeroize();
                        break 'outer;
                    }
                    record_payload.zeroize();
                    if record_payload.get(1) == Some(&0) {
                        break 'outer;
                    }
                }
                Ok(Some(_)) => {
                    record_payload.zeroize();
                    break 'outer;
                }
                Ok(None) => break,
                Err(_) => break 'outer,
            }
        }
        if drained_record {
            continue;
        }

        match tokio::time::timeout(MUX_TCP_IDLE_TIMEOUT, client_read.read(&mut wire)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Err(_) => {
                metrics.inc_idle_timeouts();
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

    for (_, weak_entry) in state.active_xudp_entries {
        if let Some(entry) = weak_entry.upgrade() {
            entry.clear_sink_if_same(&mux_tx);
        }
    }
    state.udp_dns_tasks.abort_all();
    drop(mux_tx);
    for (_, sub) in state.subs {
        if let MuxSubsession::Tcp((tx, handle)) = sub {
            drop(tx);
            handle.abort();
        }
    }
    udp_table.cleanup_tunnel_locals(tunnel_id);
    writer_handle.abort();
}

async fn write_tls_record_timed(
    tls_writer: &mut RealityTlsWriter,
    client_write: &mut OwnedWriteHalf,
    plaintext: &[u8],
    record_buf: &mut Vec<u8>,
) -> bool {
    if tls_writer
        .seal_app_data_into(plaintext, record_buf)
        .is_err()
    {
        record_buf.zeroize();
        return false;
    }
    let ok = matches!(
        tokio::time::timeout(MUX_CLIENT_WRITE_TIMEOUT, client_write.write_all(record_buf)).await,
        Ok(Ok(()))
    );
    record_buf.zeroize();
    ok
}

async fn write_split_records(
    tls_writer: &mut RealityTlsWriter,
    client_write: &mut OwnedWriteHalf,
    frame_buf: &[u8],
    record_buf: &mut Vec<u8>,
) -> bool {
    let mut off = 0usize;
    while off < frame_buf.len() {
        let end = off
            .saturating_add(MAX_TLS_RECORD_FRAGMENT)
            .min(frame_buf.len());
        let Some(chunk) = frame_buf.get(off..end) else {
            return false;
        };
        if !write_tls_record_timed(tls_writer, client_write, chunk, record_buf).await {
            return false;
        }
        off = end;
    }
    true
}

async fn run_mux_writer(
    mut mux_rx: mpsc::Receiver<MuxFrame>,
    mut tls_writer: RealityTlsWriter,
    mut client_write: OwnedWriteHalf,
) {
    let mut frame_buf = Zeroizing::new(Vec::with_capacity(4096));
    let mut batch_buf = Zeroizing::new(Vec::with_capacity(MAX_TLS_RECORD_FRAGMENT));
    let mut record_buf = Zeroizing::new(Vec::with_capacity(MAX_TLS_RECORD_FRAGMENT + 32));

    while let Some(frame) = mux_rx.recv().await {
        if encode_mux_frame_into(&frame, &mut frame_buf).is_err() {
            break;
        }
        batch_buf.zeroize();
        batch_buf.clear();

        if frame_buf.len() <= MAX_TLS_RECORD_FRAGMENT {
            batch_buf.extend_from_slice(&frame_buf);

            while batch_buf.len() < MAX_TLS_RECORD_FRAGMENT {
                match mux_rx.try_recv() {
                    Ok(next_frame) => {
                        if encode_mux_frame_into(&next_frame, &mut frame_buf).is_err() {
                            let _ = tokio::time::timeout(
                                MUX_CLIENT_WRITE_TIMEOUT,
                                client_write.shutdown(),
                            )
                            .await;
                            return;
                        }
                        if batch_buf.len().saturating_add(frame_buf.len())
                            <= MAX_TLS_RECORD_FRAGMENT
                        {
                            batch_buf.extend_from_slice(&frame_buf);
                        } else {
                            if !batch_buf.is_empty() {
                                if !write_tls_record_timed(
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
                            if frame_buf.len() <= MAX_TLS_RECORD_FRAGMENT {
                                batch_buf.extend_from_slice(&frame_buf);
                            } else if !write_split_records(
                                &mut tls_writer,
                                &mut client_write,
                                &frame_buf,
                                &mut record_buf,
                            )
                            .await
                            {
                                return;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }

            if !batch_buf.is_empty()
                && !write_tls_record_timed(
                    &mut tls_writer,
                    &mut client_write,
                    &batch_buf,
                    &mut record_buf,
                )
                .await
            {
                return;
            }
        } else if !write_split_records(
            &mut tls_writer,
            &mut client_write,
            &frame_buf,
            &mut record_buf,
        )
        .await
        {
            return;
        }
    }

    if tls_writer.seal_close_notify_into(&mut record_buf).is_ok() {
        let _ = tokio::time::timeout(
            MUX_CLIENT_WRITE_TIMEOUT,
            client_write.write_all(&record_buf),
        )
        .await;
        record_buf.zeroize();
    }
    let _ = tokio::time::timeout(MUX_CLIENT_WRITE_TIMEOUT, client_write.shutdown()).await;
}

async fn try_enqueue_tcp_payload(
    up_tx: &mpsc::Sender<QueuedMuxPayload>,
    byte_budget: &Arc<Semaphore>,
    payload: Zeroizing<Vec<u8>>,
) -> bool {
    if payload.is_empty() {
        return true;
    }
    let Ok(byte_count) = u32::try_from(payload.len()) else {
        return false;
    };
    let permit = match Arc::clone(byte_budget).try_acquire_many_owned(byte_count) {
        Ok(p) => p,
        Err(_) => match tokio::time::timeout(
            MUX_SUBSTREAM_SEND_TIMEOUT,
            Arc::clone(byte_budget).acquire_many_owned(byte_count),
        )
        .await
        {
            Ok(Ok(p)) => p,
            _ => return false,
        },
    };
    let item = QueuedMuxPayload {
        data: payload,
        _byte_permit: permit,
    };
    match up_tx.try_send(item) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Closed(_)) => false,
        Err(mpsc::error::TrySendError::Full(item)) => matches!(
            tokio::time::timeout(MUX_SUBSTREAM_SEND_TIMEOUT, up_tx.send(item)).await,
            Ok(Ok(()))
        ),
    }
}

fn send_error_end(mux_tx: &mpsc::Sender<MuxFrame>, id: u16) {
    let _ = mux_tx.try_send(MuxFrame {
        id,
        status: MuxStatus::End,
        opt_data: false,
        opt_error: true,
        target: None,
        global_id: None,
        payload: Zeroizing::new(Vec::new()),
    });
}

async fn handle_decoded_mux_frame(frame: MuxFrame, state: &mut MuxLoopState) {
    match frame.status {
        MuxStatus::KeepAlive => {}
        MuxStatus::End => {
            if let Some(sub) = state.subs.remove(&frame.id) {
                match sub {
                    MuxSubsession::Tcp((tx, handle)) => {
                        drop(tx);
                        handle.abort();
                    }
                    MuxSubsession::Udp(u) => match u.key {
                        UdpNatKey::Local {
                            tunnel_id: tid,
                            session_id: sid,
                        } => {
                            state.udp_table.remove_local_session(tid, sid);
                        }
                        UdpNatKey::Xudp { .. } => {
                            if let Some(weak) = state.active_xudp_entries.get(&u.key) {
                                if let Some(entry) = weak.upgrade() {
                                    entry.clear_sink_if_session(frame.id, &state.mux_tx);
                                }
                            }
                        }
                    },
                }
            }
        }
        MuxStatus::New => {
            let Some(target) = frame.target else {
                return;
            };
            if state.subs.contains_key(&frame.id) || state.subs.len() >= MAX_MUX_SUBSESSIONS {
                send_error_end(&state.mux_tx, frame.id);
                return;
            }
            match target.network {
                MuxNetwork::Tcp => {
                    state.metrics.inc_mux_substreams();
                    let (up_tx, up_rx) =
                        mpsc::channel::<QueuedMuxPayload>(MUX_SUBSTREAM_CHANNEL_CAPACITY);
                    if !frame.payload.is_empty()
                        && !try_enqueue_tcp_payload(
                            &up_tx,
                            &state.tunnel_byte_budget,
                            frame.payload,
                        )
                        .await
                    {
                        send_error_end(&state.mux_tx, frame.id);
                        return;
                    }
                    let id = frame.id;
                    let egress = state.egress_ctx;
                    let resolver = state.dns_resolver.as_ref().map(Arc::clone);
                    let tx_out = state.mux_tx.clone();
                    let m = Arc::clone(&state.metrics);
                    let handle = tokio::spawn(async move {
                        run_mux_tcp_substream(id, target, egress, resolver, up_rx, tx_out, m).await;
                    });
                    state
                        .subs
                        .insert(frame.id, MuxSubsession::Tcp((up_tx, handle)));
                }
                MuxNetwork::Udp => {
                    state.metrics.inc_mux_substreams();
                    let key = match frame.global_id {
                        Some(gid) => UdpNatKey::Xudp {
                            uuid: state.uuid_bytes,
                            global_id: gid,
                        },
                        None => UdpNatKey::Local {
                            tunnel_id: state.tunnel_id,
                            session_id: frame.id,
                        },
                    };
                    if matches!(key, UdpNatKey::Xudp { .. })
                        && !state.active_xudp_entries.contains_key(&key)
                        && state.active_xudp_entries.len() >= MAX_PER_UUID_XUDP_SESSIONS
                    {
                        send_error_end(&state.mux_tx, frame.id);
                        return;
                    }
                    let mut handle = UdpSessionHandle {
                        key,
                        default_target: Some(target.clone()),
                        resolved_cache: Arc::new(Mutex::new(None)),
                    };
                    if !frame.payload.is_empty() {
                        dispatch_udp_payload(
                            frame.id,
                            Some(&target),
                            &frame.payload,
                            &mut handle,
                            state,
                        )
                        .await;
                    }
                    state.subs.insert(frame.id, MuxSubsession::Udp(handle));
                }
            }
        }
        MuxStatus::Keep => match state.subs.get_mut(&frame.id) {
            Some(MuxSubsession::Tcp((up_tx, _))) => {
                if !frame.payload.is_empty()
                    && !try_enqueue_tcp_payload(up_tx, &state.tunnel_byte_budget, frame.payload)
                        .await
                {
                    if let Some(MuxSubsession::Tcp((_, h))) = state.subs.remove(&frame.id) {
                        h.abort();
                    }
                    send_error_end(&state.mux_tx, frame.id);
                }
            }
            Some(MuxSubsession::Udp(_)) => {
                if !frame.payload.is_empty() {
                    if let Some(MuxSubsession::Udp(mut sub)) = state.subs.remove(&frame.id) {
                        dispatch_udp_payload(
                            frame.id,
                            frame.target.as_ref(),
                            &frame.payload,
                            &mut sub,
                            state,
                        )
                        .await;
                        state.subs.insert(frame.id, MuxSubsession::Udp(sub));
                    }
                }
            }
            None => {
                // Single-XUDP / client resumption: `Keep` carrying a `GlobalID` + target
                // after an implicit session `0` setup.
                if let (Some(target), Some(gid)) = (&frame.target, frame.global_id) {
                    if target.network == MuxNetwork::Udp && state.subs.len() < MAX_MUX_SUBSESSIONS {
                        let key = UdpNatKey::Xudp {
                            uuid: state.uuid_bytes,
                            global_id: gid,
                        };
                        if !state.active_xudp_entries.contains_key(&key)
                            && state.active_xudp_entries.len() >= MAX_PER_UUID_XUDP_SESSIONS
                        {
                            return;
                        }
                        let mut sub = UdpSessionHandle {
                            key,
                            default_target: Some(target.clone()),
                            resolved_cache: Arc::new(Mutex::new(None)),
                        };
                        if !frame.payload.is_empty() {
                            dispatch_udp_payload(
                                frame.id,
                                Some(target),
                                &frame.payload,
                                &mut sub,
                                state,
                            )
                            .await;
                        }
                        state.subs.insert(frame.id, MuxSubsession::Udp(sub));
                    }
                }
            }
        },
    }
}

fn record_active_xudp(
    active_xudp_entries: &mut HashMap<UdpNatKey, Weak<UdpNatEntry>>,
    key: UdpNatKey,
    entry: &Arc<UdpNatEntry>,
) -> bool {
    if !matches!(key, UdpNatKey::Xudp { .. }) {
        return true;
    }
    if let std::collections::hash_map::Entry::Occupied(mut e) = active_xudp_entries.entry(key) {
        e.insert(Arc::downgrade(entry));
        return true;
    }
    active_xudp_entries.retain(|_, w| w.strong_count() > 0);
    if active_xudp_entries.len() >= MAX_PER_UUID_XUDP_SESSIONS {
        return false;
    }
    active_xudp_entries.insert(key, Arc::downgrade(entry));
    true
}

async fn dispatch_udp_payload(
    session_id: u16,
    override_target: Option<&MuxTarget>,
    payload: &[u8],
    sub: &mut UdpSessionHandle,
    state: &mut MuxLoopState,
) {
    if payload.is_empty() || payload.len() > MAX_UDP_DATAGRAM_BYTES {
        return;
    }
    let Some(target) = override_target.or(sub.default_target.as_ref()) else {
        return;
    };
    if target.network != MuxNetwork::Udp {
        return;
    }

    // 1. Substream-local resolved cache fast path (zero network I/O, already egress-validated).
    let cached_hit = {
        let guard = sub.resolved_cache.lock().unwrap_or_else(|e| e.into_inner());
        match &*guard {
            Some((cached_addr, cached_port, cached_sock))
                if cached_addr == &target.address && *cached_port == target.port =>
            {
                Some(*cached_sock)
            }
            _ => None,
        }
    };

    let dest_sock = if let Some(sock_addr) = cached_hit {
        Some(sock_addr)
    } else if let Some(targets) = state.egress_ctx.try_resolve_cached_and_validate(
        &target.address,
        target.port,
        TransportProtocol::Udp,
        state.dns_resolver.as_deref(),
        &state.metrics,
    ) {
        let Some(&sa) = targets.first() else {
            // Denied by egress policy or negative DNS cache: return BEFORE allocating NAT entry (SEC-09).
            return;
        };
        let mut guard = sub.resolved_cache.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some((target.address.clone(), target.port, sa));
        Some(sa)
    } else {
        // 2. DNS cache miss: resolve and validate egress FIRST, only then allocate NAT entry.
        let Ok(permit) = Arc::clone(&state.udp_dns_sem).try_acquire_owned() else {
            state.metrics.inc_xudp_dropped();
            return;
        };
        if matches!(sub.key, UdpNatKey::Xudp { .. })
            && !state.active_xudp_entries.contains_key(&sub.key)
            && state.active_xudp_entries.len() >= MAX_PER_UUID_XUDP_SESSIONS
        {
            state.metrics.inc_xudp_dropped();
            return;
        }
        let target_owned = target.clone();
        let payload_owned = Zeroizing::new(payload.to_vec());
        let egress = state.egress_ctx;
        let resolver = state.dns_resolver.as_ref().map(Arc::clone);
        let key = sub.key;
        let cache_slot = Arc::clone(&sub.resolved_cache);
        let table = Arc::clone(&state.udp_table);
        let mux_tx = state.mux_tx.clone();
        let m = Arc::clone(&state.metrics);
        state.udp_dns_tasks.spawn(async move {
            let _permit = permit;
            let targets = egress
                .resolve_and_validate(
                    &target_owned.address,
                    target_owned.port,
                    TransportProtocol::Udp,
                    resolver.as_deref(),
                    &m,
                )
                .await;
            let Some(&sock_addr) = targets.first() else {
                return;
            };
            {
                let mut guard = cache_slot.lock().unwrap_or_else(|e| e.into_inner());
                *guard = Some((target_owned.address, target_owned.port, sock_addr));
            }
            let Some(entry) = table.get_or_insert(key, session_id, &mux_tx) else {
                m.inc_xudp_dropped();
                return;
            };
            let Some(sock) = ensure_udp_socket_and_spawn_reader(
                key,
                sock_addr.is_ipv6(),
                entry,
                table,
                egress,
                Arc::clone(&m),
            )
            .await
            else {
                return;
            };
            if sock.send_to(&payload_owned, sock_addr).await.is_ok() {
                m.inc_xudp_packets();
            }
        });
        return;
    };

    let Some(dest_sock) = dest_sock else {
        return;
    };
    let Some(entry) = state
        .udp_table
        .get_or_insert(sub.key, session_id, &state.mux_tx)
    else {
        state.metrics.inc_xudp_dropped();
        return;
    };
    if !record_active_xudp(&mut state.active_xudp_entries, sub.key, &entry) {
        state.metrics.inc_xudp_dropped();
        return;
    }

    let Some(sock) = ensure_udp_socket_and_spawn_reader(
        sub.key,
        dest_sock.is_ipv6(),
        entry,
        Arc::clone(&state.udp_table),
        state.egress_ctx,
        Arc::clone(&state.metrics),
    )
    .await
    else {
        return;
    };

    if sock.send_to(payload, dest_sock).await.is_ok() {
        state.metrics.inc_xudp_packets();
    }
}

async fn ensure_udp_socket_and_spawn_reader(
    key: UdpNatKey,
    is_ipv6: bool,
    entry: Arc<UdpNatEntry>,
    udp_table: Arc<GlobalUdpTable>,
    egress_ctx: EgressContext,
    metrics: Arc<Metrics>,
) -> Option<Arc<UdpSocket>> {
    if entry.is_closed() {
        return None;
    }
    let slot = if is_ipv6 {
        &entry.v6_sock
    } else {
        &entry.v4_sock
    };

    let mut guard = slot.lock().await;
    if entry.is_closed() {
        return None;
    }
    if let Some(existing) = &*guard {
        return Some(Arc::clone(existing));
    }

    let bind_addr = if is_ipv6 { "[::]:0" } else { "0.0.0.0:0" };
    let sock = Arc::new(UdpSocket::bind(bind_addr).await.ok()?);
    tune_udp_socket(&sock, XUDP_UDP_SOCKET_BUFFER_BYTES);
    *guard = Some(Arc::clone(&sock));

    let reader_sock = Arc::clone(&sock);
    let reader_entry = Arc::clone(&entry);
    let policy = egress_ctx.build_policy();
    let join_handle = tokio::spawn(async move {
        let mut buf = Zeroizing::new(vec![0u8; MAX_UDP_DATAGRAM_BYTES]);
        let idle_ms = u64::try_from(XUDP_IDLE_TIMEOUT.as_millis()).unwrap_or(120_000);
        loop {
            match tokio::time::timeout(XUDP_IDLE_TIMEOUT, reader_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, peer))) => {
                    let Some(slice) = buf.get(..n) else {
                        break;
                    };
                    // SEC-10: Filter incoming Full-Cone UDP peer through EgressPolicy before
                    // refreshing idle timer or relaying to client.
                    let Ok(validated_peer) =
                        policy.validate_target(peer.ip(), peer.port(), TransportProtocol::Udp)
                    else {
                        continue;
                    };
                    let active = {
                        let mut sink_guard = reader_entry
                            .active_sink
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        match &*sink_guard {
                            Some((sid, tx)) if !tx.is_closed() => Some((*sid, tx.clone())),
                            Some(_) => {
                                *sink_guard = None;
                                None
                            }
                            None => None,
                        }
                    };
                    let Some((session_id, tx)) = active else {
                        // Do NOT refresh `last_active_ms` without an active client sink (SEC-10).
                        continue;
                    };

                    let now_ms = udp_table.now_ms();
                    reader_entry.last_active_ms.store(now_ms, Ordering::Relaxed);

                    let addr = match validated_peer.ip() {
                        IpAddr::V4(v4) => VlessAddress::Ipv4(v4),
                        IpAddr::V6(v6) => VlessAddress::Ipv6(v6),
                    };
                    let frame = MuxFrame {
                        id: session_id,
                        status: MuxStatus::Keep,
                        opt_data: true,
                        opt_error: false,
                        target: Some(MuxTarget {
                            network: MuxNetwork::Udp,
                            port: validated_peer.port(),
                            address: addr,
                        }),
                        global_id: None,
                        payload: Zeroizing::new(slice.to_vec()),
                    };
                    if tx.try_send(frame).is_err() {
                        metrics.inc_xudp_dropped();
                    }
                }
                Err(_) => {
                    let now_ms = udp_table.now_ms();
                    let last_ms = reader_entry.last_active_ms.load(Ordering::Relaxed);
                    if now_ms.saturating_sub(last_ms) < idle_ms {
                        continue;
                    }
                    break;
                }
                Ok(Err(_)) => {
                    break;
                }
            }
        }
        let exit_slot = if is_ipv6 {
            &reader_entry.v6_sock
        } else {
            &reader_entry.v4_sock
        };
        *exit_slot.lock().await = None;
        udp_table.remove_if_idle(key, idle_ms);
    });

    let abort_slot = if is_ipv6 {
        &entry.v6_reader
    } else {
        &entry.v4_reader
    };
    if let Some(prev) = abort_slot
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .replace(join_handle.abort_handle())
    {
        prev.abort();
    }
    drop(guard);

    if entry.is_closed() {
        entry.shutdown();
        return None;
    }

    Some(sock)
}

async fn send_mux_end(mux_tx: &mpsc::Sender<MuxFrame>, id: u16, opt_error: bool) {
    let _ = mux_tx
        .send(MuxFrame {
            id,
            status: MuxStatus::End,
            opt_data: false,
            opt_error,
            target: None,
            global_id: None,
            payload: Zeroizing::new(Vec::new()),
        })
        .await;
}

async fn run_mux_tcp_substream(
    id: u16,
    target: MuxTarget,
    egress: EgressContext,
    dns_resolver: Option<Arc<DnsResolver>>,
    mut up_rx: mpsc::Receiver<QueuedMuxPayload>,
    mux_tx: mpsc::Sender<MuxFrame>,
    metrics: Arc<Metrics>,
) {
    let targets = egress
        .resolve_and_validate(
            &target.address,
            target.port,
            TransportProtocol::Tcp,
            dns_resolver.as_deref(),
            &metrics,
        )
        .await;
    if targets.is_empty() {
        send_mux_end(&mux_tx, id, true).await;
        return;
    }

    let Some(upstream) = connect_happy_eyeballs_with_options(
        &targets,
        egress.happy_eyeballs_delay,
        egress.tcp_keepalive,
    )
    .await
    else {
        send_mux_end(&mux_tx, id, true).await;
        return;
    };

    let (mut up_read, mut up_write) = upstream.into_split();
    let peer_closed = HalfCloseSignal::new();

    let up_fut = pump_mux_tcp_uplink(
        &mut up_rx,
        &mut up_write,
        egress.half_close_timeout,
        &peer_closed,
        &metrics,
    );
    let down_fut = pump_mux_tcp_downlink(
        id,
        &mut up_read,
        &mux_tx,
        egress.half_close_timeout,
        &peer_closed,
        &metrics,
    );

    tokio::pin!(up_fut);
    tokio::pin!(down_fut);

    tokio::select! {
        biased;
        down_error = &mut down_fut => {
            peer_closed.mark_closed();
            // Immediately signal upstream EOF/error to client (no 300s stall, SEC-17),
            // then allow a bounded half-close drain for uplink before closing.
            send_mux_end(&mux_tx, id, down_error).await;
            let _ = tokio::time::timeout(egress.half_close_timeout, &mut up_fut).await;
        }
        () = &mut up_fut => {
            peer_closed.mark_closed();
            let down_error = down_fut.await;
            send_mux_end(&mux_tx, id, down_error).await;
        }
    }
}

async fn pump_mux_tcp_uplink(
    up_rx: &mut mpsc::Receiver<QueuedMuxPayload>,
    up_write: &mut OwnedWriteHalf,
    half_close_timeout: Duration,
    peer_closed: &HalfCloseSignal,
    metrics: &Metrics,
) {
    loop {
        match timeout_with_half_close(
            MUX_TCP_IDLE_TIMEOUT,
            half_close_timeout,
            peer_closed,
            up_rx.recv(),
        )
        .await
        {
            Ok(Some(chunk)) => {
                if !chunk.data.is_empty() {
                    let write_res = tokio::time::timeout(
                        MUX_CLIENT_WRITE_TIMEOUT,
                        up_write.write_all(&chunk.data),
                    )
                    .await;
                    if !matches!(write_res, Ok(Ok(()))) {
                        break;
                    }
                }
            }
            Ok(None) => {
                let _ = tokio::time::timeout(half_close_timeout, up_write.shutdown()).await;
                break;
            }
            Err(RelayElapsed) => {
                metrics.inc_idle_timeouts();
                break;
            }
        }
    }
    peer_closed.mark_closed();
}

async fn pump_mux_tcp_downlink(
    id: u16,
    up_read: &mut OwnedReadHalf,
    mux_tx: &mpsc::Sender<MuxFrame>,
    half_close_timeout: Duration,
    peer_closed: &HalfCloseSignal,
    metrics: &Metrics,
) -> bool {
    let mut buf = Zeroizing::new(vec![0u8; MUX_RELAY_CHUNK_SIZE]);
    loop {
        match timeout_with_half_close(
            MUX_TCP_IDLE_TIMEOUT,
            half_close_timeout,
            peer_closed,
            up_read.read(&mut buf),
        )
        .await
        {
            Ok(Ok(0)) => {
                peer_closed.mark_closed();
                return false;
            }
            Ok(Err(_)) => {
                peer_closed.mark_closed();
                return true;
            }
            Err(RelayElapsed) => {
                metrics.inc_idle_timeouts();
                peer_closed.mark_closed();
                return true;
            }
            Ok(Ok(n)) => {
                let Some(slice) = buf.get(..n) else {
                    peer_closed.mark_closed();
                    return true;
                };
                let frame = MuxFrame {
                    id,
                    status: MuxStatus::Keep,
                    opt_data: true,
                    opt_error: false,
                    target: None,
                    global_id: None,
                    payload: Zeroizing::new(slice.to_vec()),
                };
                if mux_tx.send(frame).await.is_err() {
                    peer_closed.mark_closed();
                    return true;
                }
            }
        }
    }
}
