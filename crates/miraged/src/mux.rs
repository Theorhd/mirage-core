//! `Mux.Cool` (`v1.mux.cool`) sub-stream multiplexer and `XUDP` Full-Cone NAT.
//!
//! Supports concurrent multiplexed TCP streams and connectionless Full-Cone
//! UDP NAT sessions keyed by `(VlessUuid, GlobalID)` (or ephemeral local ID),
//! with strict `EgressPolicy` validation on every initial and per-packet
//! destination override.

use core::net::{IpAddr, SocketAddr};
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use mirage_core::mux::{
    decode_mux_frame, encode_mux_frame_into, MuxFrame, MuxNetwork, MuxStatus, MuxTarget,
};
use mirage_core::reality::{RealityTlsReader, RealityTlsWriter};
use mirage_core::tls_parser::MAX_TLS_RECORD_FRAGMENT;
use mirage_core::vless::{encode_vless_response_header, VlessAddress, VlessUuid};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::{AbortHandle, JoinHandle};
use zeroize::{Zeroize, Zeroizing};

use crate::dns::DnsResolver;
use crate::metrics::Metrics;
use crate::net_opt::{tune_udp_socket, UDP_SOCKET_BUFFER_BYTES};
use crate::outbound::{connect_happy_eyeballs_with_options, EgressContext};

/// Maximum buffered undecoded Mux stream bytes per connection (`256 KiB`).
const MAX_MUX_STREAM_BUFFER: usize = 256 * 1024;

/// Maximum concurrent multiplexed TCP sub-sessions allowed per tunnel.
const MAX_MUX_TCP_SUBSESSIONS: usize = 256;

/// Maximum concurrent multiplexed UDP sub-sessions tracked per tunnel.
const MAX_MUX_UDP_SUBSESSIONS: usize = 256;

/// Maximum distinct Full-Cone XUDP sessions referenced by a single tunnel.
const MAX_TUNNEL_XUDP_SESSIONS: usize = 128;

/// Maximum concurrent Full-Cone XUDP/UDP NAT mappings retained globally in RAM.
const MAX_GLOBAL_UDP_SESSIONS: usize = 1024;

/// Maximum outbound Mux frames queued per client tunnel before backpressure.
const MUX_OUTBOUND_CHANNEL_CAPACITY: usize = 1024;

/// Maximum queued uplink chunks per Mux TCP sub-session.
const MUX_SUBSTREAM_CHANNEL_CAPACITY: usize = 128;

/// Maximum time the Mux reader loop waits for a single stalled TCP sub-stream
/// channel before terminating that sub-stream to avoid tunnel-wide Head-of-Line blocking.
const MUX_SUBSTREAM_SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum concurrent background DNS resolutions spawned for Mux UDP cache misses per tunnel.
const MAX_MUX_ASYNC_UDP_DNS_TASKS: usize = 32;

/// Read chunk size for TCP sub-streams and TLS record framing (`16 KiB` matches max TLS 1.3 fragment).
const MUX_RELAY_CHUNK_SIZE: usize = 16 * 1024;

/// Idle timeout for Mux tunnel & TCP sub-streams.
const MUX_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Idle timeout for Full-Cone XUDP NAT sockets.
const XUDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum UDP datagram payload accepted by XUDP NAT receivers.
const MAX_UDP_DATAGRAM_BYTES: usize = 65_507;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum UdpNatKey {
    Xudp { uuid: [u8; 16], global_id: [u8; 8] },
    Local { tunnel_id: u64, session_id: u16 },
}

struct UdpNatEntry {
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
            v4_sock: tokio::sync::Mutex::new(None),
            v6_sock: tokio::sync::Mutex::new(None),
            v4_reader: Mutex::new(None),
            v6_reader: Mutex::new(None),
            active_sink: Mutex::new(Some((session_id, tx))),
            last_active_ms: AtomicU64::new(now_ms),
        }
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

    fn shutdown(&self) {
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

/// Shared RAM-only Full-Cone UDP NAT table keyed by `(VlessUuid, GlobalID)`
/// for XUDP and `(tunnel_id, session_id)` for standard Mux UDP.
pub struct GlobalUdpTable {
    started_at: Instant,
    next_tunnel_id: AtomicU64,
    entries: Mutex<HashMap<UdpNatKey, Arc<UdpNatEntry>>>,
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
            entries: Mutex::new(HashMap::new()),
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
    ) -> Arc<UdpNatEntry> {
        let now_ms = self.now_ms();
        let idle_ms = u64::try_from(XUDP_IDLE_TIMEOUT.as_millis()).unwrap_or(120_000);

        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = guard.get(&key) {
            existing.touch(now_ms, session_id, tx);
            return Arc::clone(existing);
        }

        if guard.len() >= MAX_GLOBAL_UDP_SESSIONS {
            guard.retain(|_, v| {
                let keep =
                    now_ms.saturating_sub(v.last_active_ms.load(Ordering::Relaxed)) < idle_ms;
                if !keep {
                    v.shutdown();
                }
                keep
            });
            if guard.len() >= MAX_GLOBAL_UDP_SESSIONS {
                if let Some(oldest_key) = guard
                    .iter()
                    .min_by_key(|(_, v)| v.last_active_ms.load(Ordering::Relaxed))
                    .map(|(k, _)| *k)
                {
                    if let Some(evicted) = guard.remove(&oldest_key) {
                        evicted.shutdown();
                    }
                }
            }
        }

        let entry = Arc::new(UdpNatEntry::new(now_ms, session_id, tx.clone()));
        guard.insert(key, Arc::clone(&entry));
        entry
    }

    fn remove_local_session(&self, tunnel_id: u64, session_id: u16) {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(removed) = guard.remove(&UdpNatKey::Local {
            tunnel_id,
            session_id,
        }) {
            removed.shutdown();
        }
    }

    fn cleanup_tunnel_locals(&self, tunnel_id: u64) {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|k, v| {
            let is_local =
                matches!(k, UdpNatKey::Local { tunnel_id: tid, .. } if *tid == tunnel_id);
            if is_local {
                v.shutdown();
            }
            !is_local
        });
    }

    fn remove_if_idle(&self, key: UdpNatKey, idle_ms: u64) {
        let now_ms = self.now_ms();
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.get(&key) {
            if now_ms.saturating_sub(entry.last_active_ms.load(Ordering::Relaxed)) >= idle_ms {
                if let Some(removed) = guard.remove(&key) {
                    removed.shutdown();
                }
            }
        }
    }
}

type TcpSubstreamEntry = (mpsc::Sender<Zeroizing<Vec<u8>>>, JoinHandle<()>);

type SharedResolvedUdpTarget = Arc<Mutex<Option<(VlessAddress, u16, SocketAddr)>>>;

struct UdpSessionHandle {
    key: UdpNatKey,
    default_target: Option<MuxTarget>,
    resolved_cache: SharedResolvedUdpTarget,
}

/// Runs a `Mux.Cool` + `XUDP` multiplexed tunnel over Reality TLS 1.3.
#[allow(clippy::too_many_arguments)]
pub async fn relay_vless_mux(
    mut client: tokio::net::TcpStream,
    mut tls_reader: RealityTlsReader,
    mut tls_writer: RealityTlsWriter,
    uuid: VlessUuid,
    mut trailing_app_data: Zeroizing<Vec<u8>>,
    egress_ctx: EgressContext,
    dns_resolver: Option<Arc<DnsResolver>>,
    udp_table: Arc<GlobalUdpTable>,
    metrics: Arc<Metrics>,
) {
    let resp_hdr = encode_vless_response_header();
    let Ok(sealed_hdr) = tls_writer.seal_app_data(&resp_hdr) else {
        return;
    };
    if client.write_all(&sealed_hdr).await.is_err() {
        return;
    }

    let tunnel_id = udp_table.alloc_tunnel_id();
    let uuid_bytes = *uuid.as_bytes();
    let (mut client_read, mut client_write) = client.into_split();

    let (mux_tx, mut mux_rx) = mpsc::channel::<MuxFrame>(MUX_OUTBOUND_CHANNEL_CAPACITY);

    let writer_handle = tokio::spawn(async move {
        let mut frame_buf = Zeroizing::new(Vec::with_capacity(4096));
        let mut batch_buf = Zeroizing::new(Vec::with_capacity(MAX_TLS_RECORD_FRAGMENT));
        let mut record_buf = Zeroizing::new(Vec::with_capacity(MAX_TLS_RECORD_FRAGMENT + 32));
        while let Some(frame) = mux_rx.recv().await {
            if encode_mux_frame_into(&frame, &mut frame_buf).is_err() {
                break;
            }
            batch_buf.clear();
            if frame_buf.len() <= MAX_TLS_RECORD_FRAGMENT {
                batch_buf.extend_from_slice(&frame_buf);

                // Opportunistically coalesce queued frames into a single 16 KiB TLS 1.3 record.
                while batch_buf.len() < MAX_TLS_RECORD_FRAGMENT {
                    match mux_rx.try_recv() {
                        Ok(next_frame) => {
                            if encode_mux_frame_into(&next_frame, &mut frame_buf).is_err() {
                                let _ = client_write.shutdown().await;
                                return;
                            }
                            if batch_buf.len().saturating_add(frame_buf.len())
                                <= MAX_TLS_RECORD_FRAGMENT
                            {
                                batch_buf.extend_from_slice(&frame_buf);
                            } else {
                                if !batch_buf.is_empty() {
                                    if tls_writer
                                        .seal_app_data_into(&batch_buf, &mut record_buf)
                                        .is_err()
                                        || client_write.write_all(&record_buf).await.is_err()
                                    {
                                        return;
                                    }
                                    batch_buf.clear();
                                }
                                if frame_buf.len() <= MAX_TLS_RECORD_FRAGMENT {
                                    batch_buf.extend_from_slice(&frame_buf);
                                } else {
                                    let mut off = 0usize;
                                    while off < frame_buf.len() {
                                        let end = off
                                            .saturating_add(MAX_TLS_RECORD_FRAGMENT)
                                            .min(frame_buf.len());
                                        let Some(chunk) = frame_buf.get(off..end) else {
                                            break;
                                        };
                                        if tls_writer
                                            .seal_app_data_into(chunk, &mut record_buf)
                                            .is_err()
                                            || client_write.write_all(&record_buf).await.is_err()
                                        {
                                            return;
                                        }
                                        off = end;
                                    }
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }

                if !batch_buf.is_empty()
                    && (tls_writer
                        .seal_app_data_into(&batch_buf, &mut record_buf)
                        .is_err()
                        || client_write.write_all(&record_buf).await.is_err())
                {
                    return;
                }
            } else {
                let mut off = 0usize;
                while off < frame_buf.len() {
                    let end = off
                        .saturating_add(MAX_TLS_RECORD_FRAGMENT)
                        .min(frame_buf.len());
                    let Some(chunk) = frame_buf.get(off..end) else {
                        break;
                    };
                    if tls_writer
                        .seal_app_data_into(chunk, &mut record_buf)
                        .is_err()
                        || client_write.write_all(&record_buf).await.is_err()
                    {
                        return;
                    }
                    off = end;
                }
            }
        }
        let _ = client_write.shutdown().await;
    });

    let mut tcp_subs: HashMap<u16, TcpSubstreamEntry> = HashMap::new();
    let mut udp_subs: HashMap<u16, UdpSessionHandle> = HashMap::new();
    let mut active_xudp_entries: HashMap<UdpNatKey, Arc<UdpNatEntry>> = HashMap::new();
    let udp_dns_sem = Arc::new(Semaphore::new(MAX_MUX_ASYNC_UDP_DNS_TASKS));

    let mut mux_buf = Zeroizing::new(Vec::with_capacity(8192));
    let mut mux_off = 0usize;
    mux_buf.extend_from_slice(&trailing_app_data);
    trailing_app_data.zeroize();

    let mut wire = [0u8; MUX_RELAY_CHUNK_SIZE];
    let mut record_payload = Zeroizing::new(Vec::with_capacity(MAX_TLS_RECORD_FRAGMENT + 32));

    'outer: loop {
        loop {
            let Some(avail) = mux_buf.get(mux_off..) else {
                mux_buf.clear();
                mux_off = 0;
                break;
            };
            match decode_mux_frame(avail) {
                Ok(Some((frame, consumed))) => {
                    mux_off = mux_off.saturating_add(consumed);
                    handle_decoded_mux_frame(
                        frame,
                        tunnel_id,
                        uuid_bytes,
                        &egress_ctx,
                        dns_resolver.as_ref(),
                        &udp_table,
                        &mux_tx,
                        &mut tcp_subs,
                        &mut udp_subs,
                        &mut active_xudp_entries,
                        &udp_dns_sem,
                        &metrics,
                    )
                    .await;
                }
                Ok(None) => break,
                Err(_) => break 'outer,
            }
        }

        if mux_off >= mux_buf.len() {
            mux_buf.clear();
            mux_off = 0;
        } else if mux_off >= 16 * 1024 {
            mux_buf.drain(..mux_off);
            mux_off = 0;
        }

        // Reap finished TCP sub-session tasks without scanning on every frame.
        tcp_subs.retain(|_, (_, h)| !h.is_finished());

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
                    record_payload.zeroize();
                    break 'outer;
                }
                Ok(Some(_)) => {
                    record_payload.zeroize();
                    continue;
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
                if let Some(s) = wire.get(..n) {
                    tls_reader.push_wire_bytes(s);
                }
            }
        }
    }

    for (_, entry) in active_xudp_entries {
        entry.clear_sink_if_same(&mux_tx);
    }
    drop(mux_tx);
    for (_, (tx, handle)) in tcp_subs {
        drop(tx);
        handle.abort();
    }
    udp_table.cleanup_tunnel_locals(tunnel_id);
    writer_handle.abort();
}

#[allow(clippy::too_many_arguments)]
async fn handle_decoded_mux_frame(
    frame: MuxFrame,
    tunnel_id: u64,
    uuid_bytes: [u8; 16],
    egress_ctx: &EgressContext,
    dns_resolver: Option<&Arc<DnsResolver>>,
    udp_table: &Arc<GlobalUdpTable>,
    mux_tx: &mpsc::Sender<MuxFrame>,
    tcp_subs: &mut HashMap<u16, TcpSubstreamEntry>,
    udp_subs: &mut HashMap<u16, UdpSessionHandle>,
    active_xudp_entries: &mut HashMap<UdpNatKey, Arc<UdpNatEntry>>,
    udp_dns_sem: &Arc<Semaphore>,
    metrics: &Arc<Metrics>,
) {
    match frame.status {
        MuxStatus::KeepAlive => {}
        MuxStatus::End => {
            if let Some((tx, handle)) = tcp_subs.remove(&frame.id) {
                drop(tx);
                handle.abort();
            }
            if let Some(u) = udp_subs.remove(&frame.id) {
                if let UdpNatKey::Local {
                    tunnel_id: tid,
                    session_id: sid,
                } = u.key
                {
                    udp_table.remove_local_session(tid, sid);
                }
            }
        }
        MuxStatus::New => {
            let Some(target) = frame.target else {
                return;
            };
            match target.network {
                MuxNetwork::Tcp => {
                    if tcp_subs.contains_key(&frame.id) || tcp_subs.len() >= MAX_MUX_TCP_SUBSESSIONS
                    {
                        let _ = mux_tx.try_send(MuxFrame {
                            id: frame.id,
                            status: MuxStatus::End,
                            opt_data: false,
                            opt_error: true,
                            target: None,
                            global_id: None,
                            payload: Zeroizing::new(Vec::new()),
                        });
                        return;
                    }
                    metrics.inc_mux_substreams();
                    let (up_tx, up_rx) =
                        mpsc::channel::<Zeroizing<Vec<u8>>>(MUX_SUBSTREAM_CHANNEL_CAPACITY);
                    if !frame.payload.is_empty() {
                        let _ = up_tx.try_send(frame.payload);
                    }
                    let id = frame.id;
                    let egress = *egress_ctx;
                    let resolver = dns_resolver.map(Arc::clone);
                    let tx_out = mux_tx.clone();
                    let m = Arc::clone(metrics);
                    let handle = tokio::spawn(async move {
                        run_mux_tcp_substream(id, target, egress, resolver, up_rx, tx_out, m).await;
                    });
                    tcp_subs.insert(frame.id, (up_tx, handle));
                }
                MuxNetwork::Udp => {
                    if !udp_subs.contains_key(&frame.id)
                        && udp_subs.len() >= MAX_MUX_UDP_SUBSESSIONS
                    {
                        let _ = mux_tx.try_send(MuxFrame {
                            id: frame.id,
                            status: MuxStatus::End,
                            opt_data: false,
                            opt_error: true,
                            target: None,
                            global_id: None,
                            payload: Zeroizing::new(Vec::new()),
                        });
                        return;
                    }
                    metrics.inc_mux_substreams();
                    let key = match frame.global_id {
                        Some(gid) => UdpNatKey::Xudp {
                            uuid: uuid_bytes,
                            global_id: gid,
                        },
                        None => UdpNatKey::Local {
                            tunnel_id,
                            session_id: frame.id,
                        },
                    };
                    let handle = UdpSessionHandle {
                        key,
                        default_target: Some(target.clone()),
                        resolved_cache: Arc::new(Mutex::new(None)),
                    };
                    if let Some(prev) = udp_subs.insert(frame.id, handle) {
                        if prev.key != key {
                            if let UdpNatKey::Local {
                                tunnel_id: tid,
                                session_id: sid,
                            } = prev.key
                            {
                                udp_table.remove_local_session(tid, sid);
                            }
                        }
                    }

                    if !frame.payload.is_empty() {
                        if let Some(sub) = udp_subs.get_mut(&frame.id) {
                            dispatch_udp_payload(
                                frame.id,
                                Some(&target),
                                &frame.payload,
                                sub,
                                egress_ctx,
                                dns_resolver,
                                udp_table,
                                mux_tx,
                                active_xudp_entries,
                                udp_dns_sem,
                                metrics,
                            )
                            .await;
                        }
                    } else {
                        let entry = udp_table.get_or_insert(key, frame.id, mux_tx);
                        if matches!(key, UdpNatKey::Xudp { .. })
                            && active_xudp_entries.len() < MAX_TUNNEL_XUDP_SESSIONS
                        {
                            active_xudp_entries.entry(key).or_insert(entry);
                        }
                    }
                }
            }
        }
        MuxStatus::Keep => {
            if let Some((up_tx, _)) = tcp_subs.get(&frame.id) {
                if !frame.payload.is_empty() {
                    // Fast path: enqueue without yielding; on backpressure wait only up to
                    // `MUX_SUBSTREAM_SEND_TIMEOUT` so a single stalled substream never causes
                    // Head-of-Line blocking across the entire Mux tunnel.
                    let stalled_or_closed = match up_tx.try_send(frame.payload) {
                        Ok(()) => false,
                        Err(mpsc::error::TrySendError::Closed(_)) => true,
                        Err(mpsc::error::TrySendError::Full(payload)) => !matches!(
                            tokio::time::timeout(MUX_SUBSTREAM_SEND_TIMEOUT, up_tx.send(payload))
                                .await,
                            Ok(Ok(()))
                        ),
                    };
                    if stalled_or_closed {
                        if let Some((_, h)) = tcp_subs.remove(&frame.id) {
                            h.abort();
                        }
                        let _ = mux_tx.try_send(MuxFrame {
                            id: frame.id,
                            status: MuxStatus::End,
                            opt_data: false,
                            opt_error: true,
                            target: None,
                            global_id: None,
                            payload: Zeroizing::new(Vec::new()),
                        });
                    }
                }
                return;
            }

            if let Some(sub) = udp_subs.get_mut(&frame.id) {
                if !frame.payload.is_empty() {
                    dispatch_udp_payload(
                        frame.id,
                        frame.target.as_ref(),
                        &frame.payload,
                        sub,
                        egress_ctx,
                        dns_resolver,
                        udp_table,
                        mux_tx,
                        active_xudp_entries,
                        udp_dns_sem,
                        metrics,
                    )
                    .await;
                }
                return;
            }

            // Single-XUDP / client resumption: `Keep` carrying a `GlobalID` or target
            // after an implicit session `0` setup.
            if let (Some(target), Some(gid)) = (&frame.target, frame.global_id) {
                if target.network == MuxNetwork::Udp && udp_subs.len() < MAX_MUX_UDP_SUBSESSIONS {
                    let key = UdpNatKey::Xudp {
                        uuid: uuid_bytes,
                        global_id: gid,
                    };
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
                            egress_ctx,
                            dns_resolver,
                            udp_table,
                            mux_tx,
                            active_xudp_entries,
                            udp_dns_sem,
                            metrics,
                        )
                        .await;
                    }
                    udp_subs.insert(frame.id, sub);
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_udp_payload(
    session_id: u16,
    override_target: Option<&MuxTarget>,
    payload: &[u8],
    sub: &mut UdpSessionHandle,
    egress_ctx: &EgressContext,
    dns_resolver: Option<&Arc<DnsResolver>>,
    udp_table: &Arc<GlobalUdpTable>,
    mux_tx: &mpsc::Sender<MuxFrame>,
    active_xudp_entries: &mut HashMap<UdpNatKey, Arc<UdpNatEntry>>,
    udp_dns_sem: &Arc<Semaphore>,
    metrics: &Arc<Metrics>,
) {
    let Some(target) = override_target.or(sub.default_target.as_ref()) else {
        return;
    };
    if target.network != MuxNetwork::Udp {
        return;
    }

    let entry = udp_table.get_or_insert(sub.key, session_id, mux_tx);
    if matches!(sub.key, UdpNatKey::Xudp { .. })
        && active_xudp_entries.len() < MAX_TUNNEL_XUDP_SESSIONS
    {
        active_xudp_entries
            .entry(sub.key)
            .or_insert_with(|| Arc::clone(&entry));
    }

    // 1. Substream-local resolved cache fast path (zero network I/O).
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
    } else if let Some(targets) = egress_ctx.try_resolve_cached_and_validate(
        &target.address,
        target.port,
        false,
        dns_resolver.map(Arc::as_ref),
        metrics,
    ) {
        let sock_addr = targets.first().copied();
        if let Some(sa) = sock_addr {
            let mut guard = sub.resolved_cache.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some((target.address.clone(), target.port, sa));
        }
        sock_addr
    } else {
        // 2. DNS cache miss: offload resolution + send to a bounded background task
        // so the Mux reader loop never stalls on network DNS I/O.
        let Ok(permit) = Arc::clone(udp_dns_sem).try_acquire_owned() else {
            metrics.inc_xudp_dropped();
            return;
        };
        let target_owned = target.clone();
        let payload_owned = Zeroizing::new(payload.to_vec());
        let egress = *egress_ctx;
        let resolver = dns_resolver.map(Arc::clone);
        let key = sub.key;
        let cache_slot = Arc::clone(&sub.resolved_cache);
        let table = Arc::clone(udp_table);
        let m = Arc::clone(metrics);
        tokio::spawn(async move {
            let _permit = permit;
            let targets = egress
                .resolve_and_validate(
                    &target_owned.address,
                    target_owned.port,
                    false,
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
            let Some(sock) = ensure_udp_socket_and_spawn_reader(
                key,
                sock_addr.is_ipv6(),
                entry,
                table,
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

    let Some(sock) = ensure_udp_socket_and_spawn_reader(
        sub.key,
        dest_sock.is_ipv6(),
        entry,
        Arc::clone(udp_table),
        Arc::clone(metrics),
    )
    .await
    else {
        return;
    };

    if sock.send_to(payload, dest_sock).await.is_ok() {
        metrics.inc_xudp_packets();
    }
}

async fn ensure_udp_socket_and_spawn_reader(
    key: UdpNatKey,
    is_ipv6: bool,
    entry: Arc<UdpNatEntry>,
    udp_table: Arc<GlobalUdpTable>,
    metrics: Arc<Metrics>,
) -> Option<Arc<UdpSocket>> {
    let slot = if is_ipv6 {
        &entry.v6_sock
    } else {
        &entry.v4_sock
    };

    let mut guard = slot.lock().await;
    if let Some(existing) = &*guard {
        return Some(Arc::clone(existing));
    }

    let bind_addr = if is_ipv6 { "[::]:0" } else { "0.0.0.0:0" };
    let sock = Arc::new(UdpSocket::bind(bind_addr).await.ok()?);
    tune_udp_socket(&sock, UDP_SOCKET_BUFFER_BYTES);
    *guard = Some(Arc::clone(&sock));
    drop(guard);

    let reader_sock = Arc::clone(&sock);
    let reader_entry = Arc::clone(&entry);
    let join_handle = tokio::spawn(async move {
        let mut buf = [0u8; MAX_UDP_DATAGRAM_BYTES];
        let idle_ms = u64::try_from(XUDP_IDLE_TIMEOUT.as_millis()).unwrap_or(120_000);
        loop {
            match tokio::time::timeout(XUDP_IDLE_TIMEOUT, reader_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, peer))) => {
                    let Some(slice) = buf.get(..n) else {
                        break;
                    };
                    let now_ms = udp_table.now_ms();
                    reader_entry.last_active_ms.store(now_ms, Ordering::Relaxed);
                    let sink = reader_entry
                        .active_sink
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    if let Some((session_id, tx)) = sink {
                        let addr = match peer.ip() {
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
                                port: peer.port(),
                                address: addr,
                            }),
                            global_id: None,
                            payload: Zeroizing::new(slice.to_vec()),
                        };
                        if tx.try_send(frame).is_err() {
                            metrics.inc_xudp_dropped();
                        }
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
    mut up_rx: mpsc::Receiver<Zeroizing<Vec<u8>>>,
    mux_tx: mpsc::Sender<MuxFrame>,
    metrics: Arc<Metrics>,
) {
    let targets = egress
        .resolve_and_validate(
            &target.address,
            target.port,
            true,
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

    let up_fut = pump_mux_tcp_uplink(&mut up_rx, &mut up_write, &metrics);
    let down_fut = pump_mux_tcp_downlink(id, &mut up_read, &mux_tx, &metrics);
    let _ = tokio::join!(up_fut, down_fut);

    send_mux_end(&mux_tx, id, false).await;
}

async fn pump_mux_tcp_uplink(
    up_rx: &mut mpsc::Receiver<Zeroizing<Vec<u8>>>,
    up_write: &mut OwnedWriteHalf,
    metrics: &Metrics,
) {
    loop {
        match tokio::time::timeout(MUX_TCP_IDLE_TIMEOUT, up_rx.recv()).await {
            Ok(Some(chunk)) => {
                if !chunk.is_empty() && up_write.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            Ok(None) => {
                let _ = up_write.shutdown().await;
                break;
            }
            Err(_) => {
                metrics.inc_idle_timeouts();
                break;
            }
        }
    }
}

async fn pump_mux_tcp_downlink(
    id: u16,
    up_read: &mut OwnedReadHalf,
    mux_tx: &mpsc::Sender<MuxFrame>,
    metrics: &Metrics,
) {
    let mut buf = [0u8; MUX_RELAY_CHUNK_SIZE];
    loop {
        match tokio::time::timeout(MUX_TCP_IDLE_TIMEOUT, up_read.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Err(_) => {
                metrics.inc_idle_timeouts();
                break;
            }
            Ok(Ok(n)) => {
                let Some(slice) = buf.get(..n) else {
                    break;
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
                    break;
                }
            }
        }
    }
}
