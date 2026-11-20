//! Lock-free, aggregate-only in-memory counters (zero PII, zero labels).

use core::sync::atomic::{AtomicU64, Ordering};

/// Cache-line aligned atomic counter preventing cross-thread false sharing (`RUST-06`).
#[repr(align(64))]
#[derive(Debug, Default)]
struct PaddedAtomicU64(AtomicU64);

impl PaddedAtomicU64 {
    #[inline]
    fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// In-memory aggregate connection counters.
#[derive(Debug, Default)]
pub struct Metrics {
    accepted: PaddedAtomicU64,
    delegated_fallback: PaddedAtomicU64,
    sni_matched: PaddedAtomicU64,
    timeout_delegated: PaddedAtomicU64,
    oversize_delegated: PaddedAtomicU64,
    dial_dest_failed: PaddedAtomicU64,
    reality_authenticated: PaddedAtomicU64,
    reality_auth_failed: PaddedAtomicU64,
    reality_replayed_or_saturated: PaddedAtomicU64,
    reality_dest_profile_fallback: PaddedAtomicU64,
    reality_handshake_completed: PaddedAtomicU64,
    vless_tcp_sessions: PaddedAtomicU64,
    vless_udp_sessions: PaddedAtomicU64,
    vless_mux_sessions: PaddedAtomicU64,
    mux_substreams: PaddedAtomicU64,
    xudp_packets: PaddedAtomicU64,
    idle_timeouts: PaddedAtomicU64,
    vless_auth_failed: PaddedAtomicU64,
    egress_blocked: PaddedAtomicU64,
    vision_direct_switches: PaddedAtomicU64,
    dest_profile_cache_hits: PaddedAtomicU64,
    xudp_dropped: PaddedAtomicU64,
    quic_blocked: PaddedAtomicU64,
    splice_direct_copies: PaddedAtomicU64,
}

impl Metrics {
    /// Creates zeroed metrics counters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_accepted(&self) {
        self.accepted.inc();
    }

    pub fn inc_delegated_fallback(&self) {
        self.delegated_fallback.inc();
    }

    pub fn inc_sni_matched(&self) {
        self.sni_matched.inc();
    }

    pub fn inc_timeout_delegated(&self) {
        self.timeout_delegated.inc();
    }

    pub fn inc_oversize_delegated(&self) {
        self.oversize_delegated.inc();
    }

    pub fn inc_dial_dest_failed(&self) {
        self.dial_dest_failed.inc();
    }

    pub fn inc_reality_authenticated(&self) {
        self.reality_authenticated.inc();
    }

    pub fn inc_reality_auth_failed(&self) {
        self.reality_auth_failed.inc();
    }

    pub fn inc_reality_replayed_or_saturated(&self) {
        self.reality_replayed_or_saturated.inc();
    }

    pub fn inc_reality_dest_profile_fallback(&self) {
        self.reality_dest_profile_fallback.inc();
    }

    pub fn inc_reality_handshake_completed(&self) {
        self.reality_handshake_completed.inc();
    }

    pub fn inc_vless_tcp_sessions(&self) {
        self.vless_tcp_sessions.inc();
    }

    pub fn inc_vless_udp_sessions(&self) {
        self.vless_udp_sessions.inc();
    }

    pub fn inc_vless_mux_sessions(&self) {
        self.vless_mux_sessions.inc();
    }

    pub fn inc_mux_substreams(&self) {
        self.mux_substreams.inc();
    }

    pub fn inc_xudp_packets(&self) {
        self.xudp_packets.inc();
    }

    pub fn inc_idle_timeouts(&self) {
        self.idle_timeouts.inc();
    }

    pub fn inc_vless_auth_failed(&self) {
        self.vless_auth_failed.inc();
    }

    pub fn inc_egress_blocked(&self) {
        self.egress_blocked.inc();
    }

    pub fn inc_vision_direct_switches(&self) {
        self.vision_direct_switches.inc();
    }

    pub fn inc_dest_profile_cache_hits(&self) {
        self.dest_profile_cache_hits.inc();
    }

    pub fn inc_xudp_dropped(&self) {
        self.xudp_dropped.inc();
    }

    pub fn inc_quic_blocked(&self) {
        self.quic_blocked.inc();
    }

    pub fn inc_splice_direct_copies(&self) {
        self.splice_direct_copies.inc();
    }

    #[must_use]
    pub fn accepted(&self) -> u64 {
        self.accepted.get()
    }

    #[must_use]
    pub fn delegated_fallback(&self) -> u64 {
        self.delegated_fallback.get()
    }

    #[must_use]
    pub fn sni_matched(&self) -> u64 {
        self.sni_matched.get()
    }

    #[must_use]
    pub fn timeout_delegated(&self) -> u64 {
        self.timeout_delegated.get()
    }

    #[must_use]
    pub fn oversize_delegated(&self) -> u64 {
        self.oversize_delegated.get()
    }

    #[must_use]
    pub fn dial_dest_failed(&self) -> u64 {
        self.dial_dest_failed.get()
    }

    #[must_use]
    pub fn reality_authenticated(&self) -> u64 {
        self.reality_authenticated.get()
    }

    #[must_use]
    pub fn reality_auth_failed(&self) -> u64 {
        self.reality_auth_failed.get()
    }

    #[must_use]
    pub fn reality_replayed_or_saturated(&self) -> u64 {
        self.reality_replayed_or_saturated.get()
    }

    #[must_use]
    pub fn reality_dest_profile_fallback(&self) -> u64 {
        self.reality_dest_profile_fallback.get()
    }

    #[must_use]
    pub fn reality_handshake_completed(&self) -> u64 {
        self.reality_handshake_completed.get()
    }

    #[must_use]
    pub fn vless_tcp_sessions(&self) -> u64 {
        self.vless_tcp_sessions.get()
    }

    #[must_use]
    pub fn vless_udp_sessions(&self) -> u64 {
        self.vless_udp_sessions.get()
    }

    #[must_use]
    pub fn vless_mux_sessions(&self) -> u64 {
        self.vless_mux_sessions.get()
    }

    #[must_use]
    pub fn mux_substreams(&self) -> u64 {
        self.mux_substreams.get()
    }

    #[must_use]
    pub fn xudp_packets(&self) -> u64 {
        self.xudp_packets.get()
    }

    #[must_use]
    pub fn idle_timeouts(&self) -> u64 {
        self.idle_timeouts.get()
    }

    #[must_use]
    pub fn vless_auth_failed(&self) -> u64 {
        self.vless_auth_failed.get()
    }

    #[must_use]
    pub fn egress_blocked(&self) -> u64 {
        self.egress_blocked.get()
    }

    #[must_use]
    pub fn vision_direct_switches(&self) -> u64 {
        self.vision_direct_switches.get()
    }

    #[must_use]
    pub fn dest_profile_cache_hits(&self) -> u64 {
        self.dest_profile_cache_hits.get()
    }

    #[must_use]
    pub fn xudp_dropped(&self) -> u64 {
        self.xudp_dropped.get()
    }

    #[must_use]
    pub fn quic_blocked(&self) -> u64 {
        self.quic_blocked.get()
    }

    #[must_use]
    pub fn splice_direct_copies(&self) -> u64 {
        self.splice_direct_copies.get()
    }
}
