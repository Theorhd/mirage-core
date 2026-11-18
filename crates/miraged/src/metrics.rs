//! Lock-free, aggregate-only in-memory counters (zero PII, zero labels).

use core::sync::atomic::{AtomicU64, Ordering};

/// In-memory aggregate connection counters.
#[derive(Debug, Default)]
pub struct Metrics {
    accepted: AtomicU64,
    delegated_fallback: AtomicU64,
    sni_matched: AtomicU64,
    timeout_delegated: AtomicU64,
    oversize_delegated: AtomicU64,
    dial_dest_failed: AtomicU64,
}

impl Metrics {
    /// Creates zeroed metrics counters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_accepted(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_delegated_fallback(&self) {
        self.delegated_fallback.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_sni_matched(&self) {
        self.sni_matched.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_timeout_delegated(&self) {
        self.timeout_delegated.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_oversize_delegated(&self) {
        self.oversize_delegated.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_dial_dest_failed(&self) {
        self.dial_dest_failed.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn delegated_fallback(&self) -> u64 {
        self.delegated_fallback.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn sni_matched(&self) -> u64 {
        self.sni_matched.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn timeout_delegated(&self) -> u64 {
        self.timeout_delegated.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn oversize_delegated(&self) -> u64 {
        self.oversize_delegated.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn dial_dest_failed(&self) -> u64 {
        self.dial_dest_failed.load(Ordering::Relaxed)
    }
}
