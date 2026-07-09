//! Per-call memory limiter — the memory axis of resource accounting (R5).
//!
//! Lives in the `Store` data so the limiter closure borrows *into* the store
//! (see [`crate::engine::SandboxEngine::build_store`]); a limiter built inside
//! the closure would not outlive the borrow.

use wasmtime::ResourceLimiter;

/// Table growth ceiling (elements). Independent of the memory cap; a large
/// default that still bounds pathological table growth.
const MAX_TABLE_ELEMENTS: usize = 10_000;

/// Caps guest linear-memory growth at the grant's `max_memory_bytes`.
///
/// `memory_growing` returning `Ok(false)` makes the guest `memory.grow` return
/// `-1`; a guest that then touches the memory it assumed it got traps as an
/// out-of-bounds access, which surfaces as `ExecutionOutcome::ResourceExceeded`.
#[derive(Debug, Clone)]
pub struct MemoryLimiter {
    max_bytes: usize,
    peak_bytes: usize,
}

impl MemoryLimiter {
    pub fn new(max_bytes: u64) -> Self {
        // Saturate rather than wrap on 32-bit hosts: a grant asking for more
        // than the host address space is capped at the host maximum.
        let max_bytes = usize::try_from(max_bytes).unwrap_or(usize::MAX);
        Self {
            max_bytes,
            peak_bytes: 0,
        }
    }

    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    pub fn peak_bytes(&self) -> u64 {
        u64::try_from(self.peak_bytes).unwrap_or(u64::MAX)
    }

    fn record_size(&mut self, size: usize) {
        self.peak_bytes = self.peak_bytes.max(size);
    }
}

impl ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        self.record_size(current);
        self.record_size(desired);
        Ok(desired <= self.max_bytes)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok(desired <= MAX_TABLE_ELEMENTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_growth_up_to_cap() {
        let mut limiter = MemoryLimiter::new(128 * 1024);
        assert!(limiter.memory_growing(0, 64 * 1024, None).unwrap());
        assert!(limiter.memory_growing(64 * 1024, 128 * 1024, None).unwrap());
    }

    #[test]
    fn denies_growth_past_cap() {
        let mut limiter = MemoryLimiter::new(128 * 1024);
        assert!(!limiter
            .memory_growing(128 * 1024, 128 * 1024 + 1, None)
            .unwrap());
    }

    #[test]
    fn deny_all_grant_blocks_any_memory() {
        let mut limiter = MemoryLimiter::new(0);
        assert!(!limiter.memory_growing(0, 1, None).unwrap());
    }

    #[test]
    fn tracks_peak_memory() {
        let mut limiter = MemoryLimiter::new(128 * 1024);
        assert!(limiter.memory_growing(0, 64 * 1024, None).unwrap());
        assert_eq!(limiter.peak_bytes(), 64 * 1024);
        assert!(!limiter
            .memory_growing(64 * 1024, 256 * 1024, None)
            .unwrap());
        assert_eq!(limiter.peak_bytes(), 256 * 1024);
    }

    #[test]
    fn caps_table_growth() {
        let mut limiter = MemoryLimiter::new(u64::MAX);
        assert!(limiter.table_growing(0, MAX_TABLE_ELEMENTS, None).unwrap());
        assert!(!limiter
            .table_growing(0, MAX_TABLE_ELEMENTS + 1, None)
            .unwrap());
    }
}
