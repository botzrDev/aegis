//! In-memory, per-process fixed-window rate limiting.
//!
//! Counters are process-local and reset on restart — documented in G12, not a
//! bug. They live here (in the engine), *not* in [`crate::set::PolicySet`], so a
//! hot reload of the rule set never resets an in-flight window. Persistent /
//! cross-process counters are post-v1 (matter mainly for the sidecar).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::set::RateSpec;

/// A single fixed window: when it opened and how many calls it has admitted.
#[derive(Debug, Clone, Copy)]
struct Window {
    opened_at: Instant,
    count: u32,
}

/// Thread-safe fixed-window limiter keyed by an opaque string (rule id + tool +
/// optional session). Lock is held only for a map lookup + counter bump, well
/// under the <100 µs eval budget.
#[derive(Debug, Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<String, Window>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to admit one call under `spec` for `key`. Returns `true` if within
    /// the limit (and records the call), `false` if the window is exhausted.
    pub fn check(&self, key: &str, spec: RateSpec) -> bool {
        self.check_at(key, spec, Instant::now())
    }

    /// [`RateLimiter::check`] with an injected clock — enables deterministic
    /// tests without sleeping through real windows.
    pub fn check_at(&self, key: &str, spec: RateSpec, now: Instant) -> bool {
        let window_len = Duration::from_secs(spec.per_seconds);
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let window = windows.entry(key.to_string()).or_insert(Window {
            opened_at: now,
            count: 0,
        });

        if now.duration_since(window.opened_at) >= window_len {
            window.opened_at = now;
            window.count = 0;
        }

        if window.count < spec.max {
            window.count += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_up_to_max_then_trips() {
        let limiter = RateLimiter::new();
        let spec = RateSpec {
            max: 2,
            per_seconds: 60,
        };
        let t0 = Instant::now();

        assert!(limiter.check_at("k", spec, t0));
        assert!(limiter.check_at("k", spec, t0));
        assert!(!limiter.check_at("k", spec, t0), "third call trips");
    }

    #[test]
    fn window_resets_after_elapsed() {
        let limiter = RateLimiter::new();
        let spec = RateSpec {
            max: 1,
            per_seconds: 10,
        };
        let t0 = Instant::now();

        assert!(limiter.check_at("k", spec, t0));
        assert!(!limiter.check_at("k", spec, t0));
        let later = t0 + Duration::from_secs(11);
        assert!(
            limiter.check_at("k", spec, later),
            "new window admits again"
        );
    }

    #[test]
    fn distinct_keys_are_independent() {
        let limiter = RateLimiter::new();
        let spec = RateSpec {
            max: 1,
            per_seconds: 60,
        };
        let t0 = Instant::now();
        assert!(limiter.check_at("a", spec, t0));
        assert!(limiter.check_at("b", spec, t0));
    }
}
