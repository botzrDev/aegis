//! The mechanism that reduces the calling process's authority to a profile.

use crate::error::ConfineError;
use crate::profile::{ConfinementProfile, EnforcedConfinement};

/// A mechanism that can narrow **the calling process** to a [`ConfinementProfile`].
///
/// Object-safe on purpose: the selection in [`active_confiner`] returns
/// `&'static dyn Confiner`, so adding a mechanism is a new impl rather than a
/// new `cfg` arm at every call site.
pub trait Confiner {
    /// Restrict **the calling process** and return what the kernel actually
    /// enforced.
    ///
    /// Fails closed: when `best_effort` is false and the profile cannot be
    /// fully enforced this is an error, and the caller must not `exec`.
    ///
    /// Irreversible. A Landlock domain cannot be lifted for the life of the
    /// process, so this is called in the re-exec helper and never in-process
    /// by a test.
    fn restrict_self(
        &self,
        profile: &ConfinementProfile,
    ) -> Result<EnforcedConfinement, ConfineError>;
}

/// The mechanism with no mechanism: every profile is refused.
///
/// Compiled on **every** target, not only non-Linux ones, so the trait has two
/// impls under test on the platform CI actually runs.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedConfiner;

impl Confiner for UnsupportedConfiner {
    fn restrict_self(
        &self,
        _profile: &ConfinementProfile,
    ) -> Result<EnforcedConfinement, ConfineError> {
        Err(ConfineError::Unsupported)
    }
}

/// The mechanism this build will use.
#[cfg(target_os = "linux")]
pub fn active_confiner() -> &'static dyn Confiner {
    &crate::linux::LinuxConfiner
}

/// The mechanism this build will use.
#[cfg(not(target_os = "linux"))]
pub fn active_confiner() -> &'static dyn Confiner {
    &UnsupportedConfiner
}

#[cfg(test)]
mod tests {
    // Nothing in this module may confine the test process. A Landlock domain
    // cannot be lifted once installed, so a test that invoked the Linux
    // mechanism would confine this test binary for the rest of its life and
    // silently confine every test that ran after it. Only `UnsupportedConfiner`
    // is safe to exercise in-process: it refuses before touching the kernel.
    // The Linux mechanism is proven by spawned children in `tests/escape.rs`,
    // `tests/adr0007_smoke.rs` and `crates/botzr-aegis-cli/tests/confine.rs`.

    use botzr_aegis_core::{CapabilityGrant, ToolId};

    use super::*;

    fn deny_all_profile() -> ConfinementProfile {
        ConfinementProfile::from_grant(&CapabilityGrant::deny_all(ToolId::new("t"), "g0"))
    }

    /// `best_effort` must not turn a refusal into a success: a mechanism that
    /// cannot confine at all has nothing to be best-effort about.
    #[test]
    fn unsupported_confiner_refuses_every_profile() {
        let confiner = UnsupportedConfiner;

        for profile in [
            deny_all_profile(),
            deny_all_profile().with_best_effort(true),
        ] {
            assert!(
                matches!(
                    confiner.restrict_self(&profile),
                    Err(ConfineError::Unsupported)
                ),
                "best_effort={} must still be refused, not downgraded to success",
                profile.best_effort
            );
        }
    }

    /// Compile-time proof that both impls satisfy the trait. The coercion to
    /// `&dyn Confiner` is the whole assertion; no kernel call happens here.
    #[test]
    fn confiner_is_object_safe() {
        fn takes(_: &dyn Confiner) {}

        takes(&UnsupportedConfiner);
        #[cfg(target_os = "linux")]
        takes(&crate::linux::LinuxConfiner);
    }
}
