//! Linux Landlock + seccomp confinement derived from a [`CapabilityGrant`].
//!
//! # Authority-reducing only
//!
//! This crate holds no privilege, is not setuid, and its only powers are to
//! narrow the calling process and (via `aegis __confine-exec`) replace that
//! process's image with the target. An attacker who invokes the helper with
//! an empty profile gets exactly what running the target directly would have
//! given them ([ADR-0007]). That is what separates this from the setuid
//! sandbox helpers that have historically been a vulnerability class.
//!
//! `aegis __confine-exec` is an internal re-exec target, not operator
//! surface: it is dispatched first in `parse_args` and kept out of
//! `usage_text()`. The profile travels in [`PROFILE_ENV`], never argv.
//!
//! [`CapabilityGrant`]: botzr_aegis_core::CapabilityGrant
//! [ADR-0007]: https://github.com/botzrDev/aegis/blob/main/docs/adr/0007-confinement-via-self-restricting-re-exec.md

mod error;
mod profile;

pub use error::ConfineError;
pub use profile::{
    exec_support_paths, ConfinementProfile, EnforcedConfinement, NetAllow, EXEC_SUPPORT_PATHS,
    PROFILE_ENV, REPORT_ENV,
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    apply_landlock, apply_seccomp, load_profile_from_env, open_report, probe_landlock_abi,
    restrict_self, write_report, LandlockOutcome, SeccompOutcome,
};

#[cfg(not(target_os = "linux"))]
pub fn restrict_self(_profile: &ConfinementProfile) -> Result<EnforcedConfinement, ConfineError> {
    Err(ConfineError::Unsupported)
}
