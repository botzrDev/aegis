//! Failures from applying a confinement profile to the calling process.

use thiserror::Error;

/// Why `restrict_self` refused to confine the calling process.
///
/// Every variant is a reason **not** to exec. A loud warning that still
/// continues is how a script inherits a child that was never confined
/// (ADR-0007).
#[derive(Debug, Error)]
pub enum ConfineError {
    /// The running kernel cannot enforce the full profile, and
    /// `best_effort` was not set.
    #[error("requested confinement cannot be fully enforced: {0}")]
    NotFullyEnforced(String),

    /// Landlock is unavailable on this kernel and `best_effort` was not set.
    #[error("Landlock is not available on this kernel")]
    LandlockUnavailable,

    /// A granted path could not be opened for a Landlock rule.
    #[error("cannot open granted path {path}: {source}")]
    Path {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Building or installing the seccomp filter failed.
    #[error("seccomp filter failed: {0}")]
    Seccomp(String),

    /// The profile JSON in `AEGIS_CONFINE_PROFILE` could not be read.
    #[error("invalid AEGIS_CONFINE_PROFILE: {0}")]
    Profile(String),

    /// Writing the enforcement report failed.
    #[error("could not write confinement report: {0}")]
    Report(#[from] std::io::Error),

    /// Confinement is Linux-only.
    #[error("confinement is only implemented on Linux")]
    Unsupported,
}
