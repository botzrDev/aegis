//! Policy engine errors — surfaced at load/reload time, never on the hot path.

use thiserror::Error;

/// Failure to parse or validate a policy document. Parsing happens once at
/// startup (or on hot reload); evaluation is infallible and never returns this.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    #[error("policy parse error: {0}")]
    Parse(String),

    #[error("unsupported policy version {found} (supported: {supported})")]
    UnsupportedVersion { found: u32, supported: u32 },

    #[error("invalid rule `{id}`: {reason}")]
    InvalidRule { id: String, reason: String },

    #[error("duplicate rule id `{id}`")]
    DuplicateRuleId { id: String },

    #[error("policy source read error for `{path}`: {reason}")]
    Io { path: String, reason: String },
}
