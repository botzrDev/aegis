//! Runtime registration errors (tool registry + component integrity).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegisterError {
    #[error("component bytes required for registration")]
    MissingComponent,

    #[error("sha256 mismatch: expected {expected}, got {actual}")]
    Sha256Mismatch { expected: String, actual: String },

    #[error("sandbox prepare failed: {0}")]
    SandboxPrepare(String),
}
