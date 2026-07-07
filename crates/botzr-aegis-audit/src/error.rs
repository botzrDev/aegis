//! Audit persistence errors — fail-closed by default (G3).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("unsupported audit schema version {found} (supported: {supported})")]
    UnsupportedSchema { found: u32, supported: u32 },

    #[error("audit write failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("audit serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}
