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

    /// A line could not be reduced to its canonical form, so there is no
    /// well-defined thing to hash or sign. Fail rather than write a line whose
    /// hash a third-party verifier would compute differently.
    #[error("audit canonicalization failed: {0}")]
    Canonicalize(#[from] botzr_aegis_core::JcsError),

    /// The file's last line is not parseable JSON — a torn write. Opening a new
    /// Session on it would chain onto bytes nobody can hash reproducibly, so a
    /// recoverable `Indeterminate` tail is not silently turned into a permanent
    /// chain break.
    #[error("audit file has a torn final line at line {line}; refusing to chain onto it")]
    TornTail { line: usize },
}
