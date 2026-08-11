//! Audit persistence errors — fail-closed by default (G3).

use std::path::PathBuf;

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

    /// No signing key at that path. Its own variant rather than an `Io` string
    /// because it is the one key-file failure an operator causes by forgetting
    /// `aegis keygen`, and the fix differs from every other read failure.
    #[error("no signing key at {path}; generate one with `aegis keygen --out {path}`")]
    KeyFileMissing { path: PathBuf },

    /// [`crate::generate_signing_key`] was asked to write over a key that
    /// already exists. Overwriting is how a Session's published public key
    /// becomes unverifiable, so it needs `force` to be spelled out.
    #[error("signing key {path} already exists; refusing to overwrite it without --force")]
    KeyFileExists { path: PathBuf },

    /// The key file is readable by group or others. Fail closed: a private key
    /// anyone on the host can read is not a private key, and signing with it
    /// would put a `Verified (pinned)` label on a secret that leaked.
    #[error("signing key {path} is readable beyond its owner (mode {mode:04o}); chmod 600 it")]
    KeyFilePermissions { path: PathBuf, mode: u32 },

    /// The bytes on disk are not a 32-byte seed in the documented dialect —
    /// exactly 64 lowercase hex characters and an optional trailing newline.
    #[error("signing key {path} is not a 64-character lowercase hex seed: {reason}")]
    KeyFileMalformed { path: PathBuf, reason: String },

    /// Reading or writing the key file failed for any other reason. Carries the
    /// path, which a bare [`AuditError::Io`] would lose.
    #[error("signing key {path}: {source}")]
    KeyFileIo {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The OS would not supply 32 random bytes, so no key was generated.
    /// Reported as text rather than a typed source so the entropy crate stays
    /// out of this crate's public API.
    #[error("could not read 32 random bytes from the operating system: {detail}")]
    Entropy { detail: String },
}
