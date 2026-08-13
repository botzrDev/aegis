//! Failures the relay can meet before or during a wrap session.
//!
//! Deliberately small: a wrap process either fails to *start* (no child, no
//! key, no audit sink) or fails while moving bytes. Anything the child itself
//! says — including a JSON-RPC `error` object — is not an error of wrap's, and
//! has no variant here.
//!
//! Neither `Clone` nor `PartialEq` is derived: [`botzr_aegis_audit::AuditError`]
//! is neither, and widening this enum to match would mean re-spelling an audit
//! failure as a string and losing its source.

use botzr_aegis_audit::AuditError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WrapError {
    /// `WrapConfig::child_argv` was empty. There is nothing to interpose on, and
    /// silently relaying client stdin to nowhere would look like a working
    /// session that records nothing.
    #[error("wrap needs a child command to run: child_argv is empty")]
    EmptyArgv,

    /// The child program could not be started. Carries the program name because
    /// a bare `No such file or directory` does not say *which* file.
    #[error("could not spawn child `{program}`: {source}")]
    Spawn {
        program: String,
        source: std::io::Error,
    },

    /// Moving bytes between the client and the child failed.
    #[error("wrap relay I/O failed: {0}")]
    Io(#[from] std::io::Error),

    /// The audit sink refused a record. Fail-closed: a relay that cannot record
    /// a `tools/call` stops rather than keeping the pipe open unrecorded.
    #[error("wrap audit failed: {0}")]
    Audit(#[from] AuditError),
}
