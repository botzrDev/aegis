//! What a wrap session is configured with, and where its four streams come
//! from.

use std::io::{Read, Write};
use std::path::PathBuf;

/// One wrap session: a child to interpose on, and the record file to write.
///
/// Both paths are required. There is no temp-sink mode and no dev-key fallback
/// — a persistent record file an operator may later pin must never be signed by
/// the seed compiled into the published audit crate (AILAB-620).
#[derive(Debug, Clone)]
pub struct WrapConfig {
    /// `[0]` is the program, the rest are its arguments. Must be non-empty;
    /// an empty argv is [`crate::WrapError::EmptyArgv`].
    pub child_argv: Vec<String>,
    pub audit_path: PathBuf,
    pub signing_key_path: PathBuf,
    /// When `Some`, the child is spawned as
    /// `current_exe() __confine-exec -- <original argv>` with the profile in
    /// `AEGIS_CONFINE_PROFILE` (AILAB-628). Off unless the operator passed
    /// `--confine`.
    pub confinement: Option<botzr_aegis_confine::ConfinementProfile>,
}

/// The client-facing ends of a wrap session.
///
/// `run_wrap` fills these from the process's own stdio. They are a parameter at
/// all because the relay has to be testable against a **real** child process
/// without an in-process pipe: `std::io::pipe` is 1.87 and the workspace MSRV
/// is 1.86. This is a testability seam, not a narrowing of the product surface.
///
/// `child_err` is the sink the child's stderr is teed to — never swallowed, and
/// never merged into `client_out`, which carries JSON-RPC only. The tee is
/// byte-for-byte and imposes no encoding of its own: a server that emits a
/// progress bar, an ANSI escape or a stray non-UTF-8 byte still gets every
/// following byte through. Wrap's own lifecycle diagnostics share this sink.
pub struct WrapStreams {
    pub client_in: Box<dyn Read + Send>,
    pub client_out: Box<dyn Write + Send>,
    pub child_err: Box<dyn Write + Send>,
}
