//! `aegis wrap` — the CLI surface over the stdio interposer in
//! `botzr-aegis-wrap` (AILAB-625).
//!
//! **Argument shim and exit mapping only.** The relay — the reader threads, the
//! event loop, the audit sessions, the bounded reap — lives in
//! [`botzr_aegis_wrap::run_wrap`] and stays there. A second pump in the CLI
//! would be a second thing to keep deadlock-free, and the one in the library is
//! the one the relay tests drive against a real child process.
//!
//! Nothing here reaches for the runtime, a policy, or a sandbox. Wrap's only
//! station is AUDIT: the child is an ordinary OS process, not a WASM guest, and
//! this module must never grow the ability to make it look like one.
//!
//! The exit code is the child's, passed through. An operator who scripts
//! `aegis wrap -- some-server` gets the same code they would have got running
//! `some-server` directly, so putting Aegis in the middle does not rewrite the
//! meaning of a failure. Exit 1 is reserved for wrap itself failing to start or
//! to record — which, since a wrap session that cannot record is a session with
//! no reason to exist, is a refusal rather than a degraded run.

use std::process::ExitCode;

use botzr_aegis_wrap::{run_wrap, WrapConfig};

use crate::WrapArgs;

pub(crate) fn run(args: &WrapArgs) -> ExitCode {
    let config = WrapConfig {
        child_argv: args.child_argv.clone(),
        audit_path: args.audit.clone(),
        signing_key_path: args.signing_key.clone(),
    };

    match run_wrap(&config) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}
