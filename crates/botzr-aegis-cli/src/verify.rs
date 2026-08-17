//! `aegis verify` — the CLI surface over the Chain walker in
//! `botzr-aegis-audit` (ADR-0002 verdicts, ADR-0004 trust labels).
//!
//! **Formatter and exit mapping only.** The walk lives in
//! [`botzr_aegis_audit::verify_chain_file_with_trust`] and stays there: a second
//! implementation of the chain rules in the CLI would be a second thing to keep
//! correct, and the one in the library is the one under test. Nothing in this
//! module recomputes a hash, checks a signature, or decides a verdict — it turns
//! a [`Verification`] into bytes and a process exit code.
//!
//! Nothing here reaches for the runtime, the sandbox, or a policy: verifying a
//! record is reading a file, and an auditor must not have to instantiate a
//! wasmtime engine to do it. Nothing here reads a clock or a socket either —
//! the report is a pure function of the file's bytes, which is what makes two
//! runs over the same file byte-identical (ADR-0002: the verdict is
//! deterministic, asserted as a property).

use std::path::Path;
use std::process::ExitCode;

use botzr_aegis_audit::{
    load_trust_store, verify_chain_file_with_trust, AuditError, IndeterminateReason, TrustLabel,
    TrustStoreError, Verdict, Verification,
};
use botzr_aegis_core::PublicKey;

// LOAD-BEARING: these four are API the moment anyone scripts `if aegis verify`
// (ADR-0002). Exit 1 is shared with the usage-error path `main.rs` already
// owns — a caller that cannot tell "you typed it wrong" from "the file is
// forged" is reading stderr anyway. Do not add a fifth.
const EXIT_VERIFIED: u8 = 0;
const EXIT_TAMPERED: u8 = 1;
const EXIT_COULD_NOT_READ: u8 = 2;
const EXIT_INDETERMINATE: u8 = 3;
/// Spelled as its own name so the one usage error this module can raise — a
/// trust-store line that is not a key — is not read as a claim about the record.
const EXIT_USAGE: u8 = EXIT_TAMPERED;

/// Verify one Chain file and print its report.
///
/// `keys` are `--key` values and `trust_store` the optional store path; their
/// union is the trust slice. Supplying *neither* is an unpinned walk, which is a
/// different question from a failed one — see the `pinned` computation below.
/// The store's grammar is not this module's: it belongs to the record format,
/// and [`load_trust_store`] owns it.
pub fn run(path: &Path, keys: &[PublicKey], trust_store: Option<&Path>) -> ExitCode {
    // LOAD-BEARING: whether the walk is pinned is what the operator *asked for*,
    // decided here, before the store is read. A store that turns out to hold no
    // keys must not silently become an unpinned walk.
    let pinned = !keys.is_empty() || trust_store.is_some();
    // `--key` values first, then store entries. Duplicates across the two are
    // kept rather than collapsed: the slice is only ever searched with
    // `contains`, so a repeated key costs nothing and dropping one would mean
    // deciding which spelling of "the same key" wins.
    let mut trust = keys.to_vec();
    if let Some(store) = trust_store {
        match load_trust_store(store) {
            Ok(store_keys) => trust.extend(store_keys),
            Err(error) => return report_trust_store_failure(&error),
        }
    }
    // `None` and `Some(&[])` are not the same claim: `None` says "I anchored no
    // keys", while `Some(&[])` says "I accept these zero keys", so the first
    // `open` fails the pin and the file is `Tampered`. Deciding between them
    // from `trust.is_empty()` would erase the operator's stated intent before
    // the library ever saw it — a `--trust-store` that got truncated or
    // mis-mounted would keep a CI gate green with its anchor gone, which is the
    // ADR-0004 failure this flag exists to prevent.
    let trust = if pinned { Some(trust.as_slice()) } else { None };

    match verify_chain_file_with_trust(path, trust) {
        Ok(verification) => {
            print!("{}", render(&verification));
            exit_for(&verification.verdict)
        }
        // Could-not-read prints nothing on stdout: a script that pipes stdout
        // into a report must not find a half-answer there when the file was
        // never read. The user-supplied path goes to stderr only.
        Err(error) => report_read_failure(path, &error),
    }
}

/// Map a trust-store failure to an exit code and an stderr line.
///
/// The two cases exit differently on purpose. A store nobody can read is the
/// same class of failure as a Chain file nobody can read — exit 2. A store that
/// reads fine and contains something that is not a key is the operator's typo,
/// exactly like `--key deadbeef` — exit 1, the usage code.
///
/// The wording after `error: ` is the library error's own `Display`. Re-spelling
/// it here would let the message and the dialect that produced it drift, and the
/// dialect is the one under test.
fn report_trust_store_failure(error: &TrustStoreError) -> ExitCode {
    eprintln!("error: {error}");
    // Exhaustive rather than a `_` arm, so a new variant fails this build and
    // gets an exit code decided by a person.
    ExitCode::from(match error {
        TrustStoreError::Read { .. } => EXIT_COULD_NOT_READ,
        TrustStoreError::MalformedEntry { .. } => EXIT_USAGE,
    })
}

fn exit_for(verdict: &Verdict) -> ExitCode {
    ExitCode::from(match verdict {
        Verdict::Verified => EXIT_VERIFIED,
        Verdict::Tampered { .. } => EXIT_TAMPERED,
        Verdict::Indeterminate { .. } => EXIT_INDETERMINATE,
    })
}

/// Map a library error to an exit code and an stderr line.
///
/// Matched exhaustively rather than through a `_` arm so that a new
/// [`AuditError`] variant fails this build and gets an exit code decided by a
/// person. Every variant lands on 2 today for one reason: exit 2 is
/// "could not read", and a failure to produce a verdict at all is precisely
/// that. Exit 1 would assert tampering the file has not been shown to contain,
/// and exit 3 is a *verdict* — one we do not have.
fn report_read_failure(path: &Path, error: &AuditError) -> ExitCode {
    let path = path.display();
    match error {
        // The only variant this entry point can produce today: it reads the
        // file and hands the text to a pure walker. `AuditError::Io`'s own
        // `Display` reads "audit write failed", which is wrong on a read path,
        // so the source error is forwarded under our own wording.
        AuditError::Io(source) => eprintln!("error: read {path}: {source}"),
        // Not reachable through `verify_chain_file_with_trust`: the walk
        // returns a `Verdict` for every malformed input and `TornTail` is the
        // *writer* refusing to append. Handled anyway rather than assumed away.
        AuditError::UnsupportedSchema { .. }
        | AuditError::Serialize(_)
        | AuditError::Canonicalize(_)
        | AuditError::TornTail { .. } => eprintln!("error: verify {path}: {error}"),
        // `verify` never loads a *signing* key: it reads a record file and
        // checks signatures against public keys handed to it on the command
        // line. These variants belong to the emit path (AILAB-620) and cannot
        // arrive here — named rather than swept under a `_` so a future
        // key-loading verify surface has to choose its own exit code. Their
        // `Display` already names the key file, which is a different path from
        // the record file, so nothing is prefixed with `{path}`.
        AuditError::KeyFileMissing { .. }
        | AuditError::KeyFileExists { .. }
        | AuditError::KeyFilePermissions { .. }
        | AuditError::KeyFileMalformed { .. }
        | AuditError::KeyFileIo { .. }
        | AuditError::Entropy { .. }
        // Also an emit-path variant: a Durable Sink refusing the dev key is
        // raised when a Session is *opened*, and `verify` opens none. Its
        // `Display` names no path, so nothing is prefixed here either.
        | AuditError::DurableSinkNeedsProvisionedKey => eprintln!("error: {error}"),
    }
    ExitCode::from(EXIT_COULD_NOT_READ)
}

/// The report body, exactly as it goes to stdout.
///
/// A pure function of the [`Verification`] — no clock, no path, no environment
/// — so the same file yields the same bytes on every run and on every machine.
fn render(verification: &Verification) -> String {
    let mut lines = vec![label(verification)];

    // Every observed key, always, on success *and* on failure: ADR-0004 makes
    // printing the fingerprint mandatory, and an operator staring at a
    // `Tampered` file wants to know whose key signed what was there.
    for key_id in &verification.key_ids {
        lines.push(format!("key_id {key_id}"));
    }

    // `Position` already spells `session {i} seq {n}`; re-spelling it here
    // would let the CLI and the library drift on what an address looks like.
    if let Some(coverage) = verification.coverage {
        lines.push(format!("coverage {coverage}"));
    }

    // Exit-3 output names the in-flight Calls (ADR-0002): three intents for
    // workspace reads is a shrug, one for `net.post` is where an operator
    // starts looking. `if let` rather than a `match`, because
    // `IndeterminateReason` is `#[non_exhaustive]` and this is the one reason
    // that carries Calls.
    if let Verdict::Indeterminate {
        reason: IndeterminateReason::UnanchoredTail {
            in_flight_calls, ..
        },
    } = &verification.verdict
    {
        for call_id in in_flight_calls {
            lines.push(format!("in_flight {call_id}"));
        }
    }

    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// The first line: the verdict, and for a success the trust label.
fn label(verification: &Verification) -> String {
    match &verification.verdict {
        // `TrustLabel::Pinned` is set by the library only when a slice was
        // supplied *and* the walk verified, so the pinned spellings cannot
        // appear over a chain that failed.
        Verdict::Verified => match (verification.trust, verification.key_ids.as_slice()) {
            (TrustLabel::Unpinned, _) => "Verified (unpinned)".to_string(),
            (TrustLabel::Pinned, [key_id]) => format!("Verified (pinned to {key_id})"),
            // Several keys is legal rotation across Sessions, not a finding —
            // every one of them was in the store or the walk would have stopped
            // at `UntrustedKey`. The fingerprints follow on their own lines.
            // (Zero keys with a `Verified` verdict is unreachable: a verified
            // chain has an `Open`.)
            (TrustLabel::Pinned, _) => "Verified (pinned)".to_string(),
        },
        Verdict::Tampered { reason } => format!("Tampered: {reason}"),
        Verdict::Indeterminate { reason } => format!("Indeterminate: {reason}"),
    }
}
