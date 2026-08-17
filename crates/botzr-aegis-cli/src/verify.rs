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

#[cfg(test)]
mod tests {
    //! `render` and `label` are pure functions of a [`Verification`], so their
    //! subject is reachable without a process, a file, or a signing key — the
    //! value is built here and the string is compared here.
    //!
    //! The sibling suite in `tests/verify.rs` keeps what only a process can
    //! answer: the exit code a shell sees, an empty stdout on could-not-read,
    //! and which *mechanism* fired for a given mutation. Neither file is a
    //! substitute for the other, and the wording assertions live here because a
    //! formatter regression should not cost a binary spawn to find.

    use botzr_aegis_audit::{Position, TamperedReason};
    use botzr_aegis_core::KeyId;

    use super::*;

    /// A fingerprint, derived rather than spelled.
    ///
    /// `key_id` is the SHA-256 *of* a public key, and a 64-hex literal in this
    /// file could disagree with the value an `open` line really publishes while
    /// every assertion below still passed. Fixed seeds so a failure reproduces
    /// byte for byte.
    fn key_id(seed: u8) -> KeyId {
        KeyId::of_public_key(&PublicKey::from_bytes([seed; 32]))
    }

    fn verified(trust: TrustLabel, key_ids: Vec<KeyId>) -> Verification {
        Verification {
            verdict: Verdict::Verified,
            coverage: None,
            key_ids,
            trust,
        }
    }

    fn indeterminate(reason: IndeterminateReason) -> Verification {
        Verification {
            verdict: Verdict::Indeterminate { reason },
            coverage: None,
            key_ids: Vec::new(),
            trust: TrustLabel::Unpinned,
        }
    }

    fn tampered(reason: TamperedReason) -> Verification {
        Verification {
            verdict: Verdict::Tampered { reason },
            coverage: None,
            key_ids: Vec::new(),
            trust: TrustLabel::Unpinned,
        }
    }

    /// Every [`IndeterminateReason`] this build can meet, each paired with the
    /// fragments of *its own data* that have to survive onto the verdict line.
    ///
    /// The fragments are what stops the loop below from being a mirror of the
    /// implementation. `label(v) == format!("Indeterminate: {reason}")` holds by
    /// construction and would keep holding if a variant's `Display` quietly
    /// stopped naming the address it found the problem at; asserting that the
    /// values built *here* come back out is a claim about the report an operator
    /// reads. `EmptyChain` carries no data, so it has none — the exact spelling
    /// of that one is pinned on its own, above.
    ///
    /// Maintained by hand, and it has to be: the enum is `#[non_exhaustive]`,
    /// so a `match` in this crate is *required* to carry a wildcard arm and the
    /// compiler will not point here when a variant is added upstream. The list
    /// is therefore "every variant as of this build", not a totality proof —
    /// saying otherwise would be the kind of claim this repo does not make.
    fn every_indeterminate_reason() -> Vec<(IndeterminateReason, &'static [&'static str])> {
        vec![
            (
                IndeterminateReason::UnknownLineType {
                    at: Position {
                        session_index: 0,
                        seq: 3,
                    },
                    line_type: "something-from-2027".to_owned(),
                },
                // The emitter's own token, so an operator gets the name of the
                // thing this build could not read rather than "parse error".
                &["something-from-2027", "session 0 seq 3"],
            ),
            (
                IndeterminateReason::ReservedCheckpoint {
                    at: Position {
                        session_index: 1,
                        seq: 4,
                    },
                },
                &["session 1 seq 4"],
            ),
            (IndeterminateReason::TornFinalLine { line: 9 }, &["line 9"]),
            (
                IndeterminateReason::UnanchoredTail {
                    session_index: 2,
                    in_flight_calls: vec!["call-a".to_owned()],
                },
                &["session 2", "1 call"],
            ),
            (
                IndeterminateReason::MissingLine {
                    session_index: 0,
                    expected: 5,
                    found: 8,
                },
                // The range as a unit, not `5` and `8` apart: single digits
                // survive an `expected`/`found` swap, which is the one mistake
                // a fragment check on this variant exists to catch.
                &["session 0", "seq 5..8"],
            ),
            (IndeterminateReason::EmptyChain, &[]),
        ]
    }

    // ---- label: the verdict line ----------------------------------------

    #[test]
    fn a_verified_walk_with_no_trust_slice_is_labelled_unpinned() {
        // A key is present, because a verified chain always has an `Open` that
        // published one. `Unpinned` is about what the *caller* anchored, not
        // about whether the file named a key, so the fingerprint must not leak
        // onto this line and read as a pin nobody asked for (ADR-0004).
        // Byte-exact rather than "does not contain the fingerprint": the exact
        // string already excludes it, and a `!contains` beside an `assert_eq!`
        // on the same value is an assertion that cannot fail.
        assert_eq!(
            label(&verified(TrustLabel::Unpinned, vec![key_id(1)])),
            "Verified (unpinned)"
        );
    }

    #[test]
    fn a_verified_walk_pinned_to_one_key_names_that_fingerprint() {
        let fingerprint = key_id(1);
        assert_eq!(
            label(&verified(TrustLabel::Pinned, vec![fingerprint])),
            format!("Verified (pinned to {fingerprint})")
        );
    }

    #[test]
    fn a_verified_walk_pinned_across_two_keys_names_neither_on_the_verdict_line() {
        // Rotation across Sessions is legal and not a finding: every key was in
        // the store or the walk would have stopped at `UntrustedKey`. Naming
        // the first would tell an operator the file is pinned to one key when
        // it is pinned to two — the fingerprints follow on their own lines.
        assert_eq!(
            label(&verified(TrustLabel::Pinned, vec![key_id(1), key_id(2)])),
            "Verified (pinned)"
        );
    }

    #[test]
    fn a_tampered_verdict_line_is_the_class_then_the_librarys_own_reason() {
        // The wording after the colon is `TamperedReason`'s `Display` and is
        // deliberately not re-spelled here — the dialect belongs to the record
        // format, and two spellings of it would drift. What this pins is the
        // CLI's own contribution: the class name and the `: ` that lets an
        // operator's `head -1` tell the three verdicts apart.
        assert_eq!(
            label(&tampered(TamperedReason::MalformedLine {
                line: 7,
                detail: "no seq".to_owned(),
            })),
            "Tampered: line 7: no seq"
        );
    }

    #[test]
    fn a_failed_verdict_is_never_given_a_pinned_spelling() {
        // The library cannot hand us this pair — `finish` sets `Pinned` only
        // over a `Verified` verdict. The formatter must not depend on that:
        // `label` routes on the *verdict* first, so a chain that failed can
        // never be labelled with a key, whichever way the trust field is set.
        // Printing "pinned" over a failure would name a key for a chain nobody
        // should be reading (ADR-0004).
        for verification in [
            Verification {
                trust: TrustLabel::Pinned,
                ..tampered(TamperedReason::MalformedLine {
                    line: 1,
                    detail: "no seq".to_owned(),
                })
            },
            Verification {
                trust: TrustLabel::Pinned,
                ..indeterminate(IndeterminateReason::EmptyChain)
            },
        ] {
            let line = label(&verification);
            assert!(!line.contains("pinned"), "line={line}");
            assert!(!line.contains("Verified"), "line={line}");
        }
    }

    #[test]
    fn an_indeterminate_verdict_line_is_the_class_then_the_librarys_own_reason() {
        assert_eq!(
            label(&indeterminate(IndeterminateReason::EmptyChain)),
            "Indeterminate: no lines to verify"
        );
    }

    #[test]
    fn every_indeterminate_reason_reaches_the_verdict_line_intact() {
        for (reason, fragments) in every_indeterminate_reason() {
            let line = label(&indeterminate(reason.clone()));
            // Carried verbatim: the CLI adds a class prefix and nothing else,
            // so a reason can never be truncated or paraphrased on the way out.
            assert_eq!(line, format!("Indeterminate: {reason}"));
            // And the values this reason was built from are in it. An exit-3
            // report that named no address or no token would send an operator
            // to read the file to learn what the verifier already knew.
            for fragment in fragments {
                assert!(line.contains(fragment), "missing `{fragment}`: line={line}");
            }
            // The verdict line is one line. `render` puts it first and every
            // downstream reader — the subprocess suite's `verdict_line`, an
            // operator's `head -1` — treats it as the whole answer, so a reason
            // whose `Display` wrapped would silently hide its own tail.
            assert!(!line.contains('\n'), "line={line}");
            // A guard for the variants this list will grow, not a live check:
            // every reason today has a non-empty `Display`, so this cannot fail
            // on this build. It is here so a future variant that forgot its
            // wording is caught by the loop it gets added to.
            assert!(
                line.len() > "Indeterminate: ".len(),
                "reason rendered to nothing: line={line}"
            );
        }
    }

    // ---- render: the report body ----------------------------------------

    #[test]
    fn a_report_names_every_observed_key_one_per_line_in_walk_order() {
        // ADR-0004 makes the fingerprint mandatory on every report. Order is
        // first-seen, which is the library's, so a rotation reads in the order
        // the Sessions actually used the keys.
        //
        // LOAD-BEARING: seed 2 first. `key_id(1)` is `72cd6e84…` and `key_id(2)`
        // is `75877bb4…`, so a fixture in seed order is also in *sorted* order
        // and a `render` that sorted the fingerprints would pass while claiming
        // walk order in its own test name. Feeding them descending is what makes
        // the two hypotheses distinguishable.
        assert_eq!(
            render(&verified(TrustLabel::Unpinned, vec![key_id(2), key_id(1)])),
            format!(
                "Verified (unpinned)\nkey_id {}\nkey_id {}\n",
                key_id(2),
                key_id(1)
            )
        );
        assert!(
            key_id(1).to_string() < key_id(2).to_string(),
            "the fixture is only descending if seed 1 sorts before seed 2"
        );
    }

    #[test]
    fn coverage_is_printed_after_the_keys_in_the_librarys_spelling_of_an_address() {
        // `session {i} seq {n}` is `Position`'s own `Display`. Coverage is a
        // pair and not a bare `seq` precisely because `seq` restarts per
        // Session, so a report that dropped the Session would name two
        // different lines with one address.
        let verification = Verification {
            coverage: Some(Position {
                session_index: 1,
                seq: 4,
            }),
            ..verified(TrustLabel::Unpinned, vec![key_id(1)])
        };
        assert_eq!(
            render(&verification),
            format!(
                "Verified (unpinned)\nkey_id {}\ncoverage session 1 seq 4\n",
                key_id(1)
            )
        );
    }

    #[test]
    fn no_coverage_prints_no_coverage_line_rather_than_a_placeholder() {
        // `None` is "nothing was covered", and a `coverage session 0 seq 0`
        // stand-in would name a line that was never verified.
        assert_eq!(
            render(&indeterminate(IndeterminateReason::EmptyChain)),
            "Indeterminate: no lines to verify\n"
        );
    }

    #[test]
    fn an_unanchored_tail_names_every_call_in_flight_last_and_in_walk_order() {
        // The richest report the formatter emits: verdict, key, coverage and
        // the in-flight Calls, in that order. Three intents for workspace reads
        // is a shrug; one for `net.post` is where an operator starts looking
        // (ADR-0002), which is why the ids are printed and not merely counted.
        //
        // LOAD-BEARING: `call-b` before `call-a`, for the reason the key fixture
        // above is descending. Walk order is the claim, and an ascending fixture
        // cannot tell it from a sort.
        let verification = Verification {
            coverage: Some(Position {
                session_index: 0,
                seq: 2,
            }),
            key_ids: vec![key_id(1)],
            ..indeterminate(IndeterminateReason::UnanchoredTail {
                session_index: 0,
                in_flight_calls: vec!["call-b".to_owned(), "call-a".to_owned()],
            })
        };
        assert_eq!(
            render(&verification),
            format!(
                "Indeterminate: session 0 has no close record and nothing anchors beyond it; \
                 2 call(s) in flight\n\
                 key_id {}\n\
                 coverage session 0 seq 2\n\
                 in_flight call-b\n\
                 in_flight call-a\n",
                key_id(1)
            )
        );
    }

    #[test]
    fn an_unanchored_tail_with_nothing_in_flight_prints_no_in_flight_lines() {
        // The plain SIGKILL case: a Session that died between an outcome and
        // its `Close`. An empty section header would read as a finding.
        //
        // Byte-exact rather than `!contains("in_flight")`: an absence assertion
        // alone also passes over an empty report, so it cannot tell "printed no
        // in-flight lines" from "printed nothing".
        assert_eq!(
            render(&indeterminate(IndeterminateReason::UnanchoredTail {
                session_index: 0,
                in_flight_calls: Vec::new(),
            })),
            "Indeterminate: session 0 has no close record and nothing anchors \
             beyond it; 0 call(s) in flight\n"
        );
    }

    #[test]
    fn no_other_verdict_prints_an_in_flight_line() {
        // `in_flight` is `UnanchoredTail` surface and nothing else: it names
        // Calls whose outcome no signature covers. Printing it under any other
        // verdict would assert an uncovered tail the walk did not find.
        //
        // The needle is `in_flight` with an underscore, and it only discriminates
        // because `UnanchoredTail`'s own `Display` spells the phrase with a
        // *space* — "N call(s) in flight". If that wording ever loses the space,
        // this assertion silently stops being able to fail.
        let mut verifications = vec![
            verified(TrustLabel::Pinned, vec![key_id(1)]),
            tampered(TamperedReason::MalformedLine {
                line: 1,
                detail: "no seq".to_owned(),
            }),
        ];
        verifications.extend(
            every_indeterminate_reason()
                .into_iter()
                .map(|(reason, _)| reason)
                .filter(|reason| !matches!(reason, IndeterminateReason::UnanchoredTail { .. }))
                .map(indeterminate),
        );

        for verification in verifications {
            let report = render(&verification);
            assert!(!report.contains("in_flight"), "report={report}");
        }
    }

    #[test]
    fn a_report_is_one_trailing_newline_and_no_blank_lines() {
        // stdout is read by shells and by humans. A missing final newline runs
        // the next prompt into the verdict; a doubled one reads as a section
        // break the report does not have.
        for verification in [
            verified(TrustLabel::Unpinned, vec![key_id(1)]),
            Verification {
                coverage: Some(Position {
                    session_index: 0,
                    seq: 1,
                }),
                key_ids: vec![key_id(1)],
                ..indeterminate(IndeterminateReason::UnanchoredTail {
                    session_index: 0,
                    in_flight_calls: vec!["call-a".to_owned()],
                })
            },
        ] {
            let report = render(&verification);
            assert!(report.ends_with('\n'), "report={report}");
            // Covers the doubled-newline case too: `"x\n\n".lines()` yields a
            // trailing empty string.
            assert!(
                report.lines().all(|line| !line.is_empty()),
                "report={report}"
            );
        }
    }
}
