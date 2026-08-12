//! `aegis recheck` — the CLI surface over the would-block preview in
//! `botzr-aegis-policy` (ADR-0001 decision axes, ADR-0008 forensic verbs).
//!
//! **Formatter and exit mapping only.** Every verdict is decided by
//! [`botzr_aegis_policy::recheck_record`], and every *word* in a verdict clause
//! is rendered by that crate's `Display` impls. This module walks JSONL, prefixes
//! each clause with the call's identity, and turns the tally into a process exit
//! code. It classifies nothing: a second spelling of "newly blocked" in the CLI
//! would be a second thing to keep in step with the crate under test, and the
//! two would drift the first time a variant was added.
//!
//! Two verdicts are constructed here rather than fetched, and only because they
//! cannot be fetched: `recheck_record` takes an [`AuditRecord`], so no line this
//! build cannot parse into one ever reaches it. A line from another schema is
//! answered with the policy crate's own `UnknownPolicySetHash` — the same
//! variant `recheck_record` returns for the version mismatch it *can* see — and
//! a line from *this* schema that will not deserialize with its `NoBinding`
//! (see [`verdict_for`]). Both are the crate's own variants, so the exception
//! adds call sites, never a word. The crate's version gate stays where it is as
//! defence in depth.
//!
//! Nothing here reaches for the runtime, the sandbox, a capability resolver, or
//! a component engine. A recheck answers a question *about a finished call* —
//! nothing is executed, nothing is minted, nothing is granted. Nor does it check
//! signatures: `aegis verify` answers "is this chain intact?", and asking "what
//! would today's rules do to these calls?" of a file that verify would call
//! `Tampered` is a legitimate forensic question, not a contradiction. The two
//! verbs are deliberately independent, so neither can quietly become a
//! precondition for the other.
//!
//! The report is a pure function of two byte strings — the policy file and the
//! record file. No clock, no environment, no echo of the paths the operator
//! typed, no key fingerprints. In particular the recorded
//! `decision_axes.fs.path_canonical` is *evidence*, not an input: this module
//! never resolves, stats or opens it, so a symlink repointed after the call ran
//! cannot move a verdict, and an auditor on a machine that never saw the call
//! reads the same lines. (The ticket's anti-pattern grep runs over this file, so
//! the prohibited calls are not spelled out here even in prose.)

use std::path::Path;
use std::process::ExitCode;

use botzr_aegis_core::{AuditRecord, PolicySetHash, ToolId, AUDIT_SCHEMA_VERSION};
use botzr_aegis_policy::{recheck_record, PolicyEngine, RecheckIndeterminate, RecheckVerdict};
use serde_json::Value;

// LOAD-BEARING: these four are API the moment anyone scripts `if aegis recheck`.
// They deliberately mirror `verify`'s shape — 0 is the clean answer, 2 is "no
// answer at all", 3 is "an answer was withheld" — so an operator scripting both
// verbs does not have to hold two tables in their head.
const EXIT_ALL_UNCHANGED: u8 = 0;
const EXIT_CHANGED: u8 = 1;
const EXIT_COULD_NOT_READ: u8 = 2;
const EXIT_INDETERMINATE: u8 = 3;

/// Printed in place of a `call_id` on a line that claims to be an outcome and
/// carries none.
///
/// A constant, so the report stays a pure function of the input bytes, and a
/// glyph rather than an empty string, so the column does not silently collapse
/// and leave `call  session 0 ...` for a human to misread as a spacing bug.
const ABSENT_CALL_ID: &str = "-";

/// Printed in place of a `seq` on the same kind of line.
///
/// Zero is unambiguous rather than arbitrary: `seq` restarts at 0 on each
/// Session's `open` line, so no outcome any emitter in this repo can write ever
/// occupies it. Deriving something from the line number instead would put a
/// number in the `seq` column that is not a `seq`.
const ABSENT_SEQ: u64 = 0;

/// Re-evaluate every recorded outcome in `path` against the Policy Set in
/// `policy`, print the diff, and map the tally to an exit code.
pub fn run(policy: &Path, path: &Path) -> ExitCode {
    // Both failures print nothing on stdout: exit 2 is "no report", and a script
    // piping stdout into a diff must not find a half-answer there. The
    // operator-supplied paths go to stderr only.
    let engine = match PolicyEngine::load(policy) {
        Ok(engine) => engine,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(EXIT_COULD_NOT_READ);
        }
    };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("error: read {}: {error}", path.display());
            return ExitCode::from(EXIT_COULD_NOT_READ);
        }
    };

    let report = walk(&engine, &text);
    print!("{}", report.body);
    ExitCode::from(report.exit)
}

/// The report body plus the exit code the tally earns.
struct Report {
    body: String,
    exit: u8,
}

/// Walk the record file and render one line per recorded outcome, in file order.
///
/// The walk is deliberately shallow, but "shallow" is not "reads one field".
/// Three fields *route* a line — `line_type`, `phase` and `schema_version`
/// decide whether it is an outcome at all, whether it opens a Session, and
/// which of the two locally-constructed verdicts it earns — and four more are
/// read only to *label* a row or fill a payload: `call_id` and `seq` are the
/// identity columns of the printed line, `tool_id` names the tool inside a
/// [`RecheckIndeterminate::NoBinding`], and `policy_set_hash` fills the payload
/// of an `UnknownPolicySetHash` that is never printed at all. None of the seven
/// is read in order to weigh a recorded call against a rule — that comparison
/// is `recheck_record`'s alone, and the two verdicts built here (see the module
/// header) exist because the line cannot be handed over, not because this
/// module formed an opinion about what it contains. Everything else goes to the
/// policy crate whole; the chain fields, the signatures and the Session
/// structure are `aegis verify`'s subject, not this one's. That is also why an
/// unparseable line is stepped over rather than reported: a torn tail is a
/// statement about the file's integrity, and answering it here would be a
/// second, weaker verifier living next to the real one.
///
/// The two routing fields beyond `line_type` are what it costs to notice a
/// record this build cannot account for. `phase` is the v1 spelling of `line_type`: a
/// schema-v1 outcome carries `phase: "outcome"` and no `line_type` at all, so a
/// walk keyed on `line_type` alone steps over a genuine recorded call as though
/// it were a checkpoint — dropping it from a diff an operator is reading as
/// complete, which is the one failure a forensic verb must not have. And
/// `schema_version` is read *before* the line is offered to [`AuditRecord`],
/// because the two ways a line can fail to deserialize are not the same
/// finding. A line from another schema is unreadable by construction — its
/// field names were given meaning by rules this build does not have — whereas a
/// line from *this* schema that will not deserialize is a damaged or incomplete
/// record. The first is `unknown_policy_set_hash`; the second is `no_binding`;
/// and a v1 line routed through the deserializer would report the second, which
/// says "this line named no tool" and sends a reader hunting for corruption
/// instead of an older emitter. A line carrying no `schema_version` at all is
/// only unlabelled, not another schema's, and still goes to the deserializer.
fn walk(engine: &PolicyEngine, text: &str) -> Report {
    let mut lines: Vec<String> = Vec::new();
    let mut changed = false;
    let mut indeterminate = false;

    // `None` until the first `open`, then 0, 1, 2 … — the same rule the audit
    // crate's walker uses (`session_index.map_or(0, |i| i + 1)`), so a coverage
    // address printed by `aegis verify` names the same Session as a diff line
    // printed here. An outcome seen before any `open` is reported under session
    // 0, which is what verify does with the same file.
    let mut session: Option<usize> = None;

    for (number, raw) in text.lines().enumerate() {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(raw) else {
            eprintln!("warning: line {} is not JSON, skipped", number + 1);
            continue;
        };

        // Intents, decisions, closes, checkpoints and anything a newer emitter
        // writes carry no recorded policy outcome, so there is nothing for a
        // Policy Set to be re-run against and they fall out of both arms.
        if is_outcome_shaped(&value) {
            let verdict = if is_from_another_schema(&value) {
                RecheckVerdict::Indeterminate {
                    reason: RecheckIndeterminate::UnknownPolicySetHash {
                        recorded: recorded_hash(&value),
                    },
                }
            } else {
                verdict_for(engine, &value, number + 1)
            };
            lines.push(format!(
                "call {} session {} seq {}: {verdict}",
                call_id(&value),
                session.unwrap_or(0),
                seq(&value),
            ));
            match verdict {
                RecheckVerdict::Unchanged { .. } => {}
                RecheckVerdict::Indeterminate { .. } => indeterminate = true,
                RecheckVerdict::NewlyBlocked { .. }
                | RecheckVerdict::NewlyAllowed { .. }
                | RecheckVerdict::NewlyParked { .. } => changed = true,
            }
        } else if value.get("line_type").and_then(Value::as_str) == Some("open") {
            session = Some(session.map_or(0, |index| index + 1));
        }
    }

    let mut body = lines.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }

    Report {
        body,
        // LOAD-BEARING order: 3 outranks 1. A run that could not answer for one
        // call has not established that the rest of the file is a complete
        // diff, and reporting "some calls would now be blocked" over an
        // incomplete read invites an operator to act on a subset as though it
        // were the whole finding.
        exit: if indeterminate {
            EXIT_INDETERMINATE
        } else if changed {
            EXIT_CHANGED
        } else {
            EXIT_ALL_UNCHANGED
        },
    }
}

/// Whether the line claims to be a post-work outcome, under either spelling of
/// the tag.
///
/// `line_type` is the v2 field; `phase` was v1's. Both are accepted because the
/// question this verb answers — "what would today's rules do to this recorded
/// call?" — is asked of files an older build wrote, and a record that named
/// itself an outcome in the vocabulary of its own schema is an outcome.
///
/// The two are read in order, not as alternatives: `line_type` is authoritative
/// whenever the line carries one, and `phase` is consulted only as a fallback
/// for records written before `line_type` existed. (A `line_type` that is
/// present but not a string is no tag either, and falls through to the fallback
/// exactly as it always has.) Nothing is lost by the ordering, because a genuine
/// v1 outcome carries `phase: "outcome"` and no `line_type` at all — the
/// fallback still reaches every line it was added for.
///
/// LOAD-BEARING: the fallback must not be allowed to speak over a `line_type`
/// that is there. To the audit walker a line tagged `open` is a Session
/// boundary and nothing else — it numbers Sessions on `line_type` alone and
/// never looks at `phase` — and the counter in [`walk`] has to stay the same
/// rule, or a session address printed here names a different Session from the
/// one `aegis verify` prints for the same file, and a finding stops carrying
/// between the two reports. Reading `phase: "outcome"` off a line already
/// tagged `open` would do both halves of that damage at once: a boundary would
/// be reported as a call, and the counter would never advance past it.
///
/// Note that only the *outcome* spelling is honoured: a v1 `phase: "intent"`
/// line stays skipped, exactly as `line_type: "intent"` does, because an intent
/// carries no recorded decision to compare against.
fn is_outcome_shaped(value: &Value) -> bool {
    match value.get("line_type").and_then(Value::as_str) {
        Some(line_type) => line_type == "outcome",
        None => value.get("phase").and_then(Value::as_str) == Some("outcome"),
    }
}

/// Whether the line was written under a schema this build is not the author of.
///
/// Present-and-a-number is the whole test: a line that carries no
/// `schema_version` is *unlabelled* rather than another schema's, and is left
/// to the deserializer — reporting an absent field as "from another schema" would
/// invent provenance the bytes do not claim. A number that is not this build's
/// version answers **yes**, this line is another schema's, whatever the number's
/// shape — including a number that is not a `u32` at all. That last case is
/// deliberate rather than incidental: a version written as `2.0` or `2e0` is one
/// no emitter in this repo could have produced, and this build has no way to
/// match it against its own version, so the conservative reading is the one
/// taken here. The line is answered `indeterminate`, which withholds a verdict,
/// rather than being read as a version it does not spell, which would invent
/// one.
fn is_from_another_schema(value: &Value) -> bool {
    value.get("schema_version").is_some_and(|version| {
        version.is_number() && version.as_u64() != Some(u64::from(AUDIT_SCHEMA_VERSION))
    })
}

/// The Policy Set hash a line from another schema recorded, if it recorded one.
///
/// Never printed — [`RecheckIndeterminate`] renders as its token alone — so
/// this is the variant's payload rather than report content, and a v1 line,
/// which has no `policy_set_hash` field at all, still has to produce one. The
/// hash of no bytes is the honest stand-in: it names no Policy Set that any run
/// could have used, and it keeps the payload a `PolicySetHash` rather than
/// widening the variant to `Option` for the sake of a field nobody reads.
fn recorded_hash(value: &Value) -> PolicySetHash {
    value
        .get("policy_set_hash")
        .and_then(|hash| serde_json::from_value::<PolicySetHash>(hash.clone()).ok())
        .unwrap_or_else(|| PolicySetHash::of_canonical_bytes(&[]))
}

/// The verdict for one `outcome` line.
///
/// A line that will not deserialize as an [`AuditRecord`] is
/// [`RecheckIndeterminate::NoBinding`]: there is no tool, and therefore no
/// question a Policy Set can be asked. The canonical instance is an outcome
/// object with no `tool_id` at all; the same answer covers any other shape this
/// build cannot read, because the honest report in every case is "this line was
/// not bound to a rule", never a confident `unchanged`. The parse error itself
/// goes to stderr so an operator is not left guessing which of the two it was.
fn verdict_for(engine: &PolicyEngine, value: &Value, number: usize) -> RecheckVerdict {
    match serde_json::from_value::<AuditRecord>(value.clone()) {
        Ok(record) => recheck_record(engine, &record),
        Err(error) => {
            eprintln!("warning: line {number} is not a readable outcome record: {error}");
            RecheckVerdict::Indeterminate {
                reason: RecheckIndeterminate::NoBinding {
                    // Never printed — the reason renders as its token alone —
                    // so this is the variant's payload, not report content. An
                    // absent `tool_id` becomes an empty id, which is the
                    // truthful reading of "names no tool".
                    tool_id: ToolId::new(
                        value
                            .get("tool_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    ),
                },
            }
        }
    }
}

/// The call's label, or [`ABSENT_CALL_ID`] when the line carries none.
fn call_id(value: &Value) -> &str {
    value
        .get("call_id")
        .and_then(Value::as_str)
        .unwrap_or(ABSENT_CALL_ID)
}

/// The line's chain position, or [`ABSENT_SEQ`] when the line carries none.
fn seq(value: &Value) -> u64 {
    value
        .get("seq")
        .and_then(Value::as_u64)
        .unwrap_or(ABSENT_SEQ)
}

#[cfg(test)]
mod tests {
    use super::*;
    use botzr_aegis_core::{
        CapabilityOutcome, ExecutionOutcome, PolicyOutcome, PolicySetHash, RequestDigest,
    };

    fn engine(yaml: &str) -> PolicyEngine {
        PolicyEngine::from_yaml(yaml).expect("fixture policy parses")
    }

    fn allow_all() -> PolicyEngine {
        engine("version: 1\ndefault: allow\nrules: []\n")
    }

    /// A serialized outcome line, built by the real constructor so the wire
    /// shape cannot drift from `AuditRecord`.
    fn outcome_line(call_id: &str, tool: &str, policy: PolicyOutcome) -> String {
        let record = AuditRecord::new(
            call_id,
            ToolId::new(tool),
            RequestDigest::of_request_bytes(b"{}"),
            PolicySetHash::of_canonical_bytes(b"recorded-set"),
            policy,
            CapabilityOutcome::Denied {
                reason: "not evaluated".to_string(),
                denied_capability: None,
            },
            ExecutionOutcome::Success,
        );
        serde_json::to_string(&record).expect("an audit record serializes")
    }

    /// Session numbering follows the audit walker's rule exactly: the first
    /// `open` is 0, and an outcome seen before any `open` is reported under 0
    /// as well.
    ///
    /// The second `open` also carries a stray `phase: "outcome"`, which is the
    /// case where the two tags disagree. `line_type` wins, so that line stays a
    /// Session boundary: it prints no row of its own, and — the assertion that
    /// matters — `call-second` is still session **1**. Letting `phase` speak
    /// over `line_type` would report the boundary as a call *and* stall the
    /// counter, so every address after it would name a different Session from
    /// the one `aegis verify` prints for the same file.
    #[test]
    fn sessions_are_numbered_from_zero_at_each_open() {
        let text = format!(
            "{}\n{{\"line_type\":\"open\"}}\n{}\n\
             {{\"line_type\":\"open\",\"phase\":\"outcome\"}}\n{}\n",
            outcome_line("call-before", "t", PolicyOutcome::Allowed),
            outcome_line("call-first", "t", PolicyOutcome::Allowed),
            outcome_line("call-second", "t", PolicyOutcome::Allowed),
        );
        let report = walk(&allow_all(), &text);
        assert_eq!(
            report.body,
            "call call-before session 0 seq 0: unchanged allowed\n\
             call call-first session 0 seq 0: unchanged allowed\n\
             call call-second session 1 seq 0: unchanged allowed\n"
        );
        assert_eq!(report.exit, EXIT_ALL_UNCHANGED);
    }

    /// Every line type that is not an outcome is stepped over, including one no
    /// build here emits.
    ///
    /// The last two rows are the v1 spelling of the same skip, and they are
    /// what pins the `== "outcome"` comparison in [`is_outcome_shaped`]: with
    /// only `line_type` rows here, the fallback could be widened to "any
    /// `phase` at all" without a test noticing, and a v1 **intent** — which
    /// records no decision for a Policy Set to be re-run against — would start
    /// appearing in the diff as a call that was never answered.
    #[test]
    fn non_outcome_lines_produce_no_report_line() {
        let text = "{\"line_type\":\"open\"}\n\
                    {\"line_type\":\"intent\",\"call_id\":\"call-1\"}\n\
                    {\"line_type\":\"decision\"}\n\
                    {\"line_type\":\"checkpoint\"}\n\
                    {\"line_type\":\"something-from-2027\"}\n\
                    \n   \n\
                    {\"line_type\":\"close\"}\n\
                    {\"schema_version\":1,\"phase\":\"intent\",\"call_id\":\"call-1\",\"tool_id\":\"t\"}\n\
                    {\"schema_version\":1,\"phase\":\"something-from-2019\"}\n";
        let report = walk(&allow_all(), text);
        assert_eq!(report.body, "");
        assert_eq!(report.exit, EXIT_ALL_UNCHANGED);
    }

    /// A genuine schema-v1 outcome — the `phase` spelling, no `line_type`, and
    /// none of the v2 chain fields — is reported rather than stepped over.
    ///
    /// This is the shape an emitter actually wrote before AILAB-619, so it is
    /// the shape the skip would have swallowed in the field: no `line_type`
    /// meant no report line at all, and a call that ran under rules nobody can
    /// re-derive would have gone missing from a diff read as complete. `seq` is
    /// [`ABSENT_SEQ`] because v1 had no chain and therefore no `seq` to print.
    #[test]
    fn a_v1_outcome_line_is_reported_as_indeterminate() {
        let text = "{\"schema_version\":1,\"phase\":\"outcome\",\"call_id\":\"call-legacy\",\
                    \"tool_id\":\"legacy\",\
                    \"input_digest\":\"0000000000000000000000000000000000000000000000000000000000000000\",\
                    \"policy\":{\"status\":\"allowed\"},\
                    \"capability\":{\"status\":\"denied\",\"reason\":\"not evaluated\"},\
                    \"execution\":{\"status\":\"success\"}}\n";
        let report = walk(&allow_all(), text);
        assert_eq!(
            report.body,
            "call call-legacy session 0 seq 0: indeterminate unknown_policy_set_hash\n"
        );
        assert_eq!(report.exit, EXIT_INDETERMINATE);
    }

    /// 3 beats 1, computed after the whole walk rather than at the first
    /// finding.
    #[test]
    fn indeterminate_outranks_a_would_block() {
        let text = format!(
            "{}\n{{\"line_type\":\"outcome\",\"call_id\":\"call-2\",\"seq\":9}}\n",
            outcome_line("call-1", "writer", PolicyOutcome::Allowed),
        );
        let report = walk(&engine("version: 1\ndefault: deny\nrules: []\n"), &text);
        assert_eq!(
            report.body,
            "call call-1 session 0 seq 0: newly_blocked was=allowed now=denied\n\
             call call-2 session 0 seq 9: indeterminate no_binding\n"
        );
        assert_eq!(report.exit, EXIT_INDETERMINATE);
    }

    /// An outcome with neither identity field still occupies one line, under
    /// the two documented placeholders.
    #[test]
    fn an_outcome_with_no_identity_uses_the_documented_placeholders() {
        let report = walk(&allow_all(), "{\"line_type\":\"outcome\"}\n");
        assert_eq!(
            report.body,
            "call - session 0 seq 0: indeterminate no_binding\n"
        );
        assert_eq!(report.exit, EXIT_INDETERMINATE);
        // The two placeholders are spelled once, here and in the constants —
        // a change to either has to be made on purpose.
        assert_eq!((ABSENT_CALL_ID, ABSENT_SEQ), ("-", 0));
    }
}
