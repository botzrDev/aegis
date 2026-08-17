//! `aegis verify` — the AILAB-621 amendment §3 tamper matrix, one test per row,
//! asserted against the real binary.
//!
//! **Why the binary and not the library.** The subject here is the *exit code*,
//! and an exit code only exists once a process has run. ADR-0002 makes 0/1/2/3
//! API — CI gates will script them — so what is under test is what `aegis
//! verify` hands back to a shell, not what the walker returns to a caller.
//! `botzr-aegis-audit`'s own suites already pin the verdicts; nothing here
//! re-derives one.
//!
//! Every assertion is on `status.code()` and never on `status.success()`: 1, 2
//! and 3 are all unsuccessful, so `success()` cannot tell "the record is forged"
//! from "the record is not there" — which is the entire distinction this command
//! exists to draw.
//!
//! Each row also asserts the *reason* the report printed. An exit code cannot
//! tell one `Tampered` row from another, so without that a mutation could fire
//! on the wrong mechanism — a stale `prev_hash` row failing on a broken
//! signature, say — and the matrix would still look green.
//!
//! Fixtures follow `botzr-aegis-audit/tests/verdict.rs`. Anything an emitter can
//! produce is produced by the real [`AuditWriter`], so a fixture cannot drift
//! from the writer; only the lines no emitter in this repo is allowed to write —
//! here, the unknown `line_type` a newer build might emit — are hand-built, by
//! the same stamp-sign-hash rule the writer follows.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use botzr_aegis_audit::{line_hash, AuditWriter, SigningKey};
use botzr_aegis_core::{
    to_canonical_json, ApprovalId, ApprovalVerdict, AuditDecision, AuditIntent, AuditRecord,
    CapabilityOutcome, ExecutionOutcome, PolicyOutcome, PolicySetHash, PrevHash, RequestDigest,
    ToolId, AUDIT_SCHEMA_VERSION,
};
use serde_json::{json, Map, Value};
use tempfile::TempDir;

// ---- running the binary --------------------------------------------------

fn verify(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aegis"))
        .arg("verify")
        .args(args)
        .output()
        .expect("spawn aegis")
}

fn verify_path(path: &Path) -> Output {
    verify(&[path_arg(path)])
}

fn path_arg(path: &Path) -> &str {
    path.to_str().expect("fixture paths are utf-8")
}

/// Assert the exact exit code. Both streams go into the failure message: an
/// exit-code mismatch on its own tells an operator nothing about which of the
/// four answers came back, or why.
#[track_caller]
fn assert_exit(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Assert the verdict line's label *and* the reason printed with it.
#[track_caller]
fn assert_verdict(output: &Output, label: &str, reason: &str) {
    let verdict = verdict_line(output);
    assert!(
        verdict.starts_with(label) && verdict.contains(reason),
        "expected a `{label}` verdict naming `{reason}`, got stdout={}",
        stdout(output)
    );
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The verdict line — the first line of the report, and the one line ADR-0002
/// and ADR-0004 pin the spelling of.
fn verdict_line(output: &Output) -> String {
    stdout(output).lines().next().unwrap_or_default().to_owned()
}

// ---- keys ----------------------------------------------------------------

/// The key every fixture Session below is signed with.
///
/// A fixed seed that is **not** the dev key's: these fixtures write real Chain
/// files, and a Durable Sink refuses `insecure_dev_key` (ADR-0012). Fixed rather
/// than random so a failing case reproduces byte for byte.
fn session_key() -> SigningKey {
    SigningKey::from_seed([0x2a; 32])
}

/// What `--key` takes: the `public_key` an `open` line publishes.
fn session_public_key() -> String {
    session_key().public_key().to_hex()
}

/// What the report prints: the `key_id` fingerprint. Deliberately a different
/// value from [`session_public_key`] — pinning compares published keys, and a test that
/// confused the two would pin nothing and still pass.
fn session_fingerprint() -> String {
    session_key().key_id().to_hex()
}

fn foreign_key() -> String {
    SigningKey::from_seed([9u8; 32]).public_key().to_hex()
}

// ---- fixtures ------------------------------------------------------------

fn temp_chain() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("session.jsonl");
    (dir, path)
}

fn outcome(call_id: &str) -> AuditRecord {
    AuditRecord::new(
        call_id,
        ToolId::new("echo"),
        RequestDigest::of_request_bytes(b"{}"),
        PolicySetHash::of_canonical_bytes(b"policy"),
        PolicyOutcome::Allowed,
        CapabilityOutcome::Denied {
            reason: "not evaluated".into(),
            denied_capability: None,
        },
        ExecutionOutcome::Success,
    )
}

fn intent(call_id: &str) -> AuditIntent {
    AuditIntent::new(
        call_id,
        ToolId::new("echo"),
        RequestDigest::of_request_bytes(b"{}"),
    )
}

/// One closed Session: an intent/outcome pair per call id, then the `Close`
/// that `Drop` writes.
fn closed_session(path: &Path, call_ids: &[&str]) {
    let writer = AuditWriter::open(path, session_key()).expect("open chain");
    for call_id in call_ids {
        writer.emit_intent(&mut intent(call_id)).expect("intent");
        writer.emit_outcome(&mut outcome(call_id)).expect("outcome");
    }
    // Dropped here, which writes the `Close` line that anchors the Session.
}

/// A Session with no `Close`, exactly as SIGKILL leaves one: `mem::forget`
/// skips the `Drop` that writes the anchor, and the lines already appended stay
/// durable. `in_flight` names Calls that get an intent and no outcome — the only
/// content the unverified tail may legally hold.
fn unclosed_session(path: &Path, completed: &[&str], in_flight: &[&str]) {
    let writer = AuditWriter::open(path, session_key()).expect("open chain");
    for call_id in completed {
        writer.emit_intent(&mut intent(call_id)).expect("intent");
        writer.emit_outcome(&mut outcome(call_id)).expect("outcome");
    }
    for call_id in in_flight {
        writer.emit_intent(&mut intent(call_id)).expect("intent");
    }
    std::mem::forget(writer);
}

/// Two closed Sessions in one file — one outcome each, so `rows` reads
/// open/outcome/close twice and the indices below stay legible.
fn two_sessions(path: &Path) {
    for session in 0..2 {
        let writer = AuditWriter::open(path, session_key()).expect("open chain");
        writer
            .emit_outcome(&mut outcome(&format!("call-s{session}")))
            .expect("outcome");
        // Drop closes this Session before the next one opens.
    }
}

fn rows(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .expect("chain file readable")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

fn write_rows(path: &Path, rows: &[String]) {
    let mut text = rows.join("\n");
    text.push('\n');
    std::fs::write(path, text).expect("write chain file");
}

fn parse(row: &str) -> Value {
    serde_json::from_str(row).expect("a chain row is JSON")
}

/// The hash the *next* line carries as its `prev_hash`.
///
/// Borrowed from the audit crate rather than spelled out here: `line_hash` is
/// the writer's own rule (canonical form, signature included), and a second
/// spelling of it in a test is a second thing that can drift from the format.
fn hash_of(row: &str) -> PrevHash {
    line_hash(&parse(row)).expect("canonical form")
}

/// Re-sign a line by the rule `FixtureChain::push` follows: drop `signature`,
/// canonicalize with `key_id` present, sign *that*, put the hex back, and
/// canonicalize the complete line.
///
/// A mutation passed through here comes out validly signed. What it cannot fix
/// is the *next* line's `prev_hash`, which is the point of the row that uses it.
fn resign(mut value: Value) -> String {
    let key = session_key();
    let body = value.as_object_mut().expect("a chain line is an object");
    body.remove("signature");
    body.insert("key_id".into(), json!(key.key_id().to_hex()));
    let signing_input = to_canonical_json(&value).expect("canonical signing input");
    let signature = key.sign(signing_input.as_bytes());
    value
        .as_object_mut()
        .expect("a chain line is an object")
        .insert("signature".into(), json!(signature.to_hex()));
    to_canonical_json(&value).expect("canonical line")
}

/// Append a hand-built signed line, stamped and chained the way the writer
/// would. It exists for the lines no emitter here is allowed to write.
fn append_line(path: &Path, line_type: &str) {
    let mut rows = rows(path);
    let last = rows.last().expect("a chain to append to").clone();
    let mut body = Map::new();
    body.insert("line_type".into(), json!(line_type));
    body.insert("schema_version".into(), json!(AUDIT_SCHEMA_VERSION));
    body.insert(
        "seq".into(),
        json!(parse(&last)["seq"].as_u64().expect("every line has seq") + 1),
    );
    body.insert("prev_hash".into(), json!(hash_of(&last).to_hex()));
    rows.push(resign(Value::Object(body)));
    write_rows(path, &rows);
}

// ---- matrix row 1 --------------------------------------------------------

#[test]
fn an_unmodified_closed_session_verifies_unpinned() {
    let (_dir, path) = temp_chain();
    closed_session(&path, &["call-0", "call-1"]);

    let output = verify_path(&path);
    assert_exit(&output, 0);
    assert_eq!(verdict_line(&output), "Verified (unpinned)");
    // ADR-0004: the fingerprint is printed on every report, not only on a pin,
    // so an operator can compare it against a key they hold out of band.
    assert!(
        stdout(&output).contains(&format!("key_id {}", session_fingerprint())),
        "stdout={}",
        stdout(&output)
    );
}

// ---- matrix row 2 --------------------------------------------------------

#[test]
fn the_same_bytes_with_the_open_key_supplied_are_pinned_to_its_fingerprint() {
    // The pair with row 1 is the property: identical bytes, identical walk, and
    // the only thing `--key` changes is the label. A difference in *verdict*
    // would mean the trust slice had become a second crypto path (ADR-0004).
    let (_dir, path) = temp_chain();
    closed_session(&path, &["call-0", "call-1"]);

    let output = verify(&["--key", &session_public_key(), path_arg(&path)]);
    assert_exit(&output, 0);
    assert_eq!(
        verdict_line(&output),
        format!("Verified (pinned to {})", session_fingerprint())
    );
}

// ---- matrix row 3 --------------------------------------------------------

#[test]
fn a_bit_flip_in_a_payload_field_is_tampering() {
    // Flipped on the *intent* line, which is the one line type that is never
    // signed. So no signature can catch this: the hash chain does, when the
    // following outcome's `prev_hash` stops matching. That is the amendment's
    // "prev_hash mismatch at seq N+1", and it is why intent lines are hashed at
    // all.
    let (_dir, path) = temp_chain();
    closed_session(&path, &["call-0"]);
    let mut rows = rows(&path);

    let mut intent = parse(&rows[1]);
    assert_eq!(intent["line_type"], json!("intent"));
    intent["call_id"] = json!("call-elsewhere");
    rows[1] = to_canonical_json(&intent).expect("canonical line");
    write_rows(&path, &rows);

    let output = verify_path(&path);
    assert_exit(&output, 1);
    assert_verdict(&output, "Tampered:", "session 0 seq 2 chains to");
}

// ---- matrix row 4 --------------------------------------------------------

#[test]
fn a_bit_flip_in_a_signature_is_tampering() {
    let (_dir, path) = temp_chain();
    closed_session(&path, &["call-0"]);
    let mut rows = rows(&path);

    let mut record = parse(&rows[2]);
    assert_eq!(record["line_type"], json!("outcome"));
    let signature = record["signature"]
        .as_str()
        .expect("an outcome is signed")
        .to_owned();
    let flipped = if signature.starts_with('0') { '1' } else { '0' };
    record["signature"] = json!(format!("{flipped}{}", &signature[1..]));
    rows[2] = to_canonical_json(&record).expect("canonical line");
    write_rows(&path, &rows);

    let output = verify_path(&path);
    assert_exit(&output, 1);
    assert_verdict(&output, "Tampered:", "signature does not match this line");
}

// ---- matrix row 5 --------------------------------------------------------

#[test]
fn two_reordered_lines_are_tampering() {
    // Both lines are untouched and one of them is still validly signed — only
    // their order changed, and the chain is what notices.
    let (_dir, path) = temp_chain();
    closed_session(&path, &["call-0"]);
    let mut lines = rows(&path);
    let before = lines.len();
    assert_eq!(parse(&lines[1])["line_type"], json!("intent"));
    assert_eq!(parse(&lines[2])["line_type"], json!("outcome"));
    lines.swap(1, 2);
    write_rows(&path, &lines);

    // The fixture precondition, asserted on the mutated *file*: a reorder keeps
    // every line and exchanges two known ones. The deletion row next door
    // produces the same `ChainBroken` at the same position, so without this the
    // two fixtures would be interchangeable and neither row would prove its own
    // mutation happened.
    let mutated = rows(&path);
    assert_eq!(mutated.len(), before, "a reorder loses no line");
    assert_eq!(parse(&mutated[1])["line_type"], json!("outcome"));
    assert_eq!(parse(&mutated[2])["line_type"], json!("intent"));

    let output = verify_path(&path);
    assert_exit(&output, 1);
    assert_verdict(&output, "Tampered:", "chains to");
}

// ---- matrix row 6 --------------------------------------------------------

#[test]
fn a_deleted_interior_line_is_tampering() {
    // Removing a line always breaks the *next* line's `prev_hash`, and
    // re-signing the remainder needs the key. That is what makes the chain, not
    // a record count, the deletion detector.
    let (_dir, path) = temp_chain();
    closed_session(&path, &["call-0"]);
    let mut lines = rows(&path);
    let before = lines.len();
    assert_eq!(parse(&lines[1])["line_type"], json!("intent"));
    lines.remove(1);
    write_rows(&path, &lines);

    // The fixture precondition the reorder row cannot satisfy: the file is one
    // line shorter and the removed line is gone from it entirely. Both rows
    // report `ChainBroken` at session 0 seq 2, so the mutation itself is the
    // only thing that distinguishes them.
    let mutated = rows(&path);
    assert_eq!(mutated.len(), before - 1, "a deletion drops a line");
    assert!(
        !mutated
            .iter()
            .any(|row| parse(row)["line_type"] == json!("intent")),
        "the deleted intent line must not still be in the file: {mutated:?}"
    );

    let output = verify_path(&path);
    assert_exit(&output, 1);
    assert_verdict(&output, "Tampered:", "chains to");
}

// ---- matrix row 7 --------------------------------------------------------

#[test]
fn a_validly_resigned_record_leaves_the_next_prev_hash_stale() {
    // The sharpest row in the matrix: the edited line's own signature is
    // *valid*, because this fixture holds the key the file was signed with. So
    // nothing about that line is detectable in isolation. What gives it away is
    // the line after it, whose `prev_hash` still commits to the pre-edit bytes —
    // hence the assertion on seq 3, one past the line that was rewritten. An
    // attacker holding the key would have to re-sign the entire remainder.
    let (_dir, path) = temp_chain();
    closed_session(&path, &["call-0", "call-1"]);
    let mut rows = rows(&path);

    let mut record = parse(&rows[2]);
    assert_eq!(record["line_type"], json!("outcome"));
    record["call_id"] = json!("call-rewritten");
    rows[2] = resign(record);
    write_rows(&path, &rows);

    let output = verify_path(&path);
    assert_exit(&output, 1);
    assert_verdict(&output, "Tampered:", "session 0 seq 3 chains to");
}

// ---- matrix row 8 --------------------------------------------------------

#[test]
fn a_record_spliced_in_from_another_session_is_tampering() {
    // The spliced line is genuine: written by the real writer, validly signed,
    // and signed by the *same* key, since both files use the dev key. Its
    // provenance is not what fails — its position is.
    let (_dir, path) = temp_chain();
    let donor = path.with_file_name("donor.jsonl");
    closed_session(&path, &["call-here"]);
    closed_session(&donor, &["call-elsewhere"]);

    let donor_rows = rows(&donor);
    let mut rows = rows(&path);
    assert_eq!(parse(&donor_rows[2])["line_type"], json!("outcome"));
    rows[2] = donor_rows[2].clone();
    write_rows(&path, &rows);

    let output = verify_path(&path);
    assert_exit(&output, 1);
    assert_verdict(&output, "Tampered:", "session 0 seq 2 chains to");
}

// ---- matrix row 9 --------------------------------------------------------

#[test]
fn an_outcome_line_with_its_signature_stripped_is_tampering() {
    // Dropping the `Close` first is what makes this test mean something:
    // stripping the signature off the *last* line breaks no `prev_hash`, so the
    // chain alone would shrug. The rule that catches it is ADR-0002's — the
    // unverified tail may hold intent lines and at most one torn final line,
    // never an outcome.
    let (_dir, path) = temp_chain();
    closed_session(&path, &["call-0"]);
    let mut rows = rows(&path);
    rows.pop();

    let last = rows.len() - 1;
    let mut record = parse(&rows[last]);
    assert_eq!(record["line_type"], json!("outcome"));
    record
        .as_object_mut()
        .expect("a chain line is an object")
        .remove("signature");
    rows[last] = to_canonical_json(&record).expect("canonical line");
    write_rows(&path, &rows);

    let output = verify_path(&path);
    assert_exit(&output, 1);
    assert_verdict(&output, "Tampered:", "line carries no signature");
}

// ---- matrix row 10 -------------------------------------------------------

#[test]
fn truncating_a_non_final_session_is_tampering() {
    // Truncation is not detectable from a chain alone — every remaining line
    // still links and still verifies. It is detectable *here* because the second
    // Session's signed `Open` back-references the first Session's final hash.
    let (_dir, path) = temp_chain();
    two_sessions(&path);
    let mut rows = rows(&path);
    rows.remove(2); // the first Session's `Close`
    write_rows(&path, &rows);

    let output = verify_path(&path);
    assert_exit(&output, 1);
    assert_verdict(&output, "Tampered:", "session 1 back-references");
}

// ---- matrix row 11 -------------------------------------------------------

#[test]
fn a_key_that_is_not_the_open_key_is_tampering_not_merely_unpinned() {
    // Downgrading this to `Verified (unpinned)` would let any well-formed file
    // pass a `--key` gate by ignoring the key it was gated on.
    let (_dir, path) = temp_chain();
    closed_session(&path, &["call-0"]);

    let output = verify(&["--key", &foreign_key(), path_arg(&path)]);
    assert_exit(&output, 1);
    assert_verdict(&output, "Tampered:", "not in the supplied trust store");
    // The report still names the key the file published, so an operator can
    // compare fingerprints without re-reading the record.
    assert!(
        stdout(&output).contains(&format!("key_id {}", session_fingerprint())),
        "stdout={}",
        stdout(&output)
    );
}

// ---- matrix row 12 -------------------------------------------------------

#[test]
fn two_decisions_for_one_approval_id_are_tampering() {
    // Both lines come from the real writer, are validly signed, and chain
    // perfectly. This is a rule about the record, not about the crypto: without
    // it a recorded denial can be followed by an approval for the same park and
    // the file still verifies (ADR-0005).
    let (_dir, path) = temp_chain();
    {
        let writer = AuditWriter::open(&path, session_key()).expect("open chain");
        for _ in 0..2 {
            let mut decision = AuditDecision::new(
                ApprovalId::new("apr-1"),
                ApprovalVerdict::Denied {
                    reason: "operator said no".into(),
                },
            );
            writer.emit_decision(&mut decision).expect("decision");
        }
    }

    let output = verify_path(&path);
    assert_exit(&output, 1);
    assert_verdict(&output, "Tampered:", "decides approval apr-1 a second time");
}

// ---- matrix row 13 -------------------------------------------------------

#[test]
fn a_final_session_with_no_close_is_indeterminate() {
    // The SIGKILL case, and also the live-file case: a file still being appended
    // to always shows an uncovered tail. Both are the same `UnanchoredTail`, so
    // this row covers the live file too — without watching one, which would make
    // the suite time-dependent for no extra evidence.
    let (_dir, path) = temp_chain();
    unclosed_session(&path, &["call-0"], &[]);

    let output = verify_path(&path);
    assert_exit(&output, 3);
    assert_verdict(&output, "Indeterminate:", "no close record");
}

// ---- matrix row 14 -------------------------------------------------------

#[test]
fn a_trailing_torn_line_is_indeterminate() {
    // Distinct from "no close record": a torn write says a line was being
    // appended when the process died, which is a different operator story from a
    // Session that simply has not closed yet.
    let (_dir, path) = temp_chain();
    unclosed_session(&path, &["call-0"], &[]);
    let mut text = std::fs::read_to_string(&path).expect("chain file readable");
    text.push_str("{\"line_type\":\"outcome\",\"seq\"");
    std::fs::write(&path, &text).expect("write chain file");

    let output = verify_path(&path);
    assert_exit(&output, 3);
    assert_verdict(&output, "Indeterminate:", "torn write");
    // Everything before the torn line stays covered: a torn tail is not a reason
    // to disown the Session's verified prefix.
    assert!(
        stdout(&output).contains("coverage session 0 seq 2"),
        "stdout={}",
        stdout(&output)
    );
}

// ---- matrix row 15 -------------------------------------------------------

#[test]
fn an_unknown_line_type_is_indeterminate_even_with_a_valid_signature() {
    // The extensibility story. This line is correctly chained *and* correctly
    // signed, so nothing contradicts it — and the `Close` appended after it
    // still chains and still verifies, which is what the coverage assertion
    // below proves. The verdict is withheld anyway: a verifier that reported
    // `Verified` over content it cannot read is how a newer emitter smuggles a
    // line past an old auditor.
    //
    // A signature present and *invalid* on such a line would be exit 1 instead —
    // forgery is decidable without understanding the line, and it outranks the
    // cap. That is the library's rule, not this row's.
    let (_dir, path) = temp_chain();
    unclosed_session(&path, &["call-0"], &[]);
    append_line(&path, "something-from-2027");
    append_line(&path, "close");

    let output = verify_path(&path);
    assert_exit(&output, 3);
    // The emitter's own token survives into the report: an operator gets the
    // name of the thing this build could not read, not "parse error".
    assert_verdict(
        &output,
        "Indeterminate:",
        "unknown line type `something-from-2027`",
    );
    assert!(
        stdout(&output).contains("coverage session 0 seq 4"),
        "the Close after the unknown line must still chain and verify, stdout={}",
        stdout(&output)
    );
}

// ---- matrix row 16 -------------------------------------------------------

#[test]
fn a_path_that_does_not_exist_exits_two_with_nothing_on_stdout() {
    // Exit 2 is "no verdict", not a verdict. stdout stays empty so a script that
    // pipes it into a report never finds a half-answer there; the user-supplied
    // path goes to stderr only.
    let (dir, _path) = temp_chain();
    let missing = dir.path().join("no-such-record.jsonl");

    let output = verify_path(&missing);
    assert_exit(&output, 2);
    assert_eq!(output.stdout, b"", "stdout={}", stdout(&output));
    assert!(
        stderr(&output).starts_with("error:"),
        "stderr={}",
        stderr(&output)
    );
}

// ---- cross-Session anchoring ---------------------------------------------

#[test]
fn truncating_the_first_session_exits_one_and_truncating_the_second_exits_three() {
    // The headline property and its honest half, over one fixture: the
    // undecidable set is *one* Session, not every Session. Only the final
    // Session's tail has nothing signed beyond it; every earlier Session is
    // anchored by the next `Open`.
    let (_dir, path) = temp_chain();
    let both = path.with_file_name("both.jsonl");
    two_sessions(&both);
    let original = rows(&both);

    let mut truncated_first = original.clone();
    truncated_first.remove(2);
    write_rows(&both, &truncated_first);
    let output = verify_path(&both);
    assert_exit(&output, 1);
    assert_verdict(&output, "Tampered:", "session 1 back-references");

    let mut truncated_second = original;
    truncated_second.pop();
    write_rows(&both, &truncated_second);
    let output = verify_path(&both);
    assert_exit(&output, 3);
    assert_verdict(&output, "Indeterminate:", "session 1 has no close record");
}

// ---- determinism ---------------------------------------------------------

#[test]
fn two_runs_over_the_same_bytes_produce_byte_identical_output() {
    // Compared on the raw bytes, not on lossy strings: a timestamp, a path, or a
    // hash-map iteration order leaking into the report would show up here and
    // nowhere else. The fixture is the richest report the formatter emits —
    // verdict, key_id, coverage and in_flight lines — so every section is inside
    // the comparison.
    let (_dir, path) = temp_chain();
    unclosed_session(&path, &["call-done"], &["call-a", "call-b"]);

    let first = verify(&["--key", &session_public_key(), path_arg(&path)]);
    let second = verify(&["--key", &session_public_key(), path_arg(&path)]);
    assert_exit(&first, 3);
    assert_eq!(first.status.code(), second.status.code());
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.stderr, second.stderr);
}

// ---- what an exit-3 report has to name -----------------------------------

#[test]
fn an_exit_three_report_names_every_call_in_flight_in_walk_order() {
    // Three intents for workspace reads is a shrug; one for `net.post` is where
    // an operator starts looking. An `Indeterminate` that only said "uncovered
    // tail" would send them to read the file to learn which.
    let (_dir, path) = temp_chain();
    unclosed_session(&path, &[], &["call-a", "call-b"]);

    let output = verify_path(&path);
    assert_exit(&output, 3);
    let in_flight: Vec<String> = stdout(&output)
        .lines()
        .filter(|line| line.starts_with("in_flight "))
        .map(str::to_owned)
        .collect();
    assert_eq!(
        in_flight,
        vec!["in_flight call-a".to_owned(), "in_flight call-b".to_owned()],
        "stdout={}",
        stdout(&output)
    );
}

// ---- argument surface ----------------------------------------------------

#[test]
fn verify_without_a_path_is_a_usage_error() {
    // Exit 1 is shared with `Tampered` on purpose — ADR-0002 pins four codes
    // and no more — so the distinction lives on stderr.
    let output = verify(&[]);
    assert_exit(&output, 1);
    assert!(
        stderr(&output).contains("requires <PATH>"),
        "stderr={}",
        stderr(&output)
    );
}

#[test]
fn the_usage_text_names_verify_and_both_trust_flags() {
    let usage = botzr_aegis_cli::usage_text();
    for token in ["verify", "--key", "--trust-store"] {
        assert!(usage.contains(token), "usage missing {token}");
    }
    // And it is reachable from the binary, on stderr, without exiting non-zero.
    let output = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .arg("--help")
        .output()
        .expect("spawn aegis");
    assert_exit(&output, 0);
    assert_eq!(stderr(&output), usage);
}

// ---- the trust store -----------------------------------------------------

#[test]
fn a_key_that_only_the_trust_store_supplies_satisfies_the_pin() {
    // The wiring row, and the only one here that ends in exit 0. Every other
    // trust-store test asserts a *failure*, so all of them stay green if the
    // parsed keys never reach the trust slice at all — a `--trust-store` that
    // silently anchored nothing would look exactly like a suite that passes.
    // Verified by mutation: dropping the store's keys on the floor keeps the
    // rest of this file, and all of `botzr-aegis-audit`, green.
    //
    // This is not a parser-shape test — those moved to `botzr-aegis-audit`'s
    // `trust` module (AILAB-704). The key is passed *only* via the store and
    // never via `--key`, so the assertion is that the store path carries a key
    // all the way to a `Verified (pinned)` label. The surrounding comment and
    // blank lines are here so the file the CLI hands the library is one an
    // operator would really write, not to re-test that they are skipped.
    let (dir, path) = temp_chain();
    closed_session(&path, &["call-0"]);
    let store = dir.path().join("trusted-keys.txt");
    std::fs::write(
        &store,
        format!(
            "# keys this auditor accepts\n\
             \n\
             {}\n",
            session_public_key()
        ),
    )
    .expect("write trust store");

    let output = verify(&["--trust-store", path_arg(&store), path_arg(&path)]);
    assert_exit(&output, 0);
    assert_eq!(
        verdict_line(&output),
        format!("Verified (pinned to {})", session_fingerprint())
    );
}

#[test]
fn an_empty_trust_store_fails_the_pin_rather_than_silently_going_unpinned() {
    // The ADR-0004 failure this flag exists to prevent: a CI gate whose trust
    // store gets truncated or mis-mounted must not keep passing with its anchor
    // gone. Whether the walk is pinned is what the operator *asked for*, not
    // whether the resulting slice happened to be non-empty — so an empty store
    // is a pin nothing can satisfy, and the record it is gating verifies clean
    // without it, which is what makes this row about the store.
    let (dir, path) = temp_chain();
    closed_session(&path, &["call-0"]);
    assert_exit(&verify_path(&path), 0);

    let store = dir.path().join("empty-keys.txt");
    std::fs::write(&store, "").expect("write trust store");

    let output = verify(&["--trust-store", path_arg(&store), path_arg(&path)]);
    assert_exit(&output, 1);
    assert_verdict(&output, "Tampered:", "not in the supplied trust store");
}

#[test]
fn a_trust_store_of_only_comments_and_blank_lines_fails_the_pin() {
    // The same hole one step further in: a store that *reads* fine, parses
    // fine, and yields nothing. That comments and blanks are skipped at all is
    // now covered in `botzr-aegis-audit`'s `trust` module, in process; what this
    // row proves is the orchestration fact only the CLI holds — skipping them
    // all the way down is not a way back to `Verified (unpinned)`.
    let (dir, path) = temp_chain();
    closed_session(&path, &["call-0"]);
    let store = dir.path().join("commented-out-keys.txt");
    std::fs::write(
        &store,
        "# the key that used to live here was rotated out\n\
         \n\
         # and nobody put the new one back\n\
         \n",
    )
    .expect("write trust store");

    let output = verify(&["--trust-store", path_arg(&store), path_arg(&path)]);
    assert_exit(&output, 1);
    assert_verdict(&output, "Tampered:", "not in the supplied trust store");
}

#[test]
fn a_trust_store_that_cannot_be_read_exits_two() {
    // The same class of failure as a record nobody can read: no verdict was
    // produced, so neither 0 nor 1 nor 3 would be honest. The record itself is
    // untouched and verifies clean, which is what makes this row about the store.
    let (dir, path) = temp_chain();
    closed_session(&path, &["call-0"]);
    let missing = dir.path().join("no-such-store.txt");

    let output = verify(&["--trust-store", path_arg(&missing), path_arg(&path)]);
    assert_exit(&output, 2);
    assert_eq!(output.stdout, b"", "stdout={}", stdout(&output));
    assert!(
        stderr(&output).contains("trust store"),
        "stderr={}",
        stderr(&output)
    );
}

#[test]
fn a_trust_store_entry_that_is_not_a_key_exits_one_and_names_the_line() {
    // The other half of the exit mapping, and the half that must *not* be 2: a
    // store that read fine and holds a typo is the operator's mistake, exactly
    // like `--key deadbeef` — exit 1, the usage code. The line number is on
    // stderr because a store an operator annotates is a store an operator has to
    // be able to find the bad row in. Parser mechanics live in
    // `botzr-aegis-audit`'s `trust` module; what is asserted here is the code
    // and the rendering a shell sees.
    let (dir, path) = temp_chain();
    closed_session(&path, &["call-0"]);
    let store = dir.path().join("typo-keys.txt");
    std::fs::write(
        &store,
        format!(
            "# the good key first, so the failure is not just \"line 1\"\n\
             {}\n\
             deadbeef\n",
            session_public_key()
        ),
    )
    .expect("write trust store");

    let output = verify(&["--trust-store", path_arg(&store), path_arg(&path)]);
    assert_exit(&output, 1);
    assert_eq!(output.stdout, b"", "stdout={}", stdout(&output));
    let stderr = stderr(&output);
    assert!(stderr.contains("line 3"), "stderr={stderr}");
    assert!(stderr.contains("not a public key"), "stderr={stderr}");
}
