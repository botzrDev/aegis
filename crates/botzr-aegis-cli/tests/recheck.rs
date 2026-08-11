//! `aegis recheck` — the AILAB-622 §3.3 acceptance rows, one test per row,
//! asserted against the real binary.
//!
//! **Why the binary and not the library.** The subject is the *exit code* and
//! the *bytes on stdout*, and neither exists until a process has run. 0/1/2/3
//! are API the moment anyone scripts `if aegis recheck` in a policy-change
//! review, so what is under test is what the command hands back to a shell.
//! `botzr-aegis-policy`'s own suite already pins the verdict matrix; nothing
//! here re-derives a verdict.
//!
//! Every assertion is on `status.code()` and never on `status.success()`: 1, 2
//! and 3 are all unsuccessful, so `success()` cannot tell "these calls would now
//! be blocked" from "the policy file is not there" — which is the distinction
//! the command exists to draw.
//!
//! Each row also asserts the printed clause, not only the code. An exit code
//! cannot tell `newly_blocked` from `newly_parked`, nor one `indeterminate`
//! reason from another, so without the text a row could fire on the wrong
//! mechanism and still look green.
//!
//! **Fixtures are committed, not generated here.** They live under
//! `tests/fixtures/recheck/` and are re-read on every run, so the byte-identical
//! row compares two runs over the *same* bytes rather than over two files a
//! generator happened to produce identically. They are also unsigned: recheck
//! checks no signatures, and a fixture that needed a key would tie a forensic
//! what-if to a key-management step it does not have.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

// ---- running the binary --------------------------------------------------

fn recheck(policy: &Path, path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aegis"))
        .arg("recheck")
        .arg("--policy")
        .arg(policy)
        .arg(path)
        .output()
        .expect("spawn aegis")
}

/// The common shape: a committed policy against a committed record file.
fn recheck_fixtures(policy: &str, session: &str) -> Output {
    recheck(&fixture(policy), &fixture(session))
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/recheck")
        .join(name)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Assert the exact exit code. Both streams go into the failure message: a code
/// mismatch on its own says nothing about which of the four answers came back.
#[track_caller]
fn assert_exit(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stdout={} stderr={}",
        stdout(output),
        stderr(output)
    );
}

#[track_caller]
fn assert_reports(output: &Output, line: &str) {
    assert!(
        stdout(output).lines().any(|printed| printed == line),
        "expected the report to contain `{line}`, got stdout={}",
        stdout(output)
    );
}

/// The three calls in `session_clean.jsonl`, in file order. Every row below
/// reads as a diff against this, which is what makes "one call moved" legible.
const CLEAN_UNCHANGED: &str = "call call-1 session 0 seq 2: unchanged allowed\n\
                               call call-2 session 0 seq 3: unchanged denied\n\
                               call call-3 session 0 seq 4: unchanged pending_approval\n";

// ---- row: a known would-block --------------------------------------------

#[test]
fn a_policy_that_refuses_a_recorded_call_exits_one_and_names_it() {
    // The finding the verb exists to surface: `reader` ran, and the set under
    // review would not have let it. The other two calls stay `unchanged`, so
    // the row also proves the diff is a diff and not a rewrite of the file.
    let output = recheck_fixtures("new_deny.yaml", "session_clean.jsonl");
    assert_exit(&output, 1);
    assert_eq!(
        stdout(&output),
        "call call-1 session 0 seq 2: newly_blocked was=allowed now=denied\n\
         call call-2 session 0 seq 3: unchanged denied\n\
         call call-3 session 0 seq 4: unchanged pending_approval\n"
    );
}

// ---- row: everything unchanged -------------------------------------------

#[test]
fn a_policy_that_moves_nothing_exits_zero() {
    // Exit 0 has to mean "re-evaluated, nothing moved", never "nothing was
    // evaluated" — so `unchanged.yaml` carries the rules that keep the recorded
    // deny denied and the recorded park parked. An empty rule list would report
    // both as `newly_allowed`.
    let output = recheck_fixtures("unchanged.yaml", "session_clean.jsonl");
    assert_exit(&output, 0);
    assert_eq!(stdout(&output), CLEAN_UNCHANGED);
}

// ---- row: a recorded park that is still parked ---------------------------

#[test]
fn a_recorded_park_that_is_still_parked_is_unchanged_not_newly_parked() {
    // Collapsing this into `newly_parked` would fill a review with calls
    // nothing happened to, and would imply a second approval for a park that
    // already has one recorded.
    let output = recheck_fixtures("new_park_same.yaml", "session_clean.jsonl");
    assert_exit(&output, 0);
    assert_reports(
        &output,
        "call call-3 session 0 seq 4: unchanged pending_approval",
    );
    assert!(
        !stdout(&output).contains("newly_parked"),
        "a still-parked call must not read as newly parked, stdout={}",
        stdout(&output)
    );
    // And no approval id is printed: a recheck mints none, so the only id in
    // play is the recorded one, which stays inside the record.
    assert!(
        !stdout(&output).contains("apr-"),
        "stdout={}",
        stdout(&output)
    );
}

// ---- row: newly parked ----------------------------------------------------

#[test]
fn a_call_that_would_now_be_held_for_a_human_is_newly_parked() {
    // Kept distinct from `newly_blocked` on purpose: a governance change that
    // adds a review gate is a different finding from one that refuses the call
    // outright, and collapsing the two would let the first read as an outage.
    let output = recheck_fixtures("new_park.yaml", "session_clean.jsonl");
    assert_exit(&output, 1);
    assert_reports(
        &output,
        "call call-1 session 0 seq 2: newly_parked was=allowed",
    );
    // No `now=` clause, because the only `now` available would be a
    // `pending_approval` whose id this run invented.
    assert!(
        !stdout(&output).contains("newly_parked was=allowed now="),
        "stdout={}",
        stdout(&output)
    );
}

// ---- row: a foreign schema version ---------------------------------------

#[test]
fn a_record_from_another_schema_version_is_indeterminate() {
    // Field names only mean something relative to the schema that defined them,
    // so a v1 record re-read with v2 semantics would produce a verdict that
    // looks authoritative and is unfounded. `unchanged.yaml` is the set under
    // which every *readable* call is unchanged, which is what makes this row
    // about the record rather than about the rules.
    let output = recheck_fixtures("unchanged.yaml", "session.jsonl");
    assert_exit(&output, 3);
    assert_reports(
        &output,
        "call call-4 session 0 seq 5: indeterminate unknown_policy_set_hash",
    );
}

// ---- row: an outcome that names no tool ----------------------------------

#[test]
fn an_outcome_that_names_no_tool_is_indeterminate() {
    // There is no tool, so there is no question a Policy Set can be asked. The
    // line still occupies a row in the report — a dropped line would make the
    // diff quietly incomplete — and the identity columns fall back to their
    // documented placeholders only when the record carries neither.
    let output = recheck_fixtures("unchanged.yaml", "session.jsonl");
    assert_exit(&output, 3);
    assert_reports(
        &output,
        "call call-5 session 0 seq 6: indeterminate no_binding",
    );
    // The parse failure is explained on stderr, so an operator is not left
    // guessing which unreadable shape they hit.
    assert!(
        stderr(&output).contains("tool_id"),
        "stderr={}",
        stderr(&output)
    );
}

// ---- row: a rate-limit rule ----------------------------------------------

#[test]
fn a_rate_limit_rule_is_unevaluable_offline() {
    // The window is process-local counter and wall-clock state that no record
    // carries. Reporting it as allowed or blocked would be a coin flip wearing
    // a verdict's clothes.
    let output = recheck_fixtures("new_rate.yaml", "session_clean.jsonl");
    assert_exit(&output, 3);
    assert_reports(
        &output,
        "call call-1 session 0 seq 2: indeterminate rate_limit_unevaluable",
    );
}

// ---- row: 3 beats 1 -------------------------------------------------------

#[test]
fn an_indeterminate_call_outranks_a_would_block_in_the_exit_code() {
    // The same set that exits 1 over the readable fixture exits 3 over the one
    // with unreadable lines in it, *and still prints the would-block*. A run
    // that could not answer for every call has not established that the rest is
    // a complete diff, so 1 would invite an operator to act on a subset as
    // though it were the whole finding.
    assert_exit(&recheck_fixtures("new_deny.yaml", "session_clean.jsonl"), 1);

    let output = recheck_fixtures("new_deny.yaml", "session.jsonl");
    assert_exit(&output, 3);
    assert_reports(
        &output,
        "call call-1 session 0 seq 2: newly_blocked was=allowed now=denied",
    );
}

// ---- row: nothing to read -------------------------------------------------

#[test]
fn a_record_file_that_does_not_exist_exits_two_with_nothing_on_stdout() {
    // Exit 2 is "no report", not a report. stdout stays empty so a script that
    // pipes it into a policy-change review never finds a half-answer there.
    let dir = tempfile::tempdir().expect("temp dir");
    let output = recheck(
        &fixture("unchanged.yaml"),
        &dir.path().join("no-such.jsonl"),
    );
    assert_exit(&output, 2);
    assert_eq!(output.stdout, b"", "stdout={}", stdout(&output));
    assert!(
        stderr(&output).starts_with("error:"),
        "stderr={}",
        stderr(&output)
    );
}

#[test]
fn a_policy_file_that_does_not_exist_exits_two_with_nothing_on_stdout() {
    let dir = tempfile::tempdir().expect("temp dir");
    let output = recheck(
        &dir.path().join("no-such-policy.yaml"),
        &fixture("session_clean.jsonl"),
    );
    assert_exit(&output, 2);
    assert_eq!(output.stdout, b"", "stdout={}", stdout(&output));
}

#[test]
fn a_policy_that_does_not_parse_exits_two_with_nothing_on_stdout() {
    // Same class as a file nobody can read: no diff was produced, so 0 would
    // claim nothing moved and 1 would claim something did.
    let output = recheck_fixtures("malformed.yaml", "session_clean.jsonl");
    assert_exit(&output, 2);
    assert_eq!(output.stdout, b"", "stdout={}", stdout(&output));
    assert!(
        stderr(&output).contains("policy"),
        "stderr={}",
        stderr(&output)
    );
}

// ---- determinism ----------------------------------------------------------

#[test]
fn two_runs_over_the_same_bytes_produce_byte_identical_output() {
    // Compared on raw bytes, not on lossy strings: a timestamp, a path echo, a
    // minted approval id or a hash-map iteration order leaking into the report
    // would show up here and nowhere else. `session.jsonl` is the richest input
    // the formatter has — every verdict kind and both indeterminate reasons it
    // can reach — so every branch of the renderer is inside the comparison.
    let first = recheck_fixtures("new_deny.yaml", "session.jsonl");
    let second = recheck_fixtures("new_deny.yaml", "session.jsonl");
    assert_exit(&first, 3);
    assert_eq!(first.status.code(), second.status.code());
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.stderr, second.stderr);
}

// ---- the symlink row ------------------------------------------------------

#[test]
fn a_symlink_repointed_after_the_call_cannot_move_a_verdict() {
    // `decision_axes.fs.path_canonical` is *evidence of what the call resolved
    // to*, not an input to the recheck. If it were consulted, this report would
    // describe today's filesystem rather than the one the call ran under, and
    // an auditor on a machine that never saw the call would read something
    // different again.
    //
    // The fixture records a path that does not exist. Here the same record is
    // re-pointed at a location under this test's control and the filesystem
    // underneath it is changed three ways — absent, a dangling symlink, a
    // symlink to a real file. The report must be byte-identical every time.
    let dir = tempfile::tempdir().expect("temp dir");
    let link = dir.path().join("link");
    let session = rewrite_recorded_path(&dir, &link);
    let policy = fixture("unchanged.yaml");

    // 1. Nothing at that path at all.
    let absent = recheck(&policy, &session);
    assert_exit(&absent, 0);
    assert_reports(&absent, "call call-1 session 0 seq 2: unchanged allowed");

    // 2. A dangling symlink — resolving it would fail outright.
    std::os::unix::fs::symlink("target-that-is-not-there", &link).expect("dangling symlink");
    let dangling = recheck(&policy, &session);

    // 3. Repointed at a file that does exist.
    std::fs::remove_file(&link).expect("drop the dangling link");
    let real = dir.path().join("real-file");
    std::fs::write(&real, b"contents that were never part of the call").expect("write target");
    std::os::unix::fs::symlink(&real, &link).expect("symlink to a real file");
    let repointed = recheck(&policy, &session);

    assert_eq!(absent.stdout, dangling.stdout);
    assert_eq!(absent.stdout, repointed.stdout);
    assert_eq!(absent.status.code(), dangling.status.code());
    assert_eq!(absent.status.code(), repointed.status.code());

    // And the committed fixture, whose recorded path exists nowhere, reads the
    // same — the recorded path changes nothing about the verdict, only about
    // what the record says happened.
    assert_reports(
        &recheck(&policy, &fixture("session_clean.jsonl")),
        "call call-1 session 0 seq 2: unchanged allowed",
    );
}

/// Copy `session_clean.jsonl` into `dir` with its recorded canonical path
/// swapped for `link`, so the test can put a real symlink where the record says
/// the call resolved.
fn rewrite_recorded_path(dir: &TempDir, link: &Path) -> PathBuf {
    const RECORDED: &str = "/nonexistent/aegis-recheck/dangling-target";
    let text = std::fs::read_to_string(fixture("session_clean.jsonl")).expect("fixture readable");
    assert!(
        text.contains(RECORDED),
        "the fixture must carry a dangling canonical path"
    );
    let path = dir.path().join("session.jsonl");
    std::fs::write(
        &path,
        text.replace(RECORDED, link.to_str().expect("temp paths are utf-8")),
    )
    .expect("write session copy");
    path
}

// ---- Session numbering ----------------------------------------------------

#[test]
fn sessions_are_numbered_in_file_order_from_zero() {
    // The address printed here has to be the one `aegis verify` prints, or an
    // operator cannot carry a finding from one report to the other. The audit
    // walker numbers the first `open` 0 and each later one +1; so does this.
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("two-sessions.jsonl");
    let one = std::fs::read_to_string(fixture("session_clean.jsonl")).expect("fixture readable");
    std::fs::write(&path, format!("{one}{one}")).expect("write two sessions");

    let output = recheck(&fixture("unchanged.yaml"), &path);
    assert_exit(&output, 0);
    assert_eq!(
        stdout(&output),
        format!(
            "{CLEAN_UNCHANGED}{}",
            CLEAN_UNCHANGED.replace("session 0", "session 1")
        )
    );
}

// ---- argument surface -----------------------------------------------------

#[test]
fn recheck_without_a_policy_is_a_usage_error() {
    // Exit 1 is shared with "a call moved", as `verify` shares it with
    // `Tampered` — four codes and no more — so the distinction lives on stderr.
    let output = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .arg("recheck")
        .arg(fixture("session_clean.jsonl"))
        .output()
        .expect("spawn aegis");
    assert_exit(&output, 1);
    assert!(
        stderr(&output).contains("--policy"),
        "stderr={}",
        stderr(&output)
    );
}

#[test]
fn the_usage_text_names_recheck_and_its_four_exit_codes() {
    let usage = botzr_aegis_cli::usage_text();
    for token in [
        "recheck",
        "--policy",
        "0  every call unchanged",
        "1  a call is newly blocked",
        "2  could not read the policy",
        "3  indeterminate",
    ] {
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
