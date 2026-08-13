//! Integration: the `aegis wrap` argument surface, plus one real relay through
//! the installed binary.
//!
//! The relay itself is covered where it lives, in `botzr-aegis-wrap`'s own
//! `tests/relay.rs`. What only this file can cover is the *process* path: argv
//! after `--` surviving the CLI, `run_wrap` on the binary's real stdio, and the
//! child's exit code arriving back at the shell.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use tempfile::TempDir;

/// A wrap process that has not exited by now is a hang, and a hang has to fail
/// this test rather than park CI. Generous against a loaded runner: wrap's own
/// exit path is bounded at 5 s of event loop plus 5 s of reap.
const HANG_GUARD: Duration = Duration::from_secs(30);

/// One `tools/call` for the child below to answer.
const TOOLS_CALL: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi-wrap"}}}"#;

/// A minimal, genuinely response-shaped MCP-ish child: read one request, check
/// it actually arrived, answer with a JSON-RPC **response**.
///
/// LOAD-BEARING that this is not `cat`. An echoing child sends the *request*
/// back — a frame with a `method` and no `result` — and wrap must not treat
/// that as a response: MCP servers issue their own requests to the client
/// (`sampling/createMessage`, `roots/list`) from an id space that collides with
/// the client's, so matching a request as a response completes the wrong call
/// (`botzr-aegis-wrap/src/record.rs`, `is_response_shaped`). The two `exit`s
/// make a request that never arrived fail loudly instead of passing quietly.
#[cfg(unix)]
const RESPONDING_CHILD: &str = concat!(
    "read -r line || exit 7; ",
    "case \"$line\" in *hi-wrap*) ;; *) exit 8;; esac; ",
    r#"printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"ok":true,"saw":"hi-wrap"}}'"#
);

/// Provision a signing key the way an operator does — `aegis keygen --out`.
///
/// `wrap` has no temp-sink mode and no dev-key fallback (AILAB-620), so every
/// session needs one minted first. A `TempDir` rather than a `NamedTempFile`
/// because `keygen` refuses to write over a file that already exists.
fn keygen(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("signing.key");
    let output = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args(["keygen", "--out", path.to_str().unwrap()])
        .output()
        .expect("spawn aegis keygen");
    assert!(
        output.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    path
}

/// `aegis wrap <args>` with stdin at `/dev/null`.
///
/// Safe to run to completion for every argument-level case here: each one fails
/// in `parse_args`, before a child is ever spawned.
fn wrap(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aegis"))
        .arg("wrap")
        .args(args)
        .output()
        .expect("spawn aegis wrap")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// `wait_with_output` behind a timeout.
///
/// `Child::wait_with_output` is unbounded, and this is the one case that starts
/// a real session — so a deadlock in the pump would stall the job instead of
/// reddening it.
fn wait_with_guard(child: Child) -> Output {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    rx.recv_timeout(HANG_GUARD)
        .expect("aegis wrap must exit; a hang is the failure this guard catches")
        .expect("wait_with_output")
}

#[test]
fn wrap_without_a_child_command_is_a_usage_error() {
    let dir = tempfile::tempdir().expect("temp dir");
    let audit = dir.path().join("audit.jsonl");
    let key = keygen(&dir);

    // No separator at all.
    let output = wrap(&[
        "--audit",
        audit.to_str().unwrap(),
        "--signing-key",
        key.to_str().unwrap(),
    ]);
    assert!(!output.status.success(), "expected a usage error");
    assert!(
        stderr(&output).contains("child command"),
        "{}",
        stderr(&output)
    );

    // The separator, with nothing after it.
    let output = wrap(&[
        "--audit",
        audit.to_str().unwrap(),
        "--signing-key",
        key.to_str().unwrap(),
        "--",
    ]);
    assert!(!output.status.success(), "expected a usage error");
    assert!(
        stderr(&output).contains("child command"),
        "{}",
        stderr(&output)
    );

    // A refused invocation opens nothing.
    assert!(
        !audit.exists(),
        "a refused wrap must not open the record file"
    );
}

/// LOAD-BEARING (AILAB-620): the pairing rule holds on this verb too, and here
/// it is stricter — `wrap` has no temp-sink mode, so *neither* path given is
/// also an error rather than a default.
#[test]
fn wrap_requires_both_the_record_file_and_its_key() {
    let dir = tempfile::tempdir().expect("temp dir");
    let audit = dir.path().join("audit.jsonl");
    let key = keygen(&dir);

    let output = wrap(&["--audit", audit.to_str().unwrap(), "--", "cat"]);
    assert!(!output.status.success(), "--audit alone must not run");
    assert!(
        stderr(&output).contains("--signing-key"),
        "{}",
        stderr(&output)
    );
    assert!(
        !audit.exists(),
        "a refused wrap must not open the record file"
    );

    let output = wrap(&["--signing-key", key.to_str().unwrap(), "--", "cat"]);
    assert!(!output.status.success(), "--signing-key alone must not run");
    assert!(stderr(&output).contains("--audit"), "{}", stderr(&output));

    let output = wrap(&["--", "cat"]);
    assert!(!output.status.success(), "neither path must not run");
    assert!(stderr(&output).contains("--audit"), "{}", stderr(&output));
}

#[test]
fn the_usage_text_names_wrap_and_its_flags() {
    let usage = botzr_aegis_cli::usage_text();
    for token in [
        "aegis wrap --audit <PATH> --signing-key <PATH> [--confine] -- <CMD>",
        "Wrap options:",
        "--audit",
        "--signing-key",
    ] {
        assert!(usage.contains(token), "usage missing {token}");
    }

    // `wrap --help` is wrap's own help, on stderr, exit 0 — the same shape the
    // other verbs use.
    let output = wrap(&["--help"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stderr(&output), usage);
}

/// One real session end to end: the binary parses `-- sh -c …`, spawns it,
/// relays a `tools/call`, matches the child's **response**, records it, and
/// hands back the child's exit code.
///
/// A `sh` one-liner rather than a fixture binary because `CARGO_BIN_EXE_*` only
/// resolves bins of the package under test, and the wrap crate's mirror child
/// lives in another package. See [`RESPONDING_CHILD`] for why it is not `cat`.
#[cfg(unix)]
#[test]
fn a_real_relay_through_the_binary_records_and_verifies() {
    let dir = tempfile::tempdir().expect("temp dir");
    let audit = dir.path().join("audit.jsonl");
    let key = keygen(&dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args([
            "wrap",
            "--audit",
            audit.to_str().unwrap(),
            "--signing-key",
            key.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            RESPONDING_CHILD,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aegis wrap");

    let mut stdin = child.stdin.take().expect("stdin");
    writeln!(stdin, "{TOOLS_CALL}").expect("write request");
    // Client EOF is the session's shutdown signal: wrap closes the child's
    // stdin, the child finishes, and the relay returns.
    drop(stdin);

    let output = wait_with_guard(child);
    assert!(
        output.status.success(),
        "wrap must pass through the child's exit 0 (7 = request never arrived, \
         8 = the wrong bytes arrived): status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    // stdout carries the relayed JSON-RPC and nothing else.
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        stdout.contains(r#""ok":true"#),
        "relayed response: {stdout}"
    );
    assert!(
        !stdout.contains(r#""method""#),
        "the request must not come back as a response: {stdout}"
    );

    let jsonl = std::fs::read_to_string(&audit).expect("audit readable");
    let outcome = jsonl
        .lines()
        .find(|line| line.contains("\"line_type\":\"outcome\""))
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("outcome is JSON"))
        .unwrap_or_else(|| panic!("no outcome row: {jsonl}"));
    assert!(
        jsonl.contains("\"line_type\":\"intent\""),
        "missing intent: {jsonl}"
    );
    assert_eq!(outcome["schema_version"], 2, "{outcome}");
    assert_eq!(outcome["tool_id"], "echo", "{outcome}");
    assert_eq!(outcome["execution"]["status"], "success", "{outcome}");
    // The call was closed by a *matched response*, not by the child exiting: a
    // response digest exists, and the execution status is not `host_denied`.
    assert!(
        outcome["response_digest"].is_string(),
        "the matched response must be digested: {outcome}"
    );

    // The Session closed cleanly, so the chain the wrap process left behind is
    // one `aegis verify` will walk to a verdict.
    let verified = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args(["verify", audit.to_str().unwrap()])
        .output()
        .expect("spawn aegis verify");
    assert!(
        verified.status.success(),
        "verify stdout={} stderr={}",
        String::from_utf8_lossy(&verified.stdout),
        String::from_utf8_lossy(&verified.stderr)
    );
}
