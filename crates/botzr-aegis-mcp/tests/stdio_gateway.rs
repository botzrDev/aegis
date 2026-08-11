//! E2E: drive the botzr-aegis-mcp binary over stdio (covers src/main.rs).

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use tempfile::TempDir;

/// A persistent audit sink plus the key that signs it.
///
/// `--audit` has no dev-key fallback (AILAB-620), so a gateway asked for a
/// record file needs a provisioned key or it refuses to start. The `TempDir`
/// comes back with the paths because dropping it removes both files.
fn temp_audit_sink() -> (TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let audit = dir.path().join("audit.jsonl");
    let key = dir.path().join("signing.key");
    botzr_aegis_audit::generate_signing_key(&key, false).expect("generate signing key");
    (dir, audit, key)
}

fn spawn_gateway(extra_args: &[&str]) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_botzr-aegis-mcp"))
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn botzr-aegis-mcp")
}

#[test]
fn stdio_session_initialize_list_call_and_deny() {
    let (_dir, audit_path, key_path) = temp_audit_sink();
    let mut child = spawn_gateway(&[
        "--audit",
        audit_path.to_str().unwrap(),
        "--signing-key",
        key_path.to_str().unwrap(),
    ]);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut lines = BufReader::new(stdout).lines();

    macro_rules! send_and_recv {
        ($req:expr) => {{
            writeln!(stdin, "{}", $req).expect("write request");
            lines.next().expect("response line").expect("read response")
        }};
    }

    let init = send_and_recv!(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#);
    assert!(init.contains("protocolVersion"), "init: {init}");

    let list = send_and_recv!(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
    assert!(
        list.contains("echo") && list.contains("exfil"),
        "list: {list}"
    );

    // Notification (no id): acknowledged by silence — send, do not read.
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
    )
    .unwrap();

    let echoed = send_and_recv!(
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi-e2e"}}}"#
    );
    let echoed_v: serde_json::Value = serde_json::from_str(&echoed).expect("echo JSON");
    assert!(echoed.contains("hi-e2e"), "echo: {echoed}");
    assert_eq!(
        echoed_v["result"]["isError"],
        serde_json::json!(false),
        "echo isError: {echoed}"
    );

    let denied = send_and_recv!(
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exfil","arguments":{"text":"secrets"}}}"#
    );
    let denied_v: serde_json::Value = serde_json::from_str(&denied).expect("deny JSON");
    assert_eq!(
        denied_v["result"]["isError"],
        serde_json::json!(true),
        "deny: {denied}"
    );

    let parse_err = send_and_recv!("this is not json");
    assert!(parse_err.contains("-32700"), "parse error: {parse_err}");

    drop(stdin); // EOF ends the session loop
    let status = child.wait().expect("wait");
    assert!(status.success(), "gateway exit: {status:?}");

    let jsonl = std::fs::read_to_string(&audit_path).expect("audit readable");
    assert!(
        jsonl.contains("\"line_type\":\"outcome\""),
        "audit: {jsonl}"
    );

    // The Session published the provisioned key, not the dev seed compiled into
    // the audit crate — the whole point of AILAB-620 at the MCP boundary.
    let key = botzr_aegis_audit::load_signing_key(&key_path).expect("load key");
    assert!(
        jsonl.contains(&key.public_key().to_hex()),
        "open line must publish the provisioned public key: {jsonl}"
    );
    assert!(
        !jsonl.contains(&botzr_aegis_audit::insecure_dev_key().public_key().to_hex()),
        "dev key must not sign a persistent sink: {jsonl}"
    );
}

#[test]
fn help_flag_exits_zero_with_usage() {
    let out = Command::new(env!("CARGO_BIN_EXE_botzr-aegis-mcp"))
        .arg("--help")
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Usage: botzr-aegis-mcp"),
        "stderr: {stderr}"
    );
}

#[test]
fn bad_flags_exit_nonzero() {
    for args in [
        &["--bogus"][..],
        &["--policy"][..],
        &["--audit"][..],
        &["--signing-key"][..],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_botzr-aegis-mcp"))
            .args(args)
            .output()
            .expect("spawn");
        assert!(!out.status.success(), "expected failure for {args:?}");
    }
}

/// LOAD-BEARING (AILAB-620): a gateway asked for a persistent record file it has
/// no provisioned key for must refuse to start. Starting anyway — signed by the
/// dev seed shipped in the published audit crate — is how a `Verified (pinned)`
/// label ends up pinning a public secret.
#[test]
fn a_persistent_sink_without_a_signing_key_exits_nonzero() {
    let (_dir, audit_path, key_path) = temp_audit_sink();

    let out = Command::new(env!("CARGO_BIN_EXE_botzr-aegis-mcp"))
        .args(["--audit", audit_path.to_str().unwrap()])
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "expected failure with no key");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--signing-key"), "stderr: {stderr}");
    assert!(
        !audit_path.exists(),
        "a refused gateway must not open the sink"
    );

    // The mirror: a key with no sink to sign is a mistake, not a silent no-op.
    let out = Command::new(env!("CARGO_BIN_EXE_botzr-aegis-mcp"))
        .args(["--signing-key", key_path.to_str().unwrap()])
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "expected failure with no --audit");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--audit"), "stderr: {stderr}");
}

/// A key path that cannot be loaded is fatal, not a fallback.
#[test]
fn an_unloadable_signing_key_exits_nonzero() {
    let (dir, audit_path, _key_path) = temp_audit_sink();

    let out = Command::new(env!("CARGO_BIN_EXE_botzr-aegis-mcp"))
        .args([
            "--audit",
            audit_path.to_str().unwrap(),
            "--signing-key",
            dir.path().join("absent.key").to_str().unwrap(),
        ])
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "expected failure for a missing key");
    assert!(
        !audit_path.exists(),
        "a refused gateway must not open the sink"
    );
}

#[test]
fn unreadable_policy_exits_nonzero() {
    let out = Command::new(env!("CARGO_BIN_EXE_botzr-aegis-mcp"))
        .args(["--policy", "/nonexistent/policy.yaml"])
        .output()
        .expect("spawn");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("error:"), "stderr: {stderr}");
}
