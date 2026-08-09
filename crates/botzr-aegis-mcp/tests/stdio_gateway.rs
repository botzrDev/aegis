//! E2E: drive the botzr-aegis-mcp binary over stdio (covers src/main.rs).

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use tempfile::NamedTempFile;

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
    let audit = NamedTempFile::new().expect("temp audit");
    let mut child = spawn_gateway(&["--audit", audit.path().to_str().unwrap()]);
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

    let jsonl = std::fs::read_to_string(audit.path()).expect("audit readable");
    assert!(jsonl.contains("\"phase\":\"outcome\""), "audit: {jsonl}");
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
    for args in [&["--bogus"][..], &["--policy"][..], &["--audit"][..]] {
        let out = Command::new(env!("CARGO_BIN_EXE_botzr-aegis-mcp"))
            .args(args)
            .output()
            .expect("spawn");
        assert!(!out.status.success(), "expected failure for {args:?}");
    }
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
