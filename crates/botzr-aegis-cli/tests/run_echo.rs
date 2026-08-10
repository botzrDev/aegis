//! Integration: `aegis run` registers echo.wasm and walks the full pipeline.

use std::path::PathBuf;
use std::process::Command;

use tempfile::NamedTempFile;

fn echo_wasm() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/echo-tool/echo.wasm")
}

fn deny_echo_policy() -> &'static str {
    r#"
version: 1
default: allow
rules:
  - id: deny-echo
    action: deny
    tool: echo
    reason: "blocked in cli test"
"#
}

#[test]
fn aegis_run_echo_success_and_audit() {
    let audit = NamedTempFile::new().expect("temp audit");
    let audit_path = audit.path();

    let output = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args([
            "run",
            "--component",
            echo_wasm().to_str().unwrap(),
            "--id",
            "echo",
            "--input",
            "hello-cli",
            "--audit",
            audit_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn aegis");

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"hello-cli");

    let jsonl = std::fs::read_to_string(audit_path).expect("audit readable");
    assert!(
        jsonl.contains("\"line_type\":\"intent\""),
        "missing intent: {jsonl}"
    );
    assert!(
        jsonl.contains("\"line_type\":\"outcome\""),
        "missing outcome: {jsonl}"
    );
    assert!(
        jsonl.contains("\"status\":\"success\""),
        "missing success: {jsonl}"
    );
}

#[test]
fn aegis_run_policy_deny_still_audits() {
    let audit = NamedTempFile::new().expect("temp audit");
    let policy = NamedTempFile::new().expect("temp policy");
    std::fs::write(policy.path(), deny_echo_policy()).expect("write policy");

    let output = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args([
            "run",
            "--component",
            echo_wasm().to_str().unwrap(),
            "--id",
            "echo",
            "--input",
            "nope",
            "--policy",
            policy.path().to_str().unwrap(),
            "--audit",
            audit.path().to_str().unwrap(),
        ])
        .output()
        .expect("spawn aegis");

    assert!(
        !output.status.success(),
        "expected deny failure, got success"
    );

    let jsonl = std::fs::read_to_string(audit.path()).expect("audit readable");
    assert!(
        jsonl.contains("\"line_type\":\"outcome\""),
        "missing outcome on deny: {jsonl}"
    );
    assert!(
        jsonl.contains("\"status\":\"denied\"") || jsonl.contains("blocked in cli test"),
        "expected policy deny audit, got: {jsonl}"
    );
}

#[test]
fn aegis_unknown_command_prints_usage_and_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args(["frobnicate"])
        .output()
        .expect("spawn aegis");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown command"), "stderr: {stderr}");
    assert!(stderr.contains("Usage:"), "stderr: {stderr}");
}

#[test]
fn aegis_run_reads_input_file() {
    let audit = NamedTempFile::new().expect("temp audit");
    let input = NamedTempFile::new().expect("temp input");
    std::fs::write(input.path(), b"from-file").expect("write input");

    let output = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args([
            "run",
            "--component",
            echo_wasm().to_str().unwrap(),
            "--id",
            "echo",
            "--input-file",
            input.path().to_str().unwrap(),
            "--audit",
            audit.path().to_str().unwrap(),
        ])
        .output()
        .expect("spawn aegis");

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"from-file");
}

#[test]
fn aegis_run_missing_component_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args([
            "run",
            "--component",
            "/nonexistent/tool.wasm",
            "--id",
            "ghost",
        ])
        .output()
        .expect("spawn aegis");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("read component"), "stderr: {stderr}");
}
