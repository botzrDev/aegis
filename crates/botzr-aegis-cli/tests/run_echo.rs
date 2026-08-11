//! Integration: `aegis run` registers echo.wasm and walks the full pipeline.

use std::path::PathBuf;
use std::process::Command;

use tempfile::{NamedTempFile, TempDir};

fn echo_wasm() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/echo-tool/echo.wasm")
}

/// Provision a signing key the way an operator does — `aegis keygen --out` —
/// and return its path alongside the `public_key` it published.
///
/// `--audit` has no dev-key fallback (AILAB-620), so every run that names a
/// record file has to mint one first. Shelling out to the binary under test
/// rather than calling the library keeps `keygen` itself covered end to end,
/// including the two stdout lines `aegis verify --key` consumes. A `TempDir`
/// rather than a `NamedTempFile` because `keygen` refuses to write over a file
/// that already exists.
fn keygen(dir: &TempDir) -> (PathBuf, String) {
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

    let stdout = String::from_utf8_lossy(&output.stdout);
    let public_key = stdout
        .lines()
        .find_map(|l| l.strip_prefix("public_key "))
        .unwrap_or_else(|| panic!("keygen must print `public_key <hex>`, got: {stdout}"))
        .to_string();
    assert!(
        stdout.lines().any(|l| l.starts_with("key_id ")),
        "keygen must print `key_id <hex>`, got: {stdout}"
    );
    assert_eq!(public_key.len(), 64, "public_key: {public_key}");

    (path, public_key)
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
    let dir = tempfile::tempdir().expect("temp dir");
    let audit_path = dir.path().join("audit.jsonl");
    let (key_path, public_key) = keygen(&dir);

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
            "--signing-key",
            key_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn aegis");

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"hello-cli");

    let jsonl = std::fs::read_to_string(&audit_path).expect("audit readable");
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
    // The Session published the provisioned key, so the record file is pinnable
    // to something an operator holds — not to the seed shipped inside the
    // published audit crate (AILAB-620).
    assert!(
        jsonl.contains(&public_key),
        "open line must publish the keygen'd public key {public_key}: {jsonl}"
    );

    // End to end: that same key pins the file through `aegis verify`.
    let verified = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args(["verify", "--key", &public_key, audit_path.to_str().unwrap()])
        .output()
        .expect("spawn aegis verify");
    assert!(
        verified.status.success(),
        "verify stdout={} stderr={}",
        String::from_utf8_lossy(&verified.stdout),
        String::from_utf8_lossy(&verified.stderr)
    );
    assert!(
        String::from_utf8_lossy(&verified.stdout).contains("pinned"),
        "expected a pinned verdict: {}",
        String::from_utf8_lossy(&verified.stdout)
    );
}

/// LOAD-BEARING (AILAB-620): the binary refuses a persistent record file it has
/// no provisioned key for. This is the exact hole the ticket closed — every
/// `aegis run --audit` used to be signed by `insecure_dev_key`, whose seed ships
/// in the published `botzr-aegis-audit` crate.
#[test]
fn aegis_run_audit_without_a_signing_key_is_a_usage_error() {
    let dir = tempfile::tempdir().expect("temp dir");
    let audit_path = dir.path().join("audit.jsonl");

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
        !output.status.success(),
        "--audit with no --signing-key must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--signing-key"), "stderr: {stderr}");
    assert!(
        !audit_path.exists(),
        "a refused run must not open the record file"
    );
}

#[test]
fn aegis_run_policy_deny_still_audits() {
    let dir = tempfile::tempdir().expect("temp dir");
    let audit_path = dir.path().join("audit.jsonl");
    let (key_path, _public_key) = keygen(&dir);
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
            audit_path.to_str().unwrap(),
            "--signing-key",
            key_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn aegis");

    assert!(
        !output.status.success(),
        "expected deny failure, got success"
    );

    let jsonl = std::fs::read_to_string(&audit_path).expect("audit readable");
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
    let dir = tempfile::tempdir().expect("temp dir");
    let audit_path = dir.path().join("audit.jsonl");
    let (key_path, _public_key) = keygen(&dir);
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
            audit_path.to_str().unwrap(),
            "--signing-key",
            key_path.to_str().unwrap(),
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
