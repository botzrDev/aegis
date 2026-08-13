//! `aegis __confine-exec` and `aegis wrap --confine` through the installed
//! binary. Real child processes (MSRV 1.86 has no `std::io::pipe`).

#![cfg(target_os = "linux")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use tempfile::TempDir;

const HANG_GUARD: Duration = Duration::from_secs(30);

fn aegis() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aegis"))
}

fn sibling_bin(name: &str) -> Option<PathBuf> {
    let mut p = PathBuf::from(env!("CARGO_BIN_EXE_aegis"));
    p.set_file_name(name);
    p.exists().then_some(p)
}

fn exec_support_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for p in [
        "/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin", "/etc", "/dev", "/proc", "/tmp",
    ] {
        let path = PathBuf::from(p);
        if path.exists() {
            out.push(path);
        }
    }
    if let Some(parent) = PathBuf::from(env!("CARGO_BIN_EXE_aegis")).parent() {
        out.push(parent.to_path_buf());
    }
    out
}

fn keygen(dir: &TempDir, name: &str) -> PathBuf {
    let path = dir.path().join(name);
    let output = aegis()
        .args(["keygen", "--out", path.to_str().unwrap()])
        .output()
        .expect("keygen");
    assert!(
        output.status.success(),
        "keygen: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    path
}

fn profile_json(read: &[&Path]) -> String {
    let mut read_paths: Vec<PathBuf> = exec_support_paths();
    read_paths.extend(read.iter().map(|p| p.to_path_buf()));
    serde_json::json!({
        "read_paths": read_paths,
        "write_paths": [],
        "net": [],
        "best_effort": false,
    })
    .to_string()
}

#[test]
fn confine_exec_through_the_aegis_binary() {
    let dir = tempfile::tempdir().unwrap();
    let inside = dir.path().join("ok.txt");
    std::fs::write(&inside, b"ok").unwrap();
    let report = dir.path().join("enforced.json");

    let output = aegis()
        .args(["__confine-exec", "--", "/bin/cat", inside.to_str().unwrap()])
        .env("AEGIS_CONFINE_PROFILE", profile_json(&[dir.path()]))
        .env("AEGIS_CONFINE_REPORT", &report)
        .output()
        .expect("spawn __confine-exec");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("Landlock is not available") {
            eprintln!("skip: kernel does not support Landlock ({stderr})");
            return;
        }
        panic!(
            "__confine-exec failed: status={:?} stderr={stderr}",
            output.status
        );
    }
    assert_eq!(output.stdout, b"ok");
    let enforced: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("report")).expect("json");
    assert!(
        enforced["landlock_abi"].as_i64().unwrap_or(0) > 0,
        "shape: an ABI was recorded, got {enforced}"
    );
    assert_eq!(enforced["seccomp_applied"], true, "{enforced}");
}

#[test]
fn wrap_confine_end_to_end_with_botzr_aegis_mcp() {
    let Some(mcp) = sibling_bin("botzr-aegis-mcp") else {
        eprintln!(
            "skip: botzr-aegis-mcp binary is not next to aegis \
             (build the workspace, not -p botzr-aegis-cli alone)"
        );
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("wrap.jsonl");
    let key = keygen(&dir, "wrap.key");
    let mcp_audit = dir.path().join("mcp.jsonl");
    let mcp_key = keygen(&dir, "mcp.key");

    let mut cmd = aegis();
    cmd.arg("wrap")
        .arg("--audit")
        .arg(&audit)
        .arg("--signing-key")
        .arg(&key)
        .arg("--confine");
    for p in exec_support_paths() {
        cmd.arg("--allow-read").arg(&p);
    }
    cmd.arg("--allow-read")
        .arg(dir.path())
        .arg("--allow-write")
        .arg(dir.path())
        .arg("--allow-write")
        .arg(std::env::temp_dir())
        .arg("--")
        .arg(&mcp)
        .arg("--audit")
        .arg(&mcp_audit)
        .arg("--signing-key")
        .arg(&mcp_key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn aegis wrap --confine");
    let mut stdin = child.stdin.take().expect("stdin");
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .expect("initialize");
    drop(stdin);

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let output: Output = rx
        .recv_timeout(HANG_GUARD)
        .expect("wrap --confine hung")
        .expect("wait");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("Landlock is not available")
            || stderr.contains("cannot be fully enforced")
        {
            eprintln!("skip: kernel cannot enforce confinement ({stderr})");
            return;
        }
        panic!(
            "wrap --confine with botzr-aegis-mcp failed: status={:?} stderr={stderr} stdout={}",
            output.status,
            String::from_utf8_lossy(&output.stdout)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("jsonrpc") || stdout.contains("result") || stdout.contains("protocol"),
        "mcp initialize should produce a JSON-RPC response, got {stdout:?}"
    );

    let report = {
        let mut p = audit.as_os_str().to_os_string();
        p.push(".enforced.json");
        PathBuf::from(p)
    };
    let enforced: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&report)
            .unwrap_or_else(|e| panic!("enforced report {}: {e}", report.display())),
    )
    .expect("enforced json");
    assert!(
        enforced["landlock_abi"].as_i64().unwrap_or(0) > 0,
        "shape: ABI recorded, got {enforced}"
    );
    assert_eq!(enforced["seccomp_applied"], true, "{enforced}");
}
