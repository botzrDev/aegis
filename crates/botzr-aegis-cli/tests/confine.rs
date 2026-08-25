//! `aegis __confine-exec` and `aegis wrap --confine` through the installed
//! binary. Real child processes (MSRV 1.86 has no `std::io::pipe`).
//!
//! **What the `seccomp_network_denied` assertions here are, and are not**
//! (AILAB-808). They read the field back out of the report the same run just
//! wrote, so they check the CLI wiring — the flag reached the profile, the
//! profile reached the filter, the outcome reached the record — and they check
//! the serializer. They do **not** prove the network is denied; a test that
//! reads a claim out of the artifact under test cannot.
//!
//! The behavioural proof is deliberately elsewhere, in
//! `crates/botzr-aegis-confine/tests/escape.rs`, which spawns a confined child
//! and asserts a `SIGSYS` kill on two independent routes: `socket(2)` and
//! io_uring. Keeping it there means one suite owns enforcement and this one
//! owns wiring. If the escape suite is ever deleted, these assertions become
//! self-referential again — that is the failure mode to watch for.

#![cfg(target_os = "linux")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use tempfile::TempDir;

const HANG_GUARD: Duration = Duration::from_secs(30);

/// Opt-out for a host with no Landlock. Anything else is a failure — a suite
/// that reports `ok` on zero coverage is worse than a red one (AILAB-628
/// verification, 2026-08-13).
const NO_LANDLOCK: &str = "AEGIS_ALLOW_NO_LANDLOCK";

fn no_landlock_opt_out() -> bool {
    std::env::var(NO_LANDLOCK).as_deref() == Ok("1")
}

fn aegis() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aegis"))
}

fn sibling_bin(name: &str) -> Option<PathBuf> {
    let mut p = PathBuf::from(env!("CARGO_BIN_EXE_aegis"));
    p.set_file_name(name);
    p.exists().then_some(p)
}

/// The product's loader set, plus the directory the test binaries live in.
///
/// Deliberately **not** a local list: the shipped `--allow-exec-support` and
/// this must be the same set, or the suite goes green on a profile no
/// operator can build (AILAB-628 verification, 2026-08-13).
fn exec_support_paths() -> Vec<PathBuf> {
    let mut out = botzr_aegis_confine::exec_support_paths();
    out.push(std::env::temp_dir());
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
        if stderr.contains("Landlock is not available") && no_landlock_opt_out() {
            eprintln!("skip: {NO_LANDLOCK}=1 and this kernel has no Landlock");
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
    // A filter was installed *and* it denies something. The pair is the
    // point: `seccomp_applied` alone is true for an empty rule set. This is a
    // wiring check; the enforcement is proven behaviourally in the confine
    // escape suite (see the module comment).
    assert_eq!(enforced["seccomp_network_denied"], true, "{enforced}");
}

#[test]
fn wrap_confine_end_to_end_with_botzr_aegis_mcp() {
    // A missing sibling binary is a real skip: `cargo test -p botzr-aegis-cli`
    // does not build the gateway. It is announced on stdout, which the harness
    // shows for a passing test only under --nocapture, so it is also asserted
    // by the workspace run where the binary is always present.
    let Some(mcp) = sibling_bin("botzr-aegis-mcp") else {
        println!(
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
        .arg("--confine")
        // The shipped flag, not a hand-rolled list of loader paths. This is
        // the exact invocation `docs/wrap.md` documents; if it stops being
        // enough to start a dynamically linked child, this test is where that
        // shows up rather than in an operator's terminal.
        .arg("--allow-exec-support");
    // The directory the binaries live in is not part of the loader set — the
    // child is `botzr-aegis-mcp` sitting in `target/debug`, which no shipped
    // default should be granting.
    if let Some(parent) = PathBuf::from(env!("CARGO_BIN_EXE_aegis")).parent() {
        cmd.arg("--allow-read").arg(parent);
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
        // Only a kernel with no Landlock at all is skippable, and only on the
        // explicit opt-in. "Cannot be fully enforced" used to skip here too,
        // which meant a profile this build cannot apply — the exact regression
        // worth catching — reported green.
        if stderr.contains("Landlock is not available") && no_landlock_opt_out() {
            eprintln!("skip: {NO_LANDLOCK}=1 and this kernel has no Landlock");
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
    // A filter was installed *and* it denies something. The pair is the
    // point: `seccomp_applied` alone is true for an empty rule set. This is a
    // wiring check; the enforcement is proven behaviourally in the confine
    // escape suite (see the module comment).
    assert_eq!(enforced["seccomp_network_denied"], true, "{enforced}");
}

// ---------------------------------------------------------------------------
// The refusal paths (AILAB-712).
//
// `confine_exec_through_the_aegis_binary` above covers the happy path, but it
// can never be *measured*: that path ends in `CommandExt::exec`, which replaces
// the process image, so LLVM's `atexit` handler never runs and the process
// writes no profile data at all. The whole of `confine_exec.rs` therefore reads
// as 0.00% covered while genuinely being exercised end to end. The cases below
// are the ones that `return` instead of exec-ing — they are measurable, and
// they were also the ones with no test at all.
//
// Every one asserts the same property, which is ADR-0007's actual guarantee:
// **a refusal does not exec.** A helper that warned and continued is how a
// script inherits a child that was never confined, so "exit 1 and stderr says
// why" is only half the assertion; "the target never ran" is the other half.
// ---------------------------------------------------------------------------

/// A target whose only job is to prove whether it ran: it creates `marker`.
///
/// `/bin/sh` rather than `touch`, because `touch` is not guaranteed to sit at a
/// fixed path while `sh` is.
fn witness(marker: &Path) -> Vec<String> {
    vec![
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        format!("printf ran > {}", marker.display()),
    ]
}

/// Run `aegis __confine-exec -- <witness>` with the given environment, and
/// assert it refused *without* running the target.
///
/// Returns stderr so each case can assert on the specific reason.
fn refuses_without_execing(env: &[(&str, &str)], dir: &TempDir) -> String {
    let marker = dir.path().join("target-ran.marker");
    let mut cmd = aegis();
    cmd.arg("__confine-exec").arg("--").args(witness(&marker));
    cmd.env_remove(botzr_aegis_confine::PROFILE_ENV)
        .env_remove(botzr_aegis_confine::REPORT_ENV);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("spawn __confine-exec");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(1),
        "a refusal exits 1, got {:?}: {stderr}",
        output.status
    );
    assert!(
        stderr.starts_with("aegis __confine-exec:"),
        "the refusal names the helper that refused: {stderr:?}"
    );
    assert!(
        !marker.exists(),
        "ADR-0007: a refusal must not exec — but the target ran and wrote {}",
        marker.display()
    );
    stderr
}

/// An unset `AEGIS_CONFINE_PROFILE` is a refusal, not an empty profile.
///
/// The distinction is the whole of ADR-0007's authority-reducing claim. Reading
/// a missing profile as "confine nothing" would make the helper a way to run a
/// command with the confinement silently skipped.
#[test]
fn confine_exec_without_a_profile_refuses_rather_than_execing() {
    let dir = tempfile::tempdir().unwrap();
    let stderr = refuses_without_execing(&[], &dir);
    assert!(
        stderr.contains(botzr_aegis_confine::PROFILE_ENV),
        "the reason names the variable an operator has to set: {stderr:?}"
    );
}

/// A profile that is not JSON is a refusal, and the parse error is passed
/// through rather than flattened into "invalid".
#[test]
fn confine_exec_with_a_malformed_profile_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let stderr = refuses_without_execing(&[(botzr_aegis_confine::PROFILE_ENV, "{not json")], &dir);
    assert!(
        stderr.contains("invalid AEGIS_CONFINE_PROFILE"),
        "{stderr:?}"
    );
}

/// A profile that is valid JSON but the wrong shape is refused by the same
/// path — `serde` rejects it, and the helper does not fall back to a default.
#[test]
fn confine_exec_with_a_wrong_shaped_profile_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let stderr = refuses_without_execing(
        &[(botzr_aegis_confine::PROFILE_ENV, r#"{"read_paths":"/tmp"}"#)],
        &dir,
    );
    assert!(
        stderr.contains("invalid AEGIS_CONFINE_PROFILE"),
        "{stderr:?}"
    );
}

/// A report path that cannot be opened is a refusal.
///
/// The report is opened *before* `restrict_self` because Landlock does not
/// revoke already-open fds. That ordering means an unopenable report is caught
/// before anything is enforced — and it still must not exec, or the operator
/// gets a confined child with no record that it was confined.
#[test]
fn confine_exec_with_an_unopenable_report_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let nowhere = dir.path().join("no-such-dir").join("enforced.json");
    let stderr = refuses_without_execing(
        &[
            (
                botzr_aegis_confine::PROFILE_ENV,
                profile_json(&[dir.path()]).as_str(),
            ),
            (botzr_aegis_confine::REPORT_ENV, nowhere.to_str().unwrap()),
        ],
        &dir,
    );
    assert!(
        stderr.contains("could not write confinement report"),
        "{stderr:?}"
    );
}

/// A profile naming a path that does not exist cannot be turned into a Landlock
/// rule, so it is refused rather than applied partially.
///
/// This is the `NotFullyEnforced` / `Path` family: a profile the kernel cannot
/// carry out in full must not silently become a weaker one. Commit `e92450a`
/// exists because a filter that denied nothing was recorded as applied.
#[test]
fn confine_exec_with_an_unenforceable_profile_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("definitely-not-here");
    let profile = serde_json::json!({
        "read_paths": [missing],
        "write_paths": [],
        "net": [],
        "best_effort": false,
    })
    .to_string();

    let stderr = refuses_without_execing(
        &[(botzr_aegis_confine::PROFILE_ENV, profile.as_str())],
        &dir,
    );
    if stderr.contains("Landlock is not available") && no_landlock_opt_out() {
        eprintln!("skip: {NO_LANDLOCK}=1 and this kernel has no Landlock");
        return;
    }
    assert!(
        stderr.contains("cannot open granted path") || stderr.contains("cannot be fully enforced"),
        "an unenforceable profile is refused by name: {stderr:?}"
    );
}

/// The confinement applied cleanly and the *exec itself* failed.
///
/// This is the one refusal that happens after enforcement, so it is also the
/// case that proves the earlier steps ran: the report file exists and records a
/// real Landlock ABI and a seccomp filter that denies something, and only then
/// does the helper report that it could not start the target.
#[test]
fn confine_exec_reports_a_failed_exec_after_confining() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("enforced.json");
    let absent = dir.path().join("no-such-program");

    let output = aegis()
        .args(["__confine-exec", "--"])
        .arg(&absent)
        .env(
            botzr_aegis_confine::PROFILE_ENV,
            profile_json(&[dir.path()]),
        )
        .env(botzr_aegis_confine::REPORT_ENV, &report)
        .output()
        .expect("spawn __confine-exec");

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("Landlock is not available") && no_landlock_opt_out() {
        eprintln!("skip: {NO_LANDLOCK}=1 and this kernel has no Landlock");
        return;
    }
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("exec") && stderr.contains(absent.to_str().unwrap()),
        "the failure names the program it could not start: {stderr:?}"
    );

    // Enforcement happened before the exec attempt, and it was recorded.
    let enforced: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("report")).expect("json");
    assert!(
        enforced["landlock_abi"].as_i64().unwrap_or(0) > 0,
        "the report is written before the exec is attempted: {enforced}"
    );
    assert_eq!(enforced["seccomp_applied"], true, "{enforced}");
    // Wiring, not enforcement — see the module comment.
    assert_eq!(enforced["seccomp_network_denied"], true, "{enforced}");
}

/// `--allow-net` had no test at all before AILAB-712, on either side of the
/// boundary: not in `crates/botzr-aegis-cli/tests/` and not in
/// `crates/botzr-aegis-confine/tests/`. That is a coverage gap of the ordinary
/// kind rather than a measurement artifact — the flag builds a `NetNeeds`, mints
/// a grant from it, and decides whether the seccomp filter denies the network
/// syscalls, and none of that was exercised.
///
/// The assertion is the pair, not the flag: a granted network need must show up
/// as `seccomp_network_denied: false` **while `seccomp_applied` stays true**. A
/// filter is still installed; it just does not deny sockets. Reading only
/// `seccomp_applied` is precisely the mistake commit `e92450a` was fixed for.
#[test]
fn wrap_confine_with_allow_net_installs_a_filter_that_permits_sockets() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("wrap.jsonl");
    let key = keygen(&dir, "wrap.key");

    let mut cmd = aegis();
    cmd.arg("wrap")
        .arg("--audit")
        .arg(&audit)
        .arg("--signing-key")
        .arg(&key)
        .arg("--confine")
        .arg("--allow-exec-support")
        .arg("--allow-net")
        .arg("example.invalid:443")
        .arg("--allow-read")
        .arg(dir.path())
        .arg("--allow-write")
        .arg(dir.path())
        .arg("--allow-write")
        .arg(std::env::temp_dir());
    if let Some(parent) = PathBuf::from(env!("CARGO_BIN_EXE_aegis")).parent() {
        cmd.arg("--allow-read").arg(parent);
    }
    cmd.arg("--")
        .arg("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn aegis wrap --confine --allow-net");
    drop(child.stdin.take().expect("stdin"));

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let output: Output = rx
        .recv_timeout(HANG_GUARD)
        .expect("wrap --confine --allow-net hung")
        .expect("wait");

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("Landlock is not available") && no_landlock_opt_out() {
        eprintln!("skip: {NO_LANDLOCK}=1 and this kernel has no Landlock");
        return;
    }
    assert!(output.status.success(), "wrap --allow-net: {stderr}");

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

    assert_eq!(
        enforced["seccomp_applied"], true,
        "a filter is still installed when the network is granted: {enforced}"
    );
    assert_eq!(
        enforced["seccomp_network_denied"], false,
        "a granted net need must not be recorded as a denied network: {enforced}"
    );
    assert!(
        enforced["landlock_abi"].as_i64().unwrap_or(0) > 0,
        "{enforced}"
    );
}
