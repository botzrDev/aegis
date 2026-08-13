//! Escape tests: a read/write/connect either succeeds inside the grant or
//! fails at the kernel. Real child processes (AILAB-628).

#![cfg(target_os = "linux")]

mod common;

use std::os::unix::process::ExitStatusExt;
use std::path::Path;

use botzr_aegis_confine::ConfinementProfile;
use common::{
    exec_support_paths, landlock_available, probe, profile_for_paths, restrict_exec,
    restrict_exec_with_report,
};

#[test]
fn read_inside_the_grant_succeeds() {
    if !landlock_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let inside = dir.path().join("inside.txt");
    std::fs::write(&inside, b"hello").unwrap();

    let profile = profile_for_paths(&[dir.path()], &[]);
    let output = restrict_exec(
        &profile,
        &[probe().to_str().unwrap(), "read", inside.to_str().unwrap()],
    );
    assert!(
        output.status.success(),
        "inside read must succeed: status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"hello");
}

#[test]
fn read_outside_the_grant_fails_at_the_kernel() {
    if !landlock_available() {
        return;
    }
    let inside_dir = tempfile::tempdir().unwrap();
    let outside_dir = tempfile::tempdir().unwrap();
    let outside = outside_dir.path().join("secret.txt");
    std::fs::write(&outside, b"secret").unwrap();

    let profile = profile_for_paths(&[inside_dir.path()], &[]);
    let output = restrict_exec(
        &profile,
        &[probe().to_str().unwrap(), "read", outside.to_str().unwrap()],
    );
    assert!(
        !output.status.success(),
        "outside read must fail at the kernel, got success. stdout={:?} stderr={}",
        output.stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn write_to_a_read_only_granted_path_fails() {
    if !landlock_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("ro.txt");
    std::fs::write(&file, b"stay").unwrap();

    let profile = profile_for_paths(&[dir.path()], &[]);
    let output = restrict_exec(
        &profile,
        &[probe().to_str().unwrap(), "write", file.to_str().unwrap()],
    );
    assert!(
        !output.status.success(),
        "write to a read-only grant must fail, got success"
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"stay");
}

#[test]
fn connect_with_no_net_grant_is_killed_by_seccomp_sigsys() {
    if !landlock_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let profile = profile_for_paths(&[dir.path()], &[]);
    assert!(profile.net.is_empty(), "this case is the no-NetGrant deny");

    let output = restrict_exec(
        &profile,
        &[probe().to_str().unwrap(), "connect", "127.0.0.1", "1"],
    );
    let signal = output.status.signal();
    assert_eq!(
        signal,
        Some(libc::SIGSYS),
        "a seccomp kill is SIGSYS, distinguishable from a non-zero exit; got status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fail_closed_refuses_to_exec_unless_best_effort() {
    if !landlock_available() {
        return;
    }
    let missing = Path::new("/this/path/does/not/exist/aegis-628");
    let mut read_paths = exec_support_paths();
    read_paths.push(missing.to_path_buf());

    let closed = ConfinementProfile {
        read_paths: read_paths.clone(),
        write_paths: Vec::new(),
        net: Vec::new(),
        best_effort: false,
    };
    let (output, report) = restrict_exec_with_report(&closed, &[probe().to_str().unwrap(), "nnp"]);
    assert!(!output.status.success(), "fail-closed must refuse to exec");
    assert!(
        report.is_none(),
        "a refused exec must not claim anything was enforced"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be fully enforced") || stderr.contains("Landlock"),
        "fail-closed error must name the reason, got {stderr}"
    );

    let effort = ConfinementProfile {
        best_effort: true,
        ..closed
    };
    let (output, report) = restrict_exec_with_report(&effort, &[probe().to_str().unwrap(), "nnp"]);
    assert!(
        output.status.success(),
        "--best-effort must still exec: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = report.expect("best-effort still reports what was enforced");
    // The opt-in is on the profile (never inferred). The report records
    // whether Landlock was fully enforced — with a missing path under
    // BestEffort that is not a full enforcement.
    assert!(
        !report.landlock_fully_enforced || report.seccomp_applied,
        "best-effort must record an enforcement fact, got {report:?}"
    );
}
