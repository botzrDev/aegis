//! ADR-0007's four unverified facts. A skip is a legitimate result and must
//! name the reason; a silent skip is not acceptable.

#![cfg(target_os = "linux")]

mod common;

use std::process::Command;

use botzr_aegis_confine::{ConfinementProfile, PROFILE_ENV};
use common::{
    landlock_available, probe, profile_for_paths, restrict_exec, restrict_exec_with_report,
};

fn nnp_value(stdout: &[u8]) -> Option<u8> {
    let text = String::from_utf8_lossy(stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("NoNewPrivs:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

#[test]
fn adr0007_four_facts() {
    if !landlock_available() {
        // Named reason already printed by landlock_available.
        // Facts 1–4 remain unverified on this kernel.
        eprintln!("skip: ADR-0007 facts 1–4 unverified — kernel has no Landlock");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let inside = dir.path().join("ok.txt");
    std::fs::write(&inside, b"ok").unwrap();
    let profile = profile_for_paths(&[dir.path()], &[]);
    let json = serde_json::to_string(&profile).unwrap();

    // Fact 1: Landlock domains survive execve. restrict_self then exec the
    // probe; a read inside the grant still succeeds in the new image.
    let output = restrict_exec(
        &profile,
        &[probe().to_str().unwrap(), "read", inside.to_str().unwrap()],
    );
    assert!(
        output.status.success(),
        "fact 1: Landlock domain must survive execve: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("fact 1: Landlock domain survived execve (inside read succeeded)");

    // Fact 2: does apply_landlock / restrict_self set PR_SET_NO_NEW_PRIVS?
    let landlock_nnp = Command::new(probe())
        .arg("landlock-only")
        .env(PROFILE_ENV, &json)
        .output()
        .expect("landlock-only");
    assert!(
        landlock_nnp.status.success(),
        "fact 2: landlock-only failed: stderr={}",
        String::from_utf8_lossy(&landlock_nnp.stderr)
    );
    let nnp = nnp_value(&landlock_nnp.stdout);
    eprintln!("fact 2: after apply_landlock, NoNewPrivs={nnp:?}");
    assert_eq!(
        nnp,
        Some(1),
        "fact 2: landlock::restrict_self sets PR_SET_NO_NEW_PRIVS (helper does not need its own prctl)"
    );

    // Fact 3: does seccompiler::apply_filter set NO_NEW_PRIVS?
    // A fresh process — Landlock is not applied here.
    let seccomp_profile = ConfinementProfile {
        read_paths: Vec::new(),
        write_paths: Vec::new(),
        net: Vec::new(),
        best_effort: false,
    };
    let seccomp_nnp = Command::new(probe())
        .arg("seccomp-only")
        .env(
            PROFILE_ENV,
            serde_json::to_string(&seccomp_profile).unwrap(),
        )
        .output()
        .expect("seccomp-only");
    assert!(
        seccomp_nnp.status.success(),
        "fact 3: seccomp-only failed: stderr={}",
        String::from_utf8_lossy(&seccomp_nnp.stderr)
    );
    let nnp = nnp_value(&seccomp_nnp.stdout);
    eprintln!("fact 3: after apply_seccomp, NoNewPrivs={nnp:?}");
    assert_eq!(
        nnp,
        Some(1),
        "fact 3: seccompiler::apply_filter sets PR_SET_NO_NEW_PRIVS"
    );

    // Fact 4: the filter permits execve and the dynamic loader's syscalls.
    // The probe is dynamically linked; if the filter were wrong the child
    // would die before main (typically SIGSYS) and this read would not run.
    let (output, report) = restrict_exec_with_report(
        &profile,
        &[probe().to_str().unwrap(), "read", inside.to_str().unwrap()],
    );
    assert!(
        output.status.success(),
        "fact 4: filter must permit execve and the loader: status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let report = report.expect("enforcement report");
    assert!(
        report.seccomp_applied,
        "fact 4: seccomp filter was applied, got {report:?}"
    );
    assert!(
        report.landlock_abi > 0,
        "shape: an ABI was negotiated and recorded (not a fixed number)"
    );
    assert!(
        report.landlock_fully_enforced,
        "shape: full enforcement recorded, got {report:?}"
    );
    eprintln!(
        "fact 4: execve of a dynamically linked probe succeeded; seccomp_applied={}",
        report.seccomp_applied
    );
}
