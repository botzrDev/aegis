//! Shared spawn helpers for confine integration tests.
//!
//! Real child processes, not `std::io::pipe` (1.87; MSRV is 1.86). Same
//! shape as `crates/botzr-aegis-wrap/tests/relay.rs`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use botzr_aegis_confine::{ConfinementProfile, EnforcedConfinement, PROFILE_ENV, REPORT_ENV};

pub fn probe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aegis-confine-probe"))
}

/// Prefixes a dynamically linked binary needs to exec: the loader, libc, and
/// the probe itself. Tests add the grant paths on top. Missing prefixes are
/// skipped — a path that does not exist cannot be canonicalized into a rule.
pub fn exec_support_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for p in [
        "/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin", "/etc", "/dev", "/proc",
    ] {
        let path = PathBuf::from(p);
        if path.exists() {
            out.push(path);
        }
    }
    if let Some(parent) = probe().parent() {
        out.push(parent.to_path_buf());
    }
    out.push(probe());
    out
}

pub fn profile_for_paths(read: &[&Path], write: &[&Path]) -> ConfinementProfile {
    let mut read_paths = exec_support_paths();
    read_paths.extend(read.iter().map(|p| p.to_path_buf()));
    ConfinementProfile {
        read_paths,
        write_paths: write.iter().map(|p| p.to_path_buf()).collect(),
        net: Vec::new(),
        best_effort: false,
    }
}

pub fn restrict_exec(profile: &ConfinementProfile, child_args: &[&str]) -> Output {
    let report = tempfile::NamedTempFile::new().expect("report file");
    let report_path = report.path().to_path_buf();
    // Keep the file so the child can write it; drop would unlink.
    let _persist = report.into_temp_path();

    let json = serde_json::to_string(profile).expect("profile json");
    Command::new(probe())
        .arg("restrict-exec")
        .arg("--")
        .args(child_args)
        .env(PROFILE_ENV, json)
        .env(REPORT_ENV, &report_path)
        .output()
        .expect("spawn restrict-exec")
}

pub fn restrict_exec_with_report(
    profile: &ConfinementProfile,
    child_args: &[&str],
) -> (Output, Option<EnforcedConfinement>) {
    let dir = tempfile::tempdir().expect("report dir");
    let report_path = dir.path().join("enforced.json");

    let json = serde_json::to_string(profile).expect("profile json");
    let output = Command::new(probe())
        .arg("restrict-exec")
        .arg("--")
        .args(child_args)
        .env(PROFILE_ENV, json)
        .env(REPORT_ENV, &report_path)
        .output()
        .expect("spawn restrict-exec");

    let enforced = std::fs::read(&report_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    (output, enforced)
}

pub fn landlock_available() -> bool {
    match botzr_aegis_confine::probe_landlock_abi() {
        Ok(_) => true,
        Err(e) => {
            eprintln!("skip: kernel does not support Landlock ({e})");
            false
        }
    }
}
