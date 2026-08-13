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

/// Prefixes a dynamically linked binary needs to exec, plus the probe itself.
///
/// The loader set comes from the product
/// (`botzr_aegis_confine::exec_support_paths`) rather than a copy local to the
/// tests. A private copy is how the suite passed while the shipped
/// `--confine` could not exec anything (AILAB-628 verification, 2026-08-13):
/// the tests granted the loader and the product had no way to.
pub fn exec_support_paths() -> Vec<PathBuf> {
    let mut out = botzr_aegis_confine::exec_support_paths();
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

/// Environment opt-out for a host that genuinely has no Landlock.
///
/// Set `AEGIS_ALLOW_NO_LANDLOCK=1` to turn the confinement suites into
/// announced skips. Anything else is a failure.
pub const NO_LANDLOCK_OPT_OUT: &str = "AEGIS_ALLOW_NO_LANDLOCK";

/// True when the kernel can enforce Landlock; **panics** when it cannot,
/// unless the operator opted out.
///
/// Fail closed, for the same reason the product does. The first cut returned
/// `false` and let each test `return`, so a kernel without Landlock produced
/// eleven green tests that asserted nothing — the reason lived on stderr,
/// which the harness hides unless a test fails. A suite that reports `ok` on
/// zero coverage is worse than a red one (AILAB-628 verification,
/// 2026-08-13).
pub fn landlock_available() -> bool {
    match botzr_aegis_confine::probe_landlock_abi() {
        Ok(_) => true,
        Err(e) => {
            if std::env::var(NO_LANDLOCK_OPT_OUT).as_deref() == Ok("1") {
                eprintln!("skip: {NO_LANDLOCK_OPT_OUT}=1 and this kernel has no Landlock ({e})");
                return false;
            }
            panic!(
                "this kernel cannot enforce Landlock ({e}), so nothing in this suite is \
                 actually tested. Set {NO_LANDLOCK_OPT_OUT}=1 to skip it on purpose."
            );
        }
    }
}
