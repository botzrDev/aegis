//! `aegis __confine-exec` — internal re-exec target (ADR-0007).
//!
//! Not operator surface: dispatched first in `parse_args`, kept out of
//! `usage_text()`. Applies the profile from `AEGIS_CONFINE_PROFILE` to this
//! process, writes [`botzr_aegis_confine::EnforcedConfinement`] to the path in
//! `AEGIS_CONFINE_REPORT` (a file, never stdin/stdout/stderr), strips both
//! variables, and `exec`s the target.
//!
//! Never `pre_exec`: it is unsafe. Use `CommandExt::exec` instead of it
//! (allocating in a forked child of a multithreaded process can deadlock
//! on the allocator lock).
//!
//! # This file has a coverage ceiling, and it is not a testing gap
//!
//! The success path ends in `exec`, which replaces the process image. LLVM
//! writes coverage from an `atexit` handler, and a replaced image never runs
//! one — so a run that confines and execs successfully produces **no profile
//! data at all**, including for the lines it executed on the way there.
//! `confine_exec_through_the_aegis_binary` in
//! `crates/botzr-aegis-cli/tests/confine.rs` exercises the whole path end to
//! end and asserts a real Landlock ABI plus a seccomp filter that denies
//! something; none of it can be measured.
//!
//! What *is* measurable is every path that returns instead: the refusals, and
//! the case where confinement succeeds and the exec itself fails. Those are
//! covered in the same file and are what the reported percentage describes.
//! Read a number well below 100% here as the shape of the mechanism rather
//! than as untested code (AILAB-712).
//!
//! The control that establishes this is not a general subprocess problem:
//! `main.rs` measures 100%, and `main.rs` only ever runs inside a spawned
//! binary. `exec` specifically is what erases the data.

use std::process::ExitCode;

#[cfg(unix)]
pub(crate) fn run(child_argv: &[String]) -> ExitCode {
    use std::os::unix::process::CommandExt;

    if child_argv.is_empty() {
        eprintln!("aegis __confine-exec: missing command after `--`");
        return ExitCode::from(1);
    }

    let profile = match botzr_aegis_confine::load_profile_from_env() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("aegis __confine-exec: {e}");
            return ExitCode::from(1);
        }
    };
    // Open before restrict_self: Landlock does not revoke already-open fds.
    let mut report = match botzr_aegis_confine::open_report() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("aegis __confine-exec: {e}");
            return ExitCode::from(1);
        }
    };
    let enforced = match botzr_aegis_confine::active_confiner().restrict_self(&profile) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("aegis __confine-exec: {e}");
            return ExitCode::from(1);
        }
    };
    if let Some(file) = report.as_mut() {
        if let Err(e) = botzr_aegis_confine::write_report(file, &enforced) {
            eprintln!("aegis __confine-exec: {e}");
            return ExitCode::from(1);
        }
    }

    let err = std::process::Command::new(&child_argv[0])
        .args(&child_argv[1..])
        .env_remove(botzr_aegis_confine::PROFILE_ENV)
        .env_remove(botzr_aegis_confine::REPORT_ENV)
        .exec();
    eprintln!("aegis __confine-exec: exec {}: {err}", child_argv[0]);
    // The overwhelmingly common cause, and one an operator cannot guess from
    // `Permission denied`: the confinement is working, and the loader is on
    // the wrong side of it. Landlock is deny-by-default, so a dynamically
    // linked child cannot even start without read on /lib, /usr and friends.
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        eprintln!(
            "aegis __confine-exec: the profile may not cover the dynamic loader. \
             A dynamically linked program needs read on {}. \
             Pass `--allow-exec-support` to `aegis wrap` to grant them.",
            botzr_aegis_confine::EXEC_SUPPORT_PATHS.join(" ")
        );
    }
    ExitCode::from(1)
}

#[cfg(not(unix))]
pub(crate) fn run(_child_argv: &[String]) -> ExitCode {
    eprintln!("aegis __confine-exec: confinement is only implemented on Linux");
    ExitCode::from(1)
}
