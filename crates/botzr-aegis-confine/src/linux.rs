//! Landlock + seccomp applied to **this** process.
//!
//! `pre_exec` is never used: it is unsafe and would allocate in a forked
//! child of a multithreaded process. Restrictions apply here, in an ordinary
//! process context, and Landlock domains / seccomp filters survive the
//! subsequent `execve` (ADR-0007).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use landlock::{
    path_beneath_rules, Access, AccessFs, CompatLevel, Compatible, LandlockStatus, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
};
use seccompiler::{SeccompAction, SeccompFilter};

use crate::error::ConfineError;
use crate::profile::{ConfinementProfile, EnforcedConfinement};

/// Highest ABI variant this crate's `landlock` pin knows about. Used only as
/// the ceiling of a probe; the negotiated number is whatever the kernel
/// returned, and tests must not assert a fixed value (dev is ABI 4, CI is
/// newer).
const ABI_PROBE_MAX: i32 = 9;

/// Restricts **the calling process** and returns what was enforced.
///
/// Fails closed: if `best_effort` is false and the kernel cannot enforce the
/// full profile, this is an error and the caller must not exec.
pub fn restrict_self(profile: &ConfinementProfile) -> Result<EnforcedConfinement, ConfineError> {
    let landlock = apply_landlock(profile)?;
    let seccomp_applied = apply_seccomp(profile)?;
    Ok(EnforcedConfinement {
        landlock_abi: landlock.abi,
        landlock_fully_enforced: landlock.fully,
        seccomp_applied,
    })
}

pub struct LandlockOutcome {
    pub abi: i32,
    pub fully: bool,
}

/// Probe the newest Landlock ABI this kernel will honour, without installing
/// a domain. `handle_access` of an unsupported right under HardRequirement
/// fails; the last success is the negotiated ABI.
pub fn probe_landlock_abi() -> Result<ABI, ConfineError> {
    for n in (1..=ABI_PROBE_MAX).rev() {
        let abi = ABI::from(n);
        if Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(abi))
            .is_ok()
        {
            return Ok(abi);
        }
    }
    Err(ConfineError::LandlockUnavailable)
}

pub fn apply_landlock(profile: &ConfinementProfile) -> Result<LandlockOutcome, ConfineError> {
    let abi = match probe_landlock_abi() {
        Ok(abi) => abi,
        Err(e) => {
            if profile.best_effort {
                return Ok(LandlockOutcome {
                    abi: 0,
                    fully: false,
                });
            }
            return Err(e);
        }
    };

    // The landlock crate default would silently drop rights this kernel
    // cannot honour. Fail closed unless the operator passed --best-effort —
    // a loud warning still exits 0 into a script.
    let compat = if profile.best_effort {
        CompatLevel::BestEffort // profile.best_effort opt-in
    } else {
        CompatLevel::HardRequirement
    };

    // `path_beneath_rules` silently skips unopenable paths even under
    // HardRequirement (that flag is ABI compatibility, not path presence).
    // Fail closed ourselves: a grant for a path we cannot open is not
    // fully enforceable.
    let read_paths = openable_paths(&profile.read_paths, profile.best_effort)?;
    let write_paths = openable_paths(&profile.write_paths, profile.best_effort)?;

    let read = AccessFs::from_read(abi);
    // Write rights plus the read rights a write implies for the same path:
    // a server that opens for append needs both.
    let write = AccessFs::from_read(abi) | AccessFs::from_write(abi);

    let result = (|| {
        let created = Ruleset::default()
            .set_compatibility(compat)
            .handle_access(AccessFs::from_all(abi))?
            .create()?
            .add_rules(path_beneath_rules(&read_paths, read))?
            .add_rules(path_beneath_rules(&write_paths, write))?;
        created.restrict_self()
    })();

    let status = match result {
        Ok(status) => status,
        Err(_) if profile.best_effort => {
            return Ok(LandlockOutcome {
                abi: abi as i32,
                fully: false,
            });
        }
        Err(e) => {
            return Err(ConfineError::NotFullyEnforced(e.to_string()));
        }
    };

    let fully = status.ruleset == RulesetStatus::FullyEnforced;
    let recorded_abi = match status.landlock {
        LandlockStatus::Available {
            effective_abi,
            kernel_abi,
        } => kernel_abi.unwrap_or(effective_abi as i32),
        _ => abi as i32,
    };

    if !fully && !profile.best_effort {
        return Err(ConfineError::NotFullyEnforced(format!(
            "Landlock ruleset status {:?}",
            status.ruleset
        )));
    }

    Ok(LandlockOutcome {
        abi: recorded_abi,
        fully,
    })
}

fn openable_paths(
    paths: &[std::path::PathBuf],
    best_effort: bool,
) -> Result<Vec<std::path::PathBuf>, ConfineError> {
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        match PathFd::new(p) {
            Ok(_) => out.push(p.clone()),
            Err(_) if best_effort => {}
            Err(e) => {
                return Err(ConfineError::NotFullyEnforced(format!(
                    "cannot open granted path {}: {e}",
                    p.display()
                )));
            }
        }
    }
    Ok(out)
}

/// Install a seccomp filter. Empty `profile.net` denies network syscalls
/// (`socket`/`connect`/`bind`/…); a non-empty grant leaves them allowed.
/// Default action is Allow so `execve` and the dynamic loader's syscalls
/// pass (ADR-0007 unverified fact 4).
pub fn apply_seccomp(profile: &ConfinementProfile) -> Result<bool, ConfineError> {
    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| ConfineError::Seccomp(format!("{e:?}")))?;

    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = if profile.net.is_empty() {
        network_syscalls()
            .into_iter()
            .map(|n| (n, Vec::new()))
            .collect()
    } else {
        BTreeMap::new()
    };

    // mismatch = not in the map → Allow (execve, mmap, open, …).
    // match    = a listed network syscall → KillProcess (SIGSYS).
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        arch,
    )
    .map_err(|e| ConfineError::Seccomp(e.to_string()))?;

    let bpf: seccompiler::BpfProgram = filter
        .try_into()
        .map_err(|e| ConfineError::Seccomp(format!("{e:?}")))?;

    seccompiler::apply_filter(&bpf).map_err(|e| ConfineError::Seccomp(e.to_string()))?;
    Ok(true)
}

fn network_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_shutdown,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
    ]
}

/// Load the profile from `AEGIS_CONFINE_PROFILE`.
pub fn load_profile_from_env() -> Result<ConfinementProfile, ConfineError> {
    let raw = std::env::var(crate::PROFILE_ENV)
        .map_err(|_| ConfineError::Profile("AEGIS_CONFINE_PROFILE is unset".into()))?;
    serde_json::from_str(&raw).map_err(|e| ConfineError::Profile(e.to_string()))
}

/// Open the report file **before** `restrict_self`.
///
/// Landlock does not revoke already-open fds. Writing after restrict to a
/// path that is not in the grant would fail with `EACCES`, and putting the
/// report path in the grant would publish a writable hole. Open first, write
/// through the fd after.
pub fn open_report() -> Result<Option<File>, ConfineError> {
    let Ok(path) = std::env::var(crate::REPORT_ENV) else {
        return Ok(None);
    };
    Ok(Some(File::create(Path::new(&path))?))
}

/// Write [`EnforcedConfinement`] through a fd opened by [`open_report`].
pub fn write_report(file: &mut File, enforced: &EnforcedConfinement) -> Result<(), ConfineError> {
    let bytes = serde_json::to_vec(enforced).map_err(|e| ConfineError::Profile(e.to_string()))?;
    file.write_all(&bytes)?;
    file.flush()?;
    Ok(())
}
