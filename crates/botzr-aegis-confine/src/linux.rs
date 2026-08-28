//! Landlock + seccomp applied to **this** process.
//!
//! `pre_exec` is never used: it is unsafe and would allocate in a forked
//! child of a multithreaded process. Restrictions apply here, in an ordinary
//! process context, and Landlock domains / seccomp filters survive the
//! subsequent `execve` (ADR-0007).

use std::collections::BTreeMap;

use landlock::{
    path_beneath_rules, Access, AccessFs, CompatLevel, Compatible, LandlockStatus, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
};
use seccompiler::{SeccompAction, SeccompFilter};

use crate::error::ConfineError;
use crate::profile::{ConfinementProfile, EnforcedConfinement};

/// Highest ABI variant this crate's `landlock` pin knows about. Used only as
/// the ceiling of a probe; the negotiated number is whatever the kernel
/// returned, and tests must not assert a fixed value — it varies per kernel.
///
/// Measured, not assumed. The dev box returned 3 on 2026-08-28 (kernel
/// 6.6.87.2-microsoft-standard-WSL2). Re-check it with
/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`
/// (syscall 444 on x86_64), which returns the highest ABI the running kernel
/// honours. The runner's number is deliberately not stated here — this tree
/// cannot verify it — and is printed by the "Landlock ABI (runner)" step in
/// `.github/workflows/ci.yml`.
///
/// This matters beyond bookkeeping: ABI 4 (kernel 6.7) is what adds
/// `AccessNet`, so an ABI 3 machine cannot exercise network confinement at
/// all. See AILAB-810.
const ABI_PROBE_MAX: i32 = 9;

/// Landlock + seccomp, applied to this process. See [`crate::Confiner`].
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxConfiner;

impl crate::Confiner for LinuxConfiner {
    /// Fails closed: if `best_effort` is false and the kernel cannot enforce
    /// the full profile, this is an error and the caller must not exec.
    fn restrict_self(
        &self,
        profile: &ConfinementProfile,
    ) -> Result<EnforcedConfinement, ConfineError> {
        let landlock = apply_landlock(profile)?;
        let seccomp = apply_seccomp(profile)?;
        Ok(EnforcedConfinement {
            landlock_abi: landlock.abi,
            landlock_fully_enforced: landlock.fully,
            seccomp_applied: seccomp.applied,
            seccomp_network_denied: seccomp.network_denied,
        })
    }
}

/// What the installed seccomp filter actually does, kept apart from the fact
/// that one was installed at all.
pub struct SeccompOutcome {
    pub applied: bool,
    pub network_denied: bool,
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
///
/// **The default action is Allow, so this is a deny-list of network syscalls
/// and nothing more.** It is not a general syscall sandbox: `ptrace`,
/// `unshare`, `mount` and everything else this list does not name are
/// permitted. The ticket's requirement is that network syscalls are denied
/// without a `NetGrant`, and that is exactly what this does — the returned
/// [`SeccompOutcome`] says so rather than letting a caller read more into it.
///
/// **io_uring is denied whole, and that has a price.** `io_uring_setup`,
/// `io_uring_enter` and `io_uring_register` are on the deny-list because the
/// ring's network operations are dispatched from shared memory and never reach
/// a syscall seccomp can filter (AILAB-807). seccomp cannot read submission
/// queue entries, so there is no filter that permits io_uring *file* I/O while
/// denying io_uring *network* I/O. The consequence, stated plainly: **a child
/// that uses io_uring for ordinary file I/O will die on `SIGSYS` under a
/// profile with no `NetGrant`.** That is the cost of the claim being true.
///
/// **Enumeration is still the model.** This denies the interfaces it names.
/// A kernel interface that carries a packet without crossing one of them is
/// an open path that has to be discovered rather than prevented — io_uring was
/// exactly that until 2026-08-25. AILAB-810 tracks moving the network claim to
/// Landlock `AccessNet`, which enforces at the LSM layer and does not enumerate.
pub fn apply_seccomp(profile: &ConfinementProfile) -> Result<SeccompOutcome, ConfineError> {
    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| ConfineError::Seccomp(format!("{e:?}")))?;

    let network_denied = profile.net.is_empty();
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = if network_denied {
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
    Ok(SeccompOutcome {
        applied: true,
        network_denied,
    })
}

/// Syscalls denied when the profile carries no `NetGrant`.
///
/// The first eighteen are the socket API. The last three are io_uring, and
/// they are here for a reason worth stating: since Linux 5.19 the ring
/// dispatches `IORING_OP_SOCKET` and `IORING_OP_CONNECT` from submission-queue
/// entries in memory shared with the kernel, so those operations never cross a
/// syscall boundary seccomp can inspect. Denying the socket API alone left a
/// confined process able to reach the network while the record said
/// `seccomp_network_denied: true` (AILAB-807).
///
/// **The ring goes, not its network operations.** seccomp cannot read SQEs, so
/// no filter can permit io_uring file I/O while denying io_uring network I/O —
/// the only enforceable cut is at `io_uring_setup`. The price is named in
/// [`apply_seccomp`]: a child that uses io_uring for ordinary file I/O dies
/// under a network-denying profile.
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
        // io_uring: deny the ring itself. See this function's doc comment.
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ]
}
