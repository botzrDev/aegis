//! The requested profile and the facts the kernel actually enforced.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use botzr_aegis_core::CapabilityGrant;

use crate::error::ConfineError;

/// Environment variable carrying the JSON [`ConfinementProfile`].
///
/// Travels in the environment, never argv: `/proc/<pid>/cmdline` is
/// world-readable and would publish the confinement paths to every local
/// user. `/proc/<pid>/environ` is owner-readable. Stripped with
/// `env_remove` before `exec` so the child does not inherit it (ADR-0007).
pub const PROFILE_ENV: &str = "AEGIS_CONFINE_PROFILE";

/// Environment variable naming the file the helper writes [`EnforcedConfinement`]
/// to, as one JSON object, before replacing its image.
///
/// Must not be stdin/stdout (the MCP transport) or stderr (the wrap tee).
/// Also stripped before `exec`.
pub const REPORT_ENV: &str = "AEGIS_CONFINE_REPORT";

/// Read-only paths a dynamically linked child needs before its own `main`
/// runs: the loader, libc, and the interpreter's own installation.
///
/// **This is a named hole, not a rounding error.** A profile carrying these
/// can still read `/etc/passwd` and walk `/proc`. It is not granted by
/// default and never inferred from a grant — `aegis wrap` adds it only when
/// the operator passes `--allow-exec-support`, so the widening is a decision
/// somebody made rather than one Aegis made for them.
///
/// Without it, confinement is only usable for a static binary: Landlock is
/// deny-by-default, so a profile of `--allow-read /var/data` alone means the
/// loader cannot map libc and `execve` fails with `EACCES` before the child
/// exists (AILAB-628 verification, 2026-08-13).
pub const EXEC_SUPPORT_PATHS: &[&str] = &[
    "/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin", "/etc", "/dev", "/proc",
];

/// [`EXEC_SUPPORT_PATHS`] filtered to those that exist on this host.
///
/// A path that is not there cannot be opened for a Landlock rule, and under
/// the fail-closed default an unopenable granted path refuses the exec — so
/// a `/lib32`-less distro must not be handed a profile naming it.
pub fn exec_support_paths() -> Vec<PathBuf> {
    EXEC_SUPPORT_PATHS
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect()
}

/// One host:port the grant named. An empty [`ConfinementProfile::net`] means
/// deny every network syscall — that is seccomp's job, not Landlock's.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetAllow {
    pub host: String,
    pub ports: Vec<u16>,
}

/// What the operator asked for. Derived from a grant, never authored directly.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConfinementProfile {
    pub read_paths: Vec<PathBuf>,
    pub write_paths: Vec<PathBuf>,
    /// Empty means: deny every network syscall.
    pub net: Vec<NetAllow>,
    /// Operator opt-in. Recorded, never inferred.
    pub best_effort: bool,
}

impl ConfinementProfile {
    /// A grant with `fs: None` yields no path rules — which under Landlock's
    /// deny-by-default domain means no filesystem access at all, not full access.
    pub fn from_grant(grant: &CapabilityGrant) -> Self {
        let (read_paths, write_paths) = match &grant.fs {
            Some(fs) => (
                fs.read_paths.iter().map(PathBuf::from).collect(),
                fs.write_paths.iter().map(PathBuf::from).collect(),
            ),
            None => (Vec::new(), Vec::new()),
        };
        let net = match &grant.net {
            Some(net) => net
                .http
                .iter()
                .map(|h| NetAllow {
                    host: h.host.clone(),
                    ports: h.ports.clone(),
                })
                .collect(),
            None => Vec::new(),
        };
        Self {
            read_paths,
            write_paths,
            net,
            best_effort: false,
        }
    }

    /// `--best-effort` is an operator flag, not a property of the grant.
    pub fn with_best_effort(mut self, best_effort: bool) -> Self {
        self.best_effort = best_effort;
        self
    }

    /// Add [`exec_support_paths`] as reads. Operator opt-in
    /// (`--allow-exec-support`), never inferred from the grant — see the
    /// constant's docs for what it opens up.
    pub fn with_exec_support(mut self, enabled: bool) -> Self {
        if enabled {
            for path in exec_support_paths() {
                if !self.read_paths.contains(&path) {
                    self.read_paths.push(path);
                }
            }
        }
        self
    }
}

/// What the kernel actually gave us. Distinct type from the request, on purpose:
/// ADR-0007 requires the record state what was enforced, not what was asked for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnforcedConfinement {
    pub landlock_abi: i32,
    pub landlock_fully_enforced: bool,
    /// A filter was installed. **Not** the same as "syscalls were denied":
    /// when the grant carries network authority the filter is installed with
    /// an empty rule set and denies nothing. Read this with
    /// [`Self::seccomp_network_denied`], never alone.
    pub seccomp_applied: bool,
    /// The installed filter kills the network syscalls on `SIGSYS`. False
    /// when the grant carried a `NetGrant`, because then nothing is denied.
    ///
    /// Separate field rather than a richer `seccomp_applied`, because
    /// ADR-0007's rule is that the record states what was *enforced*: a bool
    /// that is true for a filter denying nothing is precisely the overclaim
    /// that rule exists to prevent (AILAB-628 verification, 2026-08-13).
    pub seccomp_network_denied: bool,
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

#[cfg(test)]
mod tests {
    use botzr_aegis_core::{CapabilityGrant, FsGrant, HttpGrant, NetGrant, ToolId};

    use super::*;

    fn grant() -> CapabilityGrant {
        CapabilityGrant::deny_all(ToolId::new("t"), "g0")
    }

    #[test]
    fn from_grant_with_fs_none_is_no_path_rules() {
        let p = ConfinementProfile::from_grant(&grant());
        assert!(p.read_paths.is_empty());
        assert!(p.write_paths.is_empty());
        assert!(p.net.is_empty());
        assert!(!p.best_effort);
    }

    #[test]
    fn from_grant_copies_fs_and_http_entries() {
        let mut g = grant();
        g.fs = Some(FsGrant {
            read_paths: vec!["/tmp/r".into()],
            write_paths: vec!["/tmp/w".into()],
        });
        g.net = Some(NetGrant {
            http: vec![HttpGrant {
                host: "example.com".into(),
                ports: vec![443, 80],
                methods: vec!["GET".into()],
            }],
        });
        let p = ConfinementProfile::from_grant(&g);
        assert_eq!(p.read_paths, vec![PathBuf::from("/tmp/r")]);
        assert_eq!(p.write_paths, vec![PathBuf::from("/tmp/w")]);
        assert_eq!(
            p.net,
            vec![NetAllow {
                host: "example.com".into(),
                ports: vec![443, 80],
            }]
        );
    }

    /// The loader set is an operator decision, never something a grant can
    /// imply. A grant that names no paths must not acquire `/etc` and `/proc`
    /// because the child happened to be dynamically linked.
    #[test]
    fn exec_support_is_opt_in_and_never_inferred_from_the_grant() {
        let bare = ConfinementProfile::from_grant(&grant());
        assert!(bare.read_paths.is_empty(), "no grant, no paths");
        assert!(
            ConfinementProfile::from_grant(&grant())
                .with_exec_support(false)
                .read_paths
                .is_empty(),
            "opt-out must stay empty"
        );

        let opted_in = ConfinementProfile::from_grant(&grant()).with_exec_support(true);
        assert!(
            !opted_in.read_paths.is_empty(),
            "opt-in must grant the loader set on any host this can run on"
        );
        for path in exec_support_paths() {
            assert!(opted_in.read_paths.contains(&path), "missing {path:?}");
        }
        // Idempotent: two opt-ins are one grant, not a duplicated rule set.
        assert_eq!(
            opted_in.clone().with_exec_support(true).read_paths,
            opted_in.read_paths
        );
    }

    /// Every advertised support path that exists resolves; a host missing one
    /// (no `/lib32`) must not be handed a profile naming it, because an
    /// unopenable granted path refuses the exec under the fail-closed default.
    #[test]
    fn exec_support_paths_are_filtered_to_what_exists() {
        for path in exec_support_paths() {
            assert!(path.exists(), "{path:?} was offered but does not exist");
        }
    }

    #[test]
    fn best_effort_is_opt_in_never_inferred_from_the_grant() {
        let p = ConfinementProfile::from_grant(&grant()).with_best_effort(true);
        assert!(p.best_effort);
        assert!(!ConfinementProfile::from_grant(&grant()).best_effort);
    }
}
