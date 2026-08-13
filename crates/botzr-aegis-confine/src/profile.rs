//! The requested profile and the facts the kernel actually enforced.

use std::path::PathBuf;

use botzr_aegis_core::CapabilityGrant;

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
}

/// What the kernel actually gave us. Distinct type from the request, on purpose:
/// ADR-0007 requires the record state what was enforced, not what was asked for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnforcedConfinement {
    pub landlock_abi: i32,
    pub landlock_fully_enforced: bool,
    pub seccomp_applied: bool,
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

    #[test]
    fn best_effort_is_opt_in_never_inferred_from_the_grant() {
        let p = ConfinementProfile::from_grant(&grant()).with_best_effort(true);
        assert!(p.best_effort);
        assert!(!ConfinementProfile::from_grant(&grant()).best_effort);
    }
}
