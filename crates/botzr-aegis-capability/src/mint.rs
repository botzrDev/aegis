//! Grant minting — validate declared needs and produce host-side grants.

use std::path::{Component, Path, PathBuf};

use botzr_aegis_core::{CapabilityGrant, FsGrant, HttpGrant, NetGrant};

use crate::error::CapabilityError;
use crate::manifest::{HttpNeed, NetNeeds, PathNeed, ToolLimits, ToolManifest};

/// Optional policy ceiling that may only lower manifest limits, never raise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolicyCeiling {
    pub max_memory_bytes: Option<u64>,
    pub max_wall_ms: Option<u64>,
}

impl PolicyCeiling {
    /// Combine two ceilings by taking the *tighter* bound on each axis (a
    /// present cap always beats absent; two caps take the min). Used to fold a
    /// per-call policy ceiling into the resolver's standing ceiling — the result
    /// can only lower limits, never raise them.
    pub fn combine(self, other: PolicyCeiling) -> PolicyCeiling {
        PolicyCeiling {
            max_memory_bytes: tighter(self.max_memory_bytes, other.max_memory_bytes),
            max_wall_ms: tighter(self.max_wall_ms, other.max_wall_ms),
        }
    }

    pub fn apply(self, manifest: ToolLimits) -> ToolLimits {
        ToolLimits {
            max_memory_bytes: self
                .max_memory_bytes
                .map(|cap| cap.min(manifest.max_memory_bytes))
                .unwrap_or(manifest.max_memory_bytes),
            max_wall_ms: self
                .max_wall_ms
                .map(|cap| cap.min(manifest.max_wall_ms))
                .unwrap_or(manifest.max_wall_ms),
        }
    }
}

/// Take the tighter (smaller) of two optional caps; a present cap always wins
/// over an absent one.
fn tighter(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

/// Mint a grant from declared needs. Paths are canonicalized at mint time.
#[must_use = "grant minting result must be handled — denial is audit-worthy"]
pub fn mint_grant(
    manifest: &ToolManifest,
    grant_id: impl Into<String>,
    ceiling: PolicyCeiling,
) -> Result<CapabilityGrant, CapabilityError> {
    validate_http_needs(manifest.net.as_ref())?;

    let limits = ceiling.apply(manifest.limits);
    let fs = manifest
        .fs
        .as_ref()
        .map(|needs| mint_fs_grant(needs, &manifest.base_dir))
        .transpose()?;
    let net = manifest.net.as_ref().map(mint_net_grant).transpose()?;

    Ok(CapabilityGrant {
        grant_id: grant_id.into(),
        tool_id: manifest.tool.id.clone(),
        fs,
        net,
        max_memory_bytes: limits.max_memory_bytes,
        max_wall_ms: limits.max_wall_ms,
    })
}

fn mint_fs_grant(
    needs: &crate::manifest::FsNeeds,
    base: &Path,
) -> Result<FsGrant, CapabilityError> {
    let read_paths = canonicalize_paths(&needs.read, base)?;
    let write_paths = canonicalize_paths(&needs.write, base)?;
    Ok(FsGrant {
        read_paths,
        write_paths,
    })
}

fn mint_net_grant(needs: &NetNeeds) -> Result<NetGrant, CapabilityError> {
    Ok(NetGrant {
        http: needs.http.iter().map(http_need_to_grant).collect(),
    })
}

fn http_need_to_grant(need: &HttpNeed) -> HttpGrant {
    HttpGrant {
        host: need.host.clone(),
        ports: need.ports.clone(),
        methods: need.methods.clone(),
    }
}

fn validate_http_needs(net: Option<&NetNeeds>) -> Result<(), CapabilityError> {
    let Some(net) = net else {
        return Ok(());
    };
    for need in &net.http {
        if need.host.is_empty() {
            return Err(CapabilityError::NetDenied {
                host: need.host.clone(),
                reason: "host must not be empty".into(),
            });
        }
        if need.host.contains('*') {
            return Err(CapabilityError::NetDenied {
                host: need.host.clone(),
                reason: "wildcard hosts are not supported in v1".into(),
            });
        }
        if need.ports.is_empty() {
            return Err(CapabilityError::NetDenied {
                host: need.host.clone(),
                reason: "at least one port is required".into(),
            });
        }
        if need.methods.is_empty() {
            return Err(CapabilityError::NetDenied {
                host: need.host.clone(),
                reason: "at least one HTTP method is required".into(),
            });
        }
    }
    Ok(())
}

fn canonicalize_paths(needs: &[PathNeed], base: &Path) -> Result<Vec<String>, CapabilityError> {
    needs
        .iter()
        .map(|need| canonicalize_path(need, base))
        .collect()
}

fn canonicalize_path(need: &PathNeed, base: &Path) -> Result<String, CapabilityError> {
    let joined = if Path::new(&need.path).is_absolute() {
        PathBuf::from(&need.path)
    } else {
        base.join(&need.path)
    };

    let normalized = normalize_lexically(&joined);
    std::fs::canonicalize(&normalized)
        .map_err(|e| CapabilityError::InvalidPath {
            path: need.path.clone(),
            reason: e.to_string(),
        })
        .map(|p| p.to_string_lossy().into_owned())
}

/// Collapse `.` / `..` without touching the filesystem (for joining before canonicalize).
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                out.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

/// Returns true when `sub` is allowed under `parent` for narrowing checks.
pub(crate) fn path_need_allowed(
    parent: &PathNeed,
    sub: &PathNeed,
    base: &Path,
) -> Result<bool, CapabilityError> {
    let parent_canon = canonicalize_path(parent, base)?;
    let sub_canon = canonicalize_path(sub, base)?;

    if parent_canon == sub_canon {
        return Ok(true);
    }

    if !parent.recursive {
        return Ok(false);
    }

    Ok(Path::new(&sub_canon).starts_with(Path::new(&parent_canon)))
}

/// Returns true when every sub HTTP need fits inside a parent HTTP need.
pub(crate) fn http_need_allowed(parent: &HttpNeed, sub: &HttpNeed) -> bool {
    parent.host == sub.host
        && sub.ports.iter().all(|port| parent.ports.contains(port))
        && sub.methods.iter().all(|method| {
            parent
                .methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        FsNeeds, ToolInfo, ToolKind, ToolManifest, DEFAULT_MAX_MEMORY_BYTES, DEFAULT_MAX_WALL_MS,
    };
    use botzr_aegis_core::ToolId;

    #[test]
    fn mints_minimal_grant_with_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new("noop"),
                version: "0.1.0".into(),
                kind: ToolKind::Wasm,
            },
            dir.path(),
        );

        let grant = mint_grant(&manifest, "g1", PolicyCeiling::default()).unwrap();
        assert_eq!(grant.tool_id.as_str(), "noop");
        assert!(grant.fs.is_none());
        assert!(grant.net.is_none());
        assert_eq!(grant.max_memory_bytes, DEFAULT_MAX_MEMORY_BYTES);
        assert_eq!(grant.max_wall_ms, DEFAULT_MAX_WALL_MS);
    }

    #[test]
    fn policy_ceiling_lowers_limits() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new("capped"),
                version: "0.1.0".into(),
                kind: ToolKind::Wasm,
            },
            dir.path(),
        )
        .with_limits(ToolLimits {
            max_memory_bytes: 1 << 20,
            max_wall_ms: 10_000,
        });

        let grant = mint_grant(
            &manifest,
            "g1",
            PolicyCeiling {
                max_memory_bytes: Some(512 * 1024),
                max_wall_ms: Some(1_000),
            },
        )
        .unwrap();
        assert_eq!(grant.max_memory_bytes, 512 * 1024);
        assert_eq!(grant.max_wall_ms, 1_000);
    }

    #[test]
    fn rejects_wildcard_http_host() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new("bad-net"),
                version: "0.1.0".into(),
                kind: ToolKind::Host,
            },
            dir.path(),
        )
        .with_net(NetNeeds {
            http: vec![HttpNeed {
                host: "*.example.com".into(),
                ports: vec![443],
                methods: vec!["GET".into()],
            }],
        });

        let err = mint_grant(&manifest, "g1", PolicyCeiling::default()).unwrap_err();
        assert!(matches!(err, CapabilityError::NetDenied { .. }));
    }

    #[test]
    fn canonicalizes_fs_paths() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("fixtures");
        std::fs::create_dir_all(&sub).unwrap();

        let manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new("reader"),
                version: "0.1.0".into(),
                kind: ToolKind::Wasm,
            },
            dir.path(),
        )
        .with_fs(FsNeeds {
            read: vec![PathNeed::recursive("fixtures")],
            write: vec![],
        });

        let grant = mint_grant(&manifest, "g1", PolicyCeiling::default()).unwrap();
        let fs = grant.fs.expect("fs grant");
        assert_eq!(fs.read_paths.len(), 1);
        assert!(fs.read_paths[0].ends_with("fixtures"));
    }
}
