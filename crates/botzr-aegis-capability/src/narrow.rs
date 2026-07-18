//! Narrowing-only delegation — sub-grants are a strict subset of the parent.

use std::path::Path;

use botzr_aegis_core::{CapabilityGrant, ResourceCeiling};

use crate::error::CapabilityError;
use crate::manifest::{FsNeeds, NetNeeds, ToolManifest};
use crate::mint::{http_need_allowed, mint_grant, path_need_allowed};

/// Mint a sub-tool grant that is a strict subset of the parent grant + manifest.
///
/// Escalation along any axis (broader fs, net, or higher limits) is a hard error.
#[must_use = "narrowing result must be handled — escalation is audit-worthy"]
pub fn narrow_grant(
    parent_grant: &CapabilityGrant,
    parent_manifest: &ToolManifest,
    sub_manifest: &ToolManifest,
    grant_id: impl Into<String>,
    ceiling: ResourceCeiling,
) -> Result<CapabilityGrant, CapabilityError> {
    validate_fs_narrowing(
        parent_manifest.fs.as_ref(),
        sub_manifest.fs.as_ref(),
        &parent_manifest.base_dir,
    )?;
    validate_net_narrowing(parent_manifest.net.as_ref(), sub_manifest.net.as_ref())?;

    let sub = mint_grant(sub_manifest, grant_id, ceiling)?;

    // Single grant-level guard: every axis is checked by the one subset oracle
    // (the same `check_grant_subset` that backs `grant_is_subset`).
    ensure_grant_narrowed(parent_grant, &sub)?;

    Ok(sub)
}

fn validate_fs_narrowing(
    parent: Option<&FsNeeds>,
    sub: Option<&FsNeeds>,
    base: &std::path::Path,
) -> Result<(), CapabilityError> {
    let Some(sub) = sub else {
        return Ok(());
    };
    let parent = parent.cloned().unwrap_or_default();

    for sub_read in &sub.read {
        if !any_path_allowed(&parent.read, sub_read, base)? {
            return Err(CapabilityError::Escalation {
                detail: format!("fs.read escalation for path `{}`", sub_read.path),
            });
        }
    }

    for sub_write in &sub.write {
        if !any_path_allowed(&parent.write, sub_write, base)? {
            return Err(CapabilityError::Escalation {
                detail: format!("fs.write escalation for path `{}`", sub_write.path),
            });
        }
    }

    Ok(())
}

fn any_path_allowed(
    parent: &[crate::manifest::PathNeed],
    sub: &crate::manifest::PathNeed,
    base: &std::path::Path,
) -> Result<bool, CapabilityError> {
    for p in parent {
        if path_need_allowed(p, sub, base)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_net_narrowing(
    parent: Option<&NetNeeds>,
    sub: Option<&NetNeeds>,
) -> Result<(), CapabilityError> {
    let Some(sub) = sub else {
        return Ok(());
    };
    let parent = parent.cloned().unwrap_or_default();

    for sub_http in &sub.http {
        if !parent.http.iter().any(|p| http_need_allowed(p, sub_http)) {
            return Err(CapabilityError::Escalation {
                detail: format!("net.http escalation for host `{}`", sub_http.host),
            });
        }
    }

    Ok(())
}

/// The single subset oracle (AEG-39). Answers "is `sub` no broader than
/// `parent` on every grant axis?" — the `max_memory_bytes` / `max_wall_ms` /
/// `max_output_bytes` limits, filesystem read/write containment (component-aware),
/// and net http host/ports/methods (⊆, case-insensitive methods). Returns
/// `Ok(())` when `sub` is a subset, or `Err(detail)` naming the first axis on
/// which `sub` escalates.
///
/// Both the public bool verifier [`grant_is_subset`] and the production
/// narrowing guard [`ensure_grant_narrowed`] derive from this one function —
/// there is no second, divergent axis comparison anywhere in the crate. A `sub`
/// with `None` fs/net is always a subset; a `sub` with `Some` against a parent
/// `None` escalates.
fn check_grant_subset(parent: &CapabilityGrant, sub: &CapabilityGrant) -> Result<(), String> {
    if sub.max_memory_bytes > parent.max_memory_bytes {
        return Err(format!(
            "max_memory_bytes escalation: sub={} parent={}",
            sub.max_memory_bytes, parent.max_memory_bytes
        ));
    }
    if sub.max_wall_ms > parent.max_wall_ms {
        return Err(format!(
            "max_wall_ms escalation: sub={} parent={}",
            sub.max_wall_ms, parent.max_wall_ms
        ));
    }
    if sub.max_output_bytes > parent.max_output_bytes {
        return Err(format!(
            "max_output_bytes escalation: sub={} parent={}",
            sub.max_output_bytes, parent.max_output_bytes
        ));
    }

    if let Some(sub_fs) = &sub.fs {
        let parent_fs = parent.fs.as_ref();
        for path in sub_fs.read_paths.iter().chain(sub_fs.write_paths.iter()) {
            let in_parent_read = parent_fs
                .map(|p| p.read_paths.iter().any(|root| path_contained(root, path)))
                .unwrap_or(false);
            let in_parent_write = parent_fs
                .map(|p| p.write_paths.iter().any(|root| path_contained(root, path)))
                .unwrap_or(false);
            let is_write = sub_fs.write_paths.iter().any(|w| w == path);
            if is_write && !in_parent_write {
                return Err(format!("fs.write grant escalation for `{path}`"));
            }
            if !is_write && !in_parent_read && !in_parent_write {
                return Err(format!("fs.read grant escalation for `{path}`"));
            }
        }
    }

    if let Some(sub_net) = &sub.net {
        let parent_http = parent
            .net
            .as_ref()
            .map(|n| n.http.as_slice())
            .unwrap_or(&[]);
        for sub_http in &sub_net.http {
            let allowed = parent_http.iter().any(|parent| {
                parent.host == sub_http.host
                    && sub_http
                        .ports
                        .iter()
                        .all(|port| parent.ports.contains(port))
                    && sub_http.methods.iter().all(|method| {
                        parent
                            .methods
                            .iter()
                            .any(|m| m.eq_ignore_ascii_case(method))
                    })
            });
            if !allowed {
                return Err(format!(
                    "net.http grant escalation for host `{}`",
                    sub_http.host
                ));
            }
        }
    }

    Ok(())
}

/// Component-aware path containment: is `child` equal to, or nested under,
/// `parent`? Compares path *components* via [`Path::starts_with`], never a raw
/// string prefix — so sibling paths like `/tmp/foo` vs `/tmp/foobar` are never
/// confused (AEG-39). Grant strings are already absolute canonical paths from
/// mint; non-recursive need semantics stay in `path_need_allowed`.
fn path_contained(parent: &str, child: &str) -> bool {
    let parent_path = Path::new(parent);
    let child_path = Path::new(child);
    child_path == parent_path || child_path.starts_with(parent_path)
}

/// Returns true when `sub` is no broader than `parent` on every grant axis.
///
/// Thin bool view over [`check_grant_subset`] — the single subset oracle shared
/// with production narrowing.
pub fn grant_is_subset(parent: &CapabilityGrant, sub: &CapabilityGrant) -> bool {
    check_grant_subset(parent, sub).is_ok()
}

/// Guard form of the subset oracle used by [`narrow_grant`]: `Ok(())` when `sub`
/// narrows `parent`, else [`CapabilityError::Escalation`] naming the offending
/// axis. Wraps the same [`check_grant_subset`] oracle as [`grant_is_subset`] —
/// no duplicated axis logic.
fn ensure_grant_narrowed(
    parent: &CapabilityGrant,
    sub: &CapabilityGrant,
) -> Result<(), CapabilityError> {
    check_grant_subset(parent, sub).map_err(|detail| CapabilityError::Escalation { detail })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{FsNeeds, HttpNeed, NetNeeds, PathNeed, ToolInfo, ToolKind, ToolLimits};
    use botzr_aegis_core::{FsGrant, ToolId};

    /// A minimal deny-all grant with only the limit axes populated. Callers
    /// override `fs` / `net` with struct-update syntax to probe one axis.
    fn bare_grant(max_output_bytes: u64) -> CapabilityGrant {
        CapabilityGrant {
            grant_id: "g".into(),
            tool_id: ToolId::new("t"),
            fs: None,
            net: None,
            max_memory_bytes: 1024,
            max_wall_ms: 1_000,
            max_output_bytes,
        }
    }

    fn parent_fixture() -> (tempfile::TempDir, ToolManifest, CapabilityGrant) {
        let dir = tempfile::tempdir().unwrap();
        let fixtures = dir.path().join("fixtures");
        let nested = fixtures.join("nested");
        std::fs::create_dir_all(&nested).unwrap();

        let parent_manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new("parent"),
                version: "0.1.0".into(),
                kind: ToolKind::Wasm,
            },
            dir.path(),
        )
        .with_fs(FsNeeds {
            read: vec![PathNeed::recursive("fixtures")],
            write: vec![PathNeed::new("fixtures/nested")],
        })
        .with_net(NetNeeds {
            http: vec![HttpNeed {
                host: "api.example.com".into(),
                ports: vec![443],
                methods: vec!["GET".into(), "POST".into()],
            }],
        })
        .with_limits(ToolLimits {
            max_memory_bytes: 1 << 20,
            max_wall_ms: 5_000,
            ..ToolLimits::default()
        });

        let parent_grant =
            mint_grant(&parent_manifest, "parent-grant", ResourceCeiling::default()).unwrap();
        (dir, parent_manifest, parent_grant)
    }

    #[test]
    fn narrows_fs_and_net_successfully() {
        let (dir, parent_manifest, parent_grant) = parent_fixture();

        let sub_manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new("child"),
                version: "0.1.0".into(),
                kind: ToolKind::Wasm,
            },
            dir.path(),
        )
        .with_fs(FsNeeds {
            read: vec![PathNeed::new("fixtures/nested")],
            write: vec![],
        })
        .with_net(NetNeeds {
            http: vec![HttpNeed {
                host: "api.example.com".into(),
                ports: vec![443],
                methods: vec!["GET".into()],
            }],
        })
        .with_limits(ToolLimits {
            max_memory_bytes: 512 * 1024,
            max_wall_ms: 1_000,
            ..ToolLimits::default()
        });

        let sub = narrow_grant(
            &parent_grant,
            &parent_manifest,
            &sub_manifest,
            "child-grant",
            ResourceCeiling::default(),
        )
        .unwrap();

        assert!(grant_is_subset(&parent_grant, &sub));
        assert_eq!(sub.grant_id, "child-grant");
    }

    #[test]
    fn rejects_fs_write_escalation() {
        let (dir, parent_manifest, parent_grant) = parent_fixture();

        let sub_manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new("bad-child"),
                version: "0.1.0".into(),
                kind: ToolKind::Wasm,
            },
            dir.path(),
        )
        .with_fs(FsNeeds {
            read: vec![],
            write: vec![PathNeed::new("fixtures")],
        });

        let err = narrow_grant(
            &parent_grant,
            &parent_manifest,
            &sub_manifest,
            "bad-grant",
            ResourceCeiling::default(),
        )
        .unwrap_err();
        assert!(matches!(err, CapabilityError::Escalation { .. }));
    }

    #[test]
    fn rejects_output_cap_escalation() {
        // R2 subset invariant on the output axis: a sub-tool may not declare a
        // larger `max_output_bytes` than its parent.
        let (dir, parent_manifest, parent_grant) = parent_fixture();

        let sub_manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new("greedy-child"),
                version: "0.1.0".into(),
                kind: ToolKind::Wasm,
            },
            dir.path(),
        )
        .with_limits(ToolLimits {
            max_memory_bytes: 512 * 1024, // within the parent's 1 MiB
            max_wall_ms: 1_000,
            max_output_bytes: parent_grant.max_output_bytes + 1, // one byte over
        });

        let err = narrow_grant(
            &parent_grant,
            &parent_manifest,
            &sub_manifest,
            "greedy-grant",
            ResourceCeiling::default(),
        )
        .unwrap_err();
        assert!(matches!(err, CapabilityError::Escalation { .. }));
    }

    #[test]
    fn rejects_net_host_escalation() {
        let (dir, parent_manifest, parent_grant) = parent_fixture();

        let sub_manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new("bad-net-child"),
                version: "0.1.0".into(),
                kind: ToolKind::Host,
            },
            dir.path(),
        )
        .with_net(NetNeeds {
            http: vec![HttpNeed::get("evil.example.com")],
        });

        let err = narrow_grant(
            &parent_grant,
            &parent_manifest,
            &sub_manifest,
            "bad-grant",
            ResourceCeiling::default(),
        )
        .unwrap_err();
        assert!(matches!(err, CapabilityError::Escalation { .. }));
    }

    #[test]
    fn oracle_rejects_output_cap_escalation() {
        // AEG-39: the shared oracle — not only the mint path — must reject an
        // output cap that escalates. The old `grant_is_subset` ignored this axis.
        let parent = bare_grant(1024);
        let escalated = bare_grant(1025); // one byte over on the output axis only
        assert!(!grant_is_subset(&parent, &escalated));
        // An equal output cap stays a subset.
        assert!(grant_is_subset(&parent, &bare_grant(1024)));
    }

    #[test]
    fn oracle_rejects_sibling_prefix_path() {
        // AEG-39: `/tmp/foobar` is a *sibling* of `/tmp/foo`, not a child. A raw
        // string prefix would wrongly accept it; component-aware containment must not.
        let parent = CapabilityGrant {
            fs: Some(FsGrant {
                read_paths: vec!["/tmp/foo".into()],
                write_paths: vec![],
            }),
            ..bare_grant(1024)
        };
        let sibling = CapabilityGrant {
            fs: Some(FsGrant {
                read_paths: vec!["/tmp/foobar".into()],
                write_paths: vec![],
            }),
            ..bare_grant(1024)
        };
        assert!(!grant_is_subset(&parent, &sibling));

        // A genuine child under the parent path is still a subset.
        let nested = CapabilityGrant {
            fs: Some(FsGrant {
                read_paths: vec!["/tmp/foo/bar".into()],
                write_paths: vec![],
            }),
            ..bare_grant(1024)
        };
        assert!(grant_is_subset(&parent, &nested));
    }
}
