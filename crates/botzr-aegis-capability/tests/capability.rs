//! Capability resolver integration tests + narrowing property checks.

use botzr_aegis_capability::{
    grant_is_subset, narrow_grant, CapabilityError, CapabilityResolver, FsNeeds, HttpNeed,
    NetNeeds, PathNeed, ToolInfo, ToolKind, ToolLimits, ToolManifest,
};
use botzr_aegis_core::{CapabilityOutcome, ResourceCeiling, ToolId};
use proptest::prelude::*;

fn fixture_manifest(id: &str, base: &std::path::Path) -> ToolManifest {
    ToolManifest::new(
        ToolInfo {
            id: ToolId::new(id),
            version: "0.1.0".into(),
            kind: ToolKind::Wasm,
        },
        base,
    )
    .with_fs(FsNeeds {
        read: vec![PathNeed::recursive("fixtures")],
        write: vec![PathNeed::new("fixtures/nested")],
    })
    .with_net(NetNeeds {
        http: vec![HttpNeed {
            host: "api.example.com".into(),
            ports: vec![443, 8443],
            methods: vec!["GET".into(), "POST".into()],
        }],
    })
    .with_limits(ToolLimits {
        max_memory_bytes: 1 << 20,
        max_wall_ms: 5_000,
        ..ToolLimits::default()
    })
}

#[test]
fn unregistered_tool_is_denied_with_audit_axis() {
    let resolver = CapabilityResolver::new();
    let outcome = resolver.resolve(&ToolId::new("missing"));
    match outcome {
        CapabilityOutcome::Denied {
            reason,
            denied_capability,
        } => {
            assert!(reason.contains("missing"));
            assert_eq!(denied_capability.as_deref(), Some("tool.registry"));
        }
        CapabilityOutcome::Granted { .. } => panic!("expected denial"),
    }
}

#[test]
fn registered_tool_mints_grant() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("fixtures/nested")).unwrap();

    let manifest = fixture_manifest("reader", dir.path());
    let mut resolver = CapabilityResolver::new();
    // Unit-testing the resolver in isolation; `Runtime::register_tool` would
    // drag the sandbox into a capability test. No executable is paired with this
    // throwaway resolver, so the split-authority concern does not apply.
    #[allow(deprecated)]
    resolver.register(manifest);

    match resolver.resolve(&ToolId::new("reader")) {
        CapabilityOutcome::Granted { grant } => {
            assert_eq!(grant.tool_id.as_str(), "reader");
            assert!(grant.fs.is_some());
            assert!(grant.net.is_some());
        }
        CapabilityOutcome::Denied { .. } => panic!("expected grant"),
    }
}

/// AILAB-846, AC 1 — the gate that proves the ticket rather than its symptoms.
///
/// Register a tool, delete a declared path, then resolve. Resolution grants,
/// because the `std::fs::canonicalize` that would have failed already happened
/// once, at registration.
///
/// The second half is the control that makes the first half mean something.
/// `resolve_manifest` deliberately still canonicalizes per call (there is no
/// registration to have prepared — `aegis wrap --confine` mints from CLI flags),
/// so the *same* manifest against the *same* deleted path denies. One test, two
/// code paths, one difference: where the filesystem is touched. Without the
/// control arm a passing assertion could not distinguish "stopped touching the
/// filesystem" from "the path happened to still resolve".
#[test]
fn resolve_after_declared_path_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let fixtures = dir.path().join("fixtures");
    std::fs::create_dir_all(fixtures.join("nested")).unwrap();

    let manifest = fixture_manifest("reader", dir.path());
    let mut resolver = CapabilityResolver::new();
    #[allow(deprecated)]
    resolver.register(manifest.clone());

    // Registration has canonicalized. Now the declared tree goes away.
    std::fs::remove_dir_all(&fixtures).unwrap();
    assert!(!fixtures.exists(), "fixture tree must actually be gone");

    match resolver.resolve_with_ceiling(&ToolId::new("reader"), ResourceCeiling::default()) {
        CapabilityOutcome::Granted { grant } => {
            let fs = grant.fs.expect("fs grant");
            // The grant still names the absolute canonical path resolved at
            // registration — proof the canonicalization happened, just earlier.
            assert_eq!(fs.read_paths.len(), 1);
            assert!(std::path::Path::new(&fs.read_paths[0]).is_absolute());
            assert!(fs.read_paths[0].ends_with("fixtures"));
        }
        CapabilityOutcome::Denied { reason, .. } => {
            panic!("resolution still reaches the filesystem: {reason}")
        }
    }

    // Control: the call-time path, same manifest, same missing directory.
    match resolver.resolve_manifest(&manifest) {
        CapabilityOutcome::Denied {
            denied_capability, ..
        } => assert_eq!(denied_capability.as_deref(), Some("fs")),
        CapabilityOutcome::Granted { .. } => {
            panic!("resolve_manifest must still canonicalize per call")
        }
    }
}

/// AILAB-846 §3.2 ruling (b) — registration cannot fail, so the failure is
/// stored and replayed by resolution.
///
/// A manifest whose declared path never existed denies at exactly the call it
/// always denied at, with the same `fs` axis, even though the canonicalization
/// that decided it now runs at registration. This is the test that keeps the
/// ruling honest: nothing else in the suite pins where a bad declared path
/// surfaces.
#[test]
fn registration_failure_is_replayed_at_resolve() {
    let dir = tempfile::tempdir().unwrap();
    // Deliberately never created.
    let manifest = fixture_manifest("never-existed", dir.path());

    let mut resolver = CapabilityResolver::new();
    #[allow(deprecated)]
    resolver.register(manifest);

    // Twice: the stored error is replayed, not consumed.
    for _ in 0..2 {
        match resolver.resolve(&ToolId::new("never-existed")) {
            CapabilityOutcome::Denied {
                reason,
                denied_capability,
            } => {
                assert_eq!(denied_capability.as_deref(), Some("fs"));
                assert!(reason.contains("fixtures"), "{reason}");
            }
            CapabilityOutcome::Granted { .. } => panic!("expected denial"),
        }
    }
}

#[test]
fn default_deny_net_when_absent_from_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = ToolManifest::new(
        ToolInfo {
            id: ToolId::new("no-net"),
            version: "0.1.0".into(),
            kind: ToolKind::Wasm,
        },
        dir.path(),
    );

    let resolver = CapabilityResolver::new();
    match resolver.resolve_manifest(&manifest) {
        CapabilityOutcome::Granted { grant } => assert!(grant.net.is_none()),
        CapabilityOutcome::Denied { .. } => panic!("expected grant"),
    }
}

proptest! {
    #[test]
    fn narrowed_grant_never_broader_than_parent(
        sub_memory in 1u64..=(1 << 20),
        sub_wall in 1u64..=5_000u64,
        // Output cap varied within the parent's ceiling (1 MiB default) so the
        // property actually exercises the output axis the oracle now covers.
        sub_output in 1u64..=(1 << 20),
    ) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("fixtures/nested")).unwrap();

        let parent_manifest = fixture_manifest("parent", dir.path());
        let parent_grant = match CapabilityResolver::new().resolve_manifest(&parent_manifest) {
            CapabilityOutcome::Granted { grant } => grant,
            CapabilityOutcome::Denied { reason, .. } => panic!("parent mint failed: {reason}"),
        };

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
            max_memory_bytes: sub_memory,
            max_wall_ms: sub_wall,
            max_output_bytes: sub_output,
        });

        let sub = narrow_grant(
            &parent_grant,
            &parent_manifest,
            &sub_manifest,
            "child-grant",
            ResourceCeiling::default(),
        ).expect("narrowing should succeed for valid subset");

        prop_assert!(grant_is_subset(&parent_grant, &sub));
    }
}

#[test]
fn narrowing_rejects_limit_escalation() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("fixtures/nested")).unwrap();

    let parent_manifest = fixture_manifest("parent", dir.path());
    let parent_grant = match CapabilityResolver::new().resolve_manifest(&parent_manifest) {
        CapabilityOutcome::Granted { grant } => grant,
        CapabilityOutcome::Denied { reason, .. } => panic!("parent mint failed: {reason}"),
    };

    let sub_manifest = ToolManifest::new(
        ToolInfo {
            id: ToolId::new("greedy-child"),
            version: "0.1.0".into(),
            kind: ToolKind::Wasm,
        },
        dir.path(),
    )
    .with_limits(ToolLimits {
        max_memory_bytes: parent_grant.max_memory_bytes + 1,
        max_wall_ms: parent_grant.max_wall_ms,
        ..ToolLimits::default()
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
