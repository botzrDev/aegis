//! Criterion bench for the library-mode combined hot path: policy `evaluate`
//! folded into capability `resolve_with_ceiling`, mirroring the canonical
//! wiring at `runtime/src/lib.rs:143–167`.
//!
//! This is the group that owns the **< 1 ms** (median) claim for `multi_rule`
//! on the cited machine (see `benches/README.md`). By design it stops at
//! stations 1–2 and never touches the later pipeline: `SandboxEngine`,
//! `AuditWriter`, and `CallSession` are never constructed, `wasmtime` is never
//! linked, and `Runtime::execute_tool_call` is never called — this measures the
//! enforcement decision path, not tool execution.

use std::hint::black_box;
use std::path::Path;

use criterion::{criterion_group, criterion_main, Criterion};

use botzr_aegis_capability::{
    CapabilityResolver, FsNeeds, HttpNeed, NetNeeds, PathNeed, PolicyCeiling, ToolInfo, ToolKind,
    ToolLimits, ToolManifest,
};
use botzr_aegis_core::ToolId;
use botzr_aegis_policy::{PolicyEngine, PolicyRequest};

/// Multi-rule set whose most-specific `writer`/`owner` allow carries a ceiling,
/// so the combined bench exercises the policy-derived ceiling fold into the
/// resolver. Matches the policy crate's `multi_rule` fixture.
const MULTI_RULE_YAML: &str = r#"
version: 1
default: deny
rules:
  - id: broad-allow
    action: allow
    tool: "*"
  - id: specific-allow
    action: allow
    tool: writer
    role: owner
    limits: { max_memory_bytes: 1048576, max_wall_ms: 1000 }
"#;

/// Copied verbatim from `crates/botzr-aegis-capability/tests/capability.rs:10`.
/// That helper lives in a separate integration-test crate and is not importable
/// from a bench, so it is duplicated here rather than `use`d.
fn fixture_manifest(id: &str, base: &Path) -> ToolManifest {
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
    })
}

fn bench_hot_path(c: &mut Criterion) {
    // Register one tool (`writer`) used by both groups so the multi-rule policy
    // matches a registered tool and the resolve step actually mints a grant.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("fixtures/nested")).unwrap();

    let mut resolver = CapabilityResolver::new();
    resolver.register(fixture_manifest("writer", dir.path()));
    let tool_id = ToolId::new("writer");

    let mut group = c.benchmark_group("hot_path");

    // allow_all — policy imposes nothing; capability stays the default-deny layer.
    let allow_engine = PolicyEngine::allow_all();
    group.bench_function("allow_all", |b| {
        b.iter(|| {
            let decision = black_box(allow_engine.evaluate(&PolicyRequest::for_tool(&tool_id)));
            let ceiling = PolicyCeiling {
                max_memory_bytes: decision.limits.max_memory_bytes,
                max_wall_ms: decision.limits.max_wall_ms,
            };
            black_box(resolver.resolve_with_ceiling(&tool_id, ceiling));
        });
    });

    // multi_rule — role-gated allow whose ceiling folds into the resolver.
    let multi_engine = PolicyEngine::from_yaml(MULTI_RULE_YAML).expect("multi-rule YAML parses"); // setup
    group.bench_function("multi_rule", |b| {
        b.iter(|| {
            let decision =
                black_box(multi_engine.evaluate(&PolicyRequest::for_tool(&tool_id).with_role("owner")));
            let ceiling = PolicyCeiling {
                max_memory_bytes: decision.limits.max_memory_bytes,
                max_wall_ms: decision.limits.max_wall_ms,
            };
            black_box(resolver.resolve_with_ceiling(&tool_id, ceiling));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_hot_path);
criterion_main!(benches);
