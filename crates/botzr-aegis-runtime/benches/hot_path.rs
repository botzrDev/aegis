//! Combined library-mode hot path: policy eval + capability resolve.
//!
//! Mirrors `runtime/src/lib.rs` stations 1–2. Do not call sandbox, audit, or wasmtime.
//! Target: `hot_path/multi_rule` median < 1 ms.

use std::hint::black_box;
use std::path::Path;

use botzr_aegis_capability::{
    CapabilityResolver, FsNeeds, HttpNeed, NetNeeds, PathNeed, PolicyCeiling, ToolInfo, ToolKind,
    ToolLimits, ToolManifest,
};
use botzr_aegis_core::ToolId;
use botzr_aegis_policy::{PolicyEngine, PolicyRequest};
use criterion::{criterion_group, criterion_main, Criterion};

/// Multi-rule YAML from policy crate tests (setup only).
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
        ..ToolLimits::default()
    })
}

fn setup_resolver(tool_id: &str, base: &Path) -> CapabilityResolver {
    let mut resolver = CapabilityResolver::new();
    resolver.register(fixture_manifest(tool_id, base));
    resolver
}

/// Mirror runtime: evaluate → PolicyCeiling from decision.limits → resolve_with_ceiling.
fn hot_path_iter(
    engine: &PolicyEngine,
    resolver: &CapabilityResolver,
    tool_id: &ToolId,
    with_role: bool,
) {
    let decision = if with_role {
        black_box(engine.evaluate(&PolicyRequest::for_tool(tool_id).with_role("owner")))
    } else {
        black_box(engine.evaluate(&PolicyRequest::for_tool(tool_id)))
    };
    let ceiling = PolicyCeiling {
        max_memory_bytes: decision.limits.max_memory_bytes,
        max_wall_ms: decision.limits.max_wall_ms,
        max_output_bytes: decision.limits.max_output_bytes,
    };
    let _ = black_box(resolver.resolve_with_ceiling(tool_id, ceiling));
}

fn hot_path(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("fixtures/nested")).expect("fixture dirs");

    let mut group = c.benchmark_group("hot_path");

    // --- allow_all ---
    {
        let engine = PolicyEngine::allow_all();
        let tool_id = ToolId::new("reader");
        let resolver = setup_resolver("reader", dir.path());
        group.bench_function("allow_all", |b| {
            b.iter(|| hot_path_iter(&engine, &resolver, &tool_id, false));
        });
    }

    // --- multi_rule (publishable <1 ms claim) ---
    {
        let engine = PolicyEngine::from_yaml(MULTI_RULE_YAML).expect("multi-rule yaml"); // setup
        let tool_id = ToolId::new("writer");
        let resolver = setup_resolver("writer", dir.path());
        group.bench_function("multi_rule", |b| {
            b.iter(|| hot_path_iter(&engine, &resolver, &tool_id, true));
        });
    }

    group.finish();
}

criterion_group!(benches, hot_path);
criterion_main!(benches);
