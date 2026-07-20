//! Criterion benches for `CapabilityResolver::resolve_with_ceiling`.
//!
//! Isolation / regression only — no hard µs gate. Combined hot path owns <1 ms.

use std::hint::black_box;
use std::path::Path;

use botzr_aegis_capability::{
    CapabilityResolver, FsNeeds, HttpNeed, NetNeeds, PathNeed, ToolInfo, ToolKind, ToolLimits,
    ToolManifest,
};
use botzr_aegis_core::{ResourceCeiling, ToolId};
use criterion::{criterion_group, criterion_main, Criterion};

/// Same shape as `capability/tests/capability.rs` `fixture_manifest`.
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

fn capability_resolve(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("fixtures/nested")).expect("fixture dirs");

    let tool_id = ToolId::new("reader");
    let mut resolver = CapabilityResolver::new();
    resolver.register(fixture_manifest("reader", dir.path()));

    let mut group = c.benchmark_group("capability_resolve");
    group.bench_function("registered_tool", |b| {
        b.iter(|| {
            black_box(resolver.resolve_with_ceiling(&tool_id, ResourceCeiling::default()));
        });
    });
    group.finish();
}

criterion_group!(benches, capability_resolve);
criterion_main!(benches);
