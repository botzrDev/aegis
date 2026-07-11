//! Criterion bench for the capability hot path — `resolve_with_ceiling`.
//!
//! Station 2 of POLICY → CAPABILITY → SANDBOX → AUDIT. Registration and the
//! tempdir fixture are built **once** in setup; the iter body only resolves a
//! registered tool into a minted grant. No hard µs gate here — the combined
//! `hot_path` bench owns the <1 ms claim; this isolates the resolve step for
//! regression tracking.

use std::hint::black_box;
use std::path::Path;

use criterion::{criterion_group, criterion_main, Criterion};

use botzr_aegis_capability::{
    CapabilityResolver, FsNeeds, HttpNeed, NetNeeds, PathNeed, PolicyCeiling, ToolInfo, ToolKind,
    ToolLimits, ToolManifest,
};
use botzr_aegis_core::ToolId;

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

fn bench_resolve(c: &mut Criterion) {
    // Setup once: fixture dirs must exist because minting canonicalizes paths.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("fixtures/nested")).unwrap();

    let mut resolver = CapabilityResolver::new();
    resolver.register(fixture_manifest("reader", dir.path()));
    let tool_id = ToolId::new("reader");

    let mut group = c.benchmark_group("capability_resolve");
    group.bench_function("registered_tool", |b| {
        b.iter(|| {
            black_box(resolver.resolve_with_ceiling(&tool_id, PolicyCeiling::default()));
        });
    });
    group.finish();
}

criterion_group!(benches, bench_resolve);
criterion_main!(benches);
