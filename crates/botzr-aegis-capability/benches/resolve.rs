//! Criterion benches for `CapabilityResolver::resolve_manifest`.
//!
//! Isolation / regression only — no hard µs gate. Combined hot path owns <1 ms.
//!
//! **What the number covers (changed by AILAB-707 — read before comparing to an
//! older `benches/results/` entry).** This bench used to call
//! `resolve_with_ceiling(&tool_id, ResourceCeiling::default())` against a tool
//! registered through `CapabilityResolver::register`. That method is
//! `#[deprecated]` as a cross-crate visibility fence: the only sanctioned writer
//! is `botzr_aegis_runtime::Runtime::register_tool`, which pairs a manifest with
//! its executable. This crate cannot reach that path — runtime depends on
//! capability, so the reverse edge is a dependency cycle — and a *published*
//! benchmark that suppresses a deprecation to reach a forbidden path is exactly
//! the claim-integrity defect this repo forbids. So the bench moved to
//! `resolve_manifest`, the supported one-off mint route that already ships for
//! `aegis wrap --confine` (AILAB-628).
//!
//! Two pieces of work therefore **left** the measured path:
//!
//! * The `HashMap<ToolId, ToolManifest>` registry lookup — `resolve_manifest`
//!   mints from a manifest the caller already holds.
//! * The `ResourceCeiling::combine` fold — `resolve_manifest` applies the
//!   resolver's standing ceiling directly instead of folding in a per-call one.
//!   Ceiling *semantics* are unchanged: the old call passed
//!   `ResourceCeiling::default()` (all axes `None`) and `CapabilityResolver::new()`'s
//!   standing ceiling is also default, so `combine` was a no-op and `mint_grant`
//!   receives an identical unconstrained ceiling either way.
//!
//! What remains is `mint_grant` — the fs/net narrowing and limit folding that
//! dominated the old number anyway. The lookup and the `combine` fold are still
//! measured end to end by `hot_path/*` in `botzr-aegis-runtime`, which registers
//! through `Runtime::register_tool` and still calls `resolve_with_ceiling`.

use std::hint::black_box;
use std::path::Path;

use botzr_aegis_capability::{
    CapabilityResolver, FsNeeds, HttpNeed, NetNeeds, PathNeed, ToolInfo, ToolKind, ToolLimits,
    ToolManifest,
};
use botzr_aegis_core::ToolId;
use criterion::{criterion_group, criterion_main, Criterion};

/// Same shape as `capability/tests/capability.rs` `fixture_manifest`.
///
/// fs/net/limits are deliberately untouched so the minting work stays
/// comparable to the pre-AILAB-707 baseline; only the surrounding call changed.
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

    // Nothing is registered — `resolve_manifest` never consults the registry.
    // `new()` gives the default (unconstrained) standing ceiling, matching the
    // `ResourceCeiling::default()` this bench used to pass per call.
    let resolver = CapabilityResolver::new();
    let manifest = fixture_manifest("reader", dir.path());

    let mut group = c.benchmark_group("capability_resolve");
    // Renamed from `registered_tool` (AILAB-707): the tool is no longer
    // registered, and a bench id that says otherwise misdescribes the number.
    group.bench_function("mint_from_manifest", |b| {
        b.iter(|| {
            black_box(resolver.resolve_manifest(black_box(&manifest)));
        });
    });
    group.finish();
}

criterion_group!(benches, capability_resolve);
criterion_main!(benches);
