//! Combined library-mode hot path: policy eval + capability resolve.
//!
//! Mirrors `runtime/src/lib.rs` stations 1–2. Do not call sandbox, audit, or
//! wasmtime **inside `b.iter`**. Setup builds a whole `Runtime` (which does
//! construct a `SandboxEngine` and an in-memory `AuditWriter`), because
//! `Runtime::register_tool` is the only sanctioned way to put a manifest in
//! front of the resolver — see `setup_runtime`. None of that cost is measured.
//!
//! Target: `hot_path/multi_rule` median < 1 ms.

use std::hint::black_box;
use std::path::Path;

use botzr_aegis_capability::{
    CapabilityResolver, FsNeeds, HttpNeed, NetNeeds, PathNeed, ToolInfo, ToolKind, ToolLimits,
    ToolManifest,
};
use botzr_aegis_core::ToolId;
use botzr_aegis_policy::{PolicyEngine, PolicyRequest};
use botzr_aegis_runtime::{Runtime, ToolExecutable};
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
            // `Host`, not `Wasm`: `register_tool` rejects a `Wasm` manifest
            // paired with a `HostHandler` as a `KindMismatch`, and a `Wasm`
            // manifest would need real component bytes plus a sandbox prepare
            // just to reach the resolver. The kind does not change what is
            // measured — nothing on the production mint path branches on it
            // (every `ToolKind` occurrence in capability's `mint.rs` /
            // `narrow.rs` is inside a `#[cfg(test)]` fixture), and the policy
            // crate never reads it at all. fs/net/limits are unchanged, so the
            // number stays comparable to the pre-AILAB-707 baseline.
            kind: ToolKind::Host,
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

/// Build a `Runtime` holding exactly one registered tool, so the bench can
/// measure against `rt.capabilities()`.
///
/// This bench lives inside `botzr-aegis-runtime`, so it uses the sanctioned
/// registration path rather than `CapabilityResolver::register` — that method is
/// `#[deprecated]` precisely to make a manifest-without-executable write a
/// compile error outside the runtime, and a published benchmark reaching around
/// it is a claim-integrity problem. Registering is *setup*: it happens once,
/// outside `b.iter`. And a `ToolKind::Host` manifest paired with a
/// `HostHandler` performs **no sandbox prepare** — `register_tool` sends that
/// arm straight to the `Host` executable slot — so no wasmtime compilation
/// happens here either.
///
/// One tool per `Runtime` on purpose: the resolver's registry stays a one-entry
/// map, exactly as it was when the baseline in `benches/results/hot_path.md`
/// was measured. Sharing one `Runtime` across both benches would grow the
/// lookup and quietly shift the number.
fn setup_runtime(tool_id: &str, base: &Path) -> Runtime {
    let mut rt = Runtime::new();
    rt.register_tool(
        fixture_manifest(tool_id, base),
        // Identity effect, never invoked: the bench stops at stations 1–2 and
        // never calls `execute_host_call`. The handler exists only because
        // atomic registration refuses to write authority without an executable.
        ToolExecutable::HostHandler(Box::new(|_ctx, input| Ok(input.to_vec()))),
    )
    .expect("register fixture tool");
    rt
}

/// Mirror runtime: evaluate → decision.limits (a `ResourceCeiling`) → resolve_with_ceiling.
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
    // Same core type on both sides — pass the ceiling straight through.
    let ceiling = decision.limits;
    // Deliberately `resolve_with_ceiling`, not `resolve_manifest`: the <1 ms
    // claim covers the registry lookup and the `ResourceCeiling::combine` fold
    // as well as minting, which is what the runtime actually does per call.
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
        // The runtime owns the resolver; `capabilities()` is the read-only view.
        let rt = setup_runtime("reader", dir.path());
        let resolver = rt.capabilities();
        group.bench_function("allow_all", |b| {
            b.iter(|| hot_path_iter(&engine, resolver, &tool_id, false));
        });
    }

    // --- multi_rule (publishable <1 ms claim) ---
    {
        let engine = PolicyEngine::from_yaml(MULTI_RULE_YAML).expect("multi-rule yaml"); // setup
        let tool_id = ToolId::new("writer");
        let rt = setup_runtime("writer", dir.path());
        let resolver = rt.capabilities();
        group.bench_function("multi_rule", |b| {
            b.iter(|| hot_path_iter(&engine, resolver, &tool_id, true));
        });
    }

    group.finish();
}

criterion_group!(benches, hot_path);
criterion_main!(benches);
