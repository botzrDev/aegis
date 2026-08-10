//! Cell instantiation: warm re-instantiation from the cached `ToolPre` vs a
//! cold `Engine` + component compile/link.
//!
//! Shipped warm path (`src/engine.rs`): `prepare` compiles the component and
//! calls `linker.instantiate_pre` (`:81`), stored as `PreparedTool { tool_pre }`
//! (`:160-161`); each call re-instantiates via `tool_pre.instantiate_async`
//! (`:286-289`). `PreparedTool.tool_pre` is private and there is deliberately no
//! public instantiate-only API, so the warm iteration goes through
//! `SandboxEngine::execute` — `build_store` + `instantiate_async` + the WIT `run`
//! export. The median therefore includes echo's `run`, which is an identity copy
//! of the input; see `benches/results/cell_and_audit.md`.
//!
//! Cold is `SandboxEngine::new()` + `prepare` per iteration and never calls
//! `execute`, so it measures engine construction plus compile/link rather than
//! instantiation from a warm cache.
//!
//! Targets (Execution Report §7): warm < 0.5 ms, cold < 5 ms.

use std::hint::black_box;

use botzr_aegis_core::{CapabilityGrant, ToolId};
use botzr_aegis_sandbox::SandboxEngine;
use criterion::{criterion_group, criterion_main, Criterion};

/// The real WIT `tool` world component (`export run: func(list<u8>) -> ...`),
/// the same fixture the runtime E2E test loads. WAT fixtures are deliberately
/// not used here: they go through the raw-component fixture API, which is not
/// the production `PreparedTool` path this bench claims numbers for.
const ECHO: &[u8] = include_bytes!("../../../tests/fixtures/echo-tool/echo.wasm");

/// Minimal grant, same shape as `tests/sandbox.rs:10-21`. Echo touches no files,
/// so there are no preopens; caps are generous so nothing trips mid-measurement.
fn grant() -> CapabilityGrant {
    CapabilityGrant {
        grant_id: "bench-grant".to_string(),
        tool_id: ToolId::new("echo"),
        fs: None,
        net: None,
        max_memory_bytes: 64 << 20,
        max_wall_ms: 10_000,
        max_output_bytes: 1 << 20,
    }
}

fn instantiation(c: &mut Criterion) {
    let mut group = c.benchmark_group("instantiation");

    // --- warm: compile once outside the loop, re-instantiate per iteration ---
    {
        let engine = SandboxEngine::new().expect("engine");
        let prepared = engine.prepare(ECHO).expect("prepare echo");
        let grant = grant();

        // Setup-time only: a broken fixture must fail loudly here rather than be
        // timed as a fast error path.
        let probe = engine.execute(&prepared, &grant, b"ping");
        assert_eq!(
            probe.output.expect("warm probe must succeed"),
            b"ping".to_vec(),
            "echo fixture must round-trip its input"
        );

        group.bench_function("warm", |b| {
            b.iter(|| black_box(engine.execute(&prepared, &grant, b"ping")));
        });
    }

    // --- cold: fresh engine + compile/link each iteration, no execute ---
    group.bench_function("cold", |b| {
        b.iter(|| {
            let engine = SandboxEngine::new().expect("engine");
            black_box(engine.prepare(ECHO).expect("prepare echo"))
        });
    });

    // --- attribution for the cold median: informational, no target ---
    //
    // `cold` overshoots §7's 5 ms target, and an amendment that blames compile
    // cost needs a measurement behind it rather than an assertion. These two
    // split the cold group: engine construction (config + linker + epoch ticker
    // spawn, and the ticker join that `Drop` pays) against component
    // compile/link on an already-built engine.
    group.bench_function("cold_engine_only", |b| {
        b.iter(|| black_box(SandboxEngine::new().expect("engine")));
    });
    {
        let engine = SandboxEngine::new().expect("engine");
        group.bench_function("cold_compile_only", |b| {
            b.iter(|| black_box(engine.prepare(ECHO).expect("prepare echo")));
        });
    }

    group.finish();
}

criterion_group!(benches, instantiation);
criterion_main!(benches);
