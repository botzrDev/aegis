//! One **audited call, end to end** — the number the published component
//! figures do not add up to.
//!
//! `hot_path` measures stations 1–2 and says so; `audit_emission` measures the
//! two-line durable cycle on its own. Neither is the cost of a call, and 2.71 µs
//! plus 4.7185 ms is not either, because a call is not those two things laid
//! end to end. This drives `Runtime::execute_host_call` through all four
//! stations and times the whole thing.
//!
//! **Two arms, one variable.** Both runtimes are built identically — same
//! manifest, same tool, same handler, same allow-all default policy — and
//! differ only in the sink:
//!
//! - `durable_sink`: a `FileChainSink` with a provisioned key. This is the
//!   configuration that retains evidence.
//! - `volatile_sink`: the shipped default, an in-memory Chain that retains
//!   nothing past the process (ADR-0012).
//!
//! The **shape** between them is the output worth reading — two to three orders
//! of magnitude — not any single figure, and not the ratio. Six runs across two
//! sessions established which parts of this group survive re-measurement: the
//! `volatile_sink` absolute is the reproducible one (within 1.14×), while
//! `durable_sink` spans 6.1× and the ratio, inheriting all of that variance
//! through the quotient, is the least stable number the group produces. On this
//! hardware absolutes swing ±20% between runs of identical binaries (see
//! `benches/results/cell_and_audit.md`), and re-measuring on a quiet machine is
//! AILAB-796.
//!
//! A **host handler** is the executable on purpose: a WASM guest would drag
//! wasmtime compilation into a number meant to be about the audited pipeline,
//! and `instantiation/cold` already owns that cost.

use std::hint::black_box;
use std::path::Path;
use std::time::Duration;

use botzr_aegis_audit::{AuditWriter, FileChainSink, SigningKey};
use botzr_aegis_capability::{
    FsNeeds, HttpNeed, NetNeeds, PathNeed, ToolInfo, ToolKind, ToolLimits, ToolManifest,
};
use botzr_aegis_core::ToolId;
use botzr_aegis_policy::CallAxes;
use botzr_aegis_runtime::{HostCallRequest, Runtime, ToolExecutable};
use criterion::{criterion_group, criterion_main, Criterion};

const TOOL: &str = "audited";
/// Small and fixed: the input is digested on every call, and a large one would
/// put SHA-256 throughput into a number about the pipeline.
const INPUT: &[u8] = b"audited-call-bench-input";

/// The same needs shape `hot_path`'s fixture uses, so the mint this call pays
/// for is the one that file's 2.71 µs covers rather than a cheaper stand-in.
fn fixture_manifest(base: &Path) -> ToolManifest {
    ToolManifest::new(
        ToolInfo {
            id: ToolId::new(TOOL),
            version: "0.1.0".into(),
            // `Host` pairs with the `HostHandler` below; a `Wasm` manifest is a
            // `KindMismatch` at registration and would need a sandbox prepare.
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
            ports: vec![443],
            methods: vec!["GET".into()],
        }],
    })
    .with_limits(ToolLimits {
        max_memory_bytes: 1 << 20,
        max_wall_ms: 5_000,
        ..ToolLimits::default()
    })
}

/// A `Runtime` with one registered tool and the given sink. Everything here is
/// setup and none of it is timed: registration, the `SandboxEngine` the
/// `Runtime` constructs, and the writer itself.
fn setup(base: &Path, audit: Option<AuditWriter>) -> Runtime {
    let mut rt = match audit {
        Some(writer) => Runtime::new().with_audit(writer),
        // The default is the Volatile in-memory Chain — not "no audit". Records
        // are still emitted, signed and chained; they are simply not retained.
        None => Runtime::new(),
    };
    rt.register_tool(
        fixture_manifest(base),
        // Identity effect. The handler is deliberately trivial so the median is
        // the pipeline around it rather than the work inside it.
        ToolExecutable::HostHandler(Box::new(|_ctx, input| Ok(input.to_vec()))),
    )
    .expect("register bench tool");
    rt
}

fn audited_call(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("bench tempdir");
    let base = dir.path();
    std::fs::create_dir_all(base.join("fixtures/nested")).expect("fixture dirs");

    let mut group = c.benchmark_group("audited_call");

    // **The volatile sink retains every byte for the life of the process** —
    // `MemoryChainSink` holds an `Arc<Mutex<Vec<u8>>>` and never truncates. At
    // Criterion's defaults the volatile arm would append hundreds of megabytes
    // and start measuring the allocator instead of the pipeline, so the time
    // budget is capped here rather than left implicit. Both arms get the same
    // budget, so the comparison between them is unaffected.
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));
    group.sample_size(20);

    // --- durable: a real file, fsynced per line, signed by a provisioned key ---
    {
        // `dir` outlives `writer` because it is bound first and this block ends
        // before the function does: locals drop in reverse, and removing the
        // directory first would pull the file out from under the sink.
        //
        // A fixed seed, not `insecure_dev_key`: a Durable sink refuses the dev
        // key (ADR-0012), so a bench that wants the retaining configuration has
        // to provision one. `.aarl` is the record extension (ADR-0014).
        let writer = AuditWriter::with_sink(
            Box::new(FileChainSink::open(base.join("audit.aarl")).expect("bench file sink")),
            SigningKey::from_seed([7u8; 32]),
        )
        .expect("bench writer must open");
        let rt = setup(base, Some(writer));
        let tool = ToolId::new(TOOL);
        group.bench_function("durable_sink", |b| {
            b.iter(|| {
                black_box(
                    rt.execute_host_call(HostCallRequest::new(
                        tool.clone(),
                        black_box(INPUT),
                        CallAxes::default(),
                    ))
                    .expect("audited call must succeed"),
                )
            });
        });
    }

    // --- volatile: the shipped default, retaining nothing ---
    {
        let rt = setup(base, None);
        let tool = ToolId::new(TOOL);
        group.bench_function("volatile_sink", |b| {
            b.iter(|| {
                black_box(
                    rt.execute_host_call(HostCallRequest::new(
                        tool.clone(),
                        black_box(INPUT),
                        CallAxes::default(),
                    ))
                    .expect("audited call must succeed"),
                )
            });
        });
    }

    group.finish();
}

criterion_group!(benches, audited_call);
criterion_main!(benches);
