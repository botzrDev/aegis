//! Audit record emission: one `CallSession` begin → complete cycle against a
//! real `AuditWriter`.
//!
//! One cycle ships **two** JSONL lines — `intent` from `CallSession::begin`
//! (`src/session.rs:33`) and `outcome` from `complete` (`src/session.rs:91`) —
//! so the measured cycle includes two `sync_all` calls (`src/writer.rs:74`).
//! That fsync-per-line is the shipped G3 durability shape and is deliberately
//! not stripped for the bench.
//!
//! One writer is reused across iterations so `TempDir` creation is not timed;
//! the JSONL file grows for the length of the run, which is what a real
//! long-lived sink does.

use std::hint::black_box;

use botzr_aegis_audit::{to_json_line, AuditWriter, CallSession};
use botzr_aegis_core::{
    AuditIntent, AuditRecord, CallMetrics, CapabilityGrant, CapabilityOutcome, ExecutionOutcome,
    PolicyOutcome, ToolId,
};
use criterion::{criterion_group, criterion_main, Criterion};

/// Grant recorded on the `granted` capability line — same shape the sandbox
/// tests use, so the serialized outcome record is representative in size.
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

/// Mirrors the allowed-and-executed path in `runtime/src/pipeline.rs:105-149`:
/// policy allowed → capability granted → execution success with metrics.
fn emit_cycle(writer: &AuditWriter, grant: &CapabilityGrant) {
    let mut session = CallSession::begin(writer, ToolId::new("echo"), "abc123")
        .expect("begin must succeed on a temp sink");
    session.set_policy(PolicyOutcome::Allowed);
    session.set_capability(CapabilityOutcome::Granted {
        grant: grant.clone(),
    });
    session.set_execution(ExecutionOutcome::Success);
    session.set_metrics(CallMetrics {
        wall_ms: 1,
        peak_memory_bytes: 1 << 16,
    });
    session.complete().expect("complete must succeed");
}

/// Both lines of one cycle serialized, with no file write and no fsync — the
/// serde half of `begin_complete` in isolation. Uses the already-public
/// `to_json_line`; no API was added for this.
fn serialize_cycle(grant: &CapabilityGrant) {
    let intent = AuditIntent::new(
        "call-1".to_string(),
        ToolId::new("echo"),
        "abc123".to_string(),
    );
    let record = AuditRecord::new(
        "call-1".to_string(),
        ToolId::new("echo"),
        "abc123".to_string(),
        PolicyOutcome::Allowed,
        CapabilityOutcome::Granted {
            grant: grant.clone(),
        },
        ExecutionOutcome::Success,
    )
    .with_metrics(CallMetrics {
        wall_ms: 1,
        peak_memory_bytes: 1 << 16,
    });
    black_box(to_json_line(&intent).expect("intent serializes"));
    black_box(to_json_line(&record).expect("record serializes"));
}

fn emission(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_emission");

    let writer = AuditWriter::open_temp().expect("temp audit sink");
    let grant = grant();

    group.bench_function("begin_complete", |b| {
        b.iter(|| emit_cycle(black_box(&writer), black_box(&grant)));
    });

    // Attribution for `begin_complete`: informational, no target. Claiming the
    // median is fsync-bound rather than serialization-bound needs a measurement
    // behind it, not an assertion — same standard the sandbox cold splits meet.
    group.bench_function("serialize_only", |b| {
        b.iter(|| serialize_cycle(black_box(&grant)));
    });

    group.finish();
}

criterion_group!(benches, emission);
criterion_main!(benches);
