//! Audit record emission: one `CallSession` begin → complete cycle against a
//! real `AuditWriter`.
//!
//! One cycle ships **two** JSONL lines — `intent` from `CallSession::begin`
//! and `outcome` from `complete` — so the measured cycle includes two
//! `sync_all` calls. That fsync-per-line is the shipped G3 durability shape and
//! is deliberately not stripped for the bench.
//!
//! **Schema v2 caveat (AILAB-619):** each line now also carries JCS
//! canonicalization plus a chain hash, and the outcome line an ed25519
//! signature, all inside the writer lock. The published median in
//! `benches/results/cell_and_audit.md` predates that work and has not been
//! re-measured here.
//!
//! One writer is reused across iterations so `TempDir` creation is not timed;
//! the JSONL file grows for the length of the run, which is what a real
//! long-lived sink does.

use std::hint::black_box;

use botzr_aegis_audit::{to_json_line, AuditWriter, CallSession, FileChainSink, SigningKey};
use botzr_aegis_core::{
    AuditIntent, AuditRecord, CallMetrics, CapabilityGrant, CapabilityOutcome, ExecutionOutcome,
    PolicyOutcome, PolicySetHash, RequestDigest, ToolId,
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
    let mut session = CallSession::begin(
        writer,
        ToolId::new("echo"),
        RequestDigest::of_request_bytes(b"abc123"),
        PolicySetHash::of_canonical_bytes(b"policy"),
    )
    .expect("begin must succeed on the bench's file sink");
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
        RequestDigest::of_request_bytes(b"abc123"),
    );
    let record = AuditRecord::new(
        "call-1".to_string(),
        ToolId::new("echo"),
        RequestDigest::of_request_bytes(b"abc123"),
        PolicySetHash::of_canonical_bytes(b"policy"),
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

    // A **Durable** file sink, named explicitly, and never an in-memory one:
    // `begin_complete` exists to measure the fsync-per-line path, so timing a
    // buffer append and calling the result an audit emission cost would publish
    // a number for work the shipped sink does not do. A Durable sink refuses
    // `insecure_dev_key` (ADR-0012), hence the fixed provisioned seed.
    //
    // `dir` is bound before `writer` so it outlives it: locals drop in reverse,
    // and removing the directory first would pull the file out from under the
    // sink the `Close` line is still being written to.
    let dir = tempfile::tempdir().expect("bench tempdir");
    let writer = AuditWriter::with_sink(
        Box::new(FileChainSink::open(dir.path().join("audit.jsonl")).expect("bench file sink")),
        SigningKey::from_seed([7u8; 32]),
    )
    .expect("bench writer must open");
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
