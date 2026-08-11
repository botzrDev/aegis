//! Isolated ed25519 signing cost (AILAB-620).
//!
//! **What this is not.** `audit_emission/begin_complete` in `emission.rs` is the
//! whole durable two-line cycle and publishes at **4.7185 ms**, essentially all
//! of it write + fsync latency (`benches/results/cell_and_audit.md`). Signing is
//! one component inside that, and a 50µs figure quoted against the full cycle
//! would be a claim about fsync, not about crypto. So this group measures
//! exactly one thing: `SigningKey::sign` over bytes already in hand.
//!
//! Per iteration: one ed25519 signature over the canonical signing input of a
//! representative `outcome` line. No `AuditWriter`, no file, no fsync, no
//! canonicalization — the signing input is built once, outside the loop, so the
//! median is the signature and nothing else.
//!
//! The key comes from `insecure_dev_key`: signing cost is a property of ed25519,
//! not of which 32 bytes the seed holds, and a fixed seed keeps the bench
//! deterministic. Nothing here reads a key file.

use std::hint::black_box;

use botzr_aegis_audit::{insecure_dev_key, SigningKey};
use botzr_aegis_core::{
    AuditRecord, CallMetrics, CapabilityGrant, CapabilityOutcome, ExecutionOutcome, PolicyOutcome,
    PolicySetHash, PrevHash, RequestDigest, ToolId,
};
use criterion::{criterion_group, criterion_main, Criterion};

/// Same grant shape `emission.rs` uses, so the signed bytes are representative
/// in size rather than a minimal record that flatters the number.
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

/// The canonical bytes a signed `outcome` line actually covers: the JCS form of
/// the record with `signature` absent and `key_id` present (ADR-0003).
fn outcome_signing_input(key: &SigningKey) -> String {
    let mut record = AuditRecord::new(
        "call-1".to_string(),
        ToolId::new("echo"),
        RequestDigest::of_request_bytes(b"abc123"),
        PolicySetHash::of_canonical_bytes(b"policy"),
        PolicyOutcome::Allowed,
        CapabilityOutcome::Granted { grant: grant() },
        ExecutionOutcome::Success,
    )
    .with_metrics(CallMetrics {
        wall_ms: 1,
        peak_memory_bytes: 1 << 16,
    });
    record.stamp_chain(4, PrevHash::of_line(b"prev"));
    record
        .signing_input(&key.key_id())
        .expect("record canonicalizes")
}

fn signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_signing");

    let key = insecure_dev_key();
    let signing_input = outcome_signing_input(&key);

    group.bench_function("sign_outcome_line", |b| {
        b.iter(|| black_box(&key).sign(black_box(signing_input.as_bytes())));
    });

    group.finish();
}

criterion_group!(benches, signing);
criterion_main!(benches);
