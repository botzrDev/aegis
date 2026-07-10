//! Criterion benches for `PolicyEngine::evaluate` (library-mode station 1).
//!
//! Targets: `allow_all` and `multi_rule` median < 100 µs.
//! `rate_limit` is informational only (mutex path) — no hard gate.

use std::hint::black_box;

use botzr_aegis_core::ToolId;
use botzr_aegis_policy::{PolicyEngine, PolicyRequest};
use criterion::{criterion_group, criterion_main, Criterion};

/// Multi-rule set from `policy/src/lib.rs` test
/// `most_specific_allow_wins_and_carries_ceiling` (setup only — never in iter).
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

/// Rate-limit YAML from `policy/src/lib.rs` test `rate_limit_trips_after_max`.
const RATE_LIMIT_YAML: &str = r#"
version: 1
default: allow
rules:
  - id: rl
    action: rate_limit
    tool: chatty
    rate: { max: 2, per_seconds: 60 }
"#;

fn policy_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_eval");

    // --- allow_all ---
    {
        let engine = PolicyEngine::allow_all();
        let tool = ToolId::new("any-tool");
        group.bench_function("allow_all", |b| {
            b.iter(|| {
                black_box(engine.evaluate(&PolicyRequest::for_tool(&tool)));
            });
        });
    }

    // --- multi_rule (publishable <100 µs claim) ---
    {
        let engine = PolicyEngine::from_yaml(MULTI_RULE_YAML).expect("multi-rule yaml"); // setup
        let tool = ToolId::new("writer");
        group.bench_function("multi_rule", |b| {
            b.iter(|| {
                black_box(engine.evaluate(&PolicyRequest::for_tool(&tool).with_role("owner")));
            });
        });
    }

    // --- rate_limit (informational — mutex path; not under <100 µs gate) ---
    {
        let engine = PolicyEngine::from_yaml(RATE_LIMIT_YAML).expect("rate-limit yaml"); // setup
        let tool = ToolId::new("chatty");
        group.bench_function("rate_limit", |b| {
            b.iter(|| {
                // Evaluate under the rate-limit rule path (Mutex bump).
                // Window may trip after max; still measures mutex-backed check.
                black_box(engine.evaluate(&PolicyRequest::for_tool(&tool)));
            });
        });
    }

    group.finish();
}

criterion_group!(benches, policy_eval);
criterion_main!(benches);
