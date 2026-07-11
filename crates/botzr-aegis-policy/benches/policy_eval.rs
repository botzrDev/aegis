//! Criterion benches for the policy hot path — `PolicyEngine::evaluate`.
//!
//! Station 1 of POLICY → CAPABILITY → SANDBOX → AUDIT. YAML is parsed **once**
//! in setup (`from_yaml`), never inside `b.iter`. Primary claim: the
//! `allow_all` and `multi_rule` groups have a median **< 100 µs** on the cited
//! machine (see `benches/README.md`). The `rate_limit` group is informational
//! only — it takes the `RateLimiter` mutex and is not under the <100 µs claim.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};

use botzr_aegis_core::ToolId;
use botzr_aegis_policy::{PolicyEngine, PolicyRequest};

/// Multi-rule set: a broad `*` allow shadowed by a role-gated `writer` allow
/// that carries a ceiling. Lifted from the `most_specific_allow_wins_and_carries_ceiling`
/// test fixture (`policy/src/lib.rs`).
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

/// Rate-limit set from the `rate_limit_trips_after_max` fixture. Evaluation
/// takes the `RateLimiter` mutex on every call, so it lives outside the primary
/// <100 µs claim.
const RATE_LIMIT_YAML: &str = r#"
version: 1
default: allow
rules:
  - id: rl
    action: rate_limit
    tool: chatty
    rate: { max: 2, per_seconds: 60 }
"#;

fn bench_policy_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_eval");

    // allow_all — zero-config engine; policy imposes nothing (runtime default).
    let allow_engine = PolicyEngine::allow_all();
    let allow_tool = ToolId::new("writer");
    group.bench_function("allow_all", |b| {
        b.iter(|| {
            black_box(allow_engine.evaluate(&PolicyRequest::for_tool(&allow_tool)));
        });
    });

    // multi_rule — most-specific role-gated allow that carries a ceiling.
    let multi_engine = PolicyEngine::from_yaml(MULTI_RULE_YAML).expect("multi-rule YAML parses"); // setup
    let writer = ToolId::new("writer");
    group.bench_function("multi_rule", |b| {
        b.iter(|| {
            black_box(multi_engine.evaluate(&PolicyRequest::for_tool(&writer).with_role("owner")));
        });
    });

    // rate_limit — informational only (mutex path); NOT under the <100 µs claim.
    let rate_engine = PolicyEngine::from_yaml(RATE_LIMIT_YAML).expect("rate-limit YAML parses"); // setup
    let chatty = ToolId::new("chatty");
    group.bench_function("rate_limit", |b| {
        b.iter(|| {
            black_box(rate_engine.evaluate(&PolicyRequest::for_tool(&chatty)));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_policy_eval);
criterion_main!(benches);
