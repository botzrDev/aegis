//! AILAB-602 stress suite — audit exactly-once under concurrency.
//!
//! One shared `Runtime`, ≥1,000 calls issued concurrently across every outcome
//! class, then the exactly-once audit contract asserted by set equality on the
//! JSONL sink: per call exactly one intent and one outcome, call-id sets
//! identical and gap-free (`call-1..call-N`), every outcome parses as frozen
//! schema v1, and each class lands its expected `execution.status` for its own
//! tool id. No timing assertions — statuses and set equality only.

use std::collections::{HashMap, HashSet};

use botzr_aegis_audit::AuditWriter;
use botzr_aegis_capability::{ToolInfo, ToolKind, ToolLimits, ToolManifest};
use botzr_aegis_core::{
    AegisError, AuditRecord, CapabilityOutcome, ExecutionOutcome, PolicyOutcome, ToolId,
};
use botzr_aegis_policy::{PolicyEngine, PolicyRequest};
use botzr_aegis_runtime::{HostCallRequest, HostHandler, Runtime, ToolExecutable};

/// LOAD-BEARING: the whole suite drives one `Runtime` by `&self` from many
/// threads. If this stops compiling, the pipeline lost thread safety — STOP
/// and report; do not wrap `Runtime` in a Mutex (that serializes the calls
/// and voids the test).
const ASSERT_RUNTIME_IS_SYNC: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Runtime>();
};

// Component fixtures — tiny WAT, no `wasm32-wasip2` toolchain required
// (deny-suite precedent).

/// Empty guest; the success class.
const NOOP: &str = r#"
(component
  (core module $m (func (export "go")))
  (core instance $i (instantiate $m))
  (func (export "go") (canon lift (core func $i "go"))))
"#;

/// Never yields the CPU — trips the wall-clock epoch deadline.
const SPIN: &str = r#"
(component
  (core module $m
    (func (export "spin") (loop br 0)))
  (core instance $i (instantiate $m))
  (func (export "spin") (canon lift (core func $i "spin"))))
"#;

/// Grows past the memory cap (denied → -1), then stores past its actual linear
/// memory, trapping out-of-bounds. Classified as `resource_exceeded{memory}`.
const GROW_TOUCH: &str = r#"
(component
  (core module $m
    (memory 1)
    (func (export "grow_touch")
      (drop (memory.grow (i32.const 1000)))
      (i32.store (i32.const 5000000) (i32.const 1))))
  (core instance $i (instantiate $m))
  (func (export "grow-touch") (canon lift (core func $i "grow_touch"))))
"#;

/// Executes `unreachable` — the guest-trap class.
const BOOM: &str = r#"
(component
  (core module $m (func (export "boom") unreachable))
  (core instance $i (instantiate $m))
  (func (export "boom") (canon lift (core func $i "boom"))))
"#;

/// `denied-tool` and `gated-tool` exist only here; `ghost` is registered
/// nowhere at all (the capability-denied class).
const POLICY_YAML: &str = r#"
version: 1
default: allow
rules:
  - id: block-denied
    action: deny
    tool: denied-tool
    reason: "blocked in stress-suite"
  - id: gate-gated
    action: pending_approval
    tool: gated-tool
"#;

/// One outcome class per tool id — attribution in the sink is by `tool_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Model A success (`noop`).
    Success,
    /// Station 1 deny (`denied-tool`).
    PolicyDenied,
    /// Station 1 approval gate (`gated-tool`) — spec §3.D optional class.
    PendingApproval,
    /// Unregistered tool (`ghost`).
    CapabilityDenied,
    /// Guest executes `unreachable` (`boom`).
    GuestTrap,
    /// `spin` under a 50 ms wall cap.
    WallClock,
    /// `grow-touch` under a 128 KiB memory cap.
    Memory,
    /// Model B success (`host-echo`) — spec §3.D optional class.
    HostEcho,
    /// Model B handler that panics (`panic-host`); one scoped thread per call.
    HostPanic,
}

/// Default per-class counts (scaled by `AEGIS_STRESS_MULTIPLIER`); total 1,100.
/// Spin/grow are the expensive classes and stay smallest.
const CLASS_MIX: &[(Class, usize)] = &[
    (Class::Success, 400),
    (Class::PolicyDenied, 200),
    (Class::CapabilityDenied, 200),
    (Class::GuestTrap, 100),
    (Class::PendingApproval, 50),
    (Class::HostEcho, 50),
    (Class::HostPanic, 50),
    (Class::WallClock, 25),
    (Class::Memory, 25),
];

const WORKERS: usize = 16;

fn tool_id_for(class: Class) -> &'static str {
    match class {
        Class::Success => "noop",
        Class::PolicyDenied => "denied-tool",
        Class::PendingApproval => "gated-tool",
        Class::CapabilityDenied => "ghost",
        Class::GuestTrap => "boom",
        Class::WallClock => "spin",
        Class::Memory => "grow-touch",
        Class::HostEcho => "host-echo",
        Class::HostPanic => "panic-host",
    }
}

fn wasm_info(id: &str) -> ToolInfo {
    ToolInfo {
        id: ToolId::new(id),
        version: "0.1.0".into(),
        kind: ToolKind::Wasm,
    }
}

fn host_info(id: &str) -> ToolInfo {
    ToolInfo {
        id: ToolId::new(id),
        version: "0.1.0".into(),
        kind: ToolKind::Host,
    }
}

/// Deterministic round-robin interleave across classes — no RNG.
fn round_robin(counts: &[(Class, usize)]) -> Vec<Class> {
    let mut remaining: Vec<(Class, usize)> = counts.to_vec();
    let total: usize = remaining.iter().map(|(_, n)| n).sum();
    let mut plan = Vec::with_capacity(total);
    while plan.len() < total {
        for entry in &mut remaining {
            if entry.1 > 0 {
                entry.1 -= 1;
                plan.push(entry.0);
            }
        }
    }
    plan
}

/// Issue one non-panic call and assert the caller-visible error variant.
/// Statuses only — never timing.
fn run_call(rt: &Runtime, class: Class) {
    match class {
        Class::Success => {
            let out = rt.execute_tool_call(ToolId::new("noop"), b"{}");
            assert!(out.is_ok(), "noop must succeed: {out:?}");
        }
        Class::PolicyDenied => {
            let err = rt
                .execute_tool_call(ToolId::new("denied-tool"), b"{}")
                .unwrap_err();
            assert!(
                matches!(err, AegisError::PolicyDenied { .. }),
                "denied-tool: expected PolicyDenied, got {err:?}"
            );
        }
        Class::PendingApproval => {
            let err = rt
                .execute_tool_call(ToolId::new("gated-tool"), b"{}")
                .unwrap_err();
            assert!(
                matches!(err, AegisError::PendingApproval { .. }),
                "gated-tool: expected PendingApproval, got {err:?}"
            );
        }
        Class::CapabilityDenied => {
            let err = rt
                .execute_tool_call(ToolId::new("ghost"), b"{}")
                .unwrap_err();
            assert!(
                matches!(err, AegisError::CapabilityDenied { .. }),
                "ghost: expected CapabilityDenied, got {err:?}"
            );
        }
        Class::GuestTrap => {
            let err = rt
                .execute_tool_call(ToolId::new("boom"), b"{}")
                .unwrap_err();
            assert!(
                matches!(err, AegisError::Trap { .. }),
                "boom: expected Trap, got {err:?}"
            );
        }
        Class::WallClock => {
            let err = rt
                .execute_tool_call(ToolId::new("spin"), b"{}")
                .unwrap_err();
            assert!(
                matches!(err, AegisError::ResourceExceeded { ref kind } if kind == "wall_clock"),
                "spin: expected ResourceExceeded(wall_clock), got {err:?}"
            );
        }
        Class::Memory => {
            let err = rt
                .execute_tool_call(ToolId::new("grow-touch"), b"{}")
                .unwrap_err();
            assert!(
                matches!(err, AegisError::ResourceExceeded { ref kind } if kind == "memory"),
                "grow-touch: expected ResourceExceeded(memory), got {err:?}"
            );
        }
        Class::HostEcho => {
            let tool = ToolId::new("host-echo");
            let out = rt.execute_host_call(HostCallRequest::new(
                tool.clone(),
                b"{}",
                PolicyRequest::for_tool(&tool),
            ));
            assert!(out.is_ok(), "host-echo must succeed: {out:?}");
        }
        Class::HostPanic => unreachable!("panic class runs on its own scoped thread"),
    }
}

/// Assert the audited outcome record matches its class (spec fact 8).
fn assert_class_outcome(class: Class, record: &AuditRecord) {
    let id = tool_id_for(class);
    match class {
        Class::Success | Class::HostEcho => assert!(
            matches!(record.execution, ExecutionOutcome::Success),
            "{id}: expected success, got {:?}",
            record.execution
        ),
        Class::PolicyDenied => {
            assert!(
                matches!(record.policy, PolicyOutcome::Denied { .. }),
                "{id}: expected policy denied, got {:?}",
                record.policy
            );
            assert!(
                matches!(record.capability, CapabilityOutcome::Denied { .. }),
                "{id}: a denied call must never mint a grant, got {:?}",
                record.capability
            );
            assert!(
                matches!(record.execution, ExecutionOutcome::HostDenied { .. }),
                "{id}: expected host_denied, got {:?}",
                record.execution
            );
        }
        Class::PendingApproval => {
            assert!(
                matches!(record.policy, PolicyOutcome::PendingApproval { .. }),
                "{id}: expected pending_approval, got {:?}",
                record.policy
            );
            assert!(
                matches!(record.capability, CapabilityOutcome::Denied { .. }),
                "{id}: a gated call must never mint a grant, got {:?}",
                record.capability
            );
            assert!(
                matches!(record.execution, ExecutionOutcome::HostDenied { .. }),
                "{id}: expected host_denied, got {:?}",
                record.execution
            );
        }
        Class::CapabilityDenied => {
            match &record.capability {
                CapabilityOutcome::Denied {
                    denied_capability, ..
                } => assert_eq!(
                    denied_capability.as_deref(),
                    Some("tool.registry"),
                    "{id}: wrong denied capability axis"
                ),
                other => panic!("{id}: expected capability denial, got {other:?}"),
            }
            assert!(
                matches!(record.execution, ExecutionOutcome::HostDenied { .. }),
                "{id}: expected host_denied, got {:?}",
                record.execution
            );
        }
        Class::GuestTrap => assert!(
            matches!(record.execution, ExecutionOutcome::Trap { .. }),
            "{id}: expected trap, got {:?}",
            record.execution
        ),
        Class::WallClock => match &record.execution {
            ExecutionOutcome::ResourceExceeded { kind } => {
                assert_eq!(kind, "wall_clock", "{id}: wrong resource kind");
            }
            other => panic!("{id}: expected resource_exceeded, got {other:?}"),
        },
        Class::Memory => match &record.execution {
            ExecutionOutcome::ResourceExceeded { kind } => {
                assert_eq!(kind, "memory", "{id}: wrong resource kind");
            }
            other => panic!("{id}: expected resource_exceeded, got {other:?}"),
        },
        Class::HostPanic => match &record.execution {
            ExecutionOutcome::Trap { message } => assert!(
                message.contains("host panic during tool call"),
                "{id}: unexpected trap message: {message}"
            ),
            other => panic!("{id}: expected trap from CallSession::drop, got {other:?}"),
        },
    }
}

/// One big test: nothing else in this binary runs while panic-class threads
/// fire, so the process-global panic machinery stays isolated to this scenario.
#[test]
fn audit_is_exactly_once_under_concurrency() {
    ASSERT_RUNTIME_IS_SYNC();

    let multiplier: usize = std::env::var("AEGIS_STRESS_MULTIPLIER")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .max(1);

    // One Runtime, one dedicated JSONL sink in a tempdir — LOAD-BEARING: a
    // fresh writer means call ids are exactly call-1..call-N for this test.
    let dir = tempfile::tempdir().unwrap();
    let audit = AuditWriter::open(dir.path().join("stress.jsonl")).unwrap();
    let mut rt = Runtime::new()
        .with_policy(PolicyEngine::from_yaml(POLICY_YAML).unwrap())
        .with_audit(audit);

    let base = dir.path();
    rt.register_fixture(
        ToolManifest::new(wasm_info("noop"), base),
        NOOP.as_bytes().to_vec(),
        "go",
    )
    .expect("register noop");
    rt.register_fixture(
        ToolManifest::new(wasm_info("boom"), base),
        BOOM.as_bytes().to_vec(),
        "boom",
    )
    .expect("register boom");
    rt.register_fixture(
        ToolManifest::new(wasm_info("spin"), base).with_limits(ToolLimits {
            max_memory_bytes: 1 << 20,
            max_wall_ms: 50,
            ..ToolLimits::default()
        }),
        SPIN.as_bytes().to_vec(),
        "spin",
    )
    .expect("register spin");
    rt.register_fixture(
        ToolManifest::new(wasm_info("grow-touch"), base).with_limits(ToolLimits {
            max_memory_bytes: 128 * 1024,
            max_wall_ms: 1_000,
            ..ToolLimits::default()
        }),
        GROW_TOUCH.as_bytes().to_vec(),
        "grow-touch",
    )
    .expect("register grow-touch");
    let panic_handler: HostHandler = Box::new(|_ctx, _input| panic!("stress-suite host panic"));
    rt.register_tool(
        ToolManifest::new(host_info("panic-host"), base),
        ToolExecutable::HostHandler(panic_handler),
    )
    .expect("register panic-host");
    let echo_handler: HostHandler = Box::new(|_ctx, input| Ok(input.to_vec()));
    rt.register_tool(
        ToolManifest::new(host_info("host-echo"), base),
        ToolExecutable::HostHandler(echo_handler),
    )
    .expect("register host-echo");

    // Deterministic work plan, interleaved round-robin across classes.
    let counts: Vec<(Class, usize)> = CLASS_MIX
        .iter()
        .map(|&(class, n)| (class, n * multiplier))
        .collect();
    let total: usize = counts.iter().map(|(_, n)| n).sum();
    assert!(total >= 1_000, "suite must issue at least 1,000 calls");
    let (panic_calls, worker_calls): (Vec<Class>, Vec<Class>) = round_robin(&counts)
        .into_iter()
        .partition(|class| *class == Class::HostPanic);

    let rt = &rt;
    std::thread::scope(|s| {
        // Fixed worker pool over the non-panic calls; worker w takes every
        // WORKERS-th entry, preserving the class interleave per worker.
        let worker_calls = &worker_calls;
        for w in 0..WORKERS {
            s.spawn(move || {
                for class in worker_calls.iter().skip(w).step_by(WORKERS) {
                    run_call(rt, *class);
                }
            });
        }
        // Panic class: one scoped thread per call, each explicitly join()ed
        // inside the scope — scope exit re-panics for any panicked thread left
        // to auto-join, which would abort the whole test (spec facts 5–6).
        let handles: Vec<_> = panic_calls
            .iter()
            .map(|_| {
                s.spawn(move || {
                    let tool = ToolId::new("panic-host");
                    let _ = rt.execute_host_call(HostCallRequest::new(
                        tool.clone(),
                        b"{}",
                        PolicyRequest::for_tool(&tool),
                    ));
                })
            })
            .collect();
        for handle in handles {
            assert!(
                handle.join().is_err(),
                "panic-host call must panic its thread"
            );
        }
    });

    // ---- assertions, all on the JSONL sink after the scope joined ----------

    let text = std::fs::read_to_string(rt.audit().path()).expect("audit sink readable");
    let mut intent_lines = 0usize;
    let mut intent_ids: HashSet<String> = HashSet::new();
    let mut outcome_ids: HashSet<String> = HashSet::new();
    let mut outcomes: Vec<AuditRecord> = Vec::new();
    for line in text.lines() {
        // 1 — every line parses as JSON with phase exactly intent | outcome.
        let value: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("unparseable line ({e}): {line}"));
        match value["phase"].as_str() {
            Some("intent") => {
                intent_lines += 1;
                intent_ids.insert(
                    value["call_id"]
                        .as_str()
                        .unwrap_or_else(|| panic!("intent without call_id: {line}"))
                        .to_owned(),
                );
            }
            Some("outcome") => {
                // 4 — LOAD-BEARING: frozen schema v1 straight from core; no
                // hand-rolled record type.
                let record: AuditRecord = serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("outcome is not schema v1 ({e}): {line}"));
                outcome_ids.insert(record.call_id.clone());
                outcomes.push(record);
            }
            other => panic!("unexpected phase {other:?}: {line}"),
        }
    }

    // 2 — one intent and one outcome per call issued.
    assert_eq!(intent_lines, total, "exactly one intent per call");
    assert_eq!(outcomes.len(), total, "exactly one outcome per call");

    // 3 — call-id sets identical and gap-free: set equality, not counting, so
    // a duplicate-plus-gap fails even though the line counts match.
    let expected: HashSet<String> = (1..=total).map(|i| format!("call-{i}")).collect();
    assert_eq!(
        intent_ids, expected,
        "intent ids must be call-1..call-{total}"
    );
    assert_eq!(
        outcome_ids, expected,
        "outcome ids must be call-1..call-{total}"
    );

    // 5 — class attribution by tool id: per-class count + execution variant.
    let mut by_tool: HashMap<String, Vec<&AuditRecord>> = HashMap::new();
    for record in &outcomes {
        by_tool
            .entry(record.tool_id.to_string())
            .or_default()
            .push(record);
    }
    for &(class, count) in &counts {
        let id = tool_id_for(class);
        let records: &[&AuditRecord] = by_tool.get(id).map_or(&[], Vec::as_slice);
        assert_eq!(records.len(), count, "outcome count for {id}");
        for record in records {
            assert_class_outcome(class, record);
        }
    }
    assert_eq!(
        by_tool.len(),
        counts.len(),
        "no stray tool ids in the sink: {:?}",
        by_tool.keys().collect::<Vec<_>>()
    );

    // 6 — fail-closed leak check on the raw lines of every refused tool.
    for line in text.lines() {
        let refused = [
            "\"tool_id\":\"denied-tool\"",
            "\"tool_id\":\"gated-tool\"",
            "\"tool_id\":\"ghost\"",
        ];
        if refused.iter().any(|tag| line.contains(tag)) {
            assert!(
                !line.contains("\"status\":\"success\""),
                "fail-closed leak (success): {line}"
            );
            assert!(
                !line.contains("\"status\":\"granted\""),
                "fail-closed leak (granted): {line}"
            );
        }
        if line.contains("\"tool_id\":\"denied-tool\"") {
            assert!(
                !line.contains("\"status\":\"allowed\""),
                "fail-closed leak (policy allowed): {line}"
            );
        }
    }

    // 7 — one-line class-count summary for the report.
    let per_class: Vec<String> = counts
        .iter()
        .map(|&(class, count)| format!("{}={count}", tool_id_for(class)))
        .collect();
    println!(
        "stress summary: total={total} multiplier={multiplier} {}",
        per_class.join(" ")
    );
}
