//! AEG-8 deny-suite — adversarial cases driven through the full enforcement
//! pipeline (POLICY → CAPABILITY → SANDBOX → AUDIT).
//!
//! Each case asserts two things a research instrument must guarantee:
//!   1. the call is *refused* (default-deny holds on every axis), and
//!   2. the refusal is *accounted for* — an intent line plus an outcome line
//!      with the correct `execution.status`, on every exit path.
//!
//! Coverage map:
//!   * policy deny / pending-approval  — station 1 short-circuits before a grant
//!   * capability deny                 — unregistered tool, bad fs need, bad net need
//!   * resource caps                   — wall-clock (SPIN) and memory (GROW_TOUCH)
//!   * delegation                      — `narrow_grant` refuses limit escalation
//!
//! Two adversarial paths that required a compiled WIT guest are now covered by
//! `tests/adversarial-demo/` (AEG-22 / damage-bot):
//!   * guest fs write + path containment (`..`, symlink)
//!   * guest http import through `Runtime::execute_tool_call` (Model B)

use botzr_aegis_audit::to_json_line;
use botzr_aegis_capability::{
    mint_grant, narrow_grant, CapabilityError, FsNeeds, HttpNeed, NetNeeds, PathNeed,
    PolicyCeiling, ToolInfo, ToolKind, ToolLimits, ToolManifest,
};
use botzr_aegis_core::{AuditRecord, CapabilityOutcome, ExecutionOutcome, PolicyOutcome, ToolId};
use botzr_aegis_policy::PolicyEngine;
use botzr_aegis_runtime::Runtime;

// Component fixtures — tiny WAT, no `wasm32-wasip2` toolchain required.

/// Empty guest; never actually executed in the capability-deny cases (the
/// resolver refuses before the sandbox is reached), but registration compiles it.
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

// ---- helpers ---------------------------------------------------------------

fn info(id: &str) -> ToolInfo {
    ToolInfo {
        id: ToolId::new(id),
        version: "0.1.0".into(),
        kind: ToolKind::Wasm,
    }
}

/// Read the audit JSONL, assert the two-phase shape, and return the outcome.
fn outcome(rt: &Runtime) -> AuditRecord {
    let lines: Vec<String> = std::fs::read_to_string(rt.audit().path())
        .expect("audit readable")
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(lines.len(), 2, "each call writes exactly intent + outcome");
    assert!(
        lines[0].contains("\"phase\":\"intent\""),
        "first line is the intent: {}",
        lines[0]
    );
    assert!(
        lines[1].contains("\"phase\":\"outcome\""),
        "second line is the outcome: {}",
        lines[1]
    );
    serde_json::from_str(&lines[1]).expect("outcome parses")
}

/// Compare a (normalized) record to a checked-in golden line — locks the frozen
/// audit schema v1 shape (supports the OQ-6 freeze, AEG-21).
fn assert_golden(record: &AuditRecord, golden: &str) {
    let actual = to_json_line(record).expect("serialize outcome");
    assert_eq!(actual.trim(), golden.trim());
}

/// Pin the sequential grant id so the granted-path golden is stable under
/// parallel test execution (the resolver's grant counter is process-wide).
fn pin_grant_id(record: &mut AuditRecord, grant_id: &str) {
    if let CapabilityOutcome::Granted { ref mut grant } = record.capability {
        grant.grant_id = grant_id.into();
    }
}

// ---- POLICY station (station 1 short-circuits before any grant) ------------

#[test]
fn policy_deny_is_refused_and_audited() {
    let yaml = r#"
version: 1
default: allow
rules:
  - id: block-exfil
    action: deny
    tool: exfil
    reason: "blocked in deny-suite"
"#;
    let rt = Runtime::new().with_policy(PolicyEngine::from_yaml(yaml).unwrap());
    let err = rt
        .execute_tool_call(ToolId::new("exfil"), "11111111".into(), b"{}")
        .unwrap_err();
    assert_eq!(err, "policy denied: blocked in deny-suite");

    let mut record = outcome(&rt);
    assert!(matches!(record.policy, PolicyOutcome::Denied { .. }));
    // A denied call never mints a grant.
    assert!(matches!(
        record.capability,
        CapabilityOutcome::Denied { .. }
    ));
    assert!(matches!(
        record.execution,
        ExecutionOutcome::HostDenied { .. }
    ));

    record.call_id = "call-golden-policy-deny".into();
    assert_golden(&record, include_str!("golden/policy_deny.json"));
}

#[test]
fn pending_approval_is_refused_before_capability() {
    let yaml = r#"
version: 1
default: allow
rules:
  - id: gate-transfer
    action: pending_approval
    tool: transfer
"#;
    let rt = Runtime::new().with_policy(PolicyEngine::from_yaml(yaml).unwrap());
    let err = rt
        .execute_tool_call(ToolId::new("transfer"), "aaaaaaaa".into(), b"{}")
        .unwrap_err();
    assert!(
        err.starts_with("policy pending approval:"),
        "unexpected error: {err}"
    );

    let record = outcome(&rt);
    assert!(matches!(
        record.policy,
        PolicyOutcome::PendingApproval { .. }
    ));
    assert!(matches!(
        record.capability,
        CapabilityOutcome::Denied { .. }
    ));
    assert!(matches!(
        record.execution,
        ExecutionOutcome::HostDenied { .. }
    ));
}

// ---- CAPABILITY station (default-deny grant minting) -----------------------

#[test]
fn unregistered_tool_is_capability_denied() {
    // allow-all policy, but the tool was never registered with the resolver.
    let rt = Runtime::new();
    let err = rt
        .execute_tool_call(ToolId::new("ghost"), "22222222".into(), b"{}")
        .unwrap_err();
    assert_eq!(err, "execution failed");

    let mut record = outcome(&rt);
    assert!(matches!(record.policy, PolicyOutcome::Allowed));
    match &record.capability {
        CapabilityOutcome::Denied {
            denied_capability, ..
        } => assert_eq!(denied_capability.as_deref(), Some("tool.registry")),
        other => panic!("expected capability denial, got {other:?}"),
    }
    assert!(matches!(
        record.execution,
        ExecutionOutcome::HostDenied { .. }
    ));

    record.call_id = "call-golden-cap-unregistered".into();
    assert_golden(&record, include_str!("golden/capability_unregistered.json"));
}

#[test]
fn unresolvable_fs_need_is_capability_denied() {
    // The manifest declares a read path that does not resolve under its base —
    // the default-deny resolver refuses it rather than silently granting.
    let base = tempfile::tempdir().unwrap();
    let manifest = ToolManifest::new(info("fs-reader"), base.path()).with_fs(FsNeeds {
        read: vec![PathNeed::new("no-such-subdir")],
        write: vec![],
    });

    let mut rt = Runtime::new();
    rt.capabilities().register(manifest);
    let err = rt
        .execute_tool_call(ToolId::new("fs-reader"), "55555555".into(), b"{}")
        .unwrap_err();
    assert_eq!(err, "execution failed");

    let record = outcome(&rt);
    match &record.capability {
        CapabilityOutcome::Denied {
            reason,
            denied_capability,
        } => {
            assert_eq!(denied_capability.as_deref(), Some("fs"));
            assert!(reason.contains("invalid path"), "{reason}");
        }
        other => panic!("expected fs capability denial, got {other:?}"),
    }
    assert!(matches!(
        record.execution,
        ExecutionOutcome::HostDenied { .. }
    ));
    // Reason carries a platform-specific OS error, so this case asserts shape
    // rather than a golden byte-for-byte.
}

#[test]
fn wildcard_net_need_is_capability_denied() {
    let base = tempfile::tempdir().unwrap();
    let manifest = ToolManifest::new(info("net-wildcard"), base.path()).with_net(NetNeeds {
        http: vec![HttpNeed {
            host: "*.evil.example.com".into(),
            ports: vec![443],
            methods: vec!["GET".into()],
        }],
    });

    let mut rt = Runtime::new();
    rt.capabilities().register(manifest);
    let err = rt
        .execute_tool_call(ToolId::new("net-wildcard"), "33333333".into(), b"{}")
        .unwrap_err();
    assert_eq!(err, "execution failed");

    let mut record = outcome(&rt);
    match &record.capability {
        CapabilityOutcome::Denied {
            denied_capability, ..
        } => assert_eq!(denied_capability.as_deref(), Some("net.http")),
        other => panic!("expected net capability denial, got {other:?}"),
    }
    assert!(matches!(
        record.execution,
        ExecutionOutcome::HostDenied { .. }
    ));

    record.call_id = "call-golden-cap-net".into();
    assert_golden(&record, include_str!("golden/capability_net_denied.json"));
}

// ---- SANDBOX station (resource caps trip and are labeled honestly) ---------

#[test]
fn wall_clock_cap_trips_through_pipeline() {
    let base = tempfile::tempdir().unwrap();
    let manifest = ToolManifest::new(info("spin"), base.path()).with_limits(ToolLimits {
        max_memory_bytes: 1 << 20,
        max_wall_ms: 50,
    });

    let mut rt = Runtime::new();
    rt.register_fixture(manifest, SPIN.as_bytes().to_vec(), "spin")
        .expect("register spin fixture");
    let err = rt
        .execute_tool_call(ToolId::new("spin"), "66666666".into(), b"{}")
        .unwrap_err();
    assert_eq!(err, "execution failed");

    let record = outcome(&rt);
    assert!(matches!(record.policy, PolicyOutcome::Allowed));
    assert!(matches!(
        record.capability,
        CapabilityOutcome::Granted { .. }
    ));
    match &record.execution {
        ExecutionOutcome::ResourceExceeded { kind } => assert_eq!(kind, "wall_clock"),
        other => panic!("expected wall_clock resource_exceeded, got {other:?}"),
    }
    let wall_ms = record.wall_ms.expect("wall_ms recorded");
    assert!(wall_ms >= 40, "wall_ms={wall_ms}");
}

#[test]
fn memory_cap_trips_through_pipeline() {
    let base = tempfile::tempdir().unwrap();
    let manifest = ToolManifest::new(info("grow-touch"), base.path()).with_limits(ToolLimits {
        max_memory_bytes: 128 * 1024,
        max_wall_ms: 1_000,
    });

    let mut rt = Runtime::new();
    rt.register_fixture(manifest, GROW_TOUCH.as_bytes().to_vec(), "grow-touch")
        .expect("register grow-touch fixture");
    let err = rt
        .execute_tool_call(ToolId::new("grow-touch"), "44444444".into(), b"{}")
        .unwrap_err();
    assert_eq!(err, "execution failed");

    let mut record = outcome(&rt);
    assert!(matches!(
        record.capability,
        CapabilityOutcome::Granted { .. }
    ));
    match &record.execution {
        ExecutionOutcome::ResourceExceeded { kind } => assert_eq!(kind, "memory"),
        other => panic!("expected memory resource_exceeded, got {other:?}"),
    }
    assert!(record.wall_ms.is_some());
    assert!(record.peak_memory_bytes.is_some());

    // Normalize volatile fields for the schema golden (grant counter, timing).
    record.call_id = "call-golden-mem".into();
    pin_grant_id(&mut record, "grow-touch-1");
    record.wall_ms = Some(1);
    record.peak_memory_bytes = Some(131072);
    assert_golden(&record, include_str!("golden/resource_memory.json"));
}

// ---- DELEGATION (narrowing refuses escalation) -----------------------------

#[test]
fn narrowing_refuses_limit_escalation() {
    // R2 delegation invariant: a sub-tool grant is a strict subset of its
    // parent. Raising a resource ceiling is a hard error, not a silent widening.
    let base = tempfile::tempdir().unwrap();
    let parent_manifest = ToolManifest::new(info("parent"), base.path()).with_limits(ToolLimits {
        max_memory_bytes: 1 << 20,
        max_wall_ms: 1_000,
    });
    let parent_grant =
        mint_grant(&parent_manifest, "parent-1", PolicyCeiling::default()).expect("parent mints");

    let sub_manifest = ToolManifest::new(info("child"), base.path()).with_limits(ToolLimits {
        max_memory_bytes: 1 << 21, // 2 MiB — above the parent's 1 MiB
        max_wall_ms: 1_000,
    });

    let err = narrow_grant(
        &parent_grant,
        &parent_manifest,
        &sub_manifest,
        "child-1",
        PolicyCeiling::default(),
    )
    .expect_err("raising the memory ceiling must be refused");
    assert!(matches!(err, CapabilityError::Escalation { .. }), "{err:?}");
}

/// Compile-touch of the NOOP fixture so an unused-const lint never masks a
/// future granted-path case that needs it.
#[test]
fn noop_fixture_registers() {
    let base = tempfile::tempdir().unwrap();
    let manifest = ToolManifest::new(info("noop"), base.path());
    let mut rt = Runtime::new();
    rt.register_fixture(manifest, NOOP.as_bytes().to_vec(), "go")
        .expect("noop fixture registers");
}
