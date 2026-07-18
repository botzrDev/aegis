//! Golden snapshot tests — schema drift fails CI, not Layer 2 in production (OQ-6).

use botzr_aegis_audit::to_json_line;
use botzr_aegis_core::{
    AuditRecord, CapabilityGrant, CapabilityOutcome, ExecutionOutcome, FsGrant, HttpGrant,
    NetGrant, PolicyOutcome, ToolId,
};

fn fixture_grant() -> CapabilityGrant {
    CapabilityGrant {
        grant_id: "reader-1".into(),
        tool_id: ToolId::new("reader"),
        fs: Some(FsGrant {
            read_paths: vec!["/fixtures".into()],
            write_paths: vec!["/fixtures/out".into()],
        }),
        net: Some(NetGrant {
            http: vec![HttpGrant {
                host: "api.example.com".into(),
                ports: vec![443],
                methods: vec!["GET".into()],
            }],
        }),
        max_memory_bytes: 1_048_576,
        max_wall_ms: 5_000,
        max_output_bytes: 1_048_576,
    }
}

fn assert_golden(name: &str, record: &AuditRecord) {
    let actual = to_json_line(record).expect("serialize audit record");
    let path = format!("tests/golden/{name}.json");
    let expected =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing golden file: {path}"));
    assert_eq!(
        actual.trim(),
        expected.trim(),
        "golden snapshot mismatch for {name}"
    );
}

#[test]
#[ignore = "run once to refresh golden snapshots: cargo test -p botzr-aegis-audit write_golden_snapshots -- --ignored"]
fn write_golden_snapshots() {
    std::fs::create_dir_all("tests/golden").unwrap();
    let cases = [
        ("policy_deny", golden_policy_deny_record()),
        ("rate_limit", golden_rate_limit_record()),
        ("pending_approval", golden_pending_approval_record()),
        ("capability_denied", golden_capability_denied_record()),
        ("trap", golden_trap_record()),
        ("resource_exceeded", golden_resource_exceeded_record()),
        ("panic", golden_panic_record()),
        ("abandoned_session", golden_abandoned_session_record()),
    ];
    for (name, record) in cases {
        let json = to_json_line(&record).expect("serialize");
        std::fs::write(format!("tests/golden/{name}.json"), json).unwrap();
    }
}

fn golden_policy_deny_record() -> AuditRecord {
    AuditRecord::new(
        "call-golden-1",
        ToolId::new("smoke"),
        "deadbeef",
        PolicyOutcome::Denied {
            reason: "blocked in test".into(),
        },
        CapabilityOutcome::Denied {
            reason: "policy blocked before capability".into(),
            denied_capability: None,
        },
        ExecutionOutcome::HostDenied {
            reason: "not executed".into(),
        },
    )
}

fn golden_rate_limit_record() -> AuditRecord {
    AuditRecord::new(
        "call-golden-2",
        ToolId::new("chatty"),
        "cafebabe",
        PolicyOutcome::RateLimited {
            reason: "rate limit exceeded: 2 per 60s".into(),
        },
        CapabilityOutcome::Denied {
            reason: "policy blocked before capability".into(),
            denied_capability: None,
        },
        ExecutionOutcome::HostDenied {
            reason: "not executed".into(),
        },
    )
}

fn golden_pending_approval_record() -> AuditRecord {
    AuditRecord::new(
        "call-golden-3",
        ToolId::new("dream"),
        "feedface",
        PolicyOutcome::PendingApproval {
            approval_id: "apr-gate-dream-1".into(),
        },
        CapabilityOutcome::Denied {
            reason: "policy blocked before capability".into(),
            denied_capability: None,
        },
        ExecutionOutcome::HostDenied {
            reason: "not executed".into(),
        },
    )
}

fn golden_capability_denied_record() -> AuditRecord {
    AuditRecord::new(
        "call-golden-4",
        ToolId::new("missing"),
        "baadf00d",
        PolicyOutcome::Allowed,
        CapabilityOutcome::Denied {
            reason: "tool not registered: missing".into(),
            denied_capability: Some("tool.registry".into()),
        },
        ExecutionOutcome::HostDenied {
            reason: "capability denied".into(),
        },
    )
}

fn golden_trap_record() -> AuditRecord {
    AuditRecord::new(
        "call-golden-5",
        ToolId::new("reader"),
        "decafbad",
        PolicyOutcome::Allowed,
        CapabilityOutcome::Granted {
            grant: fixture_grant(),
        },
        ExecutionOutcome::Trap {
            message: "guest trapped: unreachable".into(),
        },
    )
}

fn golden_resource_exceeded_record() -> AuditRecord {
    AuditRecord::new(
        "call-golden-6",
        ToolId::new("reader"),
        "0badf00d",
        PolicyOutcome::Allowed,
        CapabilityOutcome::Granted {
            grant: fixture_grant(),
        },
        ExecutionOutcome::ResourceExceeded {
            kind: "wall_clock".into(),
        },
    )
}

/// Wire shape of the `CallSession::Drop` panic-guard outcome: default-deny
/// seeds (no station ran before the unwind) plus a host-panic trap.
fn golden_panic_record() -> AuditRecord {
    AuditRecord::new(
        "call-golden-7",
        ToolId::new("panic"),
        "dead10cc",
        PolicyOutcome::Denied {
            reason: "not evaluated".into(),
        },
        CapabilityOutcome::Denied {
            reason: "not evaluated".into(),
            denied_capability: None,
        },
        ExecutionOutcome::Trap {
            message: "host panic during tool call".into(),
        },
    )
}

/// Wire shape of an abandoned session (begun, never `complete()`d, dropped
/// without a panic): default-deny seeds plus a fail-closed host-denied.
fn golden_abandoned_session_record() -> AuditRecord {
    AuditRecord::new(
        "call-golden-8",
        ToolId::new("abandoned"),
        "0ab0ab0a",
        PolicyOutcome::Denied {
            reason: "not evaluated".into(),
        },
        CapabilityOutcome::Denied {
            reason: "not evaluated".into(),
            denied_capability: None,
        },
        ExecutionOutcome::HostDenied {
            reason: "session abandoned".into(),
        },
    )
}

#[test]
fn golden_policy_deny() {
    assert_golden("policy_deny", &golden_policy_deny_record());
}

#[test]
fn golden_rate_limit() {
    assert_golden("rate_limit", &golden_rate_limit_record());
}

#[test]
fn golden_pending_approval() {
    assert_golden("pending_approval", &golden_pending_approval_record());
}

#[test]
fn golden_capability_denied() {
    assert_golden("capability_denied", &golden_capability_denied_record());
}

#[test]
fn golden_trap() {
    assert_golden("trap", &golden_trap_record());
}

#[test]
fn golden_resource_exceeded() {
    assert_golden("resource_exceeded", &golden_resource_exceeded_record());
}

#[test]
fn golden_panic() {
    assert_golden("panic", &golden_panic_record());
}

#[test]
fn golden_abandoned_session() {
    assert_golden("abandoned_session", &golden_abandoned_session_record());
}

#[test]
fn jsonl_roundtrip_writes_intent_and_outcome() {
    let writer = botzr_aegis_audit::AuditWriter::open_temp().unwrap();
    let intent = botzr_aegis_core::AuditIntent::new("call-rt-1", ToolId::new("smoke"), "abc123");
    writer.emit_intent(&intent).unwrap();
    let outcome = AuditRecord::new(
        "call-rt-1",
        ToolId::new("smoke"),
        "abc123",
        PolicyOutcome::Denied {
            reason: "nope".into(),
        },
        CapabilityOutcome::Denied {
            reason: "policy blocked before capability".into(),
            denied_capability: None,
        },
        ExecutionOutcome::HostDenied {
            reason: "not executed".into(),
        },
    );
    writer.emit_outcome(&outcome).unwrap();

    let lines: Vec<String> = std::fs::read_to_string(writer.path())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("\"phase\":\"intent\""));
    assert!(lines[1].contains("\"phase\":\"outcome\""));
}
