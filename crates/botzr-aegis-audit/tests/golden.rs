//! Golden snapshot tests — schema drift fails CI, not Layer 2 in production (OQ-6).
//!
//! The snapshots pin the **whole schema v2 wire shape**, not a `to_json_line`
//! dump. Every case is emitted through the real [`AuditWriter`] into one temp
//! Session signed by the fixed-seed [`insecure_dev_key`], so each file holds the
//! canonical bytes production actually writes — stamped `seq` and `prev_hash`,
//! and a real ed25519 `signature` + `key_id`. LOAD-BEARING: that is what makes a
//! canonicalization change or a change to how the signing input is built fail
//! here. A snapshot of a serializer dump would still match after either.
//!
//! Reproducible because the dev key is a fixed seed, ed25519 signing is
//! deterministic, the records below are constants, and `seq`/`prev_hash` follow
//! from the emission order in [`GOLDEN_LINES`]. The chain is why that order is
//! load-bearing: inserting a case in the middle legitimately rewrites every
//! later snapshot, and the refresh workflow is how you accept that.
//!
//! Refresh: `cargo test -p botzr-aegis-audit write_golden_snapshots -- --ignored`

use std::sync::OnceLock;

use botzr_aegis_audit::{insecure_dev_key, verify_line, AuditWriter};
use botzr_aegis_core::{
    ApprovalId, ApprovalVerdict, ApprovedScope, AuditDecision, AuditIntent, AuditOpen, AuditRecord,
    CapabilityGrant, CapabilityOutcome, DecisionAxes, ExecutionOutcome, FsAxis, FsGrant, HttpGrant,
    NetGrant, PolicyOutcome, PolicySetHash, PrevHash, RequestDigest, ToolId,
};

/// Snapshot names in emission order. The chain makes this a sequence, not a set.
const GOLDEN_LINES: &[&str] = &[
    "session_open",
    "intent",
    "policy_deny",
    "rate_limit",
    "pending_approval",
    "capability_denied",
    "trap",
    "resource_exceeded",
    "panic",
    "abandoned_session",
    "decision",
    "session_close",
];

/// Stand-in for the Policy Set that governed every fixture call.
fn fixture_policy_set_hash() -> PolicySetHash {
    PolicySetHash::of_canonical_bytes(b"golden-fixture-policy-set")
}

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

/// Write the whole fixture Session once and hand back `(name, raw line)` pairs.
///
/// Built through the writer rather than assembled by hand: a golden that
/// reimplements the chain and signature construction could only ever agree with
/// itself.
fn golden_session() -> &'static [(&'static str, String)] {
    static SESSION: OnceLock<Vec<(&'static str, String)>> = OnceLock::new();
    SESSION.get_or_init(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("session.jsonl");
        {
            let writer = AuditWriter::open(&path, insecure_dev_key()).expect("open session");
            writer.emit_intent(&mut golden_intent()).expect("intent");
            for (_, mut record) in outcome_cases() {
                writer.emit_outcome(&mut record).expect("outcome");
            }
            writer
                .emit_decision(&mut golden_decision_line())
                .expect("decision");
            // Drop closes the Session — the `close` snapshot only exists because
            // of that, so the scope is the fixture.
        }
        let rows: Vec<String> = std::fs::read_to_string(&path)
            .expect("session readable")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .collect();
        assert_eq!(
            rows.len(),
            GOLDEN_LINES.len(),
            "every emitted line needs a snapshot name (and vice versa)"
        );
        GOLDEN_LINES.iter().copied().zip(rows).collect()
    })
}

fn golden_line(name: &str) -> &'static str {
    golden_session()
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, line)| line.as_str())
        .unwrap_or_else(|| panic!("no such golden line: {name}"))
}

fn assert_golden(name: &str) {
    let actual = golden_line(name);
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
    for (name, line) in golden_session() {
        std::fs::write(format!("tests/golden/{name}.json"), line).unwrap();
    }
}

fn golden_intent() -> AuditIntent {
    AuditIntent::new(
        "call-golden-0",
        ToolId::new("smoke"),
        RequestDigest::of_request_bytes(b"c0ffee"),
    )
}

/// A human approval verdict (ADR-0005) — no intent, no execution of its own.
fn golden_decision_line() -> AuditDecision {
    AuditDecision::new(
        ApprovalId::new("apr-gate-dream-1"),
        ApprovalVerdict::Approved {
            scope: ApprovedScope {
                tool_id: ToolId::new("dream"),
                fs: Some(FsGrant {
                    read_paths: vec!["/fixtures".into()],
                    write_paths: vec![],
                }),
                net: None,
            },
        },
    )
}

fn outcome_cases() -> Vec<(&'static str, AuditRecord)> {
    vec![
        ("policy_deny", golden_policy_deny_record()),
        ("rate_limit", golden_rate_limit_record()),
        ("pending_approval", golden_pending_approval_record()),
        ("capability_denied", golden_capability_denied_record()),
        ("trap", golden_trap_record()),
        ("resource_exceeded", golden_resource_exceeded_record()),
        ("panic", golden_panic_record()),
        ("abandoned_session", golden_abandoned_session_record()),
    ]
}

/// Carries the decision axes so at least one snapshot pins the populated shape;
/// `{}` is pinned by every other outcome case.
fn golden_policy_deny_record() -> AuditRecord {
    AuditRecord::new(
        "call-golden-1",
        ToolId::new("smoke"),
        RequestDigest::of_request_bytes(b"deadbeef"),
        fixture_policy_set_hash(),
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
    .with_decision_axes(DecisionAxes {
        capability: Some("fs.read".into()),
        role: Some("ops".into()),
        session: Some("sess-golden".into()),
        matched_rule: Some("block-smoke".into()),
        fs: Some(FsAxis {
            path_raw: "./notes.md".into(),
            path_canonical: "/fixtures/notes.md".into(),
        }),
        ..DecisionAxes::default()
    })
}

fn golden_rate_limit_record() -> AuditRecord {
    AuditRecord::new(
        "call-golden-2",
        ToolId::new("chatty"),
        RequestDigest::of_request_bytes(b"cafebabe"),
        fixture_policy_set_hash(),
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
        RequestDigest::of_request_bytes(b"feedface"),
        fixture_policy_set_hash(),
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
        RequestDigest::of_request_bytes(b"baadf00d"),
        fixture_policy_set_hash(),
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
        RequestDigest::of_request_bytes(b"decafbad"),
        fixture_policy_set_hash(),
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
        RequestDigest::of_request_bytes(b"0badf00d"),
        fixture_policy_set_hash(),
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
        RequestDigest::of_request_bytes(b"dead10cc"),
        fixture_policy_set_hash(),
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
        RequestDigest::of_request_bytes(b"0ab0ab0a"),
        fixture_policy_set_hash(),
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
fn golden_session_open() {
    assert_golden("session_open");
}

#[test]
fn golden_intent_line() {
    assert_golden("intent");
}

#[test]
fn golden_policy_deny() {
    assert_golden("policy_deny");
}

#[test]
fn golden_rate_limit() {
    assert_golden("rate_limit");
}

#[test]
fn golden_pending_approval() {
    assert_golden("pending_approval");
}

#[test]
fn golden_capability_denied() {
    assert_golden("capability_denied");
}

#[test]
fn golden_trap() {
    assert_golden("trap");
}

#[test]
fn golden_resource_exceeded() {
    assert_golden("resource_exceeded");
}

#[test]
fn golden_panic() {
    assert_golden("panic");
}

#[test]
fn golden_abandoned_session() {
    assert_golden("abandoned_session");
}

#[test]
fn golden_decision() {
    assert_golden("decision");
}

#[test]
fn golden_session_close() {
    assert_golden("session_close");
}

/// The snapshots are only worth pinning if the signatures in them are real.
/// Checks the committed golden *files*, not the freshly written session, so a
/// snapshot edited by hand fails here rather than passing as "expected output".
#[test]
fn every_committed_golden_line_verifies_and_chains() {
    let rows: Vec<String> = GOLDEN_LINES
        .iter()
        .map(|name| {
            std::fs::read_to_string(format!("tests/golden/{name}.json"))
                .unwrap_or_else(|_| panic!("missing golden file: {name}"))
                .trim()
                .to_owned()
        })
        .collect();

    let open: AuditOpen = serde_json::from_str(&rows[0]).expect("first golden is the Open line");
    let public_key = open.public_key;
    assert_eq!(verify_line(&open, &public_key), Ok(()));

    for (index, row) in rows.iter().enumerate() {
        let value: serde_json::Value = serde_json::from_str(row).expect("golden parses");
        assert_eq!(value["seq"], serde_json::Value::from(index as u64));
        let expected_prev = if index == 0 {
            PrevHash::GENESIS
        } else {
            PrevHash::of_line(rows[index - 1].as_bytes())
        };
        assert_eq!(
            value["prev_hash"],
            serde_json::Value::from(expected_prev.to_hex()),
            "golden {} does not chain to the one before it",
            GOLDEN_LINES[index]
        );
    }

    // Intent is hashed into the chain but never signed — it is fsynced ahead of
    // execution, so signing must stay off the pre-execution path.
    let intent: AuditIntent = serde_json::from_str(&rows[1]).expect("second golden is the intent");
    assert_eq!(intent.seq(), 1);
    let intent_value: serde_json::Value = serde_json::from_str(&rows[1]).unwrap();
    assert!(intent_value.get("signature").is_none(), "{}", rows[1]);
    assert!(intent_value.get("key_id").is_none(), "{}", rows[1]);

    for row in &rows[2..10] {
        let record: AuditRecord = serde_json::from_str(row).expect("outcome golden parses");
        assert_eq!(verify_line(&record, &public_key), Ok(()), "{row}");
    }
    let decision: AuditDecision = serde_json::from_str(&rows[10]).expect("decision golden parses");
    assert_eq!(verify_line(&decision, &public_key), Ok(()));
    let close: botzr_aegis_core::AuditClose =
        serde_json::from_str(&rows[11]).expect("close golden parses");
    assert_eq!(verify_line(&close, &public_key), Ok(()));
}

#[test]
fn jsonl_roundtrip_writes_open_intent_and_outcome() {
    let writer = AuditWriter::open_temp().unwrap();
    let mut intent = AuditIntent::new(
        "call-rt-1",
        ToolId::new("smoke"),
        RequestDigest::of_request_bytes(b"abc123"),
    );
    writer.emit_intent(&mut intent).unwrap();
    let mut outcome = AuditRecord::new(
        "call-rt-1",
        ToolId::new("smoke"),
        RequestDigest::of_request_bytes(b"abc123"),
        fixture_policy_set_hash(),
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
    writer.emit_outcome(&mut outcome).unwrap();

    let lines: Vec<String> = std::fs::read_to_string(writer.path())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    // The Session `Open` line is now the file's first line — every `lines[0]`
    // assumption from schema v1 shifts by one.
    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("\"line_type\":\"open\""));
    assert!(lines[1].contains("\"line_type\":\"intent\""));
    assert!(lines[2].contains("\"line_type\":\"outcome\""));
}
