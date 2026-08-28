//! AILAB-619 — the record explains its own verdict.
//!
//! Before schema v2 an outcome line persisted only `tool_id`, so a role-gated
//! deny could assert a verdict and nothing more: which role was asserted, which
//! capability was requested, which session it belonged to, and which rule fired
//! all died with the call. These tests pin the property that closes that gap —
//! a recorded deny can be *rechecked* from the record alone (ADR-0001).

use std::path::{Path, PathBuf};

use botzr_aegis_capability::{
    FsNeeds, HttpNeed, NetNeeds, PathNeed, ToolInfo, ToolKind, ToolManifest,
};
use botzr_aegis_core::{AegisError, AuditRecord, PolicyAction, PolicyOutcome, ToolId};
use botzr_aegis_policy::{CallAxes, PolicyEngine, PolicyRequest};
use botzr_aegis_runtime::{
    HostCallRequest, HostEffectError, Runtime, RuntimeBuilder, ToolCallRequest, ToolExecutable,
};

const ECHO_WASM: &[u8] = include_bytes!("../../../tests/fixtures/echo-tool/echo.wasm");

/// A role gate: `contractor` may not read notes, everybody else may.
const ROLE_GATED_POLICY: &str = r#"
version: 1
default: allow
rules:
  - id: no-contractor-reads
    action: deny
    tool: notes
    capability: fs.read
    role: contractor
    reason: "contractors may not read notes"
"#;

fn host_manifest(id: &str) -> ToolManifest {
    ToolManifest::new(
        ToolInfo {
            id: ToolId::new(id),
            version: "0.1.0".into(),
            kind: ToolKind::Host,
        },
        std::env::temp_dir(),
    )
}

fn wasm_manifest(id: &str) -> ToolManifest {
    ToolManifest::new(
        ToolInfo {
            id: ToolId::new(id),
            version: "0.1.0".into(),
            kind: ToolKind::Wasm,
        },
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/echo-tool"),
    )
}

fn ok_handler() -> ToolExecutable {
    ToolExecutable::HostHandler(Box::new(
        |_ctx, input| -> Result<Vec<u8>, HostEffectError> { Ok(input.to_vec()) },
    ))
}

/// Every outcome line the sink recorded, parsed.
fn outcomes(path: &Path) -> Vec<AuditRecord> {
    std::fs::read_to_string(path)
        .expect("audit readable")
        .lines()
        .filter(|line| line.contains("\"line_type\":\"outcome\""))
        .map(|line| serde_json::from_str(line).expect("outcome parses"))
        .collect()
}

fn build(audit: &Path, policy_yaml: &str) -> Runtime {
    // A persistent sink is signed by a provisioned key, never by the dev seed
    // (AILAB-620). Generate one beside the record file; both die with the
    // test's tempdir.
    let key = audit.with_extension("key");
    botzr_aegis_audit::generate_signing_key(&key, true).expect("generate signing key");

    RuntimeBuilder::new()
        .policy_yaml(policy_yaml)
        .expect("valid policy")
        .audit_file(audit, &key)
        .expect("open audit sink")
        .build()
        .expect("build runtime")
}

#[test]
fn a_role_gated_deny_is_reconstructable_from_the_record_alone() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("session.jsonl");

    let mut rt = build(&audit_path, ROLE_GATED_POLICY);
    // Registered with an effect that *would* succeed, so the denial below can
    // only have come from station 1.
    let tool = ToolId::new("notes");
    rt.register_tool(host_manifest("notes"), ok_handler())
        .expect("register notes");

    let err = rt
        .execute_host_call(HostCallRequest::new(
            tool.clone(),
            b"{}",
            CallAxes::default()
                .with_capability("fs.read")
                .with_role("contractor")
                .with_session("sess-42"),
        ))
        .expect_err("a contractor must be denied");
    assert_eq!(
        err,
        AegisError::PolicyDenied {
            reason: "contractors may not read notes".into()
        }
    );

    // ——— from here on, only what is on disk ———
    drop(rt);
    let records = outcomes(&audit_path);
    let [record] = &records[..] else {
        panic!("expected exactly one outcome, got {}", records.len())
    };

    // 1. Every axis the verdict turned on survived the call.
    let axes = &record.decision_axes;
    assert_eq!(axes.role.as_deref(), Some("contractor"));
    assert_eq!(axes.capability.as_deref(), Some("fs.read"));
    assert_eq!(axes.session.as_deref(), Some("sess-42"));
    assert_eq!(
        axes.matched_rule.as_deref(),
        Some("no-contractor-reads"),
        "the rule that decided it turns a recheck diff from a verdict flip into an explanation"
    );
    assert_eq!(record.tool_id, ToolId::new("notes"));
    assert!(matches!(record.policy, PolicyOutcome::Denied { .. }));

    // 2. The record names the ruleset it was decided under, so a recheck knows
    //    which Policy Set to load — and it is the real content hash, not the
    //    FNV text digest.
    let engine = PolicyEngine::from_yaml(ROLE_GATED_POLICY).expect("reparse policy");
    assert_eq!(record.policy_set_hash, engine.active_content_hash());
    assert_ne!(engine.active_digest(), record.policy_set_hash.to_hex());

    // 3. The load-bearing claim: rebuild the request from the record's own
    //    fields — nothing else in scope — and the verdict reproduces, with the
    //    same rule firing.
    let tool_id = record.tool_id.clone();
    let mut replayed = PolicyRequest::for_tool(&tool_id);
    if let Some(capability) = axes.capability.as_deref() {
        replayed = replayed.with_capability(capability);
    }
    if let Some(role) = axes.role.as_deref() {
        replayed = replayed.with_role(role);
    }
    if let Some(session) = axes.session.as_deref() {
        replayed = replayed.with_session(session);
    }
    let decision = engine.evaluate(&replayed);
    assert_eq!(
        decision.action,
        PolicyAction::Deny {
            reason: "contractors may not read notes".into()
        },
        "the recorded axes must reproduce the recorded verdict"
    );
    assert_eq!(decision.matched_rule, axes.matched_rule);

    // 4. …and the role is what carried it. Drop that one recorded axis and the
    //    verdict flips, which is exactly why persisting only `tool_id` made a
    //    role-gated deny unexplainable.
    let without_role = PolicyRequest::for_tool(&tool_id).with_capability("fs.read");
    assert_eq!(engine.evaluate(&without_role).action, PolicyAction::Allow);
}

/// AILAB-708 — the Model A twin of the test above, against the *same* policy.
///
/// `execute_tool_call` used to build its own `PolicyRequest` from the tool id
/// alone, so `no-contractor-reads` — gated on `capability` and `role` — could
/// never match a WASM call. The contractor was allowed on the trust model that
/// has real sandbox isolation, and the record could not say why. The echo
/// component is registered under the id the policy already names so that the
/// only difference between this test and its Model B twin is the trust model.
#[test]
fn a_role_gated_deny_fires_for_a_wasm_tool_too() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("session.jsonl");

    let mut rt = build(&audit_path, ROLE_GATED_POLICY);
    // Registered with a component that *would* succeed, so the denial below can
    // only have come from station 1.
    let tool = ToolId::new("notes");
    rt.register_tool(
        wasm_manifest("notes"),
        ToolExecutable::WasmComponent(ECHO_WASM.to_vec()),
    )
    .expect("register notes");

    // 1. The deny fires — this is the assertion that fails on `main`, where the
    //    axes could not be supplied at all and the call returned the echo.
    let err = rt
        .execute_tool_call(ToolCallRequest::new(
            tool.clone(),
            b"{}",
            CallAxes::default()
                .with_capability("fs.read")
                .with_role("contractor")
                .with_session("sess-42"),
        ))
        .expect_err("a contractor must be denied on Model A too");
    assert_eq!(
        err,
        AegisError::PolicyDenied {
            reason: "contractors may not read notes".into()
        }
    );

    // 2. …and the role is what carried it. The same call without that one axis
    //    runs the component, so the verdict above was the rule firing, not the
    //    tool id being denied outright.
    let allowed = rt
        .execute_tool_call(ToolCallRequest::new(
            tool.clone(),
            b"{}",
            CallAxes::default().with_capability("fs.read"),
        ))
        .expect("without the contractor role the same call is allowed");
    assert_eq!(allowed, b"{}");

    // ——— from here on, only what is on disk ———
    drop(rt);
    let records = outcomes(&audit_path);
    let [denied, allowed_record] = &records[..] else {
        panic!("expected exactly two outcomes, got {}", records.len())
    };

    // 3. A Model A record now carries the axes its verdict turned on, so the
    //    deny can explain itself exactly as the Model B one does.
    let axes = &denied.decision_axes;
    assert_eq!(axes.role.as_deref(), Some("contractor"));
    assert_eq!(axes.capability.as_deref(), Some("fs.read"));
    assert_eq!(axes.session.as_deref(), Some("sess-42"));
    assert_eq!(axes.matched_rule.as_deref(), Some("no-contractor-reads"));
    assert_eq!(denied.tool_id, ToolId::new("notes"));
    assert!(matches!(denied.policy, PolicyOutcome::Denied { .. }));

    // The allowed call recorded the axes it did assert, and no role.
    assert_eq!(
        allowed_record.decision_axes.capability.as_deref(),
        Some("fs.read")
    );
    assert_eq!(allowed_record.decision_axes.role, None);
}

#[test]
fn a_call_with_no_fs_or_net_need_omits_both_axes_rather_than_nulling_them() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("session.jsonl");

    let mut rt = build(&audit_path, "version: 1\ndefault: allow\nrules: []\n");
    let tool = ToolId::new("plain");
    rt.register_tool(host_manifest("plain"), ok_handler())
        .expect("register plain");
    rt.execute_host_call(HostCallRequest::new(
        tool.clone(),
        b"ping",
        CallAxes::default(),
    ))
    .expect("plain call succeeds");
    drop(rt);

    let text = std::fs::read_to_string(&audit_path).expect("audit readable");
    let outcome = text
        .lines()
        .find(|line| line.contains("\"line_type\":\"outcome\""))
        .expect("outcome line");
    // Omitted entirely, never null — a `null` axis would make the canonical
    // form choose between two spellings of "absent".
    assert!(!outcome.contains("\"fs\""), "{outcome}");
    assert!(!outcome.contains("\"net\""), "{outcome}");
    assert!(!outcome.contains("null"), "{outcome}");

    let record: AuditRecord = serde_json::from_str(outcome).expect("outcome parses");
    assert!(record.decision_axes.fs.is_none());
    assert!(record.decision_axes.net.is_none());
    // A grant *was* minted, so the record links to it and to the response.
    assert!(record.grant_id.is_some());
    assert!(record.response_digest.is_some());
}

#[test]
fn a_granted_call_records_the_resources_it_resolved_to() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("session.jsonl");
    let root = dir.path().join("data");
    std::fs::create_dir(&root).unwrap();

    let mut rt = build(&audit_path, "version: 1\ndefault: allow\nrules: []\n");
    let tool = ToolId::new("reader");
    rt.register_tool(
        host_manifest("reader")
            .with_fs(FsNeeds {
                read: vec![PathNeed {
                    path: root.to_string_lossy().into_owned(),
                    recursive: true,
                }],
                write: vec![],
            })
            .with_net(NetNeeds {
                http: vec![HttpNeed {
                    host: "api.example.com".into(),
                    ports: vec![443],
                    methods: vec!["GET".into()],
                }],
            }),
        ok_handler(),
    )
    .expect("register reader");

    rt.execute_host_call(HostCallRequest::new(
        tool.clone(),
        b"ping",
        CallAxes::default(),
    ))
    .expect("reader call succeeds");
    drop(rt);

    let records = outcomes(&audit_path);
    let [record] = &records[..] else {
        panic!("expected exactly one outcome")
    };
    let canonical_root = PathBuf::from(&root)
        .canonicalize()
        .expect("root canonicalizes");
    let fs = record.decision_axes.fs.as_ref().expect("fs axis recorded");
    assert_eq!(Path::new(&fs.path_canonical), canonical_root);
    let net = record
        .decision_axes
        .net
        .as_ref()
        .expect("net axis recorded");
    assert_eq!(net.host, "api.example.com");
    assert_eq!(net.port, 443);
}

#[test]
fn an_ambiguous_grant_omits_the_axis_rather_than_guessing_which_resource() {
    // Two granted roots and two granted hosts: the runtime has not resolved the
    // call to *a* resource — which one it touched is AILAB-626's bindings — so
    // recording either would be evidence that reads as fact and is not.
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("session.jsonl");
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();

    let mut rt = build(&audit_path, "version: 1\ndefault: allow\nrules: []\n");
    let tool = ToolId::new("wide");
    rt.register_tool(
        host_manifest("wide")
            .with_fs(FsNeeds {
                read: vec![
                    PathNeed {
                        path: first.to_string_lossy().into_owned(),
                        recursive: true,
                    },
                    PathNeed {
                        path: second.to_string_lossy().into_owned(),
                        recursive: true,
                    },
                ],
                write: vec![],
            })
            .with_net(NetNeeds {
                http: vec![
                    HttpNeed {
                        host: "a.example.com".into(),
                        ports: vec![443],
                        methods: vec!["GET".into()],
                    },
                    HttpNeed {
                        host: "b.example.com".into(),
                        ports: vec![443],
                        methods: vec!["GET".into()],
                    },
                ],
            }),
        ok_handler(),
    )
    .expect("register wide");

    rt.execute_host_call(HostCallRequest::new(
        tool.clone(),
        b"ping",
        CallAxes::default(),
    ))
    .expect("wide call succeeds");
    drop(rt);

    let records = outcomes(&audit_path);
    let [record] = &records[..] else {
        panic!("expected exactly one outcome")
    };
    assert!(record.decision_axes.fs.is_none());
    assert!(record.decision_axes.net.is_none());
}
