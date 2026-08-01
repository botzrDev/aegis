//! AEG-20 integration tests — allow + deny paths with audit records.

use botzr_aegis_core::{AegisError, ToolId};
use botzr_aegis_runtime::{HostCallRequest, Runtime};
use dreamd_poc::{
    init_agent_store, policy_engine, register_dreamd_tools, AppendInput, AppendZone,
    CAP_FS_EPISODIC, CAP_FS_PERSONAL, TOOL_APPEND, TOOL_DREAM, TOOL_SEARCH,
};
use serde_json::json;
use tempfile::TempDir;

/// A runtime whose three dreamd tools are registered with their handlers
/// (AEG-44): the effect is no longer supplied per call, so these tests exercise
/// the same registry path a real embedder would.
fn setup_runtime(dir: &TempDir) -> Runtime {
    init_agent_store(dir.path());
    let mut rt = Runtime::new().with_policy(policy_engine());
    register_dreamd_tools(&mut rt, dir.path()).unwrap();
    rt
}

#[test]
fn append_episodic_allowed_with_audit_success() {
    let dir = TempDir::new().unwrap();
    let rt = setup_runtime(&dir);

    let input = AppendInput {
        content: "tokio channels need bounded capacity".into(),
        source_harness: "aegis-poc".into(),
        skill_action: "rust::async".into(),
        zone: AppendZone::Episodic,
    };
    let bytes = serde_json::to_vec(&input).unwrap();
    let tool = ToolId::new(TOOL_APPEND);

    let out = rt
        .execute_host_call(HostCallRequest::new(
            tool.clone(),
            &bytes,
            botzr_aegis_policy::PolicyRequest::for_tool(&tool).with_capability(CAP_FS_EPISODIC),
        ))
        .expect("episodic append allowed");

    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(parsed["id"].as_str().unwrap().starts_with("evt_"));

    let jsonl = dir.path().join(".agent/episodic/AGENT_LEARNINGS.jsonl");
    let text = std::fs::read_to_string(jsonl).unwrap();
    assert!(text.contains("tokio channels"));

    let audit = std::fs::read_to_string(rt.audit().path()).unwrap();
    assert!(audit.contains("\"status\":\"success\""));
}

#[test]
fn append_personal_denied_without_owner_role() {
    let dir = TempDir::new().unwrap();
    let rt = setup_runtime(&dir);

    let input = AppendInput {
        content: "private note".into(),
        source_harness: "aegis-poc".into(),
        skill_action: "personal::journal".into(),
        zone: AppendZone::Personal,
    };
    let bytes = serde_json::to_vec(&input).unwrap();
    let tool = ToolId::new(TOOL_APPEND);

    let err = rt
        .execute_host_call(HostCallRequest::new(
            tool.clone(),
            &bytes,
            botzr_aegis_policy::PolicyRequest::for_tool(&tool).with_capability(CAP_FS_PERSONAL),
        ))
        .unwrap_err();

    // AEG-42 typed surface: a policy station denial, not a stringly error.
    assert!(
        matches!(&err, AegisError::PolicyDenied { reason }
            if reason.contains("no matching rule (default deny)") || reason.contains("personal")),
        "unexpected: {err}"
    );

    let personal = dir.path().join(".agent/personal/notes.jsonl");
    assert!(!personal.exists(), "denied write must not create file");

    let audit = std::fs::read_to_string(rt.audit().path()).unwrap();
    assert!(audit.contains("\"status\":\"denied\"") || audit.contains("default deny"));
}

#[test]
fn append_personal_allowed_with_owner_role() {
    let dir = TempDir::new().unwrap();
    let rt = setup_runtime(&dir);

    let input = AppendInput {
        content: "owner-only note".into(),
        source_harness: "aegis-poc".into(),
        skill_action: "personal::journal".into(),
        zone: AppendZone::Personal,
    };
    let bytes = serde_json::to_vec(&input).unwrap();
    let tool = ToolId::new(TOOL_APPEND);

    rt.execute_host_call(HostCallRequest::new(
        tool.clone(),
        &bytes,
        botzr_aegis_policy::PolicyRequest::for_tool(&tool)
            .with_capability(CAP_FS_PERSONAL)
            .with_role("owner"),
    ))
    .expect("owner role allows personal write");

    let personal = dir.path().join(".agent/personal/notes.jsonl");
    assert!(personal.exists());
}

#[test]
fn search_nodes_returns_seeded_hit() {
    let dir = TempDir::new().unwrap();
    let rt = setup_runtime(&dir);

    // Seed one learning directly.
    let seed = AppendInput {
        content: "wasmtime component model linking".into(),
        source_harness: "seed".into(),
        skill_action: "rust::wasm".into(),
        zone: AppendZone::Episodic,
    };
    let seed_bytes = serde_json::to_vec(&seed).unwrap();
    let append_tool = ToolId::new(TOOL_APPEND);
    rt.execute_host_call(HostCallRequest::new(
        append_tool.clone(),
        &seed_bytes,
        botzr_aegis_policy::PolicyRequest::for_tool(&append_tool).with_capability(CAP_FS_EPISODIC),
    ))
    .unwrap();

    let query = json!({ "query": "wasmtime", "k": 5 });
    let query_bytes = serde_json::to_vec(&query).unwrap();
    let search_tool = ToolId::new(TOOL_SEARCH);

    let out = rt
        .execute_host_call(HostCallRequest::new(
            search_tool.clone(),
            &query_bytes,
            botzr_aegis_policy::PolicyRequest::for_tool(&search_tool),
        ))
        .expect("search allowed");

    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let results = parsed["results"].as_array().unwrap();
    assert!(!results.is_empty());
    assert!(results[0]["content"].as_str().unwrap().contains("wasmtime"));
}

#[test]
fn dream_consolidation_requires_approval() {
    let dir = TempDir::new().unwrap();
    let rt = setup_runtime(&dir);
    let tool = ToolId::new(TOOL_DREAM);
    let input = b"{}";

    // `dream` is registered with a fail-closed handler, so this can only be
    // PendingApproval if station 1 short-circuited: had the call reached the
    // handler, the error would be HostDenied instead.
    let err = rt
        .execute_host_call(HostCallRequest::new(
            tool.clone(),
            input,
            botzr_aegis_policy::PolicyRequest::for_tool(&tool),
        ))
        .unwrap_err();

    assert!(
        matches!(err, AegisError::PendingApproval { .. }),
        "unexpected: {err}"
    );
}
