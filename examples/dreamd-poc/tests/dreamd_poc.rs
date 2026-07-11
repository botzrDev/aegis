//! AEG-20 integration tests — allow + deny paths with audit records.

use botzr_aegis_core::ToolId;
use botzr_aegis_policy::PolicyRequest;
use botzr_aegis_runtime::{sha256_hex, HostCallRequest, Runtime};
use dreamd_poc::{
    append_node_effect, init_agent_store, policy_engine, register_dreamd_tools,
    search_nodes_effect, AppendInput, AppendZone, CAP_FS_EPISODIC, CAP_FS_PERSONAL, TOOL_APPEND,
    TOOL_DREAM, TOOL_SEARCH,
};
use serde_json::json;
use tempfile::TempDir;

fn setup_runtime(dir: &TempDir) -> Runtime {
    init_agent_store(dir.path());
    let mut rt = Runtime::new().with_policy(policy_engine());
    register_dreamd_tools(rt.capabilities(), dir.path());
    rt
}

#[test]
fn append_episodic_allowed_with_audit_success() {
    let dir = TempDir::new().unwrap();
    let rt = setup_runtime(&dir);
    let root = dir.path().to_path_buf();

    let input = AppendInput {
        content: "tokio channels need bounded capacity".into(),
        source_harness: "aegis-poc".into(),
        skill_action: "rust::async".into(),
        zone: AppendZone::Episodic,
    };
    let bytes = serde_json::to_vec(&input).unwrap();
    let tool = ToolId::new(TOOL_APPEND);

    let out = rt
        .execute_host_call(
            HostCallRequest::new(
                tool.clone(),
                sha256_hex(&bytes),
                &bytes,
                PolicyRequest::for_tool(&tool).with_capability(CAP_FS_EPISODIC),
            ),
            |grant, input| append_node_effect(grant, &root, input),
        )
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
    let root = dir.path().to_path_buf();

    let input = AppendInput {
        content: "private note".into(),
        source_harness: "aegis-poc".into(),
        skill_action: "personal::journal".into(),
        zone: AppendZone::Personal,
    };
    let bytes = serde_json::to_vec(&input).unwrap();
    let tool = ToolId::new(TOOL_APPEND);

    let err = rt
        .execute_host_call(
            HostCallRequest::new(
                tool.clone(),
                sha256_hex(&bytes),
                &bytes,
                PolicyRequest::for_tool(&tool).with_capability(CAP_FS_PERSONAL),
            ),
            |grant, input| append_node_effect(grant, &root, input),
        )
        .unwrap_err();

    assert!(
        err.contains("no matching rule (default deny)") || err.contains("personal"),
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
    let root = dir.path().to_path_buf();

    let input = AppendInput {
        content: "owner-only note".into(),
        source_harness: "aegis-poc".into(),
        skill_action: "personal::journal".into(),
        zone: AppendZone::Personal,
    };
    let bytes = serde_json::to_vec(&input).unwrap();
    let tool = ToolId::new(TOOL_APPEND);

    rt.execute_host_call(
        HostCallRequest::new(
            tool.clone(),
            sha256_hex(&bytes),
            &bytes,
            PolicyRequest::for_tool(&tool)
                .with_capability(CAP_FS_PERSONAL)
                .with_role("owner"),
        ),
        |grant, input| append_node_effect(grant, &root, input),
    )
    .expect("owner role allows personal write");

    let personal = dir.path().join(".agent/personal/notes.jsonl");
    assert!(personal.exists());
}

#[test]
fn search_nodes_returns_seeded_hit() {
    let dir = TempDir::new().unwrap();
    let rt = setup_runtime(&dir);
    let root = dir.path().to_path_buf();

    // Seed one learning directly.
    let seed = AppendInput {
        content: "wasmtime component model linking".into(),
        source_harness: "seed".into(),
        skill_action: "rust::wasm".into(),
        zone: AppendZone::Episodic,
    };
    let seed_bytes = serde_json::to_vec(&seed).unwrap();
    let append_tool = ToolId::new(TOOL_APPEND);
    rt.execute_host_call(
        HostCallRequest::new(
            append_tool.clone(),
            sha256_hex(&seed_bytes),
            &seed_bytes,
            PolicyRequest::for_tool(&append_tool).with_capability(CAP_FS_EPISODIC),
        ),
        |grant, input| append_node_effect(grant, &root, input),
    )
    .unwrap();

    let query = json!({ "query": "wasmtime", "k": 5 });
    let query_bytes = serde_json::to_vec(&query).unwrap();
    let search_tool = ToolId::new(TOOL_SEARCH);

    let out = rt
        .execute_host_call(
            HostCallRequest::new(
                search_tool.clone(),
                sha256_hex(&query_bytes),
                &query_bytes,
                PolicyRequest::for_tool(&search_tool),
            ),
            |grant, input| search_nodes_effect(grant, &root, input),
        )
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
    let root = dir.path().to_path_buf();
    let tool = ToolId::new(TOOL_DREAM);
    let input = b"{}";

    let err = rt
        .execute_host_call(
            HostCallRequest::new(
                tool.clone(),
                sha256_hex(input),
                input,
                PolicyRequest::for_tool(&tool),
            ),
            |grant, _| {
                append_node_effect(
                    grant,
                    &root,
                    br#"{"content":"x","source_harness":"t","skill_action":"d::dream"}"#,
                )
            },
        )
        .unwrap_err();

    assert!(
        err.starts_with("policy pending approval:"),
        "unexpected: {err}"
    );
}
