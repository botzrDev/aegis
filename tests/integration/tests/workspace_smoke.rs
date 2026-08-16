//! Cross-crate workspace integration tests.

use std::path::Path;

use botzr_aegis_capability::{ToolInfo, ToolKind, ToolManifest};
use botzr_aegis_core::{ToolId, PIPELINE_STAGES};
use botzr_aegis_policy::PolicyRequest;
use botzr_aegis_runtime::{sha256_hex, Runtime, ToolCallRequest};

#[test]
fn pipeline_order_is_load_bearing() {
    assert_eq!(
        PIPELINE_STAGES,
        &["policy", "capability", "sandbox", "audit"]
    );
}

#[test]
fn echo_tool_e2e_through_pipeline() {
    let wasm = include_bytes!("../../fixtures/echo-tool/echo.wasm");
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/echo-tool");
    let manifest = ToolManifest::new(
        ToolInfo {
            id: ToolId::new("echo"),
            version: "0.1.0".into(),
            kind: ToolKind::Wasm,
        },
        &base,
    )
    .with_sha256(sha256_hex(wasm));

    let mut rt = Runtime::new();
    rt.register(manifest, wasm.to_vec()).expect("register echo");

    let input = b"{\"ping\":true}";
    let tool = ToolId::new("echo");
    let out = rt
        .execute_tool_call(ToolCallRequest::new(
            tool.clone(),
            input,
            PolicyRequest::for_tool(&tool),
        ))
        .expect("pipeline run succeeds");
    assert_eq!(out, input);

    let audit =
        std::fs::read_to_string(rt.audit().path().expect("the default sink is a temp file"))
            .expect("audit readable");
    // Schema v2: the Session `Open` line comes first, then the call's two lines.
    assert!(audit.contains("\"line_type\":\"open\""));
    assert!(audit.contains("\"line_type\":\"intent\""));
    assert!(audit.contains("\"line_type\":\"outcome\""));
    assert!(audit.contains("\"status\":\"success\""));
}
