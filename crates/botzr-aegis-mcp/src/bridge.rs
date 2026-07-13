//! Sync bridge: MCP tool args → `Runtime::execute_tool_call` → audit JSONL.
//!
//! Kept free of MCP transport so the research claim (pipeline + audit) is
//! unit-testable without spawning stdio.

use std::path::{Path, PathBuf};

use botzr_aegis_audit::AuditWriter;
use botzr_aegis_capability::{ToolInfo, ToolKind, ToolManifest};
use botzr_aegis_core::ToolId;
use botzr_aegis_policy::PolicyEngine;
use botzr_aegis_runtime::{sha256_hex, Runtime};

/// Demo tool advertised on the MCP `tools/list` surface (Model A WASM echo).
pub const ECHO_TOOL_ID: &str = "echo";

const ECHO_WASM: &[u8] = include_bytes!("../../../tests/fixtures/echo-tool/echo.wasm");

/// Build a runtime with the echo fixture registered and optional policy/audit paths.
pub fn build_runtime(
    policy_path: Option<&Path>,
    audit_path: Option<&Path>,
) -> Result<Runtime, String> {
    let mut rt = Runtime::new();

    if let Some(path) = policy_path {
        let yaml = std::fs::read_to_string(path)
            .map_err(|e| format!("read policy {}: {e}", path.display()))?;
        let engine = PolicyEngine::from_yaml(&yaml)
            .map_err(|e| format!("parse policy {}: {e}", path.display()))?;
        rt = rt.with_policy(engine);
    }

    if let Some(path) = audit_path {
        let writer =
            AuditWriter::open(path).map_err(|e| format!("open audit {}: {e}", path.display()))?;
        rt = rt.with_audit(writer);
    }

    let base = echo_fixture_dir();
    let manifest = ToolManifest::new(
        ToolInfo {
            id: ToolId::new(ECHO_TOOL_ID),
            version: "0.1.0".into(),
            kind: ToolKind::Wasm,
        },
        &base,
    )
    .with_sha256(sha256_hex(ECHO_WASM));

    rt.register(manifest, ECHO_WASM.to_vec())
        .map_err(|e| format!("register echo: {e}"))?;
    Ok(rt)
}

/// Run the echo tool through the full enforcement pipeline.
pub fn call_echo(rt: &Runtime, text: &str) -> Result<Vec<u8>, String> {
    let input = text.as_bytes();
    rt.execute_tool_call(ToolId::new(ECHO_TOOL_ID), sha256_hex(input), input)
}

fn echo_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/echo-tool")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn echo_tools_call_emits_schema_v1_audit_outcome() {
        let audit = NamedTempFile::new().expect("temp audit");
        let audit_path = audit.path().to_path_buf();

        let rt = build_runtime(None, Some(&audit_path)).expect("runtime");
        let out = call_echo(&rt, "hello-mcp").expect("echo succeeds");
        assert_eq!(out, b"hello-mcp");

        let jsonl = std::fs::read_to_string(&audit_path).expect("audit readable");
        let outcome = jsonl
            .lines()
            .find(|l| l.contains("\"phase\":\"outcome\""))
            .expect("outcome line");
        assert!(
            outcome.contains("\"schema_version\":1"),
            "expected schema_version 1, got: {outcome}"
        );
        assert!(
            outcome.contains("\"status\":\"success\""),
            "expected success, got: {outcome}"
        );
    }
}
