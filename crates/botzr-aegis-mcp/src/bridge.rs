//! Sync bridge: MCP tool args → `Runtime::execute_tool_call` → audit JSONL.
//!
//! Kept free of MCP transport so the research claim (pipeline + audit) is
//! unit-testable without spawning stdio.

use std::path::{Path, PathBuf};

use botzr_aegis_capability::{ToolInfo, ToolKind, ToolManifest};
use botzr_aegis_core::{AegisError, ToolId};
use botzr_aegis_runtime::{sha256_hex, Runtime, RuntimeBuilder};

/// Allow-path Model A tool on the MCP catalog.
pub const ECHO_TOOL_ID: &str = "echo";

/// Policy-denied tool on the MCP catalog (same WASM fixture; deny-smoke target).
pub const EXFIL_TOOL_ID: &str = "exfil";

/// Tools advertised on `tools/list` (order stable for hosts/tests).
pub const CATALOG_TOOL_IDS: &[&str] = &[ECHO_TOOL_ID, EXFIL_TOOL_ID];

/// Default policy when `--policy` is omitted: allow-all except `exfil` (AEG-28).
pub const DEFAULT_DENY_EXFIL_POLICY: &str = r#"
version: 1
default: allow
rules:
  - id: block-exfil
    action: deny
    tool: exfil
    reason: "MCP deny-smoke: exfil blocked at policy"
"#;

// Vendored copy so `cargo publish` verifies without the monorepo test tree.
const ECHO_WASM: &[u8] = include_bytes!("../fixtures/echo.wasm");

/// Build a runtime with the multi-tool catalog registered.
///
/// Policy/audit wiring is delegated to [`RuntimeBuilder`], so this gateway does
/// not hand-roll policy parsing or audit-sink opening itself — one construction
/// path shared with the CLI. Catalog registration stays here: which tools an MCP
/// host may see is the gateway's business, not the runtime's.
///
/// When `policy_path` is `None`, loads [`DEFAULT_DENY_EXFIL_POLICY`] so the
/// `exfil` deny-smoke path works without a host-supplied YAML file.
pub fn build_runtime(
    policy_path: Option<&Path>,
    audit_path: Option<&Path>,
) -> Result<Runtime, String> {
    let mut builder = RuntimeBuilder::new();

    builder = match policy_path {
        Some(path) => builder.policy_file(path).map_err(|e| e.to_string())?,
        None => builder
            .policy_yaml(DEFAULT_DENY_EXFIL_POLICY)
            .map_err(|e| e.to_string())?,
    };

    if let Some(path) = audit_path {
        builder = builder.audit_file(path).map_err(|e| e.to_string())?;
    }

    let mut rt = builder.build().map_err(|e| e.to_string())?;

    let base = echo_fixture_dir();
    let digest = sha256_hex(ECHO_WASM);

    for tool_id in CATALOG_TOOL_IDS {
        let manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new(*tool_id),
                version: "0.1.0".into(),
                kind: ToolKind::Wasm,
            },
            &base,
        )
        .with_sha256(digest.clone());

        rt.register(manifest, ECHO_WASM.to_vec())
            .map_err(|e| format!("register {tool_id}: {e}"))?;
    }

    Ok(rt)
}

/// Run a catalog tool through the full enforcement pipeline.
pub fn call_tool(rt: &Runtime, tool_id: &str, text: &str) -> Result<Vec<u8>, AegisError> {
    if !CATALOG_TOOL_IDS.contains(&tool_id) {
        return Err(AegisError::HostDenied {
            reason: format!("unknown tool: {tool_id}"),
        });
    }
    // The runtime derives the input digest itself; passing one here would be a
    // second source of truth for the same bytes.
    rt.execute_tool_call(ToolId::new(tool_id), text.as_bytes())
}

/// Run the echo tool through the full enforcement pipeline.
pub fn call_echo(rt: &Runtime, text: &str) -> Result<Vec<u8>, AegisError> {
    call_tool(rt, ECHO_TOOL_ID, text)
}

fn echo_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/echo-tool")
}

#[cfg(test)]
mod tests {
    use super::*;
    use botzr_aegis_core::AegisError;
    use tempfile::NamedTempFile;

    #[test]
    fn echo_tools_call_emits_schema_v2_audit_outcome() {
        let audit = NamedTempFile::new().expect("temp audit");
        let audit_path = audit.path().to_path_buf();

        let rt = build_runtime(None, Some(&audit_path)).expect("runtime");
        let out = call_echo(&rt, "hello-mcp").expect("echo succeeds");
        assert_eq!(out, b"hello-mcp");

        let jsonl = std::fs::read_to_string(&audit_path).expect("audit readable");
        let outcome = jsonl
            .lines()
            .find(|l| l.contains("\"line_type\":\"outcome\""))
            .expect("outcome line");
        assert!(
            outcome.contains("\"schema_version\":2"),
            "expected schema_version 2, got: {outcome}"
        );
        assert!(
            outcome.contains("\"status\":\"success\""),
            "expected success, got: {outcome}"
        );
    }

    #[test]
    fn exfil_policy_deny_emits_audit_outcome() {
        let audit = NamedTempFile::new().expect("temp audit");
        let rt = build_runtime(None, Some(audit.path())).expect("runtime");

        let err = call_tool(&rt, EXFIL_TOOL_ID, "secret")
            .expect_err("exfil must be denied by default policy");
        assert!(
            matches!(err, AegisError::PolicyDenied { ref reason } if reason.contains("MCP deny-smoke")),
            "unexpected error: {err:?}"
        );

        let jsonl = std::fs::read_to_string(audit.path()).expect("audit readable");
        let outcome = jsonl
            .lines()
            .find(|l| l.contains("\"line_type\":\"outcome\""))
            .expect("outcome line");
        assert!(
            outcome.contains("\"schema_version\":2"),
            "expected schema_version 2, got: {outcome}"
        );
        assert!(
            outcome.contains("\"status\":\"denied\"")
                || outcome.contains("MCP deny-smoke: exfil blocked"),
            "expected policy deny audit, got: {outcome}"
        );
        assert!(
            outcome.contains("\"tool_id\":\"exfil\""),
            "expected exfil tool_id, got: {outcome}"
        );
    }

    #[test]
    fn call_tool_rejects_non_catalog_ids() {
        let audit = NamedTempFile::new().expect("temp audit");
        let rt = build_runtime(None, Some(audit.path())).expect("runtime");
        let err = call_tool(&rt, "ghost", "x").unwrap_err();
        assert!(matches!(err, AegisError::HostDenied { .. }), "got: {err:?}");
    }

    #[test]
    fn build_runtime_accepts_policy_file() {
        let policy = NamedTempFile::new().expect("temp policy");
        std::fs::write(policy.path(), DEFAULT_DENY_EXFIL_POLICY).expect("write policy");
        let audit = NamedTempFile::new().expect("temp audit");
        let rt = build_runtime(Some(policy.path()), Some(audit.path())).expect("runtime");
        // Same deny policy as the default: exfil still refused at the policy station.
        let err = call_tool(&rt, EXFIL_TOOL_ID, "secrets").unwrap_err();
        assert!(
            matches!(err, AegisError::PolicyDenied { .. }),
            "got: {err:?}"
        );
    }
}
