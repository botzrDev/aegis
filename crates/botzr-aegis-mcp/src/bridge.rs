//! Sync bridge: MCP tool args → `Runtime::execute_tool_call` → audit JSONL.
//!
//! Kept free of MCP transport so the research claim (pipeline + audit) is
//! unit-testable without spawning stdio.

use std::path::{Path, PathBuf};

use botzr_aegis_capability::{ToolInfo, ToolKind, ToolManifest};
use botzr_aegis_core::{AegisError, ToolId};
use botzr_aegis_policy::PolicyRequest;
use botzr_aegis_runtime::{sha256_hex, Runtime, RuntimeBuilder, ToolCallRequest};

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
///
/// `audit_path` and `signing_key_path` travel together (AILAB-620). A host that
/// asks for a persistent record file must say which key signs it: a Session an
/// MCP host later pins a `Verified (pinned)` label to must not have been signed
/// by a seed compiled into the published audit crate.
///
/// **The security half of that rule now lives in the constructor.**
/// `AuditWriter::with_sink` refuses a Durable Sink signed by `insecure_dev_key`
/// (ADR-0012), so a retained file with no provisioned key is unreachable no
/// matter what this function does. The match below stays for usability — an
/// early, flag-shaped error instead of a library error mid-build — and the
/// wording is deliberately identical to the CLI's, because the rule an operator
/// hits is the same rule. Do not re-add the security claim here.
pub fn build_runtime(
    policy_path: Option<&Path>,
    audit_path: Option<&Path>,
    signing_key_path: Option<&Path>,
) -> Result<Runtime, String> {
    let mut builder = RuntimeBuilder::new();

    builder = match policy_path {
        Some(path) => builder.policy_file(path).map_err(|e| e.to_string())?,
        None => builder
            .policy_yaml(DEFAULT_DENY_EXFIL_POLICY)
            .map_err(|e| e.to_string())?,
    };

    match (audit_path, signing_key_path) {
        (Some(path), Some(key)) => {
            builder = builder.audit_file(path, key).map_err(|e| e.to_string())?;
        }
        (Some(_), None) => return Err(
            "--audit requires --signing-key <PATH>; generate one with `aegis keygen --out <PATH>`"
                .to_string(),
        ),
        (None, Some(_)) => {
            return Err(
                "--signing-key only applies with --audit <PATH> (the default sink is volatile and in memory)"
                    .to_string(),
            )
        }
        // No persistent sink: the runtime's own Volatile in-memory Chain, signed
        // by the loudly-named dev key. Nothing an operator can mistake for
        // provisioned authority, so no key is required.
        (None, None) => {}
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
    //
    // The gateway asserts no role, capability or session of its own: an MCP
    // host has not told us who is calling. Tool identity alone is what it can
    // honestly claim, so that is all it puts on the request (AILAB-708).
    let tool = ToolId::new(tool_id);
    rt.execute_tool_call(ToolCallRequest::new(
        tool.clone(),
        text.as_bytes(),
        PolicyRequest::for_tool(&tool),
    ))
}

/// Run the echo tool through the full enforcement pipeline.
pub fn call_echo(rt: &Runtime, text: &str) -> Result<Vec<u8>, AegisError> {
    call_tool(rt, ECHO_TOOL_ID, text)
}

fn echo_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/echo-tool")
}

/// A persistent audit sink and the key that signs it — test-only.
///
/// A persistent sink has no dev-key fallback (AILAB-620), so every test that
/// names an audit path has to mint a key first, exactly as an operator does with
/// `aegis keygen --out`. The `TempDir` comes back with them because dropping it
/// removes both files.
#[cfg(test)]
pub(crate) fn temp_audit_sink() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let audit = dir.path().join("audit.jsonl");
    let key = dir.path().join("signing.key");
    botzr_aegis_audit::generate_signing_key(&key, false).expect("generate signing key");
    (dir, audit, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use botzr_aegis_core::AegisError;
    use tempfile::NamedTempFile;

    #[test]
    fn echo_tools_call_emits_schema_v2_audit_outcome() {
        let (_dir, audit_path, key) = temp_audit_sink();

        let rt = build_runtime(None, Some(&audit_path), Some(&key)).expect("runtime");
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
        let (_dir, audit_path, key) = temp_audit_sink();
        let rt = build_runtime(None, Some(&audit_path), Some(&key)).expect("runtime");

        let err = call_tool(&rt, EXFIL_TOOL_ID, "secret")
            .expect_err("exfil must be denied by default policy");
        assert!(
            matches!(err, AegisError::PolicyDenied { ref reason } if reason.contains("MCP deny-smoke")),
            "unexpected error: {err:?}"
        );

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
        let (_dir, audit_path, key) = temp_audit_sink();
        let rt = build_runtime(None, Some(&audit_path), Some(&key)).expect("runtime");
        let err = call_tool(&rt, "ghost", "x").unwrap_err();
        assert!(matches!(err, AegisError::HostDenied { .. }), "got: {err:?}");
    }

    #[test]
    fn build_runtime_accepts_policy_file() {
        let policy = NamedTempFile::new().expect("temp policy");
        std::fs::write(policy.path(), DEFAULT_DENY_EXFIL_POLICY).expect("write policy");
        let (_dir, audit_path, key) = temp_audit_sink();
        let rt =
            build_runtime(Some(policy.path()), Some(&audit_path), Some(&key)).expect("runtime");
        // Same deny policy as the default: exfil still refused at the policy station.
        let err = call_tool(&rt, EXFIL_TOOL_ID, "secrets").unwrap_err();
        assert!(
            matches!(err, AegisError::PolicyDenied { .. }),
            "got: {err:?}"
        );
    }

    /// LOAD-BEARING (AILAB-620): the gateway must refuse a persistent record
    /// file it cannot sign with a provisioned key. Falling back to the dev key
    /// here would put a published seed's signature on every MCP session an
    /// operator later pins a `Verified (pinned)` label to.
    #[test]
    fn a_persistent_sink_without_a_key_is_refused() {
        let (_dir, audit_path, key) = temp_audit_sink();

        // `Runtime` has no `Debug`, so the error is destructured rather than
        // pulled out with `expect_err`.
        let Err(err) = build_runtime(None, Some(&audit_path), None) else {
            panic!("--audit with no --signing-key must not build");
        };
        assert!(err.contains("--signing-key"), "got: {err}");
        assert!(
            !audit_path.exists(),
            "a refused build must not open the sink"
        );

        // And the mirror: a key with nothing to sign is a mistake, not a no-op.
        let Err(err) = build_runtime(None, None, Some(&key)) else {
            panic!("--signing-key with no --audit must not build");
        };
        assert!(err.contains("--audit"), "got: {err}");
    }

    /// A persistent sink publishes the key it was handed — never the dev key.
    #[test]
    fn a_persistent_sink_publishes_the_provisioned_key() {
        let (_dir, audit_path, key_path) = temp_audit_sink();
        let key = botzr_aegis_audit::load_signing_key(&key_path).expect("load key");

        let rt = build_runtime(None, Some(&audit_path), Some(&key_path)).expect("runtime");
        assert_eq!(rt.audit().public_key(), key.public_key());
        assert_ne!(
            rt.audit().public_key(),
            botzr_aegis_audit::insecure_dev_key().public_key()
        );
    }
}
