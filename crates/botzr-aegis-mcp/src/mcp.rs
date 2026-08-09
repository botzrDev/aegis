//! Minimal MCP JSON-RPC (stdio, newline-delimited) — intentionally in-repo.
//!
//! Subset: `initialize`, `tools/list`, `tools/call`, `ping`. Notifications are
//! acknowledged by silence. Kept free of an external MCP SDK so every gateway
//! byte is reviewable under the workspace MSRV (1.86); see DECISIONS.md.

use serde_json::{json, Value};

use crate::bridge::{call_tool, CATALOG_TOOL_IDS, ECHO_TOOL_ID, EXFIL_TOOL_ID};
use botzr_aegis_core::AegisError;
use botzr_aegis_runtime::Runtime;

const PROTOCOL_VERSION: &str = "2024-11-05";

/// Handle one newline-delimited JSON-RPC message.
///
/// Returns `None` for notifications (no `id`) or empty input.
pub fn handle_line(rt: &Runtime, line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let msg: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return Some(
                json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("parse error: {e}") }
                })
                .to_string(),
            );
        }
    };

    let id = msg.get("id").cloned();
    // Notifications have no id — no response.
    if id.is_none() || id.as_ref().is_some_and(|v| v.is_null()) {
        return None;
    }

    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(Value::Null);

    let result = match method {
        "initialize" => Ok(initialize_result()),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(tools_list_result()),
        "tools/call" => tools_call(rt, &params),
        other => Err((-32601, format!("method not found: {other}"))),
    };

    Some(match result {
        Ok(value) => json!({ "jsonrpc": "2.0", "id": id, "result": value }).to_string(),
        Err((code, message)) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": code, "message": message }
        })
        .to_string(),
    })
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": {} },
        "serverInfo": {
            "name": "botzr-aegis-mcp",
            "version": env!("CARGO_PKG_VERSION")
        },
        "instructions": "Research instrument. Every tools/call walks POLICY → CAPABILITY → SANDBOX → AUDIT. Catalog: echo (allow) + exfil (policy-denied by default). Dreamd stays in-process (examples/dreamd-poc); this binary is for external MCP hosts."
    })
}

fn tools_list_result() -> Value {
    json!({
        "tools": [
            {
                "name": ECHO_TOOL_ID,
                "description": "Echo text through Aegis POLICY → CAPABILITY → SANDBOX → AUDIT (Model A WASM). Allowed by default policy.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "UTF-8 text echoed through the pipeline"
                        }
                    },
                    "required": ["text"]
                }
            },
            {
                "name": EXFIL_TOOL_ID,
                "description": "Deny-smoke tool: same Model A WASM as echo, but default policy denies it at station 1. Use to prove MCP → runtime → audit on refuse paths.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "Would-be payload (never executed under default policy)"
                        }
                    },
                    "required": ["text"]
                }
            }
        ]
    })
}

fn tools_call(rt: &Runtime, params: &Value) -> Result<Value, (i32, String)> {
    let name = params
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or((-32602, "tools/call missing name".into()))?;

    if !CATALOG_TOOL_IDS.contains(&name) {
        return Ok(json!({
            "content": [{ "type": "text", "text": format!("unknown tool: {name}") }],
            "isError": true
        }));
    }

    let text = params
        .pointer("/arguments/text")
        .and_then(|t| t.as_str())
        .ok_or((-32602, format!("{name} requires arguments.text")))?;

    match call_tool(rt, name, text) {
        Ok(bytes) => {
            let out = String::from_utf8_lossy(&bytes).into_owned();
            Ok(json!({
                "content": [{ "type": "text", "text": out }],
                "isError": false
            }))
        }
        // Pipeline already audited deny/trap/error. Includes a stable
        // machine-readable error code for programmatic consumers.
        Err(err) => Ok(json!({
            "content": [{ "type": "text", "text": err.to_string() }],
            "isError": true,
            "code": error_code(&err)
        })),
    }
}

/// Stable machine-readable error code for each AegisError variant.
fn error_code(err: &AegisError) -> &'static str {
    match err {
        AegisError::PolicyDenied { .. } => "POLICY_DENIED",
        AegisError::RateLimited { .. } => "RATE_LIMITED",
        AegisError::PendingApproval { .. } => "PENDING_APPROVAL",
        AegisError::CapabilityDenied { .. } => "CAPABILITY_DENIED",
        AegisError::Trap { .. } => "TRAP",
        AegisError::ResourceExceeded { .. } => "RESOURCE_EXCEEDED",
        AegisError::HostDenied { .. } => "HOST_DENIED",
        AegisError::Audit { .. } => "AUDIT_ERROR",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::build_runtime;
    use tempfile::NamedTempFile;

    #[test]
    fn tools_list_exposes_multi_tool_catalog() {
        let rt = build_runtime(None, None).expect("runtime");
        let listed = handle_line(&rt, r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
            .expect("tools/list");
        assert!(listed.contains("\"echo\""));
        assert!(listed.contains("\"exfil\""));
    }

    #[test]
    fn tools_call_via_jsonrpc_emits_audit_outcome() {
        let audit = NamedTempFile::new().expect("temp audit");
        let rt = build_runtime(None, Some(audit.path())).expect("runtime");

        let init = handle_line(
            &rt,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"#,
        )
        .expect("initialize response");
        assert!(init.contains("botzr-aegis-mcp"));

        let listed = handle_line(&rt, r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
            .expect("tools/list");
        assert!(listed.contains("\"echo\""));
        assert!(listed.contains("\"exfil\""));

        let called = handle_line(
            &rt,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"mcp-smoke"}}}"#,
        )
        .expect("tools/call");
        assert!(called.contains("mcp-smoke"));
        assert!(called.contains("\"isError\":false"));

        let jsonl = std::fs::read_to_string(audit.path()).expect("audit");
        let outcome = jsonl
            .lines()
            .find(|l| l.contains("\"phase\":\"outcome\""))
            .expect("outcome");
        assert!(outcome.contains("\"schema_version\":1"));
        assert!(outcome.contains("\"status\":\"success\""));
    }

    #[test]
    fn tools_call_exfil_deny_audited_via_jsonrpc() {
        let audit = NamedTempFile::new().expect("temp audit");
        let rt = build_runtime(None, Some(audit.path())).expect("runtime");

        let called = handle_line(
            &rt,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exfil","arguments":{"text":"payload"}}}"#,
        )
        .expect("tools/call");
        assert!(
            called.contains("\"isError\":true"),
            "expected isError, got: {called}"
        );

        let jsonl = std::fs::read_to_string(audit.path()).expect("audit");
        let outcome = jsonl
            .lines()
            .find(|l| l.contains("\"phase\":\"outcome\""))
            .expect("outcome");
        assert!(outcome.contains("\"schema_version\":1"));
        assert!(
            outcome.contains("\"status\":\"denied\"")
                || outcome.contains("MCP deny-smoke: exfil blocked"),
            "expected deny audit, got: {outcome}"
        );
        assert!(outcome.contains("\"tool_id\":\"exfil\""));
    }

    #[test]
    fn tools_call_exfil_returns_machine_readable_error_code() {
        let rt = build_runtime(None, None).expect("runtime");

        let called = handle_line(
            &rt,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exfil","arguments":{"text":"payload"}}}"#,
        )
        .expect("tools/call");
        assert!(
            called.contains("\"isError\":true"),
            "expected isError, got: {called}"
        );
        assert!(
            called.contains("POLICY_DENIED"),
            "expected POLICY_DENIED error code, got: {called}"
        );
    }

    #[test]
    fn handle_line_edges() {
        let audit = NamedTempFile::new().expect("temp audit");
        let rt = build_runtime(None, Some(audit.path())).expect("runtime");

        // Empty input and notifications (no id / null id): silence.
        assert_eq!(handle_line(&rt, ""), None);
        assert_eq!(handle_line(&rt, "   "), None);
        assert_eq!(handle_line(&rt, r#"{"jsonrpc":"2.0","method":"x"}"#), None);
        assert_eq!(
            handle_line(&rt, r#"{"jsonrpc":"2.0","id":null,"method":"x"}"#),
            None
        );

        // Parse error → -32700 with null id.
        let parse = handle_line(&rt, "{not json").expect("parse error response");
        assert!(parse.contains("-32700"), "parse: {parse}");

        // Unknown method → -32601.
        let nf = handle_line(&rt, r#"{"jsonrpc":"2.0","id":7,"method":"nope"}"#).expect("resp");
        assert!(nf.contains("-32601"), "not found: {nf}");

        // Ping → empty result object.
        let pong = handle_line(&rt, r#"{"jsonrpc":"2.0","id":8,"method":"ping"}"#).expect("resp");
        assert!(pong.contains("\"result\""), "ping: {pong}");

        // tools/call with unknown tool name → isError content, not a JSON-RPC error.
        let unk = handle_line(
            &rt,
            r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"ghost","arguments":{"text":"x"}}}"#,
        )
        .expect("resp");
        assert!(
            unk.contains("unknown tool") && unk.contains("isError"),
            "unknown: {unk}"
        );
    }
}
