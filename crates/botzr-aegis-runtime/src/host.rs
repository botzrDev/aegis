//! Model B host-tool execution — POLICY → CAPABILITY → effect → AUDIT.
//!
//! Host tools skip the WASM sandbox station; the grant is enforced by the
//! effect handler before any I/O. Audit still wraps the full call.

use botzr_aegis_core::{ExecutionOutcome, ToolId, PIPELINE_STAGES};
use botzr_aegis_policy::PolicyRequest;

use crate::pipeline::ExecutionStep;
use crate::Runtime;

/// Policy axes + payload for a Model B host tool call.
#[derive(Debug, Clone)]
pub struct HostCallRequest<'a> {
    pub tool_id: ToolId,
    pub input_digest: String,
    pub input: &'a [u8],
    pub policy: PolicyRequest<'a>,
}

impl<'a> HostCallRequest<'a> {
    pub fn new(
        tool_id: ToolId,
        input_digest: impl Into<String>,
        input: &'a [u8],
        policy: PolicyRequest<'a>,
    ) -> Self {
        Self {
            tool_id,
            input_digest: input_digest.into(),
            input,
            policy,
        }
    }
}

/// Host-side execution error surfaced to the caller after audit emission.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostEffectError {
    #[error("grant denied effect: {reason}")]
    GrantDenied { reason: String },
    #[error("effect failed: {reason}")]
    Failed { reason: String },
}

impl HostEffectError {
    fn to_execution_outcome(&self) -> ExecutionOutcome {
        match self {
            Self::GrantDenied { reason } | Self::Failed { reason } => {
                ExecutionOutcome::HostDenied {
                    reason: reason.clone(),
                }
            }
        }
    }
}

/// Pipeline stages for Model B (sandbox is not in the hot path).
pub fn host_pipeline_stages() -> &'static [&'static str] {
    &["policy", "capability", "audit"]
}

impl Runtime {
    /// Execute a Model B host tool through POLICY → CAPABILITY → effect → AUDIT.
    ///
    /// The `effect` closure receives the minted grant and must enforce it before
    /// any host-side I/O. Sandbox is not invoked.
    ///
    /// Model B adapter: the shared [`Runtime::drive_pipeline`] owns policy,
    /// capability, output-cap, and audit; this method only supplies the host
    /// effect as the execution step and Model B's caller error string (the host
    /// denial reason, or `"host execution failed"` for any other no-output
    /// outcome).
    pub fn execute_host_call<F>(
        &self,
        req: HostCallRequest<'_>,
        effect: F,
    ) -> Result<Vec<u8>, String>
    where
        F: FnOnce(&botzr_aegis_core::CapabilityGrant, &[u8]) -> Result<Vec<u8>, HostEffectError>,
    {
        let HostCallRequest {
            tool_id,
            input_digest,
            input,
            policy,
        } = req;
        self.drive_pipeline(
            tool_id,
            input_digest,
            &policy,
            // Execution step: run the host effect. It never reports sandbox
            // metrics; the driver still applies the output cap to its bytes.
            move |grant| match effect(grant, input) {
                Ok(bytes) => ExecutionStep::Produced {
                    bytes,
                    metrics: None,
                },
                Err(err) => ExecutionStep::Failed {
                    outcome: err.to_execution_outcome(),
                    metrics: None,
                },
            },
            // Model B surfaces a host denial's reason; anything else (e.g. an
            // output-cap `ResourceExceeded`) collapses to a generic string.
            |outcome| match outcome {
                ExecutionOutcome::HostDenied { reason } => reason.clone(),
                _ => "host execution failed".to_string(),
            },
        )
    }
}

/// Load-bearing WASM pipeline order (includes sandbox).
pub fn wasm_pipeline_stages() -> &'static [&'static str] {
    PIPELINE_STAGES
}

#[cfg(test)]
mod tests {
    use super::*;
    use botzr_aegis_capability::{ToolInfo, ToolKind, ToolLimits, ToolManifest};
    use botzr_aegis_core::CapabilityGrant;

    #[test]
    fn host_pipeline_omits_sandbox() {
        assert_eq!(host_pipeline_stages(), &["policy", "capability", "audit"]);
    }

    #[test]
    fn policy_deny_short_circuits_host_call() {
        let yaml = r#"
version: 1
default: allow
rules:
  - id: block-append
    action: deny
    tool: append_node
    reason: "blocked in test"
"#;
        let rt =
            Runtime::new().with_policy(botzr_aegis_policy::PolicyEngine::from_yaml(yaml).unwrap());
        let tool = ToolId::new("append_node");
        let err = rt
            .execute_host_call(
                HostCallRequest::new(
                    tool.clone(),
                    "deadbeef",
                    b"{}",
                    PolicyRequest::for_tool(&tool),
                ),
                |_grant, _input| Ok(b"ok".to_vec()),
            )
            .unwrap_err();
        assert_eq!(err, "policy denied: blocked in test");
    }

    #[test]
    fn host_call_emits_audit_on_success() {
        let mut rt = Runtime::new();
        let base = std::env::temp_dir();
        let manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new("host-echo"),
                version: "0.1.0".into(),
                kind: ToolKind::Host,
            },
            &base,
        );
        rt.capabilities().register(manifest);

        let tool = ToolId::new("host-echo");
        let input = b"ping";
        let out = rt
            .execute_host_call(
                HostCallRequest::new(
                    tool.clone(),
                    crate::sha256_hex(input),
                    input,
                    PolicyRequest::for_tool(&tool),
                ),
                |_grant, input| Ok(input.to_vec()),
            )
            .expect("host echo succeeds");
        assert_eq!(out, input);

        let lines: Vec<String> = std::fs::read_to_string(rt.audit().path())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("\"status\":\"success\""));
    }

    #[test]
    fn host_output_over_cap_trips_resource_exceeded() {
        // Model B: an effect that returns more bytes than the grant's
        // `max_output_bytes` fails closed to ResourceExceeded { kind: "output" }
        // — the same cap the runtime applies to a Model A sandbox output.
        let mut rt = Runtime::new();
        let base = std::env::temp_dir();
        let manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new("host-bulky"),
                version: "0.1.0".into(),
                kind: ToolKind::Host,
            },
            &base,
        )
        .with_limits(ToolLimits {
            max_output_bytes: 8,
            ..ToolLimits::default()
        });
        rt.capabilities().register(manifest);

        let tool = ToolId::new("host-bulky");
        let err = rt
            .execute_host_call(
                HostCallRequest::new(tool.clone(), "abc", b"{}", PolicyRequest::for_tool(&tool)),
                // Effect enforced the grant for its own I/O but returns 100 bytes.
                |_grant: &CapabilityGrant, _input| Ok(vec![b'x'; 100]),
            )
            .unwrap_err();
        assert_eq!(err, "host execution failed");

        let outcome = std::fs::read_to_string(rt.audit().path())
            .unwrap()
            .lines()
            .last()
            .unwrap()
            .to_owned();
        assert!(
            outcome.contains("\"status\":\"resource_exceeded\""),
            "expected resource_exceeded, got: {outcome}"
        );
        assert!(
            outcome.contains("\"kind\":\"output\""),
            "expected kind=output, got: {outcome}"
        );
    }

    #[test]
    fn grant_denial_is_audited() {
        let mut rt = Runtime::new();
        let base = std::env::temp_dir();
        rt.capabilities().register(ToolManifest::new(
            ToolInfo {
                id: ToolId::new("gated"),
                version: "0.1.0".into(),
                kind: ToolKind::Host,
            },
            &base,
        ));

        let tool = ToolId::new("gated");
        let err = rt
            .execute_host_call(
                HostCallRequest::new(tool.clone(), "abc", b"{}", PolicyRequest::for_tool(&tool)),
                |_grant: &CapabilityGrant, _| {
                    Err(HostEffectError::GrantDenied {
                        reason: "path outside grant".into(),
                    })
                },
            )
            .unwrap_err();
        assert_eq!(err, "path outside grant");

        let text = std::fs::read_to_string(rt.audit().path()).unwrap();
        assert!(text.contains("path outside grant"));
    }
}
