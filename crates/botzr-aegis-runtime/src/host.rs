//! Model B host-tool execution — POLICY → CAPABILITY → effect → AUDIT.
//!
//! Host tools skip the WASM sandbox station; the grant is enforced by the
//! effect handler before any I/O. Audit still wraps the full call.

use botzr_aegis_core::{AegisError, ExecutionOutcome, ToolId};
use botzr_aegis_policy::PolicyRequest;

use crate::pipeline::ExecutionStep;
use crate::{ExecutableSlot, HostEffectContext, Runtime};

/// A WASM slot reached through the Model B entry point: fail closed.
fn wasm_via_host_entry() -> ExecutionStep {
    ExecutionStep::Failed {
        outcome: ExecutionOutcome::HostDenied {
            reason: "wasm tool must be invoked via execute_tool_call".into(),
        },
        metrics: None,
    }
}

/// Policy axes + payload for a Model B host tool call.
///
/// There is deliberately no `request_digest` field: the runtime derives it
/// from the raw `input` bytes inside the pipeline so audit cannot record a
/// digest the caller made up (AEG-44 §3.C).
#[derive(Debug, Clone)]
pub struct HostCallRequest<'a> {
    pub tool_id: ToolId,
    pub input: &'a [u8],
    pub policy: PolicyRequest<'a>,
}

impl<'a> HostCallRequest<'a> {
    pub fn new(tool_id: ToolId, input: &'a [u8], policy: PolicyRequest<'a>) -> Self {
        Self {
            tool_id,
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

impl Runtime {
    /// Execute a Model B host tool through POLICY → CAPABILITY → effect → AUDIT.
    ///
    /// The effect is the [`HostHandler`](crate::HostHandler) stored when the
    /// tool was registered with [`Runtime::register_tool`]; it receives a
    /// [`HostEffectContext`] built from the minted grant, so grant enforcement
    /// is structural. Sandbox is not invoked.
    ///
    /// Fails closed when the tool is absent from the registry, and when the
    /// registered slot is a WASM executable (use
    /// [`Runtime::execute_tool_call`] for those).
    ///
    /// Model B adapter: the shared [`Runtime::drive_pipeline`] owns policy,
    /// capability, output-cap, and audit; this method only supplies the host
    /// effect as the execution step.
    pub fn execute_host_call(&self, req: HostCallRequest<'_>) -> Result<Vec<u8>, AegisError> {
        let HostCallRequest {
            tool_id,
            input,
            policy,
        } = req;
        let registry_id = tool_id.clone();
        self.drive_pipeline(
            tool_id,
            input,
            &policy,
            // Execution step: resolve the registered handler and run it behind
            // the AEG-43 choke point. It never reports sandbox metrics; the
            // driver still applies the output cap to its bytes.
            move |grant| match self.tools.get(&registry_id) {
                Some(registration) => match &registration.slot {
                    ExecutableSlot::Host(handler) => {
                        let ctx = HostEffectContext::new(grant);
                        match handler(&ctx, input) {
                            Ok(bytes) => ExecutionStep::Produced {
                                bytes,
                                metrics: None,
                            },
                            Err(err) => ExecutionStep::Failed {
                                outcome: err.to_execution_outcome(),
                                metrics: None,
                            },
                        }
                    }
                    ExecutableSlot::Wasm(_) => wasm_via_host_entry(),
                    #[cfg(feature = "test-utils")]
                    ExecutableSlot::WasmFixture { .. } => wasm_via_host_entry(),
                },
                None => ExecutionStep::Failed {
                    outcome: ExecutionOutcome::HostDenied {
                        reason: "tool not registered in runtime".into(),
                    },
                    metrics: None,
                },
            },
        )
    }

    /// Execute a Model B host tool with a caller-supplied effect closure.
    ///
    /// The `effect` closure receives the minted grant and must enforce it before
    /// any host-side I/O. Sandbox is not invoked.
    ///
    /// **Research escape hatch:** production / Aegis-owned effects must use
    /// [`HostEffectContext`](crate::HostEffectContext), which enforces the grant
    /// structurally. Grant enforcement for a raw closure passed here is the
    /// caller's responsibility — the runtime checks nothing before the effect
    /// runs, and applies only the output cap after it returns. This API is kept
    /// for research and experiment wiring; it is not a supported way to ship an
    /// effect.
    ///
    /// Prefer the registry path [`Runtime::execute_host_call`], which runs the
    /// handler registered atomically with the tool's manifest.
    ///
    /// Model B adapter: the shared [`Runtime::drive_pipeline`] owns policy,
    /// capability, output-cap, and audit; this method only supplies the host
    /// effect as the execution step.
    pub fn execute_host_call_with<F>(
        &self,
        req: HostCallRequest<'_>,
        effect: F,
    ) -> Result<Vec<u8>, AegisError>
    where
        F: FnOnce(&botzr_aegis_core::CapabilityGrant, &[u8]) -> Result<Vec<u8>, HostEffectError>,
    {
        let HostCallRequest {
            tool_id,
            input,
            policy,
        } = req;
        self.drive_pipeline(
            tool_id,
            input,
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
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use botzr_aegis_capability::{ToolInfo, ToolKind, ToolLimits, ToolManifest};
    use botzr_aegis_core::{AegisError, CapabilityGrant, HOST_PIPELINE_STAGES};

    use crate::{HostHandler, ToolExecutable};

    /// Host manifest with the given id and optional output ceiling.
    fn host_manifest(id: &str, max_output_bytes: Option<u64>) -> ToolManifest {
        let manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new(id),
                version: "0.1.0".into(),
                kind: ToolKind::Host,
            },
            std::env::temp_dir(),
        );
        match max_output_bytes {
            Some(max_output_bytes) => manifest.with_limits(ToolLimits {
                max_output_bytes,
                ..ToolLimits::default()
            }),
            None => manifest,
        }
    }

    /// Register a Host tool atomically with its effect handler.
    fn register_host(
        rt: &mut Runtime,
        id: &str,
        max_output_bytes: Option<u64>,
        handler: HostHandler,
    ) {
        rt.register_tool(
            host_manifest(id, max_output_bytes),
            ToolExecutable::HostHandler(handler),
        )
        .expect("register host tool");
    }

    #[test]
    fn host_pipeline_omits_sandbox() {
        assert_eq!(HOST_PIPELINE_STAGES, &["policy", "capability", "audit"]);
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
        let mut rt =
            Runtime::new().with_policy(botzr_aegis_policy::PolicyEngine::from_yaml(yaml).unwrap());
        // Registered with an effect that *would* succeed — so the denial below
        // can only have come from station 1.
        register_host(
            &mut rt,
            "append_node",
            None,
            Box::new(|_ctx, _input| Ok(b"ok".to_vec())),
        );

        let tool = ToolId::new("append_node");
        let err = rt
            .execute_host_call(HostCallRequest::new(
                tool.clone(),
                b"{}",
                PolicyRequest::for_tool(&tool),
            ))
            .unwrap_err();
        assert_eq!(
            err,
            AegisError::PolicyDenied {
                reason: "blocked in test".into()
            }
        );
    }

    #[test]
    fn host_call_emits_audit_on_success() {
        let mut rt = Runtime::new();
        register_host(
            &mut rt,
            "host-echo",
            None,
            Box::new(|_ctx, input| Ok(input.to_vec())),
        );

        let tool = ToolId::new("host-echo");
        let input = b"ping";
        let out = rt
            .execute_host_call(HostCallRequest::new(
                tool.clone(),
                input,
                PolicyRequest::for_tool(&tool),
            ))
            .expect("host echo succeeds");
        assert_eq!(out, input);

        let lines: Vec<String> = std::fs::read_to_string(rt.audit().path())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        // Line 0 is the Session `Open` the writer emits on construction.
        assert_eq!(lines.len(), 3, "open + intent + outcome lines");
        assert!(lines[2].contains("\"status\":\"success\""));
    }

    #[test]
    fn host_output_over_cap_trips_resource_exceeded() {
        // Model B: an effect that returns more bytes than the grant's
        // `max_output_bytes` fails closed to ResourceExceeded { kind: "output" }
        // — the same cap the runtime applies to a Model A sandbox output.
        let mut rt = Runtime::new();
        register_host(
            &mut rt,
            "host-bulky",
            Some(8),
            // Effect enforced the grant for its own I/O but returns 100 bytes.
            Box::new(|_ctx, _input| Ok(vec![b'x'; 100])),
        );

        let tool = ToolId::new("host-bulky");
        let err = rt
            .execute_host_call(HostCallRequest::new(
                tool.clone(),
                b"{}",
                PolicyRequest::for_tool(&tool),
            ))
            .unwrap_err();
        assert_eq!(
            err,
            AegisError::ResourceExceeded {
                kind: "output".into()
            }
        );

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
        register_host(
            &mut rt,
            "gated",
            None,
            Box::new(|_ctx, _input| {
                Err(HostEffectError::GrantDenied {
                    reason: "path outside grant".into(),
                })
            }),
        );

        let tool = ToolId::new("gated");
        let err = rt
            .execute_host_call(HostCallRequest::new(
                tool.clone(),
                b"{}",
                PolicyRequest::for_tool(&tool),
            ))
            .unwrap_err();
        assert_eq!(
            err,
            AegisError::HostDenied {
                reason: "path outside grant".into()
            }
        );

        let text = std::fs::read_to_string(rt.audit().path()).unwrap();
        assert!(text.contains("path outside grant"));
    }

    #[test]
    fn escape_hatch_still_runs_a_raw_closure() {
        // `execute_host_call_with` is retained for research wiring: it takes the
        // raw grant, bypasses the registry, and the driver still audits + caps.
        let mut rt = Runtime::new();
        register_host(
            &mut rt,
            "gated",
            None,
            // Registry handler would deny — the escape hatch must not consult it.
            Box::new(|_ctx, _input| {
                Err(HostEffectError::GrantDenied {
                    reason: "registry handler ran".into(),
                })
            }),
        );

        let tool = ToolId::new("gated");
        let out = rt
            .execute_host_call_with(
                HostCallRequest::new(tool.clone(), b"raw", PolicyRequest::for_tool(&tool)),
                |grant: &CapabilityGrant, input| {
                    assert_eq!(grant.tool_id, tool);
                    Ok(input.to_vec())
                },
            )
            .expect("escape hatch runs the supplied closure");
        assert_eq!(out, b"raw");

        let text = std::fs::read_to_string(rt.audit().path()).unwrap();
        assert!(text.contains("\"status\":\"success\""), "{text}");
        assert!(!text.contains("registry handler ran"), "{text}");
    }
}
