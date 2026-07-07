//! Library-mode entry point — wires the enforcement pipeline in load-bearing order.

use botzr_aegis_capability::{CapabilityResolver, PolicyCeiling};
use botzr_aegis_core::{
    AuditRecord, CapabilityOutcome, ExecutionOutcome, PolicyAction, PolicyOutcome, ToolId,
    AUDIT_SCHEMA_VERSION, PIPELINE_STAGES,
};
use botzr_aegis_policy::{PolicyEngine, PolicyRequest};
use botzr_aegis_sandbox::SandboxEngine;

/// Runtime configuration.
#[derive(Debug)]
pub struct Runtime {
    policy: PolicyEngine,
    capabilities: CapabilityResolver,
    sandbox: SandboxEngine,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            policy: PolicyEngine::allow_all(),
            capabilities: CapabilityResolver::new(),
            sandbox: SandboxEngine::default(),
        }
    }
}

impl Runtime {
    pub fn new() -> Self {
        Self::default()
    }

    /// Swap in a configured policy engine (parsed once at startup).
    pub fn with_policy(mut self, policy: PolicyEngine) -> Self {
        self.policy = policy;
        self
    }

    /// Access the policy engine (e.g. for hot reload).
    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    /// Access the capability resolver for tool registration (AEG-23 expands this).
    pub fn capabilities(&mut self) -> &mut CapabilityResolver {
        &mut self.capabilities
    }

    /// Execute a tool call through POLICY → CAPABILITY → SANDBOX → AUDIT.
    pub fn execute_tool_call(
        &self,
        tool_id: ToolId,
        input_digest: String,
        input: &[u8],
    ) -> Result<Vec<u8>, String> {
        // Station 1 — POLICY. Grab the active set once; a denied, rate-limited,
        // or pending-approval call is rejected here and never mints a grant.
        let decision = self.policy.evaluate(&PolicyRequest::for_tool(&tool_id));
        let policy_outcome = PolicyOutcome::from(&decision.action);

        if !matches!(policy_outcome, PolicyOutcome::Allowed) {
            let record = AuditRecord {
                schema_version: AUDIT_SCHEMA_VERSION,
                tool_id: tool_id.clone(),
                input_digest,
                policy: policy_outcome,
                capability: CapabilityOutcome::Denied {
                    reason: "policy blocked before capability".into(),
                    denied_capability: None,
                },
                execution: ExecutionOutcome::HostDenied {
                    reason: "not executed".into(),
                },
            };
            botzr_aegis_audit::emit(&record)?;
            return Err(policy_rejection_message(&decision.action));
        }

        // Station 2 — CAPABILITY. Fold any policy-derived ceiling into the
        // resolver (lowers limits only; never raises).
        let ceiling = PolicyCeiling {
            max_memory_bytes: decision.limits.max_memory_bytes,
            max_wall_ms: decision.limits.max_wall_ms,
        };
        let capability_outcome = self.capabilities.resolve_with_ceiling(&tool_id, ceiling);
        let (execution, output) = match &capability_outcome {
            CapabilityOutcome::Granted { grant } => match self.sandbox.execute(grant, input) {
                Ok(bytes) => (ExecutionOutcome::Success, Some(bytes)),
                Err(message) => (
                    ExecutionOutcome::Trap {
                        message: message.clone(),
                    },
                    None,
                ),
            },
            CapabilityOutcome::Denied { .. } => (
                ExecutionOutcome::HostDenied {
                    reason: "capability denied".into(),
                },
                None,
            ),
        };

        let record = AuditRecord {
            schema_version: AUDIT_SCHEMA_VERSION,
            tool_id,
            input_digest,
            policy: PolicyOutcome::Allowed,
            capability: capability_outcome,
            execution,
        };
        botzr_aegis_audit::emit(&record)?;

        output.ok_or_else(|| "execution failed".into())
    }
}

/// Returns pipeline stage names in order (for tests and docs).
pub fn pipeline_stages() -> &'static [&'static str] {
    PIPELINE_STAGES
}

/// Caller-facing message for a policy rejection at station 1. Denials are
/// actionable by design (G4) — the reason travels back to the caller.
fn policy_rejection_message(action: &PolicyAction) -> String {
    match action {
        PolicyAction::Deny { reason } => format!("policy denied: {reason}"),
        PolicyAction::RateLimited { reason } => format!("policy rate limited: {reason}"),
        PolicyAction::PendingApproval { approval_id } => {
            format!("policy pending approval: {approval_id}")
        }
        // `Allow` never reaches this path.
        PolicyAction::Allow => "policy allowed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use botzr_aegis_policy::PolicyEngine;

    #[test]
    fn pipeline_order_is_load_bearing() {
        assert_eq!(
            pipeline_stages(),
            &["policy", "capability", "sandbox", "audit"]
        );
    }

    #[test]
    fn policy_deny_short_circuits_before_capability() {
        let yaml = r#"
version: 1
default: allow
rules:
  - id: block-smoke
    action: deny
    tool: smoke
    reason: "blocked in test"
"#;
        let rt = Runtime::new().with_policy(PolicyEngine::from_yaml(yaml).unwrap());
        let err = rt
            .execute_tool_call(ToolId::new("smoke"), "deadbeef".into(), b"{}")
            .unwrap_err();
        // Policy reason surfaces — proves station 1 rejected, not capability.
        assert_eq!(err, "policy denied: blocked in test");
    }

    #[test]
    fn pending_approval_blocks_before_capability() {
        let yaml = r#"
version: 1
default: allow
rules:
  - id: gate-smoke
    action: pending_approval
    tool: smoke
"#;
        let rt = Runtime::new().with_policy(PolicyEngine::from_yaml(yaml).unwrap());
        let err = rt
            .execute_tool_call(ToolId::new("smoke"), "deadbeef".into(), b"{}")
            .unwrap_err();
        assert!(
            err.starts_with("policy pending approval: apr-gate-smoke-smoke-"),
            "unexpected error: {err}"
        );
    }
}
