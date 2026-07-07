//! Library-mode entry point — wires the enforcement pipeline in load-bearing order.

use botzr_aegis_audit::{AuditError, AuditWriter, CallSession};
use botzr_aegis_capability::{CapabilityResolver, PolicyCeiling};
use botzr_aegis_core::{
    CapabilityOutcome, ExecutionOutcome, PolicyAction, PolicyOutcome, ToolId, PIPELINE_STAGES,
};
use botzr_aegis_policy::{PolicyEngine, PolicyRequest};
use botzr_aegis_sandbox::SandboxEngine;

/// Runtime configuration.
#[derive(Debug)]
pub struct Runtime {
    policy: PolicyEngine,
    capabilities: CapabilityResolver,
    sandbox: SandboxEngine,
    audit: AuditWriter,
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

    /// Replace the audit sink (default is a temp JSONL file).
    pub fn with_audit(mut self, audit: AuditWriter) -> Self {
        self.audit = audit;
        self
    }

    /// Access the policy engine (e.g. for hot reload).
    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    /// Access the audit writer (e.g. for tests asserting JSONL output).
    pub fn audit(&self) -> &AuditWriter {
        &self.audit
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
        let mut session = CallSession::begin(&self.audit, tool_id.clone(), input_digest.clone())
            .map_err(audit_err_to_string)?;

        // Station 1 — POLICY. Grab the active set once; a denied, rate-limited,
        // or pending-approval call is rejected here and never mints a grant.
        let decision = self.policy.evaluate(&PolicyRequest::for_tool(&tool_id));
        let policy_outcome = PolicyOutcome::from(&decision.action);

        if !matches!(policy_outcome, PolicyOutcome::Allowed) {
            session.set_policy(policy_outcome);
            session.set_capability(CapabilityOutcome::Denied {
                reason: "policy blocked before capability".into(),
                denied_capability: None,
            });
            session.set_execution(ExecutionOutcome::HostDenied {
                reason: "not executed".into(),
            });
            session.complete().map_err(audit_err_to_string)?;
            return Err(policy_rejection_message(&decision.action));
        }

        session.set_policy(PolicyOutcome::Allowed);

        // Station 2 — CAPABILITY. Fold any policy-derived ceiling into the
        // resolver (lowers limits only; never raises).
        let ceiling = PolicyCeiling {
            max_memory_bytes: decision.limits.max_memory_bytes,
            max_wall_ms: decision.limits.max_wall_ms,
        };
        let capability_outcome = self.capabilities.resolve_with_ceiling(&tool_id, ceiling);
        session.set_capability(capability_outcome.clone());

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

        session.set_execution(execution);
        session.complete().map_err(audit_err_to_string)?;

        output.ok_or_else(|| "execution failed".into())
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            policy: PolicyEngine::allow_all(),
            capabilities: CapabilityResolver::new(),
            sandbox: SandboxEngine::default(),
            audit: AuditWriter::open_temp().expect("temp audit sink must open"),
        }
    }
}

/// Returns pipeline stage names in order (for tests and docs).
pub fn pipeline_stages() -> &'static [&'static str] {
    PIPELINE_STAGES
}

fn audit_err_to_string(err: AuditError) -> String {
    format!("audit failure (fail-closed): {err}")
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

        let lines: Vec<String> = std::fs::read_to_string(rt.audit().path())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(lines.len(), 2, "intent + outcome lines");
        assert!(lines[0].contains("\"phase\":\"intent\""));
        assert!(lines[1].contains("\"status\":\"denied\""));
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
