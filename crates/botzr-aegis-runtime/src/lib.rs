//! Library-mode entry point — wires the enforcement pipeline in load-bearing order.

use botzr_aegis_core::{
    AuditRecord, CapabilityOutcome, ExecutionOutcome, PolicyOutcome, ToolId, AUDIT_SCHEMA_VERSION,
    PIPELINE_STAGES,
};
use botzr_aegis_policy::{self, PolicySet};
use botzr_aegis_sandbox::SandboxEngine;

/// Runtime configuration (placeholder).
#[derive(Debug, Default)]
pub struct Runtime {
    policy: PolicySet,
    sandbox: SandboxEngine,
}

impl Runtime {
    pub fn new() -> Self {
        Self::default()
    }

    /// Execute a tool call through POLICY → CAPABILITY → SANDBOX → AUDIT.
    pub fn execute_tool_call(
        &self,
        tool_id: ToolId,
        input_digest: String,
        input: &[u8],
    ) -> Result<Vec<u8>, String> {
        let policy_action = botzr_aegis_policy::evaluate(&self.policy, &tool_id);
        let policy_outcome = PolicyOutcome::from(&policy_action);

        if !matches!(policy_outcome, PolicyOutcome::Allowed) {
            let record = AuditRecord {
                schema_version: AUDIT_SCHEMA_VERSION,
                tool_id: tool_id.clone(),
                input_digest,
                policy: policy_outcome,
                capability: CapabilityOutcome::Denied {
                    reason: "policy blocked before capability".into(),
                },
                execution: ExecutionOutcome::HostDenied {
                    reason: "not executed".into(),
                },
            };
            botzr_aegis_audit::emit(&record)?;
            return Err("policy denied".into());
        }

        let capability_outcome = botzr_aegis_capability::resolve(tool_id.clone());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_order_is_load_bearing() {
        assert_eq!(
            pipeline_stages(),
            &["policy", "capability", "sandbox", "audit"]
        );
    }
}
