//! Audit record types (schema-versioned).

use crate::grant::CapabilityGrant;
use crate::policy::PolicyAction;
use crate::tool::ToolId;

pub type AuditSchemaVersion = u32;

pub const AUDIT_SCHEMA_VERSION: AuditSchemaVersion = 1;

/// Phase marker for two-phase JSONL durability (G3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPhase {
    Intent,
    Outcome,
}

/// Pre-execution intent line — appended before sandbox work begins.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditIntent {
    pub schema_version: AuditSchemaVersion,
    pub phase: AuditPhase,
    pub call_id: String,
    pub tool_id: ToolId,
    pub input_digest: String,
}

impl AuditIntent {
    pub fn new(
        call_id: impl Into<String>,
        tool_id: ToolId,
        input_digest: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            phase: AuditPhase::Intent,
            call_id: call_id.into(),
            tool_id,
            input_digest: input_digest.into(),
        }
    }
}

/// Observed resource usage for a sandboxed call (R5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct CallMetrics {
    pub wall_ms: u64,
    pub peak_memory_bytes: u64,
}

/// Post-execution outcome line — one per call, every exit path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    pub schema_version: AuditSchemaVersion,
    pub phase: AuditPhase,
    pub call_id: String,
    pub tool_id: ToolId,
    pub input_digest: String,
    pub policy: PolicyOutcome,
    pub capability: CapabilityOutcome,
    pub execution: ExecutionOutcome,
    /// Wall-clock time for sandbox execution. Omitted when the sandbox never ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_ms: Option<u64>,
    /// Peak guest linear memory during sandbox execution. Omitted when the sandbox never ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_memory_bytes: Option<u64>,
}

impl AuditRecord {
    pub fn new(
        call_id: impl Into<String>,
        tool_id: ToolId,
        input_digest: impl Into<String>,
        policy: PolicyOutcome,
        capability: CapabilityOutcome,
        execution: ExecutionOutcome,
    ) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            phase: AuditPhase::Outcome,
            call_id: call_id.into(),
            tool_id,
            input_digest: input_digest.into(),
            policy,
            capability,
            execution,
            wall_ms: None,
            peak_memory_bytes: None,
        }
    }

    pub fn with_metrics(mut self, metrics: CallMetrics) -> Self {
        self.wall_ms = Some(metrics.wall_ms);
        self.peak_memory_bytes = Some(metrics.peak_memory_bytes);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PolicyOutcome {
    Allowed,
    Denied { reason: String },
    RateLimited { reason: String },
    PendingApproval { approval_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CapabilityOutcome {
    Granted {
        grant: CapabilityGrant,
    },
    Denied {
        reason: String,
        /// Machine-readable capability axis (e.g. `fs`, `net.http`) for audit consumers.
        denied_capability: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExecutionOutcome {
    Success,
    Trap { message: String },
    ResourceExceeded { kind: String },
    HostDenied { reason: String },
}

impl From<&PolicyAction> for PolicyOutcome {
    fn from(action: &PolicyAction) -> Self {
        match action {
            PolicyAction::Allow => Self::Allowed,
            PolicyAction::Deny { reason } => Self::Denied {
                reason: reason.clone(),
            },
            PolicyAction::RateLimited { reason } => Self::RateLimited {
                reason: reason.clone(),
            },
            PolicyAction::PendingApproval { approval_id } => Self::PendingApproval {
                approval_id: approval_id.clone(),
            },
        }
    }
}
