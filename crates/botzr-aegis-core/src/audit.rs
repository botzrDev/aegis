//! Audit record types (schema-versioned).

use crate::grant::CapabilityGrant;
use crate::policy::PolicyAction;
use crate::tool::ToolId;

pub type AuditSchemaVersion = u32;

pub const AUDIT_SCHEMA_VERSION: AuditSchemaVersion = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub schema_version: AuditSchemaVersion,
    pub tool_id: ToolId,
    pub input_digest: String,
    pub policy: PolicyOutcome,
    pub capability: CapabilityOutcome,
    pub execution: ExecutionOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyOutcome {
    Allowed,
    Denied { reason: String },
    RateLimited { reason: String },
    PendingApproval { approval_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityOutcome {
    Granted { grant: CapabilityGrant },
    Denied { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
