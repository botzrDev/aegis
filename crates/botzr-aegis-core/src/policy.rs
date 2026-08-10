//! Policy evaluation outcomes.

use std::fmt;

/// Synchronous policy verdict for a tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyAction {
    Allow,
    Deny { reason: String },
    RateLimited { reason: String },
    PendingApproval { approval_id: String },
}

/// Newtype for the identifier a `PendingApproval` verdict mints, as referenced
/// from an audit record's decision axes and from a `Decision` line.
///
/// The `approval_id ↔ decision` link is a **soft** cross-reference — it may
/// span Sessions and files, because a human approving after a restart is
/// normal (ADR-0005). `PolicyAction::PendingApproval` keeps a `String`:
/// migrating it reaches through the policy engine and the runtime error type,
/// which is outside the schema bump.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ApprovalId(pub String);

impl ApprovalId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ApprovalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
