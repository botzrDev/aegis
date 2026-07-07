//! Policy evaluation outcomes.

/// Synchronous policy verdict for a tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyAction {
    Allow,
    Deny { reason: String },
    RateLimited { reason: String },
    PendingApproval { approval_id: String },
}
