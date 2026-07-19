//! Typed errors surfaced by the runtime API.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AegisError {
    PolicyDenied {
        reason: String,
    },
    RateLimited {
        reason: String,
    },
    PendingApproval {
        approval_id: String,
    },
    CapabilityDenied {
        reason: String,
        denied_capability: Option<String>,
    },
    Trap {
        message: String,
    },
    ResourceExceeded {
        kind: String,
    },
    HostDenied {
        reason: String,
    },
    Audit {
        message: String,
    },
}

impl fmt::Display for AegisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyDenied { reason } => write!(f, "policy denied: {reason}"),
            Self::RateLimited { reason } => write!(f, "rate limited: {reason}"),
            Self::PendingApproval { approval_id } => {
                write!(f, "pending approval: {approval_id}")
            }
            Self::CapabilityDenied {
                reason,
                denied_capability: _,
            } => write!(f, "capability denied: {reason}"),
            Self::Trap { message } => write!(f, "trap: {message}"),
            Self::ResourceExceeded { kind } => write!(f, "resource exceeded: {kind}"),
            Self::HostDenied { reason } => write!(f, "host denied: {reason}"),
            Self::Audit { message } => write!(f, "audit error: {message}"),
        }
    }
}

impl std::error::Error for AegisError {}
