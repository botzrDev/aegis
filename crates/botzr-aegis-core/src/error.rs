//! Typed errors surfaced by the runtime API.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AegisError {
    PolicyDenied {
        reason: String,
    },
    CapabilityDenied {
        reason: String,
    },
    PendingApproval {
        approval_id: String,
        expires_at: String,
    },
    Sandbox {
        message: String,
    },
    Audit {
        message: String,
    },
}

impl fmt::Display for AegisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyDenied { reason } => write!(f, "policy denied: {reason}"),
            Self::CapabilityDenied { reason } => write!(f, "capability denied: {reason}"),
            Self::PendingApproval {
                approval_id,
                expires_at,
            } => write!(f, "pending approval {approval_id} (expires {expires_at})"),
            Self::Sandbox { message } => write!(f, "sandbox error: {message}"),
            Self::Audit { message } => write!(f, "audit error: {message}"),
        }
    }
}

impl std::error::Error for AegisError {}
