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
    /// A synchronous entry point was called from inside a tokio runtime.
    ///
    /// The runtime's sync entry points block on an executor, which tokio
    /// forbids from an async context. Rather than let that panic — or record
    /// an audit line for a call that never reached a station — the entry point
    /// refuses before the session opens. This is an embedder integration bug,
    /// not a denied call: no Agent Action Record is written for it.
    NestedRuntime {
        /// The sync entry that was called: `execute_tool_call`,
        /// `execute_host_call`, or `execute_host_call_with`.
        entry: String,
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
            Self::NestedRuntime { entry } => write!(
                f,
                "cannot call {entry} from inside a tokio runtime; use the async entry point"
            ),
        }
    }
}

impl std::error::Error for AegisError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_covers_every_variant() {
        let cases = [
            (
                AegisError::PolicyDenied { reason: "r".into() },
                "policy denied: r",
            ),
            (
                AegisError::RateLimited { reason: "r".into() },
                "rate limited: r",
            ),
            (
                AegisError::PendingApproval {
                    approval_id: "apr-1".into(),
                },
                "pending approval: apr-1",
            ),
            (
                AegisError::CapabilityDenied {
                    reason: "r".into(),
                    denied_capability: Some("fs".into()),
                },
                "capability denied: r",
            ),
            (
                AegisError::Trap {
                    message: "m".into(),
                },
                "trap: m",
            ),
            (
                AegisError::ResourceExceeded {
                    kind: "memory".into(),
                },
                "resource exceeded: memory",
            ),
            (
                AegisError::HostDenied { reason: "r".into() },
                "host denied: r",
            ),
            (
                AegisError::Audit {
                    message: "m".into(),
                },
                "audit error: m",
            ),
            (
                AegisError::NestedRuntime {
                    entry: "execute_tool_call".into(),
                },
                "cannot call execute_tool_call from inside a tokio runtime; use the async entry point",
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
    }
}
