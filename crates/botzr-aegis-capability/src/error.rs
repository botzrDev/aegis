//! Capability resolver errors — audit-ready, structured denials.

use thiserror::Error;

/// Resolution or narrowing failure with enough detail for audit + caller hints.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapabilityError {
    #[error("tool not registered: {tool_id}")]
    ToolNotRegistered { tool_id: String },

    #[error("invalid path `{path}`: {reason}")]
    InvalidPath { path: String, reason: String },

    #[error("unsupported capability `{capability}` in v1")]
    UnsupportedCapability { capability: String },

    #[error("net denied for host `{host}`: {reason}")]
    NetDenied { host: String, reason: String },

    #[error("capability escalation: {detail}")]
    Escalation { detail: String },

    #[error("fs denied for path `{path}`: {reason}")]
    FsDenied { path: String, reason: String },
}

impl CapabilityError {
    /// Machine-readable capability axis for audit records.
    pub fn denied_capability(&self) -> String {
        match self {
            Self::ToolNotRegistered { .. } => "tool.registry".into(),
            Self::InvalidPath { .. } | Self::FsDenied { .. } => "fs".into(),
            Self::UnsupportedCapability { capability } => capability.clone(),
            Self::NetDenied { .. } => "net.http".into(),
            Self::Escalation { detail } => {
                if detail.contains("net.http") || detail.contains("net") {
                    "net.http".into()
                } else if detail.contains("max_memory") || detail.contains("max_wall") {
                    "limits".into()
                } else {
                    "fs".into()
                }
            }
        }
    }
}
