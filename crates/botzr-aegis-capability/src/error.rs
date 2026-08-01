//! Capability resolver errors — audit-ready, structured denials.

use std::fmt;

use thiserror::Error;

/// The capability axis an escalation was attempted on.
///
/// Typed at the raise site (see `narrow.rs`) rather than recovered by sniffing
/// a human-readable message: the audit `denied_capability` field is a
/// machine-readable contract, and parsing prose to produce it makes the wording
/// of an error message load-bearing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationAxis {
    /// Filesystem read/write reach.
    Fs,
    /// Outbound HTTP host/port/method reach.
    NetHttp,
    /// Resource ceilings (memory, wall clock, output bytes).
    Limits,
}

impl EscalationAxis {
    /// Machine-readable axis name as it appears in audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fs => "fs",
            Self::NetHttp => "net.http",
            Self::Limits => "limits",
        }
    }
}

impl fmt::Display for EscalationAxis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resolution or narrowing failure with enough detail for audit + caller hints.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapabilityError {
    #[error("tool not registered: {tool_id}")]
    ToolNotRegistered { tool_id: String },

    #[error("invalid path `{path}`: {reason}")]
    InvalidPath { path: String, reason: String },

    #[error("net denied for host `{host}`: {reason}")]
    NetDenied { host: String, reason: String },

    #[error("capability escalation on {axis}: {detail}")]
    Escalation {
        axis: EscalationAxis,
        detail: String,
    },
}

impl CapabilityError {
    /// Machine-readable capability axis for audit records.
    pub fn denied_capability(&self) -> String {
        match self {
            Self::ToolNotRegistered { .. } => "tool.registry".into(),
            Self::InvalidPath { .. } => "fs".into(),
            Self::NetDenied { .. } => "net.http".into(),
            Self::Escalation { axis, .. } => axis.as_str().into(),
        }
    }
}
