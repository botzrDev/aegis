//! Host-minted capability grants (unforgeable; default-deny).

use std::fmt;

use crate::tool::ToolId;

/// Default per-call output ceiling when a manifest omits `max_output_bytes`
/// (1 MiB). The runtime enforces this orchestrator-side on the bytes a call
/// returns — it is not a wasmtime store limit (guest output is host-side).
pub const DEFAULT_MAX_OUTPUT_BYTES: u64 = 1 << 20;

/// Newtype for the identifier of a minted grant, as referenced from an audit
/// record. Distinct from [`crate::policy::ApprovalId`] so the two cannot be
/// cross-referenced to the wrong thing.
///
/// `CapabilityGrant::grant_id` is still a `String`: migrating it reaches into
/// the capability crate, the runtime, and every fixture, which is outside the
/// schema bump.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct GrantId(pub String);

impl GrantId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Resolved grant passed to sandbox configuration and host-function enforcement.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapabilityGrant {
    pub grant_id: String,
    pub tool_id: ToolId,
    /// Omitted when the grant carries no filesystem authority — never null. A
    /// grant is nested inside `CapabilityOutcome::Granted` on the audit record,
    /// so it lives under the record's own omit-never-null rule: the JCS
    /// canonicalizer refuses a `null` rather than pick a spelling for "absent"
    /// (ADR-0003).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs: Option<FsGrant>,
    /// Omitted when the grant carries no network authority — see [`Self::fs`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<NetGrant>,
    pub max_memory_bytes: u64,
    pub max_wall_ms: u64,
    /// Max bytes a single call may return. Enforced by the runtime after a
    /// successful Model A sandbox run or Model B host effect; oversize output
    /// fails closed to `ResourceExceeded { kind: "output" }` (never truncated).
    pub max_output_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FsGrant {
    pub read_paths: Vec<String>,
    pub write_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetGrant {
    pub http: Vec<HttpGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HttpGrant {
    pub host: String,
    pub ports: Vec<u16>,
    pub methods: Vec<String>,
}

impl CapabilityGrant {
    pub fn deny_all(tool_id: ToolId, grant_id: impl Into<String>) -> Self {
        Self {
            grant_id: grant_id.into(),
            tool_id,
            fs: None,
            net: None,
            max_memory_bytes: 0,
            max_wall_ms: 0,
            max_output_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_all_grants_nothing() {
        let g = CapabilityGrant::deny_all(ToolId::new("t"), "grant-0");
        assert_eq!(g.grant_id, "grant-0");
        assert_eq!(g.tool_id, ToolId::new("t"));
        assert!(g.fs.is_none());
        assert!(g.net.is_none());
        assert_eq!(g.max_memory_bytes, 0);
        assert_eq!(g.max_wall_ms, 0);
        assert_eq!(g.max_output_bytes, 0);
    }
}
