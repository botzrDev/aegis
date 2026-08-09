//! Host-minted capability grants (unforgeable; default-deny).

use crate::tool::ToolId;

/// Default per-call output ceiling when a manifest omits `max_output_bytes`
/// (1 MiB). The runtime enforces this orchestrator-side on the bytes a call
/// returns — it is not a wasmtime store limit (guest output is host-side).
pub const DEFAULT_MAX_OUTPUT_BYTES: u64 = 1 << 20;

/// Resolved grant passed to sandbox configuration and host-function enforcement.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapabilityGrant {
    pub grant_id: String,
    pub tool_id: ToolId,
    pub fs: Option<FsGrant>,
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
