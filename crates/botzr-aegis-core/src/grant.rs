//! Host-minted capability grants (unforgeable; default-deny).

use crate::tool::ToolId;

/// Resolved grant passed to sandbox configuration and host-function enforcement.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapabilityGrant {
    pub grant_id: String,
    pub tool_id: ToolId,
    pub fs: Option<FsGrant>,
    pub net: Option<NetGrant>,
    pub max_memory_bytes: u64,
    pub max_wall_ms: u64,
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
        }
    }
}
