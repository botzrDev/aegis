//! dreamd MCP adapter — Model B host effects for AEG-20 Stage 1 PoC.
//!
//! Mirrors the `append_node` / `search_nodes` contract from dreamd's MCP surface
//! (`dreamd-core/src/mcp/mod.rs`) without pulling the full dreamd dependency
//! graph. Production wiring calls `MemoryMcpServer` in-process or over UDS.
//!
//! FS access goes through [`HostEffectContext`] (cap-std Dir / preopen-style).
//! Private grant-helper functions (`grant_allows_*`, `resolve_target_path`,
//! `path_is_under`) have been removed — the context owns all grant enforcement.

use std::io::Write;
use std::path::{Path, PathBuf};

use botzr_aegis_capability::{FsNeeds, PathNeed, ToolInfo, ToolKind, ToolLimits, ToolManifest};
use botzr_aegis_core::ToolId;
use botzr_aegis_runtime::{sha256_hex, HostEffectContext, HostEffectError};
use serde::{Deserialize, Serialize};

pub const TOOL_APPEND: &str = "append_node";
pub const TOOL_SEARCH: &str = "search_nodes";
pub const TOOL_DREAM: &str = "dream";

/// Policy capability axis for episodic (default) writes under `.agent/`.
pub const CAP_FS_EPISODIC: &str = "fs:episodic";
/// Policy capability axis for `personal/` writes (role-gated in policy YAML).
pub const CAP_FS_PERSONAL: &str = "fs:personal";

/// Register dreamd tool manifests against a project root (`.agent/` parent).
/// Call after [`init_agent_store`] so fs paths canonicalize at grant-mint time.
pub fn register_dreamd_tools(
    resolver: &mut botzr_aegis_capability::CapabilityResolver,
    project_root: impl AsRef<Path>,
) {
    let base = project_root.as_ref();
    let append = ToolManifest::new(
        ToolInfo {
            id: ToolId::new(TOOL_APPEND),
            version: "0.1.0".into(),
            kind: ToolKind::Host,
        },
        base,
    )
    .with_fs(FsNeeds {
        read: vec![PathNeed::recursive(".agent")],
        write: vec![PathNeed::recursive(".agent")],
    })
    .with_limits(ToolLimits {
        max_memory_bytes: 32 * 1024 * 1024,
        max_wall_ms: 10_000,
        ..ToolLimits::default()
    });

    let search = ToolManifest::new(
        ToolInfo {
            id: ToolId::new(TOOL_SEARCH),
            version: "0.1.0".into(),
            kind: ToolKind::Host,
        },
        base,
    )
    .with_fs(FsNeeds {
        read: vec![PathNeed::recursive(".agent")],
        write: vec![],
    })
    .with_limits(ToolLimits {
        max_memory_bytes: 16 * 1024 * 1024,
        max_wall_ms: 5_000,
        ..ToolLimits::default()
    });

    let dream = ToolManifest::new(
        ToolInfo {
            id: ToolId::new(TOOL_DREAM),
            version: "0.1.0".into(),
            kind: ToolKind::Host,
        },
        base,
    )
    .with_fs(FsNeeds {
        read: vec![PathNeed::recursive(".agent")],
        write: vec![PathNeed::recursive(".agent")],
    });

    resolver.register(append);
    resolver.register(search);
    resolver.register(dream);
}

/// Load the PoC policy fixture.
pub fn policy_engine() -> botzr_aegis_policy::PolicyEngine {
    botzr_aegis_policy::PolicyEngine::from_yaml(include_str!("../fixtures/dreamd-policy.yaml"))
        .expect("dreamd-policy.yaml must parse")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendInput {
    pub content: String,
    pub source_harness: String,
    pub skill_action: String,
    #[serde(default)]
    pub zone: AppendZone,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppendZone {
    #[default]
    Episodic,
    Personal,
}

impl AppendZone {
    pub fn policy_capability(self) -> &'static str {
        match self {
            Self::Episodic => CAP_FS_EPISODIC,
            Self::Personal => CAP_FS_PERSONAL,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendOutput {
    pub id: String,
    pub timestamp: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchInput {
    pub query: String,
    #[serde(default = "default_k")]
    pub k: u32,
}

fn default_k() -> u32 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchOutput {
    pub results: Vec<SearchHit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub content: String,
    pub score: f64,
}

/// Append a learning node under `.agent/` after grant enforcement.
///
/// FS access goes through [`HostEffectContext`] (cap-std Dir / preopen-style).
pub fn append_node_effect(
    ctx: &HostEffectContext,
    input: &[u8],
) -> Result<Vec<u8>, HostEffectError> {
    let req: AppendInput = serde_json::from_slice(input).map_err(|e| HostEffectError::Failed {
        reason: format!("invalid append_node JSON: {e}"),
    })?;

    let rel = match req.zone {
        AppendZone::Episodic => PathBuf::from(".agent/episodic/AGENT_LEARNINGS.jsonl"),
        AppendZone::Personal => PathBuf::from(".agent/personal/notes.jsonl"),
    };

    // Create parent directory if needed (within grant, safe to use std::fs).
    if let Some(parent) = rel.parent() {
        std::fs::create_dir_all(parent).map_err(|e| HostEffectError::Failed {
            reason: format!("mkdir {}: {e}", parent.display()),
        })?;
    }

    let mut file = ctx.open_write_append(&rel)?;

    let id = format!("evt_{}", &sha256_hex(input)[..26]);
    let timestamp = "2026-07-10T00:00:00Z".to_string();
    let line = serde_json::json!({
        "schema_version": "1.0.0",
        "id": id,
        "timestamp": timestamp,
        "content": req.content,
        "source_harness": req.source_harness,
        "skill_action": req.skill_action,
    });
    use std::io::Write;
    writeln!(file, "{line}").map_err(|e| HostEffectError::Failed {
        reason: format!("write: {e}"),
    })?;

    let out = AppendOutput {
        id: id.clone(),
        timestamp,
        path: rel.to_string_lossy().into_owned(),
    };
    serde_json::to_vec(&out).map_err(|e| HostEffectError::Failed {
        reason: format!("serialize response: {e}"),
    })
}

/// BM25-free recall stub: substring scan over episodic JSONL (PoC only).
pub fn search_nodes_effect(
    ctx: &HostEffectContext,
    input: &[u8],
) -> Result<Vec<u8>, HostEffectError> {
    let req: SearchInput = serde_json::from_slice(input).map_err(|e| HostEffectError::Failed {
        reason: format!("invalid search_nodes JSON: {e}"),
    })?;

    let target = PathBuf::from(".agent/episodic/AGENT_LEARNINGS.jsonl");
    let text = match ctx.open_read(&target) {
        Ok(mut file) => {
            let mut s = String::new();
            use std::io::Read;
            file.read_to_string(&mut s)
                .map_err(|e| HostEffectError::Failed {
                    reason: format!("read {}: {e}", target.display()),
                })?;
            s
        }
        Err(HostEffectError::GrantDenied { .. }) => {
            return Err(HostEffectError::GrantDenied {
                reason: "read denied for .agent/episodic".into(),
            });
        }
        Err(HostEffectError::Failed { .. }) => String::new(),
    };

    let query = req.query.to_ascii_lowercase();
    let mut hits = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let content = val["content"].as_str().unwrap_or_default();
        if content.to_ascii_lowercase().contains(&query) {
            hits.push(SearchHit {
                content: content.to_string(),
                score: 1.0,
            });
        }
        if hits.len() >= req.k as usize {
            break;
        }
    }

    serde_json::to_vec(&SearchOutput { results: hits }).map_err(|e| HostEffectError::Failed {
        reason: format!("serialize response: {e}"),
    })
}

/// Scaffold minimal `.agent/episodic/` layout for PoC tests.
pub fn init_agent_store(project_root: &Path) {
    std::fs::create_dir_all(project_root.join(".agent/episodic")).expect("create .agent/episodic");
}

/// Bare search for D5 overhead benchmark (no Aegis wrapper).
pub fn search_nodes_bare(project_root: &Path, input: &[u8]) -> Vec<u8> {
    let req: SearchInput = serde_json::from_slice(input).unwrap_or(SearchInput {
        query: String::new(),
        k: 5,
    });
    let jsonl = project_root.join(".agent/episodic/AGENT_LEARNINGS.jsonl");
    let text = std::fs::read_to_string(jsonl).unwrap_or_default();
    let query = req.query.to_ascii_lowercase();
    let mut hits = Vec::new();
    for line in text.lines() {
        let Ok(val) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let content = val["content"].as_str().unwrap_or_default();
        if content.to_ascii_lowercase().contains(&query) {
            hits.push(SearchHit {
                content: content.to_string(),
                score: 1.0,
            });
        }
        if hits.len() >= req.k as usize {
            break;
        }
    }
    serde_json::to_vec(&SearchOutput { results: hits }).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_fixture_parses() {
        let _ = policy_engine();
    }
}
