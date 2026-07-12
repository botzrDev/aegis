//! Tool capability manifest — declared *needs* (G1 draft).
//!
//! Needs are a claim; the runtime mints unforgeable [`CapabilityGrant`]s from them.

use std::path::{Path, PathBuf};

use botzr_aegis_core::ToolId;

/// Default wall-clock ceiling when the manifest omits `[limits]`.
pub const DEFAULT_MAX_WALL_MS: u64 = 30_000;

/// Default memory ceiling when the manifest omits `[limits]`.
pub const DEFAULT_MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024;

/// Default per-call output ceiling when the manifest omits `[limits]`.
/// Single source of truth lives in `botzr-aegis-core`.
pub use botzr_aegis_core::DEFAULT_MAX_OUTPUT_BYTES;

/// Declared tool identity and classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInfo {
    pub id: ToolId,
    pub version: String,
    pub kind: ToolKind,
}

/// Model A (WASM guest) vs Model B (host functions for effects).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    Wasm,
    Host,
}

/// Full manifest: declared needs + limits. Paths are resolved relative to
/// [`ToolManifest::base_dir`] at grant-mint time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolManifest {
    pub tool: ToolInfo,
    pub fs: Option<FsNeeds>,
    pub net: Option<NetNeeds>,
    pub limits: ToolLimits,
    pub base_dir: PathBuf,
    /// Optional relative path to the WASM component (from `base_dir`).
    pub component_path: Option<PathBuf>,
    /// Optional SHA-256 pin (hex, lowercase). When set, registration refuses a
    /// digest mismatch (G10).
    pub sha256: Option<String>,
}

/// Filesystem needs — absence of `write` means write is denied.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FsNeeds {
    pub read: Vec<PathNeed>,
    pub write: Vec<PathNeed>,
}

/// Path-scoped fs need. `recursive` controls narrowing: a sub-tool may only
/// request a subdirectory when the parent declared `recursive = true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathNeed {
    pub path: String,
    pub recursive: bool,
}

/// Network needs — absence means full network deny.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetNeeds {
    pub http: Vec<HttpNeed>,
}

/// HTTP host allow-list entry (exact host match in v1; no subdomain wildcards).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpNeed {
    pub host: String,
    pub ports: Vec<u16>,
    pub methods: Vec<String>,
}

/// Tool-declared resource ceilings. Policy may lower these; it may never raise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolLimits {
    pub max_memory_bytes: u64,
    pub max_wall_ms: u64,
    pub max_output_bytes: u64,
}

impl Default for ToolLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
            max_wall_ms: DEFAULT_MAX_WALL_MS,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }
}

impl ToolManifest {
    pub fn new(tool: ToolInfo, base_dir: impl AsRef<Path>) -> Self {
        Self {
            tool,
            fs: None,
            net: None,
            limits: ToolLimits::default(),
            base_dir: base_dir.as_ref().to_path_buf(),
            component_path: None,
            sha256: None,
        }
    }

    pub fn with_fs(mut self, fs: FsNeeds) -> Self {
        self.fs = Some(fs);
        self
    }

    pub fn with_net(mut self, net: NetNeeds) -> Self {
        self.net = Some(net);
        self
    }

    pub fn with_limits(mut self, limits: ToolLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_component_path(mut self, path: impl AsRef<Path>) -> Self {
        self.component_path = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn with_sha256(mut self, sha256: impl Into<String>) -> Self {
        self.sha256 = Some(sha256.into());
        self
    }
}

impl PathNeed {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            recursive: false,
        }
    }

    pub fn recursive(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            recursive: true,
        }
    }
}

impl HttpNeed {
    pub fn get(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            ports: vec![443],
            methods: vec!["GET".to_string()],
        }
    }
}
