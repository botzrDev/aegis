//! Tool identity and classification.

use std::fmt;

/// Newtype for tool identifiers (`[a-z0-9-]+` per manifest G1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ToolId(pub String);

impl ToolId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ToolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Model A (WASM guest) vs Model B (host functions for effects).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    Wasm,
    Host,
}
