//! Policy engine — YAML parse once → `PolicySet`, sync eval (<100 µs target).

use botzr_aegis_core::{PolicyAction, ToolId};

/// Parsed policy set (placeholder until YAML loader lands in AEG-9).
#[derive(Debug, Default)]
pub struct PolicySet;

/// Evaluate policy for a tool call. Stub: allow-all until AEG-9.
pub fn evaluate(_policy: &PolicySet, _tool_id: &ToolId) -> PolicyAction {
    PolicyAction::Allow
}
