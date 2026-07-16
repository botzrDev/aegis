//! Phase 2 MCP gateway — thin stdio adapter over `Runtime::execute_tool_call`.
//!
//! Security-relevant path is unchanged: POLICY → CAPABILITY → SANDBOX → AUDIT.
//! See [`DECISIONS.md`](../DECISIONS.md) for the D17 lock.

mod bridge;
mod mcp;

pub use bridge::{
    build_runtime, call_echo, call_tool, CATALOG_TOOL_IDS, DEFAULT_DENY_EXFIL_POLICY, ECHO_TOOL_ID,
    EXFIL_TOOL_ID,
};
pub use mcp::handle_line;
