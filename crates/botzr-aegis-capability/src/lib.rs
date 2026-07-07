//! Capability resolver — default-deny grant minting (core IP).

use botzr_aegis_core::{CapabilityGrant, CapabilityOutcome, ToolId};

/// Resolve declared tool needs into a host-minted grant. Stub: deny-all until AEG-5.
pub fn resolve(tool_id: ToolId) -> CapabilityOutcome {
    CapabilityOutcome::Denied {
        reason: format!("capability resolver not implemented for {}", tool_id),
    }
}

/// Mint helper for tests and future manifest parsing.
pub fn mint_deny_all(tool_id: ToolId, grant_id: impl Into<String>) -> CapabilityGrant {
    CapabilityGrant::deny_all(tool_id, grant_id)
}
