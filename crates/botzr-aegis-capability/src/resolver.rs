//! Capability resolver — default-deny grant minting from registered manifests.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use botzr_aegis_core::{CapabilityGrant, CapabilityOutcome, ToolId};

use crate::error::CapabilityError;
use crate::manifest::ToolManifest;
use crate::mint::{mint_grant, PolicyCeiling};

static GRANT_SEQ: AtomicU64 = AtomicU64::new(1);

fn next_grant_id(tool_id: &ToolId) -> String {
    format!("{}-{}", tool_id, GRANT_SEQ.fetch_add(1, Ordering::Relaxed))
}

/// In-memory tool registry + resolver. Production wiring lands in AEG-23.
#[derive(Debug, Default)]
pub struct CapabilityResolver {
    tools: HashMap<ToolId, ToolManifest>,
    ceiling: PolicyCeiling,
}

impl CapabilityResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_ceiling(mut self, ceiling: PolicyCeiling) -> Self {
        self.ceiling = ceiling;
        self
    }

    /// Register a tool manifest. Re-registration replaces the prior entry.
    pub fn register(&mut self, manifest: ToolManifest) {
        self.tools.insert(manifest.tool.id.clone(), manifest);
    }

    /// Resolve declared needs for a registered tool into a host-minted grant,
    /// applying only the resolver's standing ceiling.
    #[must_use = "capability resolution must be handled — denial never reaches sandbox"]
    pub fn resolve(&self, tool_id: &ToolId) -> CapabilityOutcome {
        self.resolve_with_ceiling(tool_id, PolicyCeiling::default())
    }

    /// Resolve with an additional per-call ceiling (e.g. one the policy engine
    /// derived for this call). The call ceiling is folded into the resolver's
    /// standing ceiling by [`PolicyCeiling::combine`], so it can only *lower*
    /// limits — policy never raises what a tool declared.
    #[must_use = "capability resolution must be handled — denial never reaches sandbox"]
    pub fn resolve_with_ceiling(
        &self,
        tool_id: &ToolId,
        call_ceiling: PolicyCeiling,
    ) -> CapabilityOutcome {
        match self.resolve_inner(tool_id, self.ceiling.combine(call_ceiling)) {
            Ok(grant) => CapabilityOutcome::Granted { grant },
            Err(err) => CapabilityOutcome::Denied {
                reason: err.to_string(),
                denied_capability: Some(err.denied_capability()),
            },
        }
    }

    fn resolve_inner(
        &self,
        tool_id: &ToolId,
        ceiling: PolicyCeiling,
    ) -> Result<CapabilityGrant, CapabilityError> {
        let manifest =
            self.tools
                .get(tool_id)
                .ok_or_else(|| CapabilityError::ToolNotRegistered {
                    tool_id: tool_id.to_string(),
                })?;
        mint_grant(manifest, next_grant_id(tool_id), ceiling)
    }

    /// Resolve a manifest directly (used for tests and one-off minting).
    #[must_use = "capability resolution must be handled — denial never reaches sandbox"]
    pub fn resolve_manifest(&self, manifest: &ToolManifest) -> CapabilityOutcome {
        match mint_grant(manifest, next_grant_id(&manifest.tool.id), self.ceiling) {
            Ok(grant) => CapabilityOutcome::Granted { grant },
            Err(err) => CapabilityOutcome::Denied {
                reason: err.to_string(),
                denied_capability: Some(err.denied_capability()),
            },
        }
    }
}

/// Compatibility shim for the runtime stub until AEG-23 wires a shared registry.
///
/// Uses a process-wide empty resolver — unregistered tools are denied.
pub fn resolve(tool_id: ToolId) -> CapabilityOutcome {
    CapabilityResolver::new().resolve(&tool_id)
}

/// Mint helper for tests and deny-all baselines.
pub fn mint_deny_all(tool_id: ToolId, grant_id: impl Into<String>) -> CapabilityGrant {
    CapabilityGrant::deny_all(tool_id, grant_id)
}
