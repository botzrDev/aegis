//! Capability resolver — default-deny grant minting from registered manifests.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use botzr_aegis_core::{CapabilityGrant, CapabilityOutcome, ResourceCeiling, ToolId};

use crate::error::CapabilityError;
use crate::manifest::ToolManifest;
use crate::mint::mint_grant;

static GRANT_SEQ: AtomicU64 = AtomicU64::new(1);

fn next_grant_id(tool_id: &ToolId) -> String {
    format!("{}-{}", tool_id, GRANT_SEQ.fetch_add(1, Ordering::Relaxed))
}

/// In-memory tool registry + resolver. Production wiring lands in AEG-23.
#[derive(Debug, Default)]
pub struct CapabilityResolver {
    tools: HashMap<ToolId, ToolManifest>,
    ceiling: ResourceCeiling,
}

impl CapabilityResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_ceiling(mut self, ceiling: ResourceCeiling) -> Self {
        self.ceiling = ceiling;
        self
    }

    /// Register a tool manifest. Re-registration replaces the prior entry.
    ///
    /// **Runtime-internal.** Writing a manifest here without also installing the
    /// tool's executable is the split-authority state AEG-44 closed: it mints
    /// authority for a tool that cannot run, and lets the two be swapped
    /// independently. External crates must register through
    /// `botzr_aegis_runtime::Runtime::register_tool`, which writes both together
    /// or neither. Rust cannot scope visibility to one sibling crate, so this is
    /// marked deprecated to make external use a compile error under `deny`.
    #[doc(hidden)]
    #[deprecated(
        note = "external crates must register tools via Runtime::register_tool — \
                registering a manifest alone creates split authority"
    )]
    pub fn register(&mut self, manifest: ToolManifest) {
        self.tools.insert(manifest.tool.id.clone(), manifest);
    }

    /// Resolve declared needs for a registered tool into a host-minted grant,
    /// applying only the resolver's standing ceiling.
    #[must_use = "capability resolution must be handled — denial never reaches sandbox"]
    pub fn resolve(&self, tool_id: &ToolId) -> CapabilityOutcome {
        self.resolve_with_ceiling(tool_id, ResourceCeiling::default())
    }

    /// Resolve with an additional per-call ceiling (e.g. one the policy engine
    /// derived for this call). The call ceiling is folded into the resolver's
    /// standing ceiling by [`ResourceCeiling::combine`], so it can only *lower*
    /// limits — policy never raises what a tool declared.
    #[must_use = "capability resolution must be handled — denial never reaches sandbox"]
    pub fn resolve_with_ceiling(
        &self,
        tool_id: &ToolId,
        call_ceiling: ResourceCeiling,
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
        ceiling: ResourceCeiling,
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
    /// Requires the `test-utils` feature.
    #[cfg(feature = "test-utils")]
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

/// Test-only convenience: resolve a tool id against a fresh, empty resolver.
///
/// The resolver has no registered manifests, so every tool id is denied with
/// `ToolNotRegistered` — this is a deny-everything baseline, not a production
/// resolution path. Real resolution goes through a `CapabilityResolver` owned by
/// `botzr_aegis_runtime::Runtime`. Requires the `test-utils` feature.
#[cfg(feature = "test-utils")]
pub fn resolve(tool_id: ToolId) -> CapabilityOutcome {
    CapabilityResolver::new().resolve(&tool_id)
}

/// Mint helper for tests and deny-all baselines. Requires the `test-utils`
/// feature.
#[cfg(feature = "test-utils")]
pub fn mint_deny_all(tool_id: ToolId, grant_id: impl Into<String>) -> CapabilityGrant {
    CapabilityGrant::deny_all(tool_id, grant_id)
}
