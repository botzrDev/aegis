//! Capability resolver — default-deny grant minting from registered manifests.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use botzr_aegis_core::{CapabilityGrant, CapabilityOutcome, GrantId, ResourceCeiling, ToolId};

use crate::error::CapabilityError;
use crate::manifest::ToolManifest;
use crate::mint::{mint_grant, prepare_grant, PreparedGrant};

/// In-memory tool registry + resolver. Production wiring lands in AEG-23.
#[derive(Debug)]
pub struct CapabilityResolver {
    /// Registered tools, each already canonicalized (AILAB-846). The value is
    /// the *outcome* of preparing the manifest, error included — see
    /// [`Self::register`] for why the error is stored rather than raised there.
    tools: HashMap<ToolId, Result<PreparedGrant, CapabilityError>>,
    ceiling: ResourceCeiling,
    /// Monotonic grant-id counter, scoped to this resolver (AILAB-846). It was a
    /// process-global `static` until then, which made ids unique across every
    /// resolver in the process by accident rather than by design.
    grant_seq: AtomicU64,
}

impl Default for CapabilityResolver {
    /// Starts the grant sequence at 1, not 0, so a fresh resolver's first grant
    /// is `<tool>-1` — the numbering the process-global counter produced and the
    /// numbering the golden vectors spell.
    fn default() -> Self {
        Self {
            tools: HashMap::new(),
            ceiling: ResourceCeiling::default(),
            grant_seq: AtomicU64::new(1),
        }
    }
}

impl CapabilityResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Next grant id for `tool_id`.
    ///
    /// **Unique within this resolver, and only within it.** Two resolvers in one
    /// process now hand out the same ids; a grant id identifies a mint *relative
    /// to the resolver that minted it*, not globally, and nothing may treat it as
    /// a process-wide or cross-run key. A record that must be identified on its
    /// own carries `call_id`. Before AILAB-846 the counter was a `static` and ids
    /// happened to be process-unique — that was never a documented guarantee, and
    /// it is not one now.
    fn next_grant_id(&self, tool_id: &ToolId) -> GrantId {
        GrantId::new(format!(
            "{}-{}",
            tool_id,
            self.grant_seq.fetch_add(1, Ordering::Relaxed)
        ))
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
    ///
    /// # Declared paths are canonicalized here, once (AILAB-846)
    ///
    /// Resolution used to `std::fs::canonicalize` every declared path on every
    /// call. It now happens once, here, and [`Self::resolve_with_ceiling`] reuses
    /// the result. Two consequences, both deliberate:
    ///
    /// * **A declared path deleted after registration is no longer caught at
    ///   mint.** It used to make the next resolution deny with
    ///   [`CapabilityError::InvalidPath`]; it now mints a grant naming a path
    ///   that no longer resolves, and the call fails when the sandbox opens it.
    ///   Nothing that was protected has become unprotected: canonicalizing at
    ///   call time never closed that window either — the path could be replaced
    ///   between the `canonicalize` and the `open` — and what actually confines a
    ///   call is the cap-std preopen the sandbox builds from the grant, which is
    ///   taken at open time. The change is *where the error surfaces*, not
    ///   whether the reach is bounded. Grant revalidation is deliberately not
    ///   built here.
    /// * **Registration still cannot fail.** Canonicalization can, and this
    ///   method returns `()`. The failure is stored against the tool and returned
    ///   by resolution, so a manifest whose declared path never existed denies at
    ///   exactly the same point it always did.
    #[doc(hidden)]
    #[deprecated(
        note = "external crates must register tools via Runtime::register_tool — \
                registering a manifest alone creates split authority"
    )]
    pub fn register(&mut self, manifest: ToolManifest) {
        let tool_id = manifest.tool.id.clone();
        self.tools.insert(tool_id, prepare_grant(&manifest));
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
        let prepared = self
            .tools
            .get(tool_id)
            .ok_or_else(|| CapabilityError::ToolNotRegistered {
                tool_id: tool_id.to_string(),
            })?
            // Registration decided this and could not report it (see `register`).
            // Replaying it here keeps a bad manifest denying at the same call it
            // always denied at.
            .as_ref()
            .map_err(Clone::clone)?;
        Ok(prepared.instantiate(self.next_grant_id(tool_id), ceiling))
    }

    /// Resolve a manifest directly without registering it.
    ///
    /// One-off minting for surfaces that are not the WASM tool registry —
    /// `aegis wrap --confine` builds a `ToolManifest` from CLI flags and needs
    /// the same grant path the pipeline uses (AILAB-628). Registering that
    /// manifest would be the split-authority state `register` is deprecated
    /// against: there is no executable to pair it with.
    ///
    /// This path canonicalizes at call time and must keep doing so: there is no
    /// registry entry to have prepared, because there is no registration
    /// (AILAB-846).
    #[must_use = "capability resolution must be handled — denial never reaches sandbox"]
    pub fn resolve_manifest(&self, manifest: &ToolManifest) -> CapabilityOutcome {
        match mint_grant(
            manifest,
            self.next_grant_id(&manifest.tool.id),
            self.ceiling,
        ) {
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
pub fn mint_deny_all(tool_id: ToolId, grant_id: impl Into<GrantId>) -> CapabilityGrant {
    CapabilityGrant::deny_all(tool_id, grant_id)
}
