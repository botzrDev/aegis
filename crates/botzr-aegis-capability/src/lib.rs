//! Capability resolver — default-deny grant minting (core IP).
//!
//! Station 2 of the enforcement pipeline (POLICY → **CAPABILITY** → SANDBOX →
//! AUDIT). Tools declare *needs* via [`ToolManifest`]; the runtime mints
//! unforgeable [`CapabilityGrant`]s. Denials are audit-ready and never reach
//! the sandbox.

mod error;
mod manifest;
mod mint;
mod narrow;
mod resolver;

pub use error::CapabilityError;
pub use manifest::{
    FsNeeds, HttpNeed, NetNeeds, PathNeed, ToolInfo, ToolKind, ToolLimits, ToolManifest,
    DEFAULT_MAX_MEMORY_BYTES, DEFAULT_MAX_WALL_MS,
};
pub use mint::{mint_grant, PolicyCeiling};
pub use narrow::{grant_is_subset, narrow_grant};
pub use resolver::{mint_deny_all, resolve, CapabilityResolver};
