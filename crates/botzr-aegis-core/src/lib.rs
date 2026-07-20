//! Core types for the Aegis enforcement pipeline.
//!
//! Dependency direction: all runtime crates depend inward on this crate only.

mod audit;
mod error;
mod grant;
mod http_check;
mod limits;
mod policy;
mod tool;

pub use audit::{
    AuditIntent, AuditPhase, AuditRecord, AuditSchemaVersion, CallMetrics, CapabilityOutcome,
    ExecutionOutcome, PolicyOutcome, AUDIT_SCHEMA_VERSION,
};
pub use error::AegisError;
pub use grant::{CapabilityGrant, FsGrant, HttpGrant, NetGrant, DEFAULT_MAX_OUTPUT_BYTES};
pub use http_check::{http_get_allowed, parse_http_host};
pub use limits::ResourceCeiling;
pub use policy::PolicyAction;
pub use tool::{ToolId, ToolKind};

/// Load-bearing pipeline order (do not reorder).
pub const PIPELINE_STAGES: &[&str] = &["policy", "capability", "sandbox", "audit"];
