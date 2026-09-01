//! Core types for the Aegis enforcement pipeline.
//!
//! Dependency direction: all runtime crates depend inward on this crate only.

mod audit;
mod digest;
mod error;
mod grant;
mod http_check;
pub mod jcs;
mod limits;
mod policy;
mod tool;

pub use audit::{
    line_type_field, line_type_from_value, ApprovalVerdict, ApprovedScope, AuditClose,
    AuditDecision, AuditIntent, AuditLineType, AuditOpen, AuditRecord, AuditSchemaVersion,
    CallMetrics, CapabilityOutcome, DecisionAxes, ExecutionOutcome, FsAxis, NetAxis, PolicyOutcome,
    SessionCounter, SignedLine, AUDIT_SCHEMA_VERSION,
};
pub use digest::{
    Digest, DigestParseError, KeyId, PolicySetHash, PrevHash, PublicKey, RequestDigest,
    ResponseDigest, Signature,
};
pub use error::AegisError;
pub use grant::{
    CapabilityGrant, FsGrant, GrantId, HttpGrant, NetGrant, DEFAULT_MAX_MEMORY_BYTES,
    DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_MAX_WALL_MS,
};
pub use http_check::{http_get_allowed, parse_http_authority, parse_http_host};
pub use jcs::{canonical_digest, to_canonical_json, JcsError};
pub use limits::ResourceCeiling;
pub use policy::{ApprovalId, PolicyAction};
pub use tool::ToolId;

/// Load-bearing pipeline order (do not reorder).
///
/// This constant is documentation, not the guarantee. The order is enforced by
/// `policy_deny_never_invokes_execution_adapter` and
/// `capability_deny_never_invokes_execution_adapter` in
/// `crates/botzr-aegis-runtime/src/pipeline.rs`, which drive the pipeline with a
/// spy adapter and prove execution is unreachable behind each station.
pub const PIPELINE_STAGES: &[&str] = &["policy", "capability", "sandbox", "audit"];

/// Model B (host-effect) pipeline order — no sandbox station. Host tools run
/// their effect in host Rust, so isolation comes from the capability grant
/// and audit alone (do not reorder).
///
/// Enforced by the same two tests as [`PIPELINE_STAGES`] —
/// `policy_deny_never_invokes_execution_adapter` and
/// `capability_deny_never_invokes_execution_adapter` in
/// `crates/botzr-aegis-runtime/src/pipeline.rs`. Both register a
/// `ToolExecutable::HostHandler`, so they exercise this Model B path and not a
/// Model-A-only one.
pub const HOST_PIPELINE_STAGES: &[&str] = &["policy", "capability", "audit"];
