//! Audit record types (schema-versioned).
//!
//! Schema v2 makes every appended line a link in a hash chain: `seq` and
//! `prev_hash` fix the line's position, `signature` + `key_id` authenticate it,
//! and the decision axes carry enough of a verdict's inputs that a recorded
//! deny can explain itself rather than only assert itself (ADR-0001).
//!
//! Those five fields are **sealed** — private, stamped by `AuditWriter` inside
//! the same lock as the append, read through getters. A caller that can pick
//! its own chain position forks or forges the chain; a caller that can pick its
//! own schema version forges the trail wholesale. Sealing is what makes the
//! rule structural instead of a comment.

use crate::digest::{
    KeyId, PolicySetHash, PrevHash, PublicKey, RequestDigest, ResponseDigest, Signature,
};
use crate::grant::{CapabilityGrant, FsGrant, GrantId, NetGrant};
use crate::jcs::{self, JcsError};
use crate::policy::{ApprovalId, PolicyAction};
use crate::tool::ToolId;

pub type AuditSchemaVersion = u32;

/// v2: hash chain, digest newtypes, decision axes. Bumped from 1 by AILAB-619;
/// the Layer 2 governance ingest migrates under AILAB-624.
pub const AUDIT_SCHEMA_VERSION: AuditSchemaVersion = 2;

/// What kind of line this is. Wire field name is `line_type`.
///
/// `#[non_exhaustive]` **and** [`AuditLineType::Unknown`], deliberately both:
/// the attribute forces every downstream `match` to carry a wildcard so adding
/// a variant is not a breaking change, and `Unknown` keeps the raw token so a
/// verifier can say *"unknown line type `foo` at seq N, newer emitter"* instead
/// of failing to parse. A `#[serde(other)]` unit variant would lose the token
/// and with it the only useful half of that message.
///
/// An unrecognised line still hashes — it is bytes, and the chain stays valid —
/// but it caps a verifier's verdict at `Indeterminate`. A verifier must never
/// report `Verified` over content it does not understand, or a future emitter
/// can smuggle anything past an old auditor.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuditLineType {
    /// First line of a Session: carries the public key and the back-reference
    /// to the previous Session's tail.
    Open,
    /// Pre-execution intent line, appended and fsynced before sandbox work.
    Intent,
    /// The Agent Action Record — one per call, on every exit path.
    Outcome,
    /// A human approval verdict, with no intent and no execution (ADR-0005).
    Decision,
    /// Last line of a Session, written on `AuditWriter::drop`.
    Close,
    /// **Reserved.** No emitter in this repo ever produces a `Checkpoint`; the
    /// variant exists so that adding it later is not a breaking change for
    /// every downstream `match`. Verifiers must handle one (trivially — it is
    /// a signed line, so it extends Coverage).
    Checkpoint,
    /// A line type this build does not recognise, with its token preserved.
    /// Parse-only: nothing in this repo constructs one.
    Unknown(String),
}

impl AuditLineType {
    /// The wire token for this line type.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Open => "open",
            Self::Intent => "intent",
            Self::Outcome => "outcome",
            Self::Decision => "decision",
            Self::Close => "close",
            Self::Checkpoint => "checkpoint",
            Self::Unknown(raw) => raw,
        }
    }

    /// Parse a wire token, preserving anything unrecognised.
    pub fn from_wire(raw: &str) -> Self {
        match raw {
            "open" => Self::Open,
            "intent" => Self::Intent,
            "outcome" => Self::Outcome,
            "decision" => Self::Decision,
            "close" => Self::Close,
            "checkpoint" => Self::Checkpoint,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl std::fmt::Display for AuditLineType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for AuditLineType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for AuditLineType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <String as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Self::from_wire(&raw))
    }
}

/// The inputs a policy verdict actually turned on.
///
/// Nested under `decision_axes` rather than flattened, because `AuditRecord`
/// already has `capability` — the capability *station outcome* — and two
/// different things called `capability` on one line is the kind of collision
/// that survives review and breaks an ingest.
///
/// The object is **always emitted**, possibly as `{}`; its fields follow
/// omit-never-null. An empty `decision_axes` says "this emitter recorded no
/// axes"; an absent one would say nothing at all.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct DecisionAxes {
    /// The capability axis the call requested (e.g. `fs.read`, `net.http`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    /// The role asserted by the caller. Without it a role-gated deny cannot
    /// reproduce or explain its own verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// The policy session scope. Not the audit Session — this is the
    /// `PolicyRequest` scalar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// The rule that decided it. Turns a recheck diff from a verdict flip into
    /// an explanation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    /// The approval a resumed call was allowed under (ADR-0005). Without it,
    /// rechecking a resumed call cannot reconstruct why it was allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_ref: Option<ApprovalId>,
    /// Derived filesystem parameter, recorded when the runtime resolved one.
    /// Omitted entirely when the call had no fs need — never null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs: Option<FsAxis>,
    /// Derived network parameter, under the same omit rule as `fs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<NetAxis>,
}

/// The filesystem resource a call resolved to (ADR-0006).
///
/// Both spellings are recorded: matchers target the canonical path, and the raw
/// path is what the caller actually asked for — a diff between them is itself
/// evidence. SPEC.md must say plainly that derived paths appear in the
/// publishable Chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FsAxis {
    pub path_raw: String,
    pub path_canonical: String,
}

/// The network resource a call resolved to (ADR-0006).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetAxis {
    pub host: String,
    pub port: u16,
}

/// Pre-execution intent line — appended, flushed and fsynced before sandbox
/// work begins.
///
/// Carries nothing beyond identity and the request digest, and must stay that
/// way: everything on this line is on the pre-execution critical path. It is
/// hashed into the chain but never signed, for the same reason.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditIntent {
    /// Sealed: the schema version is owned by [`AuditIntent::new`], never the
    /// caller. A record that could be stamped with an arbitrary version is a
    /// forgeable audit trail. Read it with [`AuditIntent::schema_version`].
    schema_version: AuditSchemaVersion,
    /// Sealed: an intent line that could be relabelled `outcome` is a record
    /// claiming a call ran. Read it with [`AuditIntent::line_type`].
    line_type: AuditLineType,
    /// Sealed: chain position belongs to the writer. See
    /// [`AuditIntent::stamp_chain`].
    seq: u64,
    /// Sealed: chain position belongs to the writer. See
    /// [`AuditIntent::stamp_chain`].
    prev_hash: PrevHash,
    pub call_id: String,
    pub tool_id: ToolId,
    pub request_digest: RequestDigest,
}

impl AuditIntent {
    pub fn new(call_id: impl Into<String>, tool_id: ToolId, request_digest: RequestDigest) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            line_type: AuditLineType::Intent,
            seq: 0,
            prev_hash: PrevHash::GENESIS,
            call_id: call_id.into(),
            tool_id,
            request_digest,
        }
    }

    /// The schema version this record was stamped with at construction.
    pub fn schema_version(&self) -> AuditSchemaVersion {
        self.schema_version
    }

    pub fn line_type(&self) -> &AuditLineType {
        &self.line_type
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn prev_hash(&self) -> &PrevHash {
        &self.prev_hash
    }

    /// **Writer-only.** Assign this line's position in the chain.
    ///
    /// `seq` and `prev_hash` must be chosen and written inside the same lock as
    /// the append. Two callers that read the chain head outside that lock get
    /// the same `prev_hash` and fork the chain; a caller that picks its own
    /// `seq` forges a position the line never occupied. Never call this from
    /// the pipeline.
    pub fn stamp_chain(&mut self, seq: u64, prev_hash: PrevHash) {
        self.seq = seq;
        self.prev_hash = prev_hash;
    }
}

/// Observed resource usage for a sandboxed call (R5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct CallMetrics {
    pub wall_ms: u64,
    pub peak_memory_bytes: u64,
}

/// Post-execution outcome line — the Agent Action Record, one per call, on
/// every exit path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    /// Sealed: the schema version is owned by [`AuditRecord::new`], never the
    /// caller. A record that could be stamped with an arbitrary version is a
    /// forgeable audit trail. Read it with [`AuditRecord::schema_version`].
    schema_version: AuditSchemaVersion,
    /// Sealed: see [`AuditRecord::line_type`].
    line_type: AuditLineType,
    /// Sealed: chain position belongs to the writer. See
    /// [`AuditRecord::stamp_chain`].
    seq: u64,
    /// Sealed: chain position belongs to the writer. See
    /// [`AuditRecord::stamp_chain`].
    prev_hash: PrevHash,
    pub call_id: String,
    pub tool_id: ToolId,
    pub request_digest: RequestDigest,
    /// Which Policy Set governed this call. A real content hash — never
    /// `PolicySet::digest`, which is FNV-1a over YAML text.
    pub policy_set_hash: PolicySetHash,
    pub policy: PolicyOutcome,
    pub capability: CapabilityOutcome,
    pub execution: ExecutionOutcome,
    /// The grant this call ran under. Omitted when no grant was minted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<GrantId>,
    /// Digest of the raw response bytes. Omitted when the call produced none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_digest: Option<ResponseDigest>,
    /// Wall-clock time for sandbox execution. Omitted when the sandbox never ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_ms: Option<u64>,
    /// Peak guest linear memory during sandbox execution. Omitted when the sandbox never ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_memory_bytes: Option<u64>,
    /// Always emitted, possibly empty. See [`DecisionAxes`].
    pub decision_axes: DecisionAxes,
    /// Sealed: see [`AuditRecord::stamp_signature`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
    /// Sealed: see [`AuditRecord::stamp_signature`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<KeyId>,
}

impl AuditRecord {
    pub fn new(
        call_id: impl Into<String>,
        tool_id: ToolId,
        request_digest: RequestDigest,
        policy_set_hash: PolicySetHash,
        policy: PolicyOutcome,
        capability: CapabilityOutcome,
        execution: ExecutionOutcome,
    ) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            line_type: AuditLineType::Outcome,
            seq: 0,
            prev_hash: PrevHash::GENESIS,
            call_id: call_id.into(),
            tool_id,
            request_digest,
            policy_set_hash,
            policy,
            capability,
            execution,
            grant_id: None,
            response_digest: None,
            wall_ms: None,
            peak_memory_bytes: None,
            decision_axes: DecisionAxes::default(),
            signature: None,
            key_id: None,
        }
    }

    pub fn with_metrics(mut self, metrics: CallMetrics) -> Self {
        self.wall_ms = Some(metrics.wall_ms);
        self.peak_memory_bytes = Some(metrics.peak_memory_bytes);
        self
    }

    pub fn with_grant_id(mut self, grant_id: GrantId) -> Self {
        self.grant_id = Some(grant_id);
        self
    }

    pub fn with_response_digest(mut self, response_digest: ResponseDigest) -> Self {
        self.response_digest = Some(response_digest);
        self
    }

    pub fn with_decision_axes(mut self, decision_axes: DecisionAxes) -> Self {
        self.decision_axes = decision_axes;
        self
    }

    /// The schema version this record was stamped with at construction.
    pub fn schema_version(&self) -> AuditSchemaVersion {
        self.schema_version
    }

    pub fn line_type(&self) -> &AuditLineType {
        &self.line_type
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn prev_hash(&self) -> &PrevHash {
        &self.prev_hash
    }

    pub fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    pub fn key_id(&self) -> Option<&KeyId> {
        self.key_id.as_ref()
    }

    /// **Writer-only.** Assign this line's position in the chain.
    ///
    /// `seq` and `prev_hash` must be chosen and written inside the same lock as
    /// the append. Two callers that read the chain head outside that lock get
    /// the same `prev_hash` and fork the chain; a caller that picks its own
    /// `seq` forges a position the line never occupied. Never call this from
    /// the pipeline.
    pub fn stamp_chain(&mut self, seq: u64, prev_hash: PrevHash) {
        self.seq = seq;
        self.prev_hash = prev_hash;
    }

    /// **Writer-only.** Attach the signature and the key that produced it.
    ///
    /// The signature covers [`AuditRecord::signing_input`], so this can only be
    /// called after [`AuditRecord::stamp_chain`]. Never call this from the
    /// pipeline: a caller-supplied signature is an unverified claim about
    /// authorship written into evidence.
    pub fn stamp_signature(&mut self, signature: Signature, key_id: KeyId) {
        self.signature = Some(signature);
        self.key_id = Some(key_id);
    }

    /// The exact bytes a signature covers: this line's canonical form with
    /// `signature` omitted and `key_id` present.
    ///
    /// `key_id` is inside the signed input so a signature cannot be replayed
    /// under a different key's fingerprint. The line *hash* then covers the
    /// signature as well — strip a signature and the next line's `prev_hash`
    /// breaks, whereas hashing the pre-signature form would let
    /// signature-stripping leave a clean chain.
    pub fn signing_input(&self, key_id: &KeyId) -> Result<String, JcsError> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        unsigned.key_id = Some(*key_id);
        jcs::to_canonical_json(&unsigned)
    }
}

/// Session `Open` line — the first line of a Session, and the only place the
/// public key appears.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditOpen {
    /// Sealed: owned by [`AuditOpen::new`]. See [`AuditRecord`] for why.
    schema_version: AuditSchemaVersion,
    /// Sealed: see [`AuditOpen::line_type`].
    line_type: AuditLineType,
    /// Sealed: chain position belongs to the writer.
    seq: u64,
    /// Sealed: always [`PrevHash::GENESIS`] for an `Open` — a Session's first
    /// line has no predecessor *within the Session*.
    prev_hash: PrevHash,
    /// The previous Session's final line hash when appending to a non-empty
    /// file; omitted for a fresh file. This, not `prev_hash`, is what chains
    /// two Sessions across a boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_session_tail: Option<PrevHash>,
    /// The ed25519 public key for every signed line in this Session.
    pub public_key: PublicKey,
    /// Sealed: see [`AuditOpen::stamp_signature`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
    /// Sealed: see [`AuditOpen::stamp_signature`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<KeyId>,
}

impl AuditOpen {
    pub fn new(public_key: PublicKey, prev_session_tail: Option<PrevHash>) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            line_type: AuditLineType::Open,
            seq: 0,
            prev_hash: PrevHash::GENESIS,
            prev_session_tail,
            public_key,
            signature: None,
            key_id: None,
        }
    }

    pub fn schema_version(&self) -> AuditSchemaVersion {
        self.schema_version
    }

    pub fn line_type(&self) -> &AuditLineType {
        &self.line_type
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn prev_hash(&self) -> &PrevHash {
        &self.prev_hash
    }

    pub fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    pub fn key_id(&self) -> Option<&KeyId> {
        self.key_id.as_ref()
    }

    /// **Writer-only.** See [`AuditRecord::stamp_chain`].
    pub fn stamp_chain(&mut self, seq: u64, prev_hash: PrevHash) {
        self.seq = seq;
        self.prev_hash = prev_hash;
    }

    /// **Writer-only.** See [`AuditRecord::stamp_signature`].
    pub fn stamp_signature(&mut self, signature: Signature, key_id: KeyId) {
        self.signature = Some(signature);
        self.key_id = Some(key_id);
    }

    /// See [`AuditRecord::signing_input`].
    pub fn signing_input(&self, key_id: &KeyId) -> Result<String, JcsError> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        unsigned.key_id = Some(*key_id);
        jcs::to_canonical_json(&unsigned)
    }
}

/// Session `Close` line — written on `AuditWriter::drop`.
///
/// `Drop` does not run on SIGKILL. Close-on-drop covers clean exit and unwind
/// only; the missing `Close` is precisely what a verifier reports as
/// `Indeterminate`, and that gap is documented rather than engineered around.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditClose {
    /// Sealed: owned by [`AuditClose::new`]. See [`AuditRecord`] for why.
    schema_version: AuditSchemaVersion,
    /// Sealed: see [`AuditClose::line_type`].
    line_type: AuditLineType,
    /// Sealed: chain position belongs to the writer.
    seq: u64,
    /// Sealed: chain position belongs to the writer.
    prev_hash: PrevHash,
    /// Sealed: see [`AuditClose::stamp_signature`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
    /// Sealed: see [`AuditClose::stamp_signature`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<KeyId>,
}

impl Default for AuditClose {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditClose {
    pub fn new() -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            line_type: AuditLineType::Close,
            seq: 0,
            prev_hash: PrevHash::GENESIS,
            signature: None,
            key_id: None,
        }
    }

    pub fn schema_version(&self) -> AuditSchemaVersion {
        self.schema_version
    }

    pub fn line_type(&self) -> &AuditLineType {
        &self.line_type
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn prev_hash(&self) -> &PrevHash {
        &self.prev_hash
    }

    pub fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    pub fn key_id(&self) -> Option<&KeyId> {
        self.key_id.as_ref()
    }

    /// **Writer-only.** See [`AuditRecord::stamp_chain`].
    pub fn stamp_chain(&mut self, seq: u64, prev_hash: PrevHash) {
        self.seq = seq;
        self.prev_hash = prev_hash;
    }

    /// **Writer-only.** See [`AuditRecord::stamp_signature`].
    pub fn stamp_signature(&mut self, signature: Signature, key_id: KeyId) {
        self.signature = Some(signature);
        self.key_id = Some(key_id);
    }

    /// See [`AuditRecord::signing_input`].
    pub fn signing_input(&self, key_id: &KeyId) -> Result<String, JcsError> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        unsigned.key_id = Some(*key_id);
        jcs::to_canonical_json(&unsigned)
    }
}

/// A human approval verdict — no intent, no execution (ADR-0005).
///
/// A resumed call is a *new* Call with its own intent and outcome, linked back
/// by `approval_id`. Two `Decision` lines for one `approval_id` is a structural
/// violation: a correct emitter cannot produce it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditDecision {
    /// Sealed: owned by [`AuditDecision::new`]. See [`AuditRecord`] for why.
    schema_version: AuditSchemaVersion,
    /// Sealed: see [`AuditDecision::line_type`].
    line_type: AuditLineType,
    /// Sealed: chain position belongs to the writer.
    seq: u64,
    /// Sealed: chain position belongs to the writer.
    prev_hash: PrevHash,
    /// The park this verdict answers. A soft cross-reference: it may span
    /// Sessions and files, because a human approving after a restart is normal.
    pub approval_id: ApprovalId,
    pub verdict: ApprovalVerdict,
    /// Sealed: see [`AuditDecision::stamp_signature`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
    /// Sealed: see [`AuditDecision::stamp_signature`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<KeyId>,
}

impl AuditDecision {
    pub fn new(approval_id: ApprovalId, verdict: ApprovalVerdict) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            line_type: AuditLineType::Decision,
            seq: 0,
            prev_hash: PrevHash::GENESIS,
            approval_id,
            verdict,
            signature: None,
            key_id: None,
        }
    }

    pub fn schema_version(&self) -> AuditSchemaVersion {
        self.schema_version
    }

    pub fn line_type(&self) -> &AuditLineType {
        &self.line_type
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn prev_hash(&self) -> &PrevHash {
        &self.prev_hash
    }

    pub fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    pub fn key_id(&self) -> Option<&KeyId> {
        self.key_id.as_ref()
    }

    /// **Writer-only.** See [`AuditRecord::stamp_chain`].
    pub fn stamp_chain(&mut self, seq: u64, prev_hash: PrevHash) {
        self.seq = seq;
        self.prev_hash = prev_hash;
    }

    /// **Writer-only.** See [`AuditRecord::stamp_signature`].
    pub fn stamp_signature(&mut self, signature: Signature, key_id: KeyId) {
        self.signature = Some(signature);
        self.key_id = Some(key_id);
    }

    /// See [`AuditRecord::signing_input`].
    pub fn signing_input(&self, key_id: &KeyId) -> Result<String, JcsError> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        unsigned.key_id = Some(*key_id);
        jcs::to_canonical_json(&unsigned)
    }
}

/// What a human decided, and — when they approved — exactly what they approved.
///
/// The scope rides inside the `Approved` variant so that an approval without a
/// recorded scope is unrepresentable. Approval without recorded scope is a
/// blank check in the evidence (ADR-0005), and the resumed call's grant must be
/// a subset of what is recorded here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ApprovalVerdict {
    Approved { scope: ApprovedScope },
    Denied { reason: String },
}

/// The authority a human approval granted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApprovedScope {
    pub tool_id: ToolId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs: Option<FsGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<NetGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PolicyOutcome {
    Allowed,
    Denied { reason: String },
    RateLimited { reason: String },
    PendingApproval { approval_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CapabilityOutcome {
    Granted {
        grant: CapabilityGrant,
    },
    Denied {
        reason: String,
        /// Machine-readable capability axis (e.g. `fs`, `net.http`) for audit
        /// consumers. Omitted when unknown — never null, or the canonical form
        /// has to choose between two spellings of "absent".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        denied_capability: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExecutionOutcome {
    Success,
    Trap { message: String },
    ResourceExceeded { kind: String },
    HostDenied { reason: String },
}

impl From<&PolicyAction> for PolicyOutcome {
    fn from(action: &PolicyAction) -> Self {
        match action {
            PolicyAction::Allow => Self::Allowed,
            PolicyAction::Deny { reason } => Self::Denied {
                reason: reason.clone(),
            },
            PolicyAction::RateLimited { reason } => Self::RateLimited {
                reason: reason.clone(),
            },
            PolicyAction::PendingApproval { approval_id } => Self::PendingApproval {
                approval_id: approval_id.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Digest;

    fn record() -> AuditRecord {
        AuditRecord::new(
            "call-1",
            ToolId::new("echo"),
            RequestDigest::of_request_bytes(b"{}"),
            PolicySetHash::of_canonical_bytes(b"policy"),
            PolicyOutcome::Allowed,
            CapabilityOutcome::Denied {
                reason: "not evaluated".into(),
                denied_capability: None,
            },
            ExecutionOutcome::Success,
        )
    }

    #[test]
    fn schema_version_is_two_and_sealed_from_callers() {
        assert_eq!(AUDIT_SCHEMA_VERSION, 2);
        assert_eq!(record().schema_version(), 2);
        assert_eq!(
            AuditIntent::new("c", ToolId::new("t"), RequestDigest::of_request_bytes(b""))
                .schema_version(),
            2
        );
    }

    #[test]
    fn line_types_round_trip_and_preserve_unknown_tokens() {
        for (variant, token) in [
            (AuditLineType::Open, "open"),
            (AuditLineType::Intent, "intent"),
            (AuditLineType::Outcome, "outcome"),
            (AuditLineType::Decision, "decision"),
            (AuditLineType::Close, "close"),
            (AuditLineType::Checkpoint, "checkpoint"),
        ] {
            assert_eq!(variant.as_str(), token);
            assert_eq!(AuditLineType::from_wire(token), variant);
            assert_eq!(
                serde_json::to_string(&variant).unwrap(),
                format!("\"{token}\"")
            );
        }
        // The raw token survives parsing — a verifier can name what it did not
        // understand instead of only failing.
        let unknown: AuditLineType = serde_json::from_str("\"anchor\"").unwrap();
        assert_eq!(unknown, AuditLineType::Unknown("anchor".into()));
        assert_eq!(unknown.as_str(), "anchor");
        assert_eq!(serde_json::to_string(&unknown).unwrap(), "\"anchor\"");
    }

    #[test]
    fn wire_field_is_line_type_not_phase() {
        let json = serde_json::to_string(&record()).unwrap();
        assert!(json.contains("\"line_type\":\"outcome\""), "{json}");
        assert!(!json.contains("\"phase\""), "{json}");
    }

    #[test]
    fn absent_optionals_are_omitted_never_null() {
        let json = serde_json::to_string(&record()).unwrap();
        assert!(!json.contains("null"), "{json}");
        for absent in [
            "grant_id",
            "response_digest",
            "wall_ms",
            "peak_memory_bytes",
            "signature",
            "key_id",
            "denied_capability",
        ] {
            assert!(!json.contains(absent), "{absent} must be omitted: {json}");
        }
        // decision_axes is the exception: always emitted, possibly empty.
        assert!(json.contains("\"decision_axes\":{}"), "{json}");
    }

    #[test]
    fn every_line_type_canonicalizes_under_the_jcs_value_space() {
        let axes = DecisionAxes {
            capability: Some("fs.read".into()),
            role: Some("ops".into()),
            session: Some("s-1".into()),
            matched_rule: Some("rule-3".into()),
            approval_ref: Some(ApprovalId::new("apr-1")),
            fs: Some(FsAxis {
                path_raw: "~/notes.md".into(),
                path_canonical: "/home/a/notes.md".into(),
            }),
            net: Some(NetAxis {
                host: "example.com".into(),
                port: 443,
            }),
        };
        let outcome = record()
            .with_metrics(CallMetrics {
                wall_ms: 3,
                peak_memory_bytes: 4096,
            })
            .with_grant_id(GrantId::new("grant-1"))
            .with_response_digest(ResponseDigest::of_response_bytes(b"ok"))
            .with_decision_axes(axes);
        assert!(jcs::to_canonical_json(&outcome).is_ok());
        assert!(jcs::to_canonical_json(&record()).is_ok());
        assert!(jcs::to_canonical_json(&AuditIntent::new(
            "c",
            ToolId::new("t"),
            RequestDigest::of_request_bytes(b"")
        ))
        .is_ok());
        assert!(jcs::to_canonical_json(&AuditOpen::new(
            PublicKey::from_bytes([9u8; 32]),
            Some(PrevHash::of_line(b"tail"))
        ))
        .is_ok());
        assert!(jcs::to_canonical_json(&AuditClose::new()).is_ok());
        assert!(jcs::to_canonical_json(&AuditDecision::new(
            ApprovalId::new("apr-1"),
            ApprovalVerdict::Approved {
                scope: ApprovedScope {
                    tool_id: ToolId::new("echo"),
                    fs: None,
                    net: None,
                },
            },
        ))
        .is_ok());
    }

    #[test]
    fn chain_and_signature_fields_are_stamped_not_constructed() {
        let mut line = record();
        assert_eq!(line.seq(), 0);
        assert_eq!(*line.prev_hash(), PrevHash::GENESIS);
        assert!(line.signature().is_none() && line.key_id().is_none());

        let prev = PrevHash::of_line(b"predecessor");
        line.stamp_chain(41, prev);
        assert_eq!(line.seq(), 41);
        assert_eq!(*line.prev_hash(), prev);

        let key_id = KeyId::of_public_key(&PublicKey::from_bytes([3u8; 32]));
        line.stamp_signature(Signature::from_bytes([7u8; 64]), key_id);
        assert_eq!(line.key_id(), Some(&key_id));
        assert_eq!(line.signature(), Some(&Signature::from_bytes([7u8; 64])));
    }

    #[test]
    fn signing_input_omits_the_signature_and_carries_the_key_id() {
        let mut line = record();
        line.stamp_chain(1, PrevHash::of_line(b"prev"));
        let key_id = KeyId::of_public_key(&PublicKey::from_bytes([3u8; 32]));
        let before = line.signing_input(&key_id).unwrap();
        assert!(!before.contains("\"signature\""), "{before}");
        assert!(before.contains(&format!("\"key_id\":\"{}\"", key_id.to_hex())));

        // Stamping the signature must not change what the signature covers,
        // or verification could never reproduce it.
        line.stamp_signature(Signature::from_bytes([7u8; 64]), key_id);
        assert_eq!(line.signing_input(&key_id).unwrap(), before);

        // The line *hash* does cover the signature: stripping one breaks the
        // next line's prev_hash instead of leaving a clean chain.
        let signed_form = jcs::to_canonical_json(&line).unwrap();
        assert!(signed_form.contains("\"signature\""));
        assert_ne!(
            Digest::sha256(signed_form.as_bytes()),
            Digest::sha256(before.as_bytes())
        );
    }

    #[test]
    fn open_keeps_genesis_prev_hash_and_carries_the_back_reference() {
        let tail = PrevHash::of_line(b"previous session tail");
        let open = AuditOpen::new(PublicKey::from_bytes([9u8; 32]), Some(tail));
        assert_eq!(*open.prev_hash(), PrevHash::GENESIS);
        assert_eq!(open.prev_session_tail, Some(tail));
        let fresh = AuditOpen::new(PublicKey::from_bytes([9u8; 32]), None);
        let json = serde_json::to_string(&fresh).unwrap();
        assert!(!json.contains("prev_session_tail"), "{json}");
    }

    #[test]
    fn an_approval_without_a_recorded_scope_is_unrepresentable() {
        let decision = AuditDecision::new(
            ApprovalId::new("apr-9"),
            ApprovalVerdict::Approved {
                scope: ApprovedScope {
                    tool_id: ToolId::new("echo"),
                    fs: Some(FsGrant {
                        read_paths: vec!["/srv/data".into()],
                        write_paths: vec![],
                    }),
                    net: None,
                },
            },
        );
        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("\"verdict\":\"approved\""), "{json}");
        assert!(json.contains("/srv/data"), "{json}");
        let parsed: AuditDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, decision);
    }

    #[test]
    fn records_round_trip_through_json() {
        let mut line = record();
        line.stamp_chain(5, PrevHash::of_line(b"p"));
        line.stamp_signature(
            Signature::from_bytes([1u8; 64]),
            KeyId::of_public_key(&PublicKey::from_bytes([2u8; 32])),
        );
        let json = serde_json::to_string(&line).unwrap();
        assert_eq!(serde_json::from_str::<AuditRecord>(&json).unwrap(), line);
    }

    #[test]
    fn policy_outcome_maps_every_policy_action() {
        assert_eq!(
            PolicyOutcome::from(&PolicyAction::Allow),
            PolicyOutcome::Allowed
        );
        assert_eq!(
            PolicyOutcome::from(&PolicyAction::Deny { reason: "r".into() }),
            PolicyOutcome::Denied { reason: "r".into() }
        );
        assert_eq!(
            PolicyOutcome::from(&PolicyAction::RateLimited { reason: "r".into() }),
            PolicyOutcome::RateLimited { reason: "r".into() }
        );
        assert_eq!(
            PolicyOutcome::from(&PolicyAction::PendingApproval {
                approval_id: "a".into()
            }),
            PolicyOutcome::PendingApproval {
                approval_id: "a".into()
            }
        );
    }
}
