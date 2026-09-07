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
/// the Layer 2 governance ingest migrated under AILAB-624 and now rejects v1.
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

/// The `line_type` field alone, with no schema-v1 fallback.
///
/// `None` covers both "no such field" and "present but not a string": neither
/// is a tag, and a reader that requires one treats the two the same way.
///
/// This is the half a consumer that does **not** read schema-v1 records wants.
/// It never invents a line type out of `phase`, so a v1 record stays untagged
/// rather than becoming routable.
pub fn line_type_field(value: &serde_json::Value) -> Option<AuditLineType> {
    value
        .get("line_type")
        .and_then(serde_json::Value::as_str)
        .map(AuditLineType::from_wire)
}

/// The line's type under either spelling of the tag — `line_type`, or schema
/// v1's `phase` as a fallback.
///
/// The two are read in order, not as alternatives. A present string
/// `line_type` is authoritative even when `phase` disagrees, and `phase` is
/// consulted only for records written before `line_type` existed. A
/// `line_type` that is present but not a string is no tag either, and falls
/// through to the fallback. Nothing is lost by the ordering: a genuine v1 line
/// carries `phase` and no `line_type` at all, so the fallback still reaches
/// every line it exists for.
///
/// LOAD-BEARING: the fallback must not speak over a `line_type` that is there.
/// A line tagged `open` is a Session boundary and nothing else. Reading
/// `phase: "outcome"` off such a line would report a boundary as a call *and*
/// stall whichever [`SessionCounter`] is numbering the file, so every address
/// after it would name a different Session than a reader keyed on `line_type`
/// names for the same bytes.
///
/// Which of this and [`line_type_field`] a reader calls is that reader's
/// declaration of whether it reads v1 records at all (ADR-0013): `aegis verify`
/// does not and takes the field alone, `aegis recheck` does and takes this. The
/// choice sits at the call site rather than in a parameter here, so that no
/// caller can loosen another caller's reading.
pub fn line_type_from_value(value: &serde_json::Value) -> Option<AuditLineType> {
    line_type_field(value).or_else(|| {
        value
            .get("phase")
            .and_then(serde_json::Value::as_str)
            .map(AuditLineType::from_wire)
    })
}

/// A Session's ordinal within a Chain file: `None` until the first `Open` line,
/// then 0, 1, 2 …
///
/// Coverage is `(session_index, seq)` and not `seq` alone — `seq` restarts at 0
/// on each Session's `Open`, so one file holding two Sessions has two different
/// lines at `seq` 5. The Session ordinal is the other half of that address, and
/// every reader that prints one has to count Sessions by the same rule, or a
/// finding stops carrying between two reports about the same file.
///
/// This type **is** that rule. It was previously the same expression written
/// twice — once in the verifying walk, once in the recheck walk — held in
/// agreement by nothing but a pair of comments saying so (ADR-0013).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionCounter {
    index: Option<usize>,
}

impl SessionCounter {
    /// A counter that has not yet seen an `Open`.
    pub fn new() -> Self {
        Self::default()
    }

    /// The ordinal the next `Open` will take, without advancing to it.
    ///
    /// A reader that validates an `Open` before committing to it — a verifying
    /// walk names the Session in its tamper reports — needs the number ahead of
    /// the decision it is still entitled to refuse.
    pub fn next_index(&self) -> usize {
        self.index.map_or(0, |index| index + 1)
    }

    /// Record an `Open` line, advancing to [`Self::next_index`].
    pub fn note_open(&mut self) {
        self.index = Some(self.next_index());
    }

    /// The ordinal of the Session in progress, or `None` before the first
    /// `Open`.
    ///
    /// The distinction from [`Self::current`] is not cosmetic: a reader that
    /// requires a file to begin with an `Open` reads this `None` as "this chain
    /// does not begin with an open line", where `current` would hand it a
    /// plausible 0 and let a headless file walk on.
    pub fn index(&self) -> Option<usize> {
        self.index
    }

    /// The Session ordinal to print in an address column.
    ///
    /// A line seen before any `Open` reports 0 rather than nothing: an address
    /// is two numbers or it is not an address, and 0 names the Session such a
    /// line would sit in if the file's first `Open` were there to be read.
    pub fn current(&self) -> usize {
        self.index.unwrap_or(0)
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
///
/// `#[non_exhaustive]`: the axis set is expected to grow — a semantic risk score
/// is the live candidate (AILAB-794) — and an eighth axis must not break every
/// downstream build that already records these seven. Outside this crate the
/// attribute forbids the struct expression outright (E0639), functional-update
/// syntax included, so the recommended construction is the fluent chain —
/// `DecisionAxes::default().with_capability("fs.read").with_role("ops")` — and
/// that is what every emitter in this workspace now does. The fields are all
/// public and stay public, so assignment still compiles; the chain is what the
/// type recommends, not what it enforces.
///
/// The bare literals left are in this file's own tests, where the attribute
/// does not apply, and they are left bare on purpose: each is an eighth-axis
/// tripwire. A new axis must fail to compile there until the test names it,
/// which is how the "every axis canonicalizes" assertion keeps meaning what it
/// says — a `with_*` chain names one axis at a time and would go on compiling.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
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

impl DecisionAxes {
    /// Consuming setters, not a builder type: seven methods, no new published
    /// type, no infallible `build()`. Each future axis adds exactly one method,
    /// which is the same non-breaking property `#[non_exhaustive]` exists for
    /// (AILAB-798). Fields stay public; assignment remains legal.
    ///
    /// Same shape as [`AuditRecord::with_grant_id`] and
    /// `PolicyRequest::with_role`: take `self`, set `Some`, return `Self`.
    /// There is deliberately no clearing setter — an axis the emitter did not
    /// record is left unset, and unset is what omit-never-null encodes.
    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        self.capability = Some(capability.into());
        self
    }

    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    pub fn with_session(mut self, session: impl Into<String>) -> Self {
        self.session = Some(session.into());
        self
    }

    pub fn with_matched_rule(mut self, matched_rule: impl Into<String>) -> Self {
        self.matched_rule = Some(matched_rule.into());
        self
    }

    pub fn with_approval_ref(mut self, approval_ref: ApprovalId) -> Self {
        self.approval_ref = Some(approval_ref);
        self
    }

    pub fn with_fs(mut self, fs: FsAxis) -> Self {
        self.fs = Some(fs);
        self
    }

    pub fn with_net(mut self, net: NetAxis) -> Self {
        self.net = Some(net);
        self
    }
}

/// The filesystem resource a call resolved to (ADR-0006).
///
/// Both spellings are recorded: the canonical path is the spelling a matcher
/// would have targeted, and the raw path is what the caller actually asked for
/// — a diff between them is itself evidence. `spec/SPEC.md` §10 (Threat model
/// and non-guarantees) states that derived paths appear in the Chain and that
/// the Chain is the publishable artifact.
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

/// The four fields `spec/SPEC.md` §5 makes mandatory on every Line of every
/// type — declared once, here, instead of once per line type.
///
/// **Sealed.** All four are private to this crate. `schema_version` and
/// `line_type` are stamped by the constructor of the line the header belongs
/// to; `seq` and `prev_hash` are stamped by the writer through
/// [`Envelope::stamp_chain`]. A caller that can pick its own chain position
/// forges a position the line never occupied, or hands two lines the same one —
/// which is what a forked chain is. A caller that can pick its own schema
/// version forges the trail wholesale. Sealing is what makes the rule
/// structural instead of a comment.
///
/// This type has no methods on purpose: a line's header is read through the
/// line, on [`Envelope`], so the four readers exist once rather than twice.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LineHeader {
    schema_version: AuditSchemaVersion,
    line_type: AuditLineType,
    seq: u64,
    prev_hash: PrevHash,
}

impl LineHeader {
    /// A fresh header for a line of `line_type`, at no position yet.
    ///
    /// The version is stamped here, never taken from a caller, and the chain
    /// position starts at the genesis values the writer overwrites.
    fn new(line_type: AuditLineType) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            line_type,
            seq: 0,
            prev_hash: PrevHash::GENESIS,
        }
    }
}

/// The signature pair, declared once for the four signed line types.
///
/// **Both halves are independently optional, and that is load-bearing.**
/// [`SignedLine::unsigned_with_key`] produces exactly the state *signature
/// absent, `key_id` present*, and those are the bytes a signature covers. A
/// block whose two fields moved together could not represent what is being
/// signed.
///
/// **Sealed** for the same reason as [`LineHeader`]: a caller that can set
/// these writes an unverified claim about authorship straight into evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignatureBlock {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<KeyId>,
}

/// Marker for the payloads whose line carries a signature.
///
/// Implemented for the four signed line types and deliberately **not** for
/// [`IntentPayload`]. Every path that can attach or read a signature —
/// [`Envelope::stamp_signature`], [`Envelope::signature`],
/// [`Envelope::key_id`], and the [`SignedLine`] impl that produces the signing
/// input — is bounded on it, so an intent line has no signing surface at all
/// rather than an unused one.
///
/// This is what replaced a pair of traits that had to be kept in step by hand:
/// "which lines are signed" is now one list, and it is this one.
pub trait Signable {}

/// A Line: the mandatory header, the line type's own fields, and — for a
/// signed line — the signature pair.
///
/// One declaration instead of five. `#[serde(flatten)]` on all three parts
/// means the serialized object is a single flat map carrying the same keys in
/// the same order as when each line type declared its own header; the golden
/// and tamper vectors are what proves that, not this sentence.
///
/// **LOAD-BEARING: the order of the three fields below is the order the keys
/// come out in.** `flatten` emits each part where it is declared, so header,
/// then payload, then signature is not a stylistic choice — it is the key order
/// every line had before this type existed. Most vectors are stored canonically
/// and would not notice a swap, but
/// `crates/botzr-aegis-runtime/tests/golden/resource_exceeded_orchestrator.json`
/// is written and compared with the audit crate's non-canonical
/// `to_json_line`, so it pins this declaration order byte for byte. Moving
/// `sig` above `payload` puts `signature` and `key_id` in the middle of the
/// object and that vector stops reproducing — measured, not predicted.
///
/// **The assertion is `envelope_key_order_is_header_then_payload_then_signature`,
/// in this file's `tests` module.** Not an intra-doc link on purpose: that
/// module is `#[cfg(test)]`, so rustdoc cannot resolve a path into it and a
/// link here would ship a broken-link warning to keep a pointer readable. It reads the key sequence off a serialized line and fails
/// naming the part that moved, so the property is enforced rather than
/// described. This paragraph is the *why*; that test is the *what*. Do not
/// delete one and keep the other.
///
/// **The payload decides whether the line can be signed.** The signing surface
/// is bounded on [`Signable`], which [`IntentPayload`] does not implement, so
/// "the intent line is never signed" is a fact the compiler checks rather than
/// a rule a writer has to remember. The intent line is fsynced ahead of
/// execution, and signing it would put key material on the pre-execution
/// critical path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Envelope<P> {
    #[serde(flatten)]
    header: LineHeader,
    /// The fields this line type carries beyond the header.
    #[serde(flatten)]
    pub payload: P,
    #[serde(flatten)]
    sig: SignatureBlock,
}

impl<P> Envelope<P> {
    /// A line of `line_type` carrying `payload`, at no chain position yet and
    /// unsigned.
    ///
    /// Not `new`: each line type's own `new` is the public constructor, and an
    /// inherent `new` here would collide with all five of them.
    fn new_line(line_type: AuditLineType, payload: P) -> Self {
        Self {
            header: LineHeader::new(line_type),
            payload,
            sig: SignatureBlock::default(),
        }
    }

    /// The schema version this line was stamped with at construction.
    pub fn schema_version(&self) -> AuditSchemaVersion {
        self.header.schema_version
    }

    pub fn line_type(&self) -> &AuditLineType {
        &self.header.line_type
    }

    pub fn seq(&self) -> u64 {
        self.header.seq
    }

    pub fn prev_hash(&self) -> &PrevHash {
        &self.header.prev_hash
    }

    /// **Writer-only.** Assign this line's position in the chain.
    ///
    /// `seq` and `prev_hash` must be chosen and written inside the same lock as
    /// the append. Two callers that read the chain head outside that lock get
    /// the same `prev_hash` and fork the chain; a caller that picks its own
    /// `seq` forges a position the line never occupied. Never call this from
    /// the pipeline.
    ///
    /// One implementation, for every line type — the five that drifted apart
    /// one at a time cannot any more.
    pub fn stamp_chain(&mut self, seq: u64, prev_hash: PrevHash) {
        self.header.seq = seq;
        self.header.prev_hash = prev_hash;
    }
}

impl<P: Signable> Envelope<P> {
    pub fn signature(&self) -> Option<&Signature> {
        self.sig.signature.as_ref()
    }

    pub fn key_id(&self) -> Option<&KeyId> {
        self.sig.key_id.as_ref()
    }

    /// **Writer-only.** Attach the signature and the key that produced it.
    ///
    /// The signature covers [`SignedLine::signing_input`], so this can only be
    /// called after [`Envelope::stamp_chain`]. Never call this from the
    /// pipeline: a caller-supplied signature is an unverified claim about
    /// authorship written into evidence.
    ///
    /// Bounded on [`Signable`], so it does not exist for an intent line.
    pub fn stamp_signature(&mut self, signature: Signature, key_id: KeyId) {
        self.sig.signature = Some(signature);
        self.sig.key_id = Some(key_id);
    }
}

/// Pre-execution intent line — appended, flushed and fsynced before sandbox
/// work begins.
///
/// Carries nothing beyond identity and the request digest, and must stay that
/// way: everything on this line is on the pre-execution critical path.
///
/// **It is hashed into the chain and never signed, and the compiler is what
/// says so** — this payload does not implement [`Signable`], so an intent line
/// has no `stamp_signature` to call and no [`SignedLine`] impl to reach it
/// through. That is asserted as a compile error, against the public API a
/// consumer sees, beside the two cases that assert the seal:
/// `tests/api-surface/tests/ui/intent_line_is_unsignable.rs`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntentPayload {
    pub call_id: String,
    pub tool_id: ToolId,
    pub request_digest: RequestDigest,
}

/// The `intent` line — an [`IntentPayload`] in an [`Envelope`].
pub type AuditIntent = Envelope<IntentPayload>;

impl Envelope<IntentPayload> {
    pub fn new(call_id: impl Into<String>, tool_id: ToolId, request_digest: RequestDigest) -> Self {
        Envelope::new_line(
            AuditLineType::Intent,
            IntentPayload {
                call_id: call_id.into(),
                tool_id,
                request_digest,
            },
        )
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
pub struct RecordPayload {
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
}

impl Signable for RecordPayload {}

/// The `outcome` line — the Agent Action Record.
pub type AuditRecord = Envelope<RecordPayload>;

impl Envelope<RecordPayload> {
    pub fn new(
        call_id: impl Into<String>,
        tool_id: ToolId,
        request_digest: RequestDigest,
        policy_set_hash: PolicySetHash,
        policy: PolicyOutcome,
        capability: CapabilityOutcome,
        execution: ExecutionOutcome,
    ) -> Self {
        Envelope::new_line(
            AuditLineType::Outcome,
            RecordPayload {
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
            },
        )
    }

    pub fn with_metrics(mut self, metrics: CallMetrics) -> Self {
        self.payload.wall_ms = Some(metrics.wall_ms);
        self.payload.peak_memory_bytes = Some(metrics.peak_memory_bytes);
        self
    }

    pub fn with_grant_id(mut self, grant_id: GrantId) -> Self {
        self.payload.grant_id = Some(grant_id);
        self
    }

    pub fn with_response_digest(mut self, response_digest: ResponseDigest) -> Self {
        self.payload.response_digest = Some(response_digest);
        self
    }

    pub fn with_decision_axes(mut self, decision_axes: DecisionAxes) -> Self {
        self.payload.decision_axes = decision_axes;
        self
    }
}

/// Session `Open` line — the first line of a Session, and the only place the
/// public key appears.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OpenPayload {
    /// The previous Session's final line hash when appending to a non-empty
    /// file; omitted for a fresh file. This, not `prev_hash`, is what chains
    /// two Sessions across a boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_session_tail: Option<PrevHash>,
    /// The ed25519 public key for every signed line in this Session.
    pub public_key: PublicKey,
}

impl Signable for OpenPayload {}

/// The `open` line.
///
/// Its `prev_hash` is always [`PrevHash::GENESIS`] — a Session's first line has
/// no predecessor *within the Session*.
pub type AuditOpen = Envelope<OpenPayload>;

impl Envelope<OpenPayload> {
    pub fn new(public_key: PublicKey, prev_session_tail: Option<PrevHash>) -> Self {
        Envelope::new_line(
            AuditLineType::Open,
            OpenPayload {
                prev_session_tail,
                public_key,
            },
        )
    }
}

/// Session `Close` line — written on `AuditWriter::drop`.
///
/// It carries nothing of its own: a `Close` is the header and the signature,
/// and the fact that it is there at all is the whole content.
///
/// `Drop` does not run on SIGKILL. Close-on-drop covers clean exit and unwind
/// only; the missing `Close` is precisely what a verifier reports as
/// `Indeterminate`, and that gap is documented rather than engineered around.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClosePayload {}

impl Signable for ClosePayload {}

/// The `close` line.
pub type AuditClose = Envelope<ClosePayload>;

impl Default for Envelope<ClosePayload> {
    fn default() -> Self {
        Self::new()
    }
}

impl Envelope<ClosePayload> {
    pub fn new() -> Self {
        Envelope::new_line(AuditLineType::Close, ClosePayload {})
    }
}

/// A human approval verdict — no intent, no execution (ADR-0005).
///
/// A resumed call is a *new* Call with its own intent and outcome, linked back
/// by `approval_id`. Two `Decision` lines for one `approval_id` is a structural
/// violation: a correct emitter cannot produce it.
///
/// **This type is format-defining and has no shipped emitter.** Nothing in this
/// repository's pipeline builds a `decision` line: a `pending_approval` policy
/// verdict is recorded as an `outcome` line and returned to the caller as an
/// error, and no code path resumes the parked Call — that protocol is
/// AILAB-629's and is unbuilt. The type is here so the record format is complete
/// and so adding the approval protocol later is not a breaking change for
/// anything that reads records. A reader must still handle a `decision` line:
/// the published vectors carry them (`spec/SPEC.md` §11.2 and §11.4), built by
/// the tests that are the emitter's only callers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DecisionPayload {
    /// The park this verdict answers. A soft cross-reference: it may span
    /// Sessions and files, because a human approving after a restart is normal.
    pub approval_id: ApprovalId,
    pub verdict: ApprovalVerdict,
}

impl Signable for DecisionPayload {}

/// The `decision` line.
pub type AuditDecision = Envelope<DecisionPayload>;

impl Envelope<DecisionPayload> {
    pub fn new(approval_id: ApprovalId, verdict: ApprovalVerdict) -> Self {
        Envelope::new_line(
            AuditLineType::Decision,
            DecisionPayload {
                approval_id,
                verdict,
            },
        )
    }
}

/// The rule the whole record format rests on: a signature covers the line's
/// canonical form with the signature field dropped and `key_id` present.
///
/// It is written once, here, because a writer and a verifier that disagree
/// about which bytes a signature covers make every signature in every Chain
/// meaningless.
///
/// `key_id` sits inside the signed bytes so a signature cannot be replayed
/// under a different key's fingerprint.
///
/// [`IntentPayload`] deliberately does not implement [`Signable`], so no
/// [`Envelope`] carrying it implements this trait. That line is fsynced ahead
/// of execution, so signing it would put key material on the pre-execution
/// critical path; keeping it off the trait makes "the intent line is never
/// signed" a property of the type system rather than a rule a writer has to
/// remember.
pub trait SignedLine: Clone + serde::Serialize {
    /// A copy of this line with its signature cleared and `key_id` stamped.
    fn unsigned_with_key(&self, key_id: &KeyId) -> Self;

    /// The exact bytes a signature covers. Not meant to be overridden — an
    /// override is a second spelling of the rule, which is the drift ADR-0003
    /// exists to prevent.
    fn signing_input(&self, key_id: &KeyId) -> Result<String, JcsError> {
        let unsigned = self.unsigned_with_key(key_id);
        jcs::to_canonical_json(&unsigned)
    }
}

/// One impl for every signed line, because the part that used to differ per
/// type — which private fields get cleared and stamped — is now one shared
/// [`SignatureBlock`]. The macro that expanded this four times is gone with the
/// difference it existed to absorb.
impl<P> SignedLine for Envelope<P>
where
    P: Signable + Clone + serde::Serialize,
{
    fn unsigned_with_key(&self, key_id: &KeyId) -> Self {
        let mut line = self.clone();
        line.sig.signature = None;
        line.sig.key_id = Some(*key_id);
        line
    }
}

/// What a human decided, and — when they approved — exactly what they approved.
///
/// The scope rides inside the `Approved` variant so that an approval without a
/// recorded scope is unrepresentable. Approval without recorded scope is a
/// blank check in the evidence (ADR-0005), and the resumed call's grant must be
/// a subset of what is recorded here.
///
/// Like [`AuditDecision`], this is format-defining and has no shipped emitter:
/// it is reached only through an [`AuditDecision`], and nothing in this
/// repository's pipeline builds one. The unrepresentability rule above is
/// therefore a constraint on the format, enforced now so that the approval
/// protocol cannot later be built without it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ApprovalVerdict {
    Approved { scope: ApprovedScope },
    Denied { reason: String },
}

/// The authority a human approval granted.
///
/// Reached only through [`ApprovalVerdict::Approved`], so it is format-defining
/// and has no shipped emitter for the same reason: nothing in this repository's
/// pipeline resumes a parked Call, so nothing constructs one outside tests and
/// the published vectors they build.
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

    /// A present string `line_type` is the answer, and the strict reader never
    /// consults `phase` at all.
    #[test]
    fn the_line_type_field_is_read_without_a_fallback() {
        let tagged = serde_json::json!({"line_type": "outcome"});
        assert_eq!(line_type_field(&tagged), Some(AuditLineType::Outcome));

        // The case that separates the two readers: a genuine schema-v1 record.
        // The strict reader reports no tag rather than inventing one, which is
        // what lets `aegis verify` keep refusing v1 lines.
        let v1 = serde_json::json!({"phase": "outcome", "schema_version": 1});
        assert_eq!(line_type_field(&v1), None);

        // Present but not a string is no tag either.
        let numeric = serde_json::json!({"line_type": 7});
        assert_eq!(line_type_field(&numeric), None);
    }

    /// `line_type` wins over a disagreeing `phase` — the chimera line.
    ///
    /// This is the assertion the Session counter depends on: a line tagged
    /// `open` that also carries `phase: "outcome"` is a Session boundary, not a
    /// call. The other reading would report the boundary as a call *and* stall
    /// the counter, so every address after it would name the wrong Session.
    #[test]
    fn a_present_line_type_outranks_a_disagreeing_phase() {
        let chimera = serde_json::json!({"line_type": "open", "phase": "outcome"});
        assert_eq!(line_type_from_value(&chimera), Some(AuditLineType::Open));
        assert_eq!(line_type_field(&chimera), Some(AuditLineType::Open));
    }

    /// `phase` is consulted only when `line_type` is not a usable tag.
    #[test]
    fn phase_is_the_fallback_spelling_when_line_type_is_absent() {
        let v1_outcome = serde_json::json!({"phase": "outcome"});
        assert_eq!(
            line_type_from_value(&v1_outcome),
            Some(AuditLineType::Outcome)
        );

        // The fallback reads the whole vocabulary, not just outcomes — a v1
        // intent is still an intent, so a caller filtering for outcomes skips
        // it rather than reporting a call that recorded no decision.
        let v1_intent = serde_json::json!({"phase": "intent"});
        assert_eq!(
            line_type_from_value(&v1_intent),
            Some(AuditLineType::Intent)
        );

        // An unrecognised token keeps its spelling through the fallback too.
        let future = serde_json::json!({"phase": "something-from-2019"});
        assert_eq!(
            line_type_from_value(&future),
            Some(AuditLineType::Unknown("something-from-2019".into()))
        );

        // A non-string `line_type` falls through to the fallback.
        let numeric = serde_json::json!({"line_type": 7, "phase": "outcome"});
        assert_eq!(line_type_from_value(&numeric), Some(AuditLineType::Outcome));
    }

    /// Neither spelling present is no tag, under either reader.
    #[test]
    fn a_line_with_neither_tag_has_no_line_type() {
        let untagged = serde_json::json!({"call_id": "c", "seq": 3});
        assert_eq!(line_type_from_value(&untagged), None);
        assert_eq!(line_type_field(&untagged), None);
    }

    /// `None` until the first `Open`, then 0, 1, 2 … — and 0 in the address
    /// column before any `Open` has been seen.
    #[test]
    fn sessions_are_numbered_from_zero_at_each_open() {
        let mut counter = SessionCounter::new();
        assert_eq!(counter.index(), None);
        assert_eq!(counter.current(), 0);
        assert_eq!(counter.next_index(), 0);

        counter.note_open();
        assert_eq!(counter.index(), Some(0));
        assert_eq!(counter.current(), 0);
        assert_eq!(counter.next_index(), 1);

        counter.note_open();
        assert_eq!(counter.index(), Some(1));
        assert_eq!(counter.current(), 1);

        counter.note_open();
        assert_eq!(counter.current(), 2);
    }

    /// `next_index` is a peek, not a step: reading it does not advance.
    ///
    /// A verifying walk asks for the ordinal to name a Session in a tamper
    /// report it may then refuse to accept, so the read has to be free of the
    /// commit.
    #[test]
    fn next_index_does_not_advance_the_counter() {
        let mut counter = SessionCounter::default();
        assert_eq!(counter.next_index(), 0);
        assert_eq!(counter.next_index(), 0);
        assert_eq!(counter.index(), None);

        counter.note_open();
        assert_eq!(counter.next_index(), 1);
        assert_eq!(counter.next_index(), 1);
        assert_eq!(counter.index(), Some(0));
    }

    /// The cross-walk agreement test (ADR-0013).
    ///
    /// The same JSONL is driven through the two readers exactly as the two
    /// walks drive them — `aegis verify` routing on the `line_type` field
    /// alone, `aegis recheck` routing through the `phase` fallback — and both
    /// must place every line at the same Session ordinal.
    ///
    /// The fixture carries the three cases where an ordinal could diverge: an
    /// outcome *before* any `open` (both report Session 0), the chimera
    /// `open` + `phase: "outcome"` (both treat it as a boundary and advance),
    /// and a genuine v1 outcome with no `line_type` (which only recheck reports
    /// at all — but the two agree on the Session it sits in).
    #[test]
    fn both_readers_number_the_same_file_identically() {
        let lines = [
            r#"{"line_type":"outcome","call_id":"before-any-open"}"#,
            r#"{"line_type":"open"}"#,
            r#"{"line_type":"outcome","call_id":"first"}"#,
            r#"{"line_type":"open","phase":"outcome"}"#,
            r#"{"line_type":"outcome","call_id":"second"}"#,
            r#"{"schema_version":1,"phase":"outcome","call_id":"legacy"}"#,
        ];

        let mut verifying = SessionCounter::new();
        let mut rechecking = SessionCounter::new();
        let mut verify_addresses = Vec::new();
        let mut recheck_addresses = Vec::new();
        let mut recheck_reported = Vec::new();

        for raw in lines {
            let value: serde_json::Value = serde_json::from_str(raw).expect("fixture is JSON");

            // The verifying walk routes on the field alone — it has no reading
            // of `phase`, so a v1 line is untagged to it.
            if line_type_field(&value) == Some(AuditLineType::Open) {
                verifying.note_open();
            }
            verify_addresses.push(verifying.current());

            // The recheck walk uses the fallback to *recognise an outcome*, but
            // still takes Session boundaries off the field alone. That asymmetry
            // is the behaviour both walks shipped before the extraction.
            if line_type_field(&value) == Some(AuditLineType::Open) {
                rechecking.note_open();
            }
            if line_type_from_value(&value) == Some(AuditLineType::Outcome) {
                recheck_reported.push(rechecking.current());
            }
            recheck_addresses.push(rechecking.current());
        }

        assert_eq!(verify_addresses, recheck_addresses);
        // Outcome before any open is Session 0; the chimera advanced to 1; the
        // v1 tail line sits in the Session that was open when it was written.
        assert_eq!(verify_addresses, vec![0, 0, 0, 1, 1, 1]);
        // The four lines recheck reports — including the v1 one verify cannot
        // read — carry the ordinals verify assigns to the same file positions.
        assert_eq!(recheck_reported, vec![0, 0, 1, 1]);

        // And the chimera is an Open under *both* readers, never an outcome.
        let chimera: serde_json::Value = serde_json::from_str(lines[3]).unwrap();
        assert_eq!(line_type_from_value(&chimera), Some(AuditLineType::Open));
        assert_ne!(line_type_from_value(&chimera), Some(AuditLineType::Outcome));
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

    /// The fluent chain and the bare literal must produce the same value, so
    /// migrating an emitter to `with_*` cannot move a serialized byte. The
    /// tripwire above stays a bare literal on purpose — it fails to compile
    /// when an eighth axis lands — and this test is what pins the setters to
    /// it without borrowing that property away (AILAB-798).
    #[test]
    fn fluent_construction_equals_the_bare_literal_for_all_seven_axes() {
        let literal = DecisionAxes {
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
        let fluent = DecisionAxes::default()
            .with_capability("fs.read")
            .with_role("ops")
            .with_session("s-1")
            .with_matched_rule("rule-3")
            .with_approval_ref(ApprovalId::new("apr-1"))
            .with_fs(FsAxis {
                path_raw: "~/notes.md".into(),
                path_canonical: "/home/a/notes.md".into(),
            })
            .with_net(NetAxis {
                host: "example.com".into(),
                port: 443,
            });

        assert_eq!(fluent.capability, literal.capability);
        assert_eq!(fluent.role, literal.role);
        assert_eq!(fluent.session, literal.session);
        assert_eq!(fluent.matched_rule, literal.matched_rule);
        assert_eq!(fluent.approval_ref, literal.approval_ref);
        assert_eq!(fluent.fs, literal.fs);
        assert_eq!(fluent.net, literal.net);
        assert_eq!(fluent, literal);
        assert_eq!(
            jcs::to_canonical_json(&record().with_decision_axes(fluent)).unwrap(),
            jcs::to_canonical_json(&record().with_decision_axes(literal)).unwrap(),
        );
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
        assert_eq!(open.payload.prev_session_tail, Some(tail));
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

    /// Top-level keys of a JSON object, in the order they appear on the wire.
    ///
    /// `serde_json::to_string` emits no whitespace, so a string is a key
    /// exactly when it sits at depth 1 and the byte after its closing quote is
    /// the name separator. Nested keys live at depth 2 or deeper and are
    /// skipped — which matters here, because `capability` and `decision_axes`
    /// both carry inner objects with keys that collide with top-level names.
    fn top_level_keys(json: &str) -> Vec<&str> {
        let bytes = json.as_bytes();
        let mut keys = Vec::new();
        let mut depth = 0usize;
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'"' => {
                    let start = i + 1;
                    let mut j = start;
                    while j < bytes.len() && bytes[j] != b'"' {
                        j += if bytes[j] == b'\\' { 2 } else { 1 };
                    }
                    if depth == 1 && bytes.get(j + 1) == Some(&b':') {
                        keys.push(&json[start..j]);
                    }
                    i = j + 1;
                }
                b'{' | b'[' => {
                    depth += 1;
                    i += 1;
                }
                b'}' | b']' => {
                    depth -= 1;
                    i += 1;
                }
                _ => i += 1,
            }
        }
        keys
    }

    /// **The wire's key order is the field declaration order of [`Envelope`],
    /// and this is what enforces it** (AILAB-887).
    ///
    /// `#[serde(flatten)]` emits each part where it is declared, so reordering
    /// the three fields silently reorders every audit line. Before this test
    /// the only thing that would have noticed was
    /// `crates/botzr-aegis-runtime/tests/golden/resource_exceeded_orchestrator.json`,
    /// which pins order by accident of having been authored through the
    /// non-canonical serializer — nothing in that file's name or its test's
    /// name says so, so tidying it into canonical form would have removed the
    /// guard with every remaining test still green.
    ///
    /// **The line is built by deserializing, not by stamping.** `signature`
    /// and `key_id` are `skip_serializing_if` fields: a freshly constructed
    /// record omits them, and the tail of the object is exactly where the
    /// hazard lives. Reaching for the writer's stamping methods to fill them
    /// would tie this assertion to an API that AILAB-848 exists to seal — so
    /// this test does not name them, in prose or in code. Round-tripping a line
    /// that already carries a signature needs neither.
    #[test]
    fn envelope_key_order_is_header_then_payload_then_signature() {
        // A real signed outcome line, in the canonical (key-sorted) form every
        // vector is stored in. Sorted deliberately: the assertion below is only
        // meaningful because the output is *not* the input order.
        const CANONICAL: &str = r#"{"call_id":"call-1","capability":{"reason":"not evaluated","status":"denied"},"decision_axes":{},"execution":{"status":"success"},"key_id":"77a2c2f5952039243c043b69e7e812a2deb69e3271adb3013b8f24d3b8ea40f6","line_type":"outcome","policy":{"status":"allowed"},"policy_set_hash":"89a056813bdf93f95c1881a78793b1a86f5b6bab829c1ba9d20bb4add2aae921","prev_hash":"1f95193f1d9994b380c7fd3ff54b9f520db959c9b83888c1195c9080e51c7dcc","request_digest":"6efa0cc22bf543957fc0d08c16be0836a47920ec5a6234350b26460927848722","schema_version":2,"seq":6,"signature":"4a3a4700714e97fd1bcbae2a2539b182628197ef00ef48fca9470becaa7238bd9e77b07341ed997f37f752b905917e0a1795a7538926d502d8b01bb806c06b00","tool_id":"echo"}"#;

        let stored: Vec<&str> = top_level_keys(CANONICAL);
        let mut sorted = stored.clone();
        sorted.sort_unstable();
        assert_eq!(
            stored, sorted,
            "fixture is not canonical, so it cannot show that re-serializing reorders"
        );

        let line: AuditRecord =
            serde_json::from_str(CANONICAL).expect("a stored line deserializes");
        let emitted = serde_json::to_string(&line).expect("a line serializes");
        let keys = top_level_keys(&emitted);

        assert_eq!(
            &keys[..4],
            ["schema_version", "line_type", "seq", "prev_hash"],
            "ENVELOPE KEY ORDER MOVED: header keys are out of declaration order. \
             Got {keys:?}"
        );
        assert_eq!(
            &keys[keys.len() - 2..],
            ["signature", "key_id"],
            "ENVELOPE KEY ORDER MOVED: the SignatureBlock must come last. Moving \
             `sig` above `payload` puts signature/key_id in the middle of the \
             object, and the orchestrator golden vector stops reproducing. Got {keys:?}"
        );
        assert_ne!(
            keys, sorted,
            "ENVELOPE KEY ORDER MOVED: the emitted order is now key-sorted, so \
             declaration order and canonical order have stopped differing. That \
             is the distinction this whole property rests on"
        );
    }
}
