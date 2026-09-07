//! Per-call audit session — intent before execution, outcome on every exit path.
//!
//! A begun session is fail-closed by construction: its seeds serialize as
//! default-deny (never `allowed` / `granted` / `success`), and an incomplete
//! session always emits exactly one outcome when dropped. Panic unwinding
//! yields a trap; any other abandon / early return / error yields a host-denied
//! outcome, so a call is never left unaccounted for (design §6, G3).
//!
//! `CallSession<'a>` borrows `&'a AuditWriter`, so the writer — the Session
//! owner — structurally outlives every Call it issued, and the Session `Close`
//! line cannot be written while a Call is in flight.

use std::cell::Cell;

use botzr_aegis_core::{
    AuditIntent, AuditRecord, CallMetrics, CapabilityOutcome, DecisionAxes, ExecutionOutcome,
    GrantId, PolicyOutcome, PolicySetHash, RequestDigest, ResponseDigest, ToolId,
};

use crate::error::AuditError;
use crate::writer::AuditWriter;

/// Tracks one tool call from intent through outcome emission.
///
/// The session holds the outcome record it will emit, seeded default-deny at
/// `begin`. It is the record — there is no second copy of the twelve payload
/// fields to drift from it, and no rebuild step between the last setter and the
/// write. Both exit paths (`complete` and `Drop`) hand the writer the same
/// record, which is what makes "exactly one outcome" a property of one value
/// rather than of two construction sites agreeing.
pub struct CallSession<'a> {
    writer: &'a AuditWriter,
    record: AuditRecord,
    completed: Cell<bool>,
}

impl<'a> CallSession<'a> {
    /// Begin a Call: append and fsync the intent line before any execution.
    ///
    /// `policy_set_hash` is taken here rather than set later so that a record
    /// can never be written without naming the Policy Set that governed it — a
    /// verdict whose ruleset is unknown cannot be rechecked.
    pub fn begin(
        writer: &'a AuditWriter,
        tool_id: ToolId,
        request_digest: RequestDigest,
        policy_set_hash: PolicySetHash,
    ) -> Result<Self, AuditError> {
        let call_id = writer.next_call_id();
        writer.emit_intent(&mut AuditIntent::new(
            call_id.clone(),
            tool_id.clone(),
            request_digest,
        ))?;
        Ok(Self {
            writer,
            // Default-deny seeds: an unevaluated axis must never serialize as
            // `allowed` / `granted` / `success`. Setters overwrite these once
            // each station actually runs. They are constructor arguments, not
            // post-construction assignments, so there is no window in which a
            // record exists without them.
            record: AuditRecord::new(
                call_id,
                tool_id,
                request_digest,
                policy_set_hash,
                PolicyOutcome::Denied {
                    reason: "not evaluated".into(),
                },
                CapabilityOutcome::Denied {
                    reason: "not evaluated".into(),
                    denied_capability: None,
                },
                ExecutionOutcome::HostDenied {
                    reason: "not executed".into(),
                },
            ),
            completed: Cell::new(false),
        })
    }

    pub fn call_id(&self) -> &str {
        &self.record.payload.call_id
    }

    /// The capability outcome this call resolved to, borrowed from the record
    /// that will be emitted.
    ///
    /// The caller hands the outcome over with [`Self::set_capability`] *before*
    /// execution — so a call that panics mid-execution still emits a record
    /// naming the grant it ran under — and then reads the grant back through
    /// here for the duration of that execution. Returning a borrow rather than
    /// a clone is the point: the record owns the grant, and the pipeline works
    /// from the same value it will publish instead of from a copy of it.
    pub fn capability(&self) -> &CapabilityOutcome {
        &self.record.payload.capability
    }

    pub fn set_policy(&mut self, policy: PolicyOutcome) {
        self.record.payload.policy = policy;
    }

    pub fn set_capability(&mut self, capability: CapabilityOutcome) {
        self.record.payload.capability = capability;
    }

    pub fn set_execution(&mut self, execution: ExecutionOutcome) {
        self.record.payload.execution = execution;
    }

    /// Both halves of one measurement. `wall_ms` and `peak_memory_bytes` are
    /// two payload fields but a single observation, so they are taken together
    /// and written together — a record carrying one without the other would
    /// describe a call nobody measured that way.
    pub fn set_metrics(&mut self, metrics: CallMetrics) {
        self.record.payload.wall_ms = Some(metrics.wall_ms);
        self.record.payload.peak_memory_bytes = Some(metrics.peak_memory_bytes);
    }

    /// Record the inputs the verdict actually turned on, so a recorded deny can
    /// explain itself rather than only assert itself.
    pub fn set_decision_axes(&mut self, decision_axes: DecisionAxes) {
        self.record.payload.decision_axes = decision_axes;
    }

    /// Link the record to the grant the call ran under. Left unset when no
    /// grant was minted — omitted on the wire, never null.
    pub fn set_grant_id(&mut self, grant_id: GrantId) {
        self.record.payload.grant_id = Some(grant_id);
    }

    /// Digest of the raw response bytes, under the same verbatim rule as the
    /// request digest: hash what was produced, never a re-encoding of it.
    pub fn set_response_digest(&mut self, response_digest: ResponseDigest) {
        self.record.payload.response_digest = Some(response_digest);
    }

    /// Emit the terminal outcome exactly once. Marks the session completed only
    /// after a successful write, so a failed emit leaves `Drop` as the
    /// last-resort fail-closed sink rather than silently dropping the outcome.
    ///
    /// `mut self` is a binding mode, not part of the signature: the record is
    /// stamped in place, and `CallSession` has a `Drop` impl, so it cannot be
    /// moved out. Re-emitting after a failed write is safe because both stamps
    /// are unconditional assignments and the signing input clears the signature
    /// first — the second attempt produces exactly the bytes a fresh record
    /// would have.
    pub fn complete(mut self) -> Result<(), AuditError> {
        self.writer.emit_outcome(&mut self.record)?;
        self.completed.set(true);
        Ok(())
    }
}

impl Drop for CallSession<'_> {
    fn drop(&mut self) {
        // A completed session already emitted its single outcome — never dupe.
        if self.completed.get() {
            return;
        }
        // Force a fail-closed execution outcome: panic → trap, any other
        // abandon / early return / error → host-denied. This overwrites even a
        // `Success` a caller set but never `complete()`d, so an unconfirmed
        // call is never recorded as having run.
        self.record.payload.execution = if std::thread::panicking() {
            ExecutionOutcome::Trap {
                message: "host panic during tool call".into(),
            }
        } else {
            ExecutionOutcome::HostDenied {
                reason: "session abandoned".into(),
            }
        };
        // Best-effort last-resort sink: a write failure here has nowhere left
        // to go (the caller is already unwinding or has dropped the session).
        let _ = self.writer.emit_outcome(&mut self.record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::signing::insecure_dev_key;
    use crate::sink::MemoryChainSink;

    /// A Session over an in-memory Chain, plus the clone the test reads it back
    /// through — the shape the runtime's default Sink has since ADR-0012.
    /// `MemoryChainSink` clones share the buffer, and a Volatile sink is the
    /// pairing the dev key is allowed.
    fn memory_session() -> (AuditWriter, MemoryChainSink) {
        let store = MemoryChainSink::new();
        let writer = AuditWriter::with_sink(Box::new(store.clone()), insecure_dev_key())
            .expect("a Volatile sink accepts the dev key");
        (writer, store)
    }

    fn begin<'a>(writer: &'a AuditWriter, tool: &str) -> Result<CallSession<'a>, AuditError> {
        CallSession::begin(
            writer,
            ToolId::new(tool),
            RequestDigest::of_request_bytes(b"abc123"),
            PolicySetHash::of_canonical_bytes(b"policy"),
        )
    }

    /// Count how many `outcome` JSONL lines the sink recorded.
    fn outcome_count(text: &str) -> usize {
        text.lines()
            .filter(|line| line.contains("\"line_type\":\"outcome\""))
            .count()
    }

    #[test]
    fn panic_emits_trap_outcome() {
        let (writer, store) = memory_session();
        let result = std::panic::catch_unwind(|| {
            let _session = begin(&writer, "panic-tool").unwrap();
            panic!("simulated host panic");
        });
        assert!(result.is_err());
        let text = store.to_text();
        assert!(text.contains("host panic during tool call"));
        assert!(text.contains("\"line_type\":\"outcome\""));
        // Exactly one outcome, and default-deny seeds must not leak `allowed`
        // when nothing was evaluated before the panic.
        assert_eq!(outcome_count(&text), 1);
        assert!(!text.contains("\"policy\":{\"status\":\"allowed\"}"));
    }

    #[test]
    fn abandoned_session_emits_one_fail_closed_outcome() {
        let (writer, store) = memory_session();
        {
            let _session = begin(&writer, "abandoned-tool").unwrap();
            // No `complete()` — the session is abandoned and dropped here.
        }
        let text = store.to_text();
        // Intent plus exactly one fail-closed outcome — never an orphan intent.
        assert!(text.contains("\"line_type\":\"intent\""));
        assert_eq!(outcome_count(&text), 1, "abandon must emit one outcome");
        // Parsed rather than substring-matched: rows on disk are in canonical
        // (key-sorted) form, so field order is not the emitter's to assume.
        let outcome: serde_json::Value = serde_json::from_str(
            text.lines()
                .find(|line| line.contains("\"line_type\":\"outcome\""))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(outcome["execution"]["status"], "host_denied");
        assert_eq!(outcome["execution"]["reason"], "session abandoned");
        let outcome = outcome.to_string();
        // Default-deny: an untouched session never serializes an authority grant.
        assert!(!outcome.contains("\"status\":\"allowed\""));
        assert!(!outcome.contains("\"status\":\"granted\""));
        assert!(!outcome.contains("\"status\":\"success\""));
    }

    #[test]
    fn complete_then_drop_emits_exactly_one_outcome() {
        let (writer, store) = memory_session();
        let mut session = begin(&writer, "ok-tool").unwrap();
        session.set_policy(PolicyOutcome::Allowed);
        session.set_execution(ExecutionOutcome::Success);
        session.complete().unwrap();
        let text = store.to_text();
        // complete() consumes the session; its Drop must not append a second line.
        assert_eq!(
            outcome_count(&text),
            1,
            "complete then drop must not duplicate"
        );
        assert!(text.contains("\"execution\":{\"status\":\"success\"}"));
    }

    #[test]
    fn begin_seeds_never_serialize_allowed_or_success() {
        let (writer, _store) = memory_session();
        let session = begin(&writer, "seed-tool").unwrap();
        let json = crate::to_json_line(&session.record).unwrap();
        assert!(
            !json.contains("\"policy\":{\"status\":\"allowed\"}"),
            "seed policy must not serialize as allowed: {json}"
        );
        assert!(
            !json.contains("\"execution\":{\"status\":\"success\"}"),
            "seed execution must not serialize as success: {json}"
        );
        assert!(
            !json.contains("\"capability\":{\"status\":\"granted\""),
            "seed capability must not serialize as granted: {json}"
        );
    }

    #[test]
    fn the_new_axes_reach_the_record_and_stay_omitted_until_set() {
        let (writer, _store) = memory_session();
        let mut session = begin(&writer, "axes-tool").unwrap();
        let bare = crate::to_json_line(&session.record).unwrap();
        assert!(bare.contains("\"decision_axes\":{}"), "{bare}");
        assert!(!bare.contains("grant_id"), "{bare}");
        assert!(!bare.contains("response_digest"), "{bare}");

        let axes = DecisionAxes::default()
            .with_role("ops")
            .with_matched_rule("rule-3");
        session.set_decision_axes(axes);
        session.set_grant_id(GrantId::new("grant-1"));
        session.set_response_digest(ResponseDigest::of_response_bytes(b"ok"));
        let record = &session.record;
        assert_eq!(record.payload.decision_axes.role.as_deref(), Some("ops"));
        assert_eq!(record.payload.grant_id, Some(GrantId::new("grant-1")));
        assert_eq!(
            record.payload.response_digest,
            Some(ResponseDigest::of_response_bytes(b"ok"))
        );
        assert_eq!(
            record.payload.policy_set_hash,
            PolicySetHash::of_canonical_bytes(b"policy")
        );
    }
}
