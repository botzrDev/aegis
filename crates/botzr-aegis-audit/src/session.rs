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
pub struct CallSession<'a> {
    writer: &'a AuditWriter,
    call_id: String,
    tool_id: ToolId,
    request_digest: RequestDigest,
    policy_set_hash: PolicySetHash,
    policy: PolicyOutcome,
    capability: CapabilityOutcome,
    execution: ExecutionOutcome,
    metrics: Option<CallMetrics>,
    decision_axes: DecisionAxes,
    grant_id: Option<GrantId>,
    response_digest: Option<ResponseDigest>,
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
            call_id,
            tool_id,
            request_digest,
            policy_set_hash,
            // Default-deny seeds: an unevaluated axis must never serialize as
            // `allowed` / `granted` / `success`. Setters overwrite these once
            // each station actually runs.
            policy: PolicyOutcome::Denied {
                reason: "not evaluated".into(),
            },
            capability: CapabilityOutcome::Denied {
                reason: "not evaluated".into(),
                denied_capability: None,
            },
            execution: ExecutionOutcome::HostDenied {
                reason: "not executed".into(),
            },
            metrics: None,
            // Empty, not absent: `{}` says this emitter recorded no axes, and
            // every axis field follows omit-never-null.
            decision_axes: DecisionAxes::default(),
            grant_id: None,
            response_digest: None,
            completed: Cell::new(false),
        })
    }

    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    pub fn set_policy(&mut self, policy: PolicyOutcome) {
        self.policy = policy;
    }

    pub fn set_capability(&mut self, capability: CapabilityOutcome) {
        self.capability = capability;
    }

    pub fn set_execution(&mut self, execution: ExecutionOutcome) {
        self.execution = execution;
    }

    pub fn set_metrics(&mut self, metrics: CallMetrics) {
        self.metrics = Some(metrics);
    }

    /// Record the inputs the verdict actually turned on, so a recorded deny can
    /// explain itself rather than only assert itself.
    pub fn set_decision_axes(&mut self, decision_axes: DecisionAxes) {
        self.decision_axes = decision_axes;
    }

    /// Link the record to the grant the call ran under. Left unset when no
    /// grant was minted — omitted on the wire, never null.
    pub fn set_grant_id(&mut self, grant_id: GrantId) {
        self.grant_id = Some(grant_id);
    }

    /// Digest of the raw response bytes, under the same verbatim rule as the
    /// request digest: hash what was produced, never a re-encoding of it.
    pub fn set_response_digest(&mut self, response_digest: ResponseDigest) {
        self.response_digest = Some(response_digest);
    }

    /// Emit the terminal outcome exactly once. Marks the session completed only
    /// after a successful write, so a failed emit leaves `Drop` as the
    /// last-resort fail-closed sink rather than silently dropping the outcome.
    pub fn complete(self) -> Result<(), AuditError> {
        self.writer.emit_outcome(&mut self.to_record())?;
        self.completed.set(true);
        Ok(())
    }

    fn to_record(&self) -> AuditRecord {
        let mut record = AuditRecord::new(
            self.call_id.clone(),
            self.tool_id.clone(),
            self.request_digest,
            self.policy_set_hash,
            self.policy.clone(),
            self.capability.clone(),
            self.execution.clone(),
        )
        .with_decision_axes(self.decision_axes.clone());
        if let Some(metrics) = self.metrics {
            record = record.with_metrics(metrics);
        }
        if let Some(grant_id) = &self.grant_id {
            record = record.with_grant_id(grant_id.clone());
        }
        if let Some(response_digest) = self.response_digest {
            record = record.with_response_digest(response_digest);
        }
        record
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
        self.execution = if std::thread::panicking() {
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
        let _ = self.writer.emit_outcome(&mut self.to_record());
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
        let json = crate::to_json_line(&session.to_record()).unwrap();
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
        let bare = crate::to_json_line(&session.to_record()).unwrap();
        assert!(bare.contains("\"decision_axes\":{}"), "{bare}");
        assert!(!bare.contains("grant_id"), "{bare}");
        assert!(!bare.contains("response_digest"), "{bare}");

        let axes = DecisionAxes::default()
            .with_role("ops")
            .with_matched_rule("rule-3");
        session.set_decision_axes(axes);
        session.set_grant_id(GrantId::new("grant-1"));
        session.set_response_digest(ResponseDigest::of_response_bytes(b"ok"));
        let record = session.to_record();
        assert_eq!(record.decision_axes.role.as_deref(), Some("ops"));
        assert_eq!(record.grant_id, Some(GrantId::new("grant-1")));
        assert_eq!(
            record.response_digest,
            Some(ResponseDigest::of_response_bytes(b"ok"))
        );
        assert_eq!(
            record.policy_set_hash,
            PolicySetHash::of_canonical_bytes(b"policy")
        );
    }
}
