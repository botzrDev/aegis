//! Per-call audit session — intent before execution, outcome on every exit path.
//!
//! A begun session is fail-closed by construction: its seeds serialize as
//! default-deny (never `allowed` / `granted` / `success`), and an incomplete
//! session always emits exactly one outcome when dropped. Panic unwinding
//! yields a trap; any other abandon / early return / error yields a host-denied
//! outcome, so a call is never left unaccounted for (design §6, G3).

use std::cell::Cell;

use botzr_aegis_core::{
    AuditIntent, AuditRecord, CallMetrics, CapabilityOutcome, ExecutionOutcome, PolicyOutcome,
    ToolId,
};

use crate::error::AuditError;
use crate::writer::AuditWriter;

/// Tracks one tool call from intent through outcome emission.
pub struct CallSession<'a> {
    writer: &'a AuditWriter,
    call_id: String,
    tool_id: ToolId,
    input_digest: String,
    policy: PolicyOutcome,
    capability: CapabilityOutcome,
    execution: ExecutionOutcome,
    metrics: Option<CallMetrics>,
    completed: Cell<bool>,
}

impl<'a> CallSession<'a> {
    pub fn begin(
        writer: &'a AuditWriter,
        tool_id: ToolId,
        input_digest: impl Into<String>,
    ) -> Result<Self, AuditError> {
        let call_id = writer.next_call_id();
        let input_digest = input_digest.into();
        writer.emit_intent(&AuditIntent::new(
            call_id.clone(),
            tool_id.clone(),
            input_digest.clone(),
        ))?;
        Ok(Self {
            writer,
            call_id,
            tool_id,
            input_digest,
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

    /// Emit the terminal outcome exactly once. Marks the session completed only
    /// after a successful write, so a failed emit leaves `Drop` as the
    /// last-resort fail-closed sink rather than silently dropping the outcome.
    pub fn complete(self) -> Result<(), AuditError> {
        self.writer.emit_outcome(&self.to_record())?;
        self.completed.set(true);
        Ok(())
    }

    fn to_record(&self) -> AuditRecord {
        let record = AuditRecord::new(
            self.call_id.clone(),
            self.tool_id.clone(),
            self.input_digest.clone(),
            self.policy.clone(),
            self.capability.clone(),
            self.execution.clone(),
        );
        if let Some(metrics) = self.metrics {
            record.with_metrics(metrics)
        } else {
            record
        }
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
        let _ = self.writer.emit_outcome(&self.to_record());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Count how many `outcome` JSONL lines the sink recorded.
    fn outcome_count(text: &str) -> usize {
        text.lines()
            .filter(|line| line.contains("\"phase\":\"outcome\""))
            .count()
    }

    #[test]
    fn panic_emits_trap_outcome() {
        let writer = crate::writer::AuditWriter::open_temp().unwrap();
        let path = writer.path().to_path_buf();
        let result = std::panic::catch_unwind(|| {
            let _session =
                CallSession::begin(&writer, ToolId::new("panic-tool"), "abc123").unwrap();
            panic!("simulated host panic");
        });
        assert!(result.is_err());
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.contains("host panic during tool call"));
        assert!(text.contains("\"phase\":\"outcome\""));
        // Exactly one outcome, and default-deny seeds must not leak `allowed`
        // when nothing was evaluated before the panic.
        assert_eq!(outcome_count(&text), 1);
        assert!(!text.contains("\"policy\":{\"status\":\"allowed\"}"));
    }

    #[test]
    fn abandoned_session_emits_one_fail_closed_outcome() {
        let writer = crate::writer::AuditWriter::open_temp().unwrap();
        let path = writer.path().to_path_buf();
        {
            let _session =
                CallSession::begin(&writer, ToolId::new("abandoned-tool"), "abc123").unwrap();
            // No `complete()` — the session is abandoned and dropped here.
        }
        let text = std::fs::read_to_string(&path).unwrap();
        // Intent plus exactly one fail-closed outcome — never an orphan intent.
        assert!(text.contains("\"phase\":\"intent\""));
        assert_eq!(outcome_count(&text), 1, "abandon must emit one outcome");
        let outcome = text
            .lines()
            .find(|line| line.contains("\"phase\":\"outcome\""))
            .unwrap();
        assert!(outcome.contains("\"execution\":{\"status\":\"host_denied\""));
        assert!(outcome.contains("session abandoned"));
        // Default-deny: an untouched session never serializes an authority grant.
        assert!(!outcome.contains("\"status\":\"allowed\""));
        assert!(!outcome.contains("\"status\":\"granted\""));
        assert!(!outcome.contains("\"status\":\"success\""));
    }

    #[test]
    fn complete_then_drop_emits_exactly_one_outcome() {
        let writer = crate::writer::AuditWriter::open_temp().unwrap();
        let path = writer.path().to_path_buf();
        let mut session =
            CallSession::begin(&writer, ToolId::new("ok-tool"), "abc123").unwrap();
        session.set_policy(PolicyOutcome::Allowed);
        session.set_execution(ExecutionOutcome::Success);
        session.complete().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        // complete() consumes the session; its Drop must not append a second line.
        assert_eq!(outcome_count(&text), 1, "complete then drop must not duplicate");
        assert!(text.contains("\"execution\":{\"status\":\"success\"}"));
    }

    #[test]
    fn begin_seeds_never_serialize_allowed_or_success() {
        let writer = crate::writer::AuditWriter::open_temp().unwrap();
        let session =
            CallSession::begin(&writer, ToolId::new("seed-tool"), "abc123").unwrap();
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
}
