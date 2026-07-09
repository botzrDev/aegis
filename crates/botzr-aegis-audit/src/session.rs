//! Per-call audit session — intent before execution, outcome on every exit path.
//!
//! On host panic during an incomplete session, [`Drop`] emits a trap outcome so
//! the call is never unaccounted for (design §6, G3).

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
            policy: PolicyOutcome::Allowed,
            capability: CapabilityOutcome::Denied {
                reason: "not resolved".into(),
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

    pub fn complete(self) -> Result<(), AuditError> {
        self.completed.set(true);
        self.writer.emit_outcome(&self.to_record())
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
        if self.completed.get() {
            return;
        }
        if std::thread::panicking() {
            self.execution = ExecutionOutcome::Trap {
                message: "host panic during tool call".into(),
            };
            let _ = self.writer.emit_outcome(&self.to_record());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
