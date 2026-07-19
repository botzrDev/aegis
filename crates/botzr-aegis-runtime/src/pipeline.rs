//! One internal pipeline driver shared by Model A (WASM/fixture) and Model B
//! (host effect).
//!
//! It owns the load-bearing skeleton — session begin/complete, the policy
//! short-circuit, ceiling resolution, output-cap enforcement, and outcome
//! completion — so the two public entry points ([`Runtime::execute_tool_call`],
//! [`Runtime::execute_host_call`]) differ only in their execution step and the
//! caller-facing error string. Keeping this in one place removes the two
//! near-identical 80-line methods that previously drifted (AEG-41), while
//! preserving AEG-40 fail-closed `CallSession` semantics and AEG-38's
//! `decision.limits` pass-through.

use botzr_aegis_audit::CallSession;
use botzr_aegis_core::{
    CallMetrics, CapabilityGrant, CapabilityOutcome, ExecutionOutcome, PolicyOutcome, ToolId,
};
use botzr_aegis_policy::PolicyRequest;

use crate::{audit_err_to_string, enforce_output_cap, policy_rejection_message, Runtime};

/// What an adapter's execution step hands back to the driver.
///
/// `Produced` bytes are *candidate* success — the driver still runs them through
/// the output-cap gate before recording `Success`. `Failed` carries an
/// already-terminal execution outcome the adapter mapped itself (sandbox trap,
/// host denial, "tool not registered", …). Either variant may report resource
/// `metrics`: Model A always does (from the sandbox run), Model B never does
/// today.
pub(crate) enum ExecutionStep {
    Produced {
        bytes: Vec<u8>,
        metrics: Option<CallMetrics>,
    },
    Failed {
        outcome: ExecutionOutcome,
        metrics: Option<CallMetrics>,
    },
}

impl Runtime {
    /// Drive one tool call through POLICY → CAPABILITY → (execute) → AUDIT.
    ///
    /// `execute_step` is the only true fork between the two trust models: it runs
    /// the wasmtime sandbox / fixture (Model A) or the host effect (Model B). It
    /// is invoked **only** after policy allows *and* a grant is minted — a denied
    /// policy is rejected at station 1 and never reaches capability or the
    /// execution adapter. `map_error` turns the terminal execution outcome into
    /// the caller-facing error string, the one place Model A ("execution failed")
    /// and Model B (host reason / "host execution failed") legitimately differ.
    pub(crate) fn drive_pipeline<E, M>(
        &self,
        tool_id: ToolId,
        input_digest: String,
        policy_request: &PolicyRequest<'_>,
        execute_step: E,
        map_error: M,
    ) -> Result<Vec<u8>, String>
    where
        E: FnOnce(&CapabilityGrant) -> ExecutionStep,
        M: FnOnce(&ExecutionOutcome) -> String,
    {
        let mut session = CallSession::begin(&self.audit, tool_id.clone(), input_digest)
            .map_err(audit_err_to_string)?;

        // Station 1 — POLICY. Grab the decision once; a denied, rate-limited, or
        // pending-approval call is rejected here and never mints a grant or
        // reaches the execution adapter.
        let decision = self.policy.evaluate(policy_request);
        let policy_outcome = PolicyOutcome::from(&decision.action);

        if !matches!(policy_outcome, PolicyOutcome::Allowed) {
            session.set_policy(policy_outcome);
            session.set_capability(CapabilityOutcome::Denied {
                reason: "policy blocked before capability".into(),
                denied_capability: None,
            });
            session.set_execution(ExecutionOutcome::HostDenied {
                reason: "not executed".into(),
            });
            session.complete().map_err(audit_err_to_string)?;
            return Err(policy_rejection_message(&decision.action));
        }

        session.set_policy(PolicyOutcome::Allowed);

        // Station 2 — CAPABILITY. Fold any policy-derived ceiling into the
        // resolver (lowers limits only; never raises). `decision.limits` *is* the
        // same core `ResourceCeiling` the resolver takes — no field-by-field map,
        // so an axis transposition is impossible (AEG-38).
        let ceiling = decision.limits;
        let capability_outcome = self.capabilities.resolve_with_ceiling(&tool_id, ceiling);
        session.set_capability(capability_outcome.clone());

        let (execution, output) = match &capability_outcome {
            CapabilityOutcome::Granted { grant } => match execute_step(grant) {
                ExecutionStep::Produced { bytes, metrics } => {
                    if let Some(metrics) = metrics {
                        session.set_metrics(metrics);
                    }
                    // Output cap (G8): oversize output fails closed; bytes are
                    // never truncated and returned as success. Applied identically
                    // after Model A sandbox output and Model B host effect.
                    match enforce_output_cap(grant, bytes) {
                        Ok(bytes) => (ExecutionOutcome::Success, Some(bytes)),
                        Err(outcome) => (outcome, None),
                    }
                }
                ExecutionStep::Failed { outcome, metrics } => {
                    if let Some(metrics) = metrics {
                        session.set_metrics(metrics);
                    }
                    (outcome, None)
                }
            },
            CapabilityOutcome::Denied { .. } => (
                ExecutionOutcome::HostDenied {
                    reason: "capability denied".into(),
                },
                None,
            ),
        };

        // Derive the caller-facing error from the terminal outcome before it is
        // moved into the audit record; it is only meaningful when the call
        // produced no output.
        let failure = execution.clone();
        session.set_execution(execution);
        session.complete().map_err(audit_err_to_string)?;

        output.ok_or_else(|| map_error(&failure))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    use botzr_aegis_capability::{ToolInfo, ToolKind, ToolLimits, ToolManifest};
    use botzr_aegis_policy::PolicyEngine;

    /// Read the last JSONL line the runtime's audit sink recorded.
    fn last_audit_line(rt: &Runtime) -> String {
        std::fs::read_to_string(rt.audit().path())
            .unwrap()
            .lines()
            .last()
            .unwrap()
            .to_owned()
    }

    /// Register `tool` with an explicit output cap so a granted call is possible.
    fn register_capped(rt: &mut Runtime, tool: &ToolId, max_output_bytes: u64) {
        rt.capabilities().register(
            ToolManifest::new(
                ToolInfo {
                    id: tool.clone(),
                    version: "0.1.0".into(),
                    kind: ToolKind::Host,
                },
                std::env::temp_dir(),
            )
            .with_limits(ToolLimits {
                max_output_bytes,
                ..ToolLimits::default()
            }),
        );
    }

    #[test]
    fn policy_deny_never_invokes_execution_adapter() {
        // Even with the tool registered (so capability *would* grant), a policy
        // deny must short-circuit before capability: the fake never runs and the
        // audited capability reason is the load-bearing "policy blocked…" signal.
        let yaml = r#"
version: 1
default: allow
rules:
  - id: block-x
    action: deny
    tool: x
    reason: "blocked in test"
"#;
        let mut rt = Runtime::new().with_policy(PolicyEngine::from_yaml(yaml).unwrap());
        let tool = ToolId::new("x");
        register_capped(&mut rt, &tool, 1024);

        let called = Cell::new(false);
        let err = rt
            .drive_pipeline(
                tool.clone(),
                "digest".into(),
                &PolicyRequest::for_tool(&tool),
                |_grant| {
                    called.set(true);
                    ExecutionStep::Produced {
                        bytes: b"unreachable".to_vec(),
                        metrics: None,
                    }
                },
                |_outcome| "fake error".to_string(),
            )
            .unwrap_err();

        assert_eq!(err, "policy denied: blocked in test");
        assert!(!called.get(), "execution adapter must not run on policy deny");

        let outcome = last_audit_line(&rt);
        assert!(outcome.contains("\"status\":\"denied\""), "got: {outcome}");
        assert!(
            outcome.contains("policy blocked before capability"),
            "capability reason must survive: {outcome}"
        );
    }

    #[test]
    fn capability_deny_never_invokes_execution_adapter() {
        // allow-all policy but an unregistered tool → capability denies. The fake
        // must not run; the audited execution reason is "capability denied".
        let rt = Runtime::new();
        let tool = ToolId::new("never-registered");

        let called = Cell::new(false);
        let err = rt
            .drive_pipeline(
                tool.clone(),
                "digest".into(),
                &PolicyRequest::for_tool(&tool),
                |_grant| {
                    called.set(true);
                    ExecutionStep::Produced {
                        bytes: b"unreachable".to_vec(),
                        metrics: None,
                    }
                },
                |_outcome| "fake error".to_string(),
            )
            .unwrap_err();

        assert_eq!(err, "fake error");
        assert!(
            !called.get(),
            "execution adapter must not run on capability deny"
        );

        let outcome = last_audit_line(&rt);
        assert!(outcome.contains("capability denied"), "got: {outcome}");
    }

    #[test]
    fn allowed_grant_invokes_fake_exactly_once() {
        // allow-all + registered tool → the fake runs once, receives a grant, and
        // its bytes flow back to the caller as success.
        let mut rt = Runtime::new();
        let tool = ToolId::new("ok-tool");
        register_capped(&mut rt, &tool, 1024);

        let calls = Cell::new(0u32);
        let out = rt
            .drive_pipeline(
                tool.clone(),
                "digest".into(),
                &PolicyRequest::for_tool(&tool),
                |_grant| {
                    calls.set(calls.get() + 1);
                    ExecutionStep::Produced {
                        bytes: b"pong".to_vec(),
                        metrics: None,
                    }
                },
                |_outcome| "fake error".to_string(),
            )
            .expect("granted call succeeds");

        assert_eq!(out, b"pong");
        assert_eq!(calls.get(), 1, "execution adapter runs exactly once");

        let outcome = last_audit_line(&rt);
        assert!(outcome.contains("\"status\":\"success\""), "got: {outcome}");
    }

    #[test]
    fn output_cap_applies_after_fake_produces_oversize_bytes() {
        // Ordering: output-cap runs *after* the fake produces bytes. An 8-byte
        // cap with a 100-byte fake output fails closed to resource_exceeded, and
        // the bytes are never returned as success.
        let mut rt = Runtime::new();
        let tool = ToolId::new("bulky");
        register_capped(&mut rt, &tool, 8);

        let err = rt
            .drive_pipeline(
                tool.clone(),
                "digest".into(),
                &PolicyRequest::for_tool(&tool),
                |_grant| ExecutionStep::Produced {
                    bytes: vec![b'x'; 100],
                    metrics: None,
                },
                |_outcome| "fake error".to_string(),
            )
            .unwrap_err();

        assert_eq!(err, "fake error");

        let outcome = last_audit_line(&rt);
        assert!(
            outcome.contains("\"status\":\"resource_exceeded\""),
            "got: {outcome}"
        );
        assert!(outcome.contains("\"kind\":\"output\""), "got: {outcome}");
    }

    #[test]
    fn map_error_reads_the_terminal_outcome() {
        // The failure-string strategy sees the real terminal outcome. A Failed
        // step carrying HostDenied lets a Model-B-style strategy surface its
        // reason (proving the fork stays in the adapter, not the driver).
        let mut rt = Runtime::new();
        let tool = ToolId::new("gated");
        register_capped(&mut rt, &tool, 1024);

        let err = rt
            .drive_pipeline(
                tool.clone(),
                "digest".into(),
                &PolicyRequest::for_tool(&tool),
                |_grant| ExecutionStep::Failed {
                    outcome: ExecutionOutcome::HostDenied {
                        reason: "path outside grant".into(),
                    },
                    metrics: None,
                },
                |outcome| match outcome {
                    ExecutionOutcome::HostDenied { reason } => reason.clone(),
                    _ => "host execution failed".to_string(),
                },
            )
            .unwrap_err();

        assert_eq!(err, "path outside grant");
    }
}
