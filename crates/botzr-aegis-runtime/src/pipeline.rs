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
    AegisError, CallMetrics, CapabilityGrant, CapabilityOutcome, DecisionAxes, ExecutionOutcome,
    FsAxis, GrantId, NetAxis, PolicyAction, PolicyOutcome, RequestDigest, ResponseDigest, ToolId,
};
use botzr_aegis_policy::PolicyRequest;

use crate::{enforce_output_cap, Runtime};

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
    /// execution adapter. Error construction is station-aware: policy deny →
    /// `PolicyDenied`, capability deny → `CapabilityDenied`, execution trap →
    /// `Trap`, and so on.
    ///
    /// The audited `request_digest` is computed here from the exact `input`
    /// bytes the execution step will see (AEG-44 §3.C) — no public API accepts a
    /// caller-supplied digest, so audit cannot be made to lie about the payload.
    pub(crate) fn drive_pipeline<E>(
        &self,
        tool_id: ToolId,
        input: &[u8],
        policy_request: &PolicyRequest<'_>,
        execute_step: E,
    ) -> Result<Vec<u8>, AegisError>
    where
        E: FnOnce(&CapabilityGrant) -> ExecutionStep,
    {
        // SHA-256 over the **raw** input bytes, never a canonicalized or
        // re-encoded copy of them: this digest is what content-addresses the
        // Envelope, so reformatting the payload before hashing silently breaks
        // the link — and the break is invisible until someone runs a formatter
        // (ADR-0001).
        let request_digest = RequestDigest::of_request_bytes(input);

        // Read once, up front: the record names the Policy Set that governed the
        // call from the moment the intent line exists, so a verdict can never be
        // written without the ruleset it was decided under.
        let policy_set_hash = self.policy.active_content_hash();

        let mut session = CallSession::begin(
            &self.audit,
            tool_id.clone(),
            request_digest,
            policy_set_hash,
        )
        .map_err(|e| AegisError::Audit {
            message: format!("{e}"),
        })?;

        // Station 1 — POLICY. Grab the decision once; a denied, rate-limited, or
        // pending-approval call is rejected here and never mints a grant or
        // reaches the execution adapter.
        let decision = self.policy.evaluate(policy_request);
        let policy_outcome = PolicyOutcome::from(&decision.action);

        // Record what the verdict actually turned on, *before* the deny
        // short-circuit: a role-gated deny that persists only `tool_id` can
        // neither replay nor explain itself, and the denied call is exactly the
        // record someone comes back to read (ADR-0001).
        // Built with the fluent `with_*` chain, not a struct literal:
        // `DecisionAxes` is `#[non_exhaustive]`, so no crate but core may spell
        // it as a struct expression — functional-update syntax included. Each
        // axis is set only when the request actually carried one: an unset axis
        // is omitted, and `""` would be a recorded empty value, not an absence.
        let mut axes = DecisionAxes::default();
        if let Some(capability) = policy_request.capability {
            axes = axes.with_capability(capability);
        }
        if let Some(role) = policy_request.role {
            axes = axes.with_role(role);
        }
        if let Some(session) = policy_request.session {
            axes = axes.with_session(session);
        }
        if let Some(matched_rule) = decision.matched_rule.clone() {
            axes = axes.with_matched_rule(matched_rule);
        }
        session.set_decision_axes(axes.clone());

        if !matches!(policy_outcome, PolicyOutcome::Allowed) {
            session.set_policy(policy_outcome);
            session.set_capability(CapabilityOutcome::Denied {
                reason: "policy blocked before capability".into(),
                denied_capability: None,
            });
            session.set_execution(ExecutionOutcome::HostDenied {
                reason: "not executed".into(),
            });
            session.complete().map_err(|e| AegisError::Audit {
                message: format!("{e}"),
            })?;
            return Err(match &decision.action {
                PolicyAction::Deny { reason } => AegisError::PolicyDenied {
                    reason: reason.clone(),
                },
                PolicyAction::RateLimited { reason } => AegisError::RateLimited {
                    reason: reason.clone(),
                },
                PolicyAction::PendingApproval { approval_id } => AegisError::PendingApproval {
                    approval_id: approval_id.clone(),
                },
                PolicyAction::Allow => unreachable!(),
            });
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
            CapabilityOutcome::Granted { grant } => {
                session.set_grant_id(GrantId::new(grant.grant_id.clone()));
                // Derived capability parameters (ADR-0006): the resources this
                // call resolved to, recorded only when the grant names exactly
                // one. Reading them off the minted grant is not a matcher and
                // not a new resolution step — matcher shapes are AILAB-626.
                // Same `with_*` chain as the axes above, and same omit rule: a
                // grant that names no single resource leaves the axis unset
                // rather than recording an absence. Both are `None` here — the
                // only writer is this block — so this records exactly what the
                // direct assignment it replaced did.
                if let Some(fs) = fs_axis(grant) {
                    axes = axes.with_fs(fs);
                }
                if let Some(net) = net_axis(grant) {
                    axes = axes.with_net(net);
                }
                session.set_decision_axes(axes.clone());

                match execute_step(grant) {
                    ExecutionStep::Produced { bytes, metrics } => {
                        if let Some(metrics) = metrics {
                            session.set_metrics(metrics);
                        }
                        // Output cap (G8): oversize output fails closed; bytes are
                        // never truncated and returned as success. Applied identically
                        // after Model A sandbox output and Model B host effect.
                        match enforce_output_cap(grant, bytes) {
                            Ok(bytes) => {
                                // Only on the success path: bytes the cap
                                // rejected were never returned, so digesting
                                // them would record a response that never left.
                                session
                                    .set_response_digest(ResponseDigest::of_response_bytes(&bytes));
                                (ExecutionOutcome::Success, Some(bytes))
                            }
                            Err(outcome) => (outcome, None),
                        }
                    }
                    ExecutionStep::Failed { outcome, metrics } => {
                        if let Some(metrics) = metrics {
                            session.set_metrics(metrics);
                        }
                        (outcome, None)
                    }
                }
            }
            CapabilityOutcome::Denied { .. } => (
                ExecutionOutcome::HostDenied {
                    reason: "capability denied".into(),
                },
                None,
            ),
        };

        let failure = execution.clone();
        session.set_execution(execution);
        session.complete().map_err(|e| AegisError::Audit {
            message: format!("{e}"),
        })?;

        // Capability deny gets its own variant to the caller even though audit
        // records execution as HostDenied{"capability denied"}.
        if let CapabilityOutcome::Denied {
            reason,
            denied_capability,
        } = &capability_outcome
        {
            return Err(AegisError::CapabilityDenied {
                reason: reason.clone(),
                denied_capability: denied_capability.clone(),
            });
        }

        output.ok_or_else(|| match &failure {
            ExecutionOutcome::Trap { message } => AegisError::Trap {
                message: message.clone(),
            },
            ExecutionOutcome::ResourceExceeded { kind } => {
                AegisError::ResourceExceeded { kind: kind.clone() }
            }
            ExecutionOutcome::HostDenied { reason } => AegisError::HostDenied {
                reason: reason.clone(),
            },
            ExecutionOutcome::Success => unreachable!("no output on Err path"),
        })
    }
}

/// The filesystem resource this call resolved to, when the grant names exactly
/// one (ADR-0006).
///
/// A grant carrying several roots has not resolved the call to *a* path — which
/// of them the call touched is what AILAB-626's bindings decide — so the axis is
/// **omitted entirely rather than guessed**. Recording an arbitrary one of N
/// roots would be evidence that reads as fact and is not.
///
/// Both spellings carry the same string today: the capability resolver
/// canonicalizes at mint time (`botzr-aegis-capability`'s `mint.rs`), so a grant
/// only ever holds the canonical form. The pair exists because AILAB-626
/// resolves a caller-supplied path *against* this root, and that is where raw
/// and canonical diverge; recording one field now would make the shape a
/// breaking change then.
fn fs_axis(grant: &CapabilityGrant) -> Option<FsAxis> {
    let fs = grant.fs.as_ref()?;
    let mut roots: Vec<&String> = fs.read_paths.iter().chain(fs.write_paths.iter()).collect();
    roots.sort_unstable();
    roots.dedup();
    let [root] = roots[..] else { return None };
    Some(FsAxis {
        path_raw: root.clone(),
        path_canonical: root.clone(),
    })
}

/// The network resource this call resolved to, under the same
/// exactly-one-or-omit rule as [`fs_axis`].
fn net_axis(grant: &CapabilityGrant) -> Option<NetAxis> {
    let net = grant.net.as_ref()?;
    let [http] = &net.http[..] else { return None };
    let [port] = http.ports[..] else { return None };
    Some(NetAxis {
        host: http.host.clone(),
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    use botzr_aegis_audit::{insecure_dev_key, AuditWriter, MemoryChainSink};
    use botzr_aegis_capability::{ToolInfo, ToolKind, ToolLimits, ToolManifest};
    use botzr_aegis_core::AegisError;
    use botzr_aegis_policy::PolicyEngine;

    /// A runtime whose audit Chain the test can read back.
    ///
    /// The default Sink is Volatile and in-memory (ADR-0012) and the writer
    /// owns it, so a test that wants the bytes supplies its own
    /// [`MemoryChainSink`] and keeps a clone — `Clone` shares the buffer.
    fn audited_runtime() -> (Runtime, MemoryChainSink) {
        let store = MemoryChainSink::new();
        let rt = Runtime::new().with_audit(
            AuditWriter::with_sink(Box::new(store.clone()), insecure_dev_key())
                .expect("volatile memory sink must open"),
        );
        (rt, store)
    }

    /// Read the last JSONL line the runtime's audit sink recorded.
    fn last_audit_line(audit: &MemoryChainSink) -> String {
        audit
            .to_text()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .next_back()
            .unwrap()
            .to_owned()
    }

    /// Register `tool` with an explicit output cap so a granted call is possible.
    ///
    /// These tests drive `drive_pipeline` with their own execution step, so the
    /// stored handler is never invoked — it exists only because registration is
    /// atomic now: manifest authority cannot be written without an executable.
    fn register_capped(rt: &mut Runtime, tool: &ToolId, max_output_bytes: u64) {
        rt.register_tool(
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
            crate::ToolExecutable::HostHandler(Box::new(|_ctx, input| Ok(input.to_vec()))),
        )
        .expect("register host tool");
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
        let (rt, audit) = audited_runtime();
        let mut rt = rt.with_policy(PolicyEngine::from_yaml(yaml).unwrap());
        let tool = ToolId::new("x");
        register_capped(&mut rt, &tool, 1024);

        let called = Cell::new(false);
        let err = rt
            .drive_pipeline(
                tool.clone(),
                b"digest-input",
                &PolicyRequest::for_tool(&tool),
                |_grant| {
                    called.set(true);
                    ExecutionStep::Produced {
                        bytes: b"unreachable".to_vec(),
                        metrics: None,
                    }
                },
            )
            .unwrap_err();

        assert_eq!(
            err,
            AegisError::PolicyDenied {
                reason: "blocked in test".into()
            }
        );
        assert!(
            !called.get(),
            "execution adapter must not run on policy deny"
        );

        let outcome = last_audit_line(&audit);
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
        let (rt, audit) = audited_runtime();
        let tool = ToolId::new("never-registered");

        let called = Cell::new(false);
        let err = rt
            .drive_pipeline(
                tool.clone(),
                b"digest-input",
                &PolicyRequest::for_tool(&tool),
                |_grant| {
                    called.set(true);
                    ExecutionStep::Produced {
                        bytes: b"unreachable".to_vec(),
                        metrics: None,
                    }
                },
            )
            .unwrap_err();

        assert!(
            matches!(err, AegisError::CapabilityDenied { .. }),
            "expected CapabilityDenied, got {err:?}"
        );
        assert!(
            !called.get(),
            "execution adapter must not run on capability deny"
        );

        let outcome = last_audit_line(&audit);
        assert!(outcome.contains("capability denied"), "got: {outcome}");
    }

    #[test]
    fn allowed_grant_invokes_fake_exactly_once() {
        // allow-all + registered tool → the fake runs once, receives a grant, and
        // its bytes flow back to the caller as success.
        let (mut rt, audit) = audited_runtime();
        let tool = ToolId::new("ok-tool");
        register_capped(&mut rt, &tool, 1024);

        let calls = Cell::new(0u32);
        let out = rt
            .drive_pipeline(
                tool.clone(),
                b"digest-input",
                &PolicyRequest::for_tool(&tool),
                |_grant| {
                    calls.set(calls.get() + 1);
                    ExecutionStep::Produced {
                        bytes: b"pong".to_vec(),
                        metrics: None,
                    }
                },
            )
            .expect("granted call succeeds");

        assert_eq!(out, b"pong");
        assert_eq!(calls.get(), 1, "execution adapter runs exactly once");

        let outcome = last_audit_line(&audit);
        assert!(outcome.contains("\"status\":\"success\""), "got: {outcome}");
    }

    #[test]
    fn output_cap_applies_after_fake_produces_oversize_bytes() {
        // Ordering: output-cap runs *after* the fake produces bytes. An 8-byte
        // cap with a 100-byte fake output fails closed to resource_exceeded, and
        // the bytes are never returned as success.
        let (mut rt, audit) = audited_runtime();
        let tool = ToolId::new("bulky");
        register_capped(&mut rt, &tool, 8);

        let err = rt
            .drive_pipeline(
                tool.clone(),
                b"digest-input",
                &PolicyRequest::for_tool(&tool),
                |_grant| ExecutionStep::Produced {
                    bytes: vec![b'x'; 100],
                    metrics: None,
                },
            )
            .unwrap_err();

        assert_eq!(
            err,
            AegisError::ResourceExceeded {
                kind: "output".into()
            }
        );

        let outcome = last_audit_line(&audit);
        assert!(
            outcome.contains("\"status\":\"resource_exceeded\""),
            "got: {outcome}"
        );
        assert!(outcome.contains("\"kind\":\"output\""), "got: {outcome}");
    }

    #[test]
    fn host_denied_is_surfaced_as_typed_error() {
        // A Failed step carrying HostDenied surfaces as AegisError::HostDenied
        // (no more map_error callback — the driver maps uniformly).
        let mut rt = Runtime::new();
        let tool = ToolId::new("gated");
        register_capped(&mut rt, &tool, 1024);

        let err = rt
            .drive_pipeline(
                tool.clone(),
                b"digest-input",
                &PolicyRequest::for_tool(&tool),
                |_grant| ExecutionStep::Failed {
                    outcome: ExecutionOutcome::HostDenied {
                        reason: "path outside grant".into(),
                    },
                    metrics: None,
                },
            )
            .unwrap_err();

        assert_eq!(
            err,
            AegisError::HostDenied {
                reason: "path outside grant".into()
            }
        );
    }
}
