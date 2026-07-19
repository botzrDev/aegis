//! Library-mode entry point — wires the enforcement pipeline in load-bearing order.

mod digest;
mod error;
pub mod host;

use std::collections::HashMap;

use botzr_aegis_audit::{AuditError, AuditWriter, CallSession};
use botzr_aegis_capability::{CapabilityResolver, ToolManifest};
use botzr_aegis_core::{
    CapabilityGrant, CapabilityOutcome, ExecutionOutcome, PolicyAction, PolicyOutcome, ToolId,
    PIPELINE_STAGES,
};
use botzr_aegis_policy::{PolicyEngine, PolicyRequest};
use botzr_aegis_sandbox::{PreparedFixture, PreparedTool, SandboxEngine};

pub use digest::sha256_hex;
pub use error::RegisterError;
pub use host::{HostCallRequest, HostEffectError};

/// Runtime configuration.
pub struct Runtime {
    policy: PolicyEngine,
    capabilities: CapabilityResolver,
    sandbox: SandboxEngine,
    audit: AuditWriter,
    prepared: HashMap<ToolId, PreparedTool>,
    fixtures: HashMap<ToolId, FixtureRegistration>,
}

struct FixtureRegistration {
    prepared: PreparedFixture,
    export: String,
}

impl Runtime {
    pub fn new() -> Self {
        Self::default()
    }

    /// Swap in a configured policy engine (parsed once at startup).
    pub fn with_policy(mut self, policy: PolicyEngine) -> Self {
        self.policy = policy;
        self
    }

    /// Replace the audit sink (default is a temp JSONL file).
    pub fn with_audit(mut self, audit: AuditWriter) -> Self {
        self.audit = audit;
        self
    }

    /// Access the policy engine (e.g. for hot reload).
    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    /// Access the audit writer (e.g. for tests asserting JSONL output).
    pub fn audit(&self) -> &AuditWriter {
        &self.audit
    }

    /// Access the capability resolver for tool registration.
    pub fn capabilities(&mut self) -> &mut CapabilityResolver {
        &mut self.capabilities
    }

    /// Register a tool manifest and its WASM component bytes.
    ///
    /// When `manifest.sha256` is set, the digest must match `component_bytes`
    /// (G10). The component is prepared once and cached for repeat calls.
    pub fn register(
        &mut self,
        manifest: ToolManifest,
        component_bytes: Vec<u8>,
    ) -> Result<(), RegisterError> {
        if let Some(expected) = &manifest.sha256 {
            let actual = sha256_hex(&component_bytes);
            if &actual != expected {
                return Err(RegisterError::Sha256Mismatch {
                    expected: expected.clone(),
                    actual,
                });
            }
        }

        let prepared = self
            .sandbox
            .prepare(&component_bytes)
            .map_err(|e| RegisterError::SandboxPrepare(e.to_string()))?;
        self.capabilities.register(manifest.clone());
        self.prepared.insert(manifest.tool.id.clone(), prepared);
        Ok(())
    }

    /// Register a raw WASM fixture (no WIT `run` export) for deny-suite and
    /// resource-cap tests. `entry_export` is the component export to invoke.
    pub fn register_fixture(
        &mut self,
        manifest: ToolManifest,
        component_bytes: Vec<u8>,
        entry_export: impl Into<String>,
    ) -> Result<(), RegisterError> {
        let prepared = self
            .sandbox
            .prepare_fixture(&component_bytes)
            .map_err(|e| RegisterError::SandboxPrepare(e.to_string()))?;
        self.capabilities.register(manifest.clone());
        self.fixtures.insert(
            manifest.tool.id.clone(),
            FixtureRegistration {
                prepared,
                export: entry_export.into(),
            },
        );
        Ok(())
    }

    /// Register using bytes loaded from `manifest.component_path` relative to
    /// `manifest.base_dir`. Fails when the path is unset or unreadable.
    pub fn register_from_manifest(&mut self, manifest: ToolManifest) -> Result<(), RegisterError> {
        let rel = manifest
            .component_path
            .as_ref()
            .ok_or(RegisterError::MissingComponent)?;
        let path = manifest.base_dir.join(rel);
        let bytes = std::fs::read(&path).map_err(|e| {
            RegisterError::SandboxPrepare(format!("read component {}: {e}", path.display()))
        })?;
        self.register(manifest, bytes)
    }

    /// Execute a tool call through POLICY → CAPABILITY → SANDBOX → AUDIT.
    pub fn execute_tool_call(
        &self,
        tool_id: ToolId,
        input_digest: String,
        input: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut session = CallSession::begin(&self.audit, tool_id.clone(), input_digest.clone())
            .map_err(audit_err_to_string)?;

        // Station 1 — POLICY. Grab the active set once; a denied, rate-limited,
        // or pending-approval call is rejected here and never mints a grant.
        let decision = self.policy.evaluate(&PolicyRequest::for_tool(&tool_id));
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
        // resolver (lowers limits only; never raises). `decision.limits` is the
        // same core `ResourceCeiling` the resolver takes — no field-by-field map,
        // so an axis transposition is impossible.
        let ceiling = decision.limits;
        let capability_outcome = self.capabilities.resolve_with_ceiling(&tool_id, ceiling);
        session.set_capability(capability_outcome.clone());

        let (execution, output) = match &capability_outcome {
            CapabilityOutcome::Granted { grant } => {
                if let Some(prepared) = self.prepared.get(&tool_id) {
                    let run = self.sandbox.execute(prepared, grant, input);
                    session.set_metrics(run.metrics);
                    match run.output {
                        Ok(bytes) => match enforce_output_cap(grant, bytes) {
                            Ok(bytes) => (ExecutionOutcome::Success, Some(bytes)),
                            Err(outcome) => (outcome, None),
                        },
                        Err(err) => (err.to_execution_outcome(), None),
                    }
                } else if let Some(fixture) = self.fixtures.get(&tool_id) {
                    let run =
                        self.sandbox
                            .execute_fixture(&fixture.prepared, grant, &fixture.export);
                    session.set_metrics(run.metrics);
                    match run.output {
                        Ok(bytes) => match enforce_output_cap(grant, bytes) {
                            Ok(bytes) => (ExecutionOutcome::Success, Some(bytes)),
                            Err(outcome) => (outcome, None),
                        },
                        Err(err) => (err.to_execution_outcome(), None),
                    }
                } else {
                    (
                        ExecutionOutcome::HostDenied {
                            reason: "tool not registered in runtime".into(),
                        },
                        None,
                    )
                }
            }
            CapabilityOutcome::Denied { .. } => (
                ExecutionOutcome::HostDenied {
                    reason: "capability denied".into(),
                },
                None,
            ),
        };

        session.set_execution(execution);
        session.complete().map_err(audit_err_to_string)?;

        output.ok_or_else(|| "execution failed".into())
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            policy: PolicyEngine::allow_all(),
            capabilities: CapabilityResolver::new(),
            sandbox: SandboxEngine::default(),
            audit: AuditWriter::open_temp().expect("temp audit sink must open"),
            prepared: HashMap::new(),
            fixtures: HashMap::new(),
        }
    }
}

/// Returns pipeline stage names in order (for tests and docs).
pub fn pipeline_stages() -> &'static [&'static str] {
    PIPELINE_STAGES
}

fn audit_err_to_string(err: AuditError) -> String {
    format!("audit failure (fail-closed): {err}")
}

/// Enforce the grant's per-call output ceiling on returned bytes (G8).
///
/// This is an **orchestrator-side** cap on the bytes a call returns — not a
/// wasmtime store limit — applied identically after a Model A sandbox output
/// and a Model B host effect. Oversize output fails closed to
/// `ResourceExceeded { kind: "output" }`; the bytes are never truncated and
/// returned as success.
fn enforce_output_cap(
    grant: &CapabilityGrant,
    bytes: Vec<u8>,
) -> Result<Vec<u8>, ExecutionOutcome> {
    if bytes.len() as u64 > grant.max_output_bytes {
        Err(ExecutionOutcome::ResourceExceeded {
            kind: "output".into(),
        })
    } else {
        Ok(bytes)
    }
}

/// Caller-facing message for a policy rejection at station 1. Denials are
/// actionable by design (G4) — the reason travels back to the caller.
fn policy_rejection_message(action: &PolicyAction) -> String {
    match action {
        PolicyAction::Deny { reason } => format!("policy denied: {reason}"),
        PolicyAction::RateLimited { reason } => format!("policy rate limited: {reason}"),
        PolicyAction::PendingApproval { approval_id } => {
            format!("policy pending approval: {approval_id}")
        }
        // `Allow` never reaches this path.
        PolicyAction::Allow => "policy allowed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use botzr_aegis_capability::{ToolInfo, ToolKind, ToolLimits, ToolManifest};
    use botzr_aegis_policy::PolicyEngine;

    /// Build an echo manifest with an explicit `max_output_bytes` ceiling.
    fn echo_manifest_with_output_cap(
        base: &Path,
        digest: String,
        max_output_bytes: u64,
    ) -> ToolManifest {
        ToolManifest::new(
            ToolInfo {
                id: ToolId::new("echo"),
                version: "0.1.0".into(),
                kind: ToolKind::Wasm,
            },
            base,
        )
        .with_sha256(digest)
        .with_limits(ToolLimits {
            max_output_bytes,
            ..ToolLimits::default()
        })
    }

    #[test]
    fn pipeline_order_is_load_bearing() {
        assert_eq!(
            pipeline_stages(),
            &["policy", "capability", "sandbox", "audit"]
        );
    }

    #[test]
    fn policy_deny_short_circuits_before_capability() {
        let yaml = r#"
version: 1
default: allow
rules:
  - id: block-smoke
    action: deny
    tool: smoke
    reason: "blocked in test"
"#;
        let rt = Runtime::new().with_policy(PolicyEngine::from_yaml(yaml).unwrap());
        let err = rt
            .execute_tool_call(ToolId::new("smoke"), "deadbeef".into(), b"{}")
            .unwrap_err();
        // Policy reason surfaces — proves station 1 rejected, not capability.
        assert_eq!(err, "policy denied: blocked in test");

        let lines: Vec<String> = std::fs::read_to_string(rt.audit().path())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(lines.len(), 2, "intent + outcome lines");
        assert!(lines[0].contains("\"phase\":\"intent\""));
        assert!(lines[1].contains("\"status\":\"denied\""));
    }

    #[test]
    fn pending_approval_blocks_before_capability() {
        let yaml = r#"
version: 1
default: allow
rules:
  - id: gate-smoke
    action: pending_approval
    tool: smoke
"#;
        let rt = Runtime::new().with_policy(PolicyEngine::from_yaml(yaml).unwrap());
        let err = rt
            .execute_tool_call(ToolId::new("smoke"), "deadbeef".into(), b"{}")
            .unwrap_err();
        assert!(
            err.starts_with("policy pending approval: apr-gate-smoke-smoke-"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn echo_tool_runs_end_to_end() {
        let wasm = include_bytes!("../../../tests/fixtures/echo-tool/echo.wasm");
        let digest = sha256_hex(wasm);
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/echo-tool");
        let manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new("echo"),
                version: "0.1.0".into(),
                kind: ToolKind::Wasm,
            },
            &base,
        )
        .with_sha256(digest);

        let mut rt = Runtime::new();
        rt.register(manifest, wasm.to_vec()).expect("register echo");

        let input = b"hello-aegis";
        let out = rt
            .execute_tool_call(ToolId::new("echo"), sha256_hex(input), input)
            .expect("echo run succeeds");
        assert_eq!(out, input);

        let lines: Vec<String> = std::fs::read_to_string(rt.audit().path())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"phase\":\"intent\""));
        assert!(lines[1].contains("\"status\":\"success\""));
    }

    #[test]
    fn output_over_cap_trips_resource_exceeded() {
        // Model A: a successful sandbox run whose output exceeds the grant's
        // `max_output_bytes` fails closed to ResourceExceeded { kind: "output" }.
        let wasm = include_bytes!("../../../tests/fixtures/echo-tool/echo.wasm");
        let digest = sha256_hex(wasm);
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/echo-tool");
        let manifest = echo_manifest_with_output_cap(&base, digest, 8);

        let mut rt = Runtime::new();
        rt.register(manifest, wasm.to_vec()).expect("register echo");

        // 11-byte input echoes back 11 bytes > the 8-byte cap.
        let input = b"hello-aegis";
        assert!(input.len() > 8);
        let err = rt
            .execute_tool_call(ToolId::new("echo"), sha256_hex(input), input)
            .unwrap_err();
        assert_eq!(err, "execution failed");

        let outcome = std::fs::read_to_string(rt.audit().path())
            .unwrap()
            .lines()
            .last()
            .unwrap()
            .to_owned();
        assert!(
            outcome.contains("\"status\":\"resource_exceeded\""),
            "expected resource_exceeded, got: {outcome}"
        );
        assert!(
            outcome.contains("\"kind\":\"output\""),
            "expected kind=output, got: {outcome}"
        );
    }

    #[test]
    fn output_exactly_at_cap_succeeds() {
        // Boundary: len == cap is allowed (the check is strictly greater-than),
        // proving the cap does not reject payloads at the limit.
        let wasm = include_bytes!("../../../tests/fixtures/echo-tool/echo.wasm");
        let digest = sha256_hex(wasm);
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/echo-tool");
        let input = b"12345678"; // exactly 8 bytes
        let manifest = echo_manifest_with_output_cap(&base, digest, input.len() as u64);

        let mut rt = Runtime::new();
        rt.register(manifest, wasm.to_vec()).expect("register echo");

        let out = rt
            .execute_tool_call(ToolId::new("echo"), sha256_hex(input), input)
            .expect("payload at the cap succeeds");
        assert_eq!(out, input);
    }

    #[test]
    fn default_output_cap_allows_normal_payload() {
        // Regression guard: the default 1 MiB cap must not reject ordinary small
        // payloads (registration without explicit limits).
        let wasm = include_bytes!("../../../tests/fixtures/echo-tool/echo.wasm");
        let digest = sha256_hex(wasm);
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/echo-tool");
        let manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new("echo"),
                version: "0.1.0".into(),
                kind: ToolKind::Wasm,
            },
            &base,
        )
        .with_sha256(digest);

        let mut rt = Runtime::new();
        rt.register(manifest, wasm.to_vec()).expect("register echo");

        let input = b"a normal, well-under-1-MiB tool payload";
        let out = rt
            .execute_tool_call(ToolId::new("echo"), sha256_hex(input), input)
            .expect("normal payload under default cap succeeds");
        assert_eq!(out, input);
    }

    #[test]
    fn sha256_mismatch_rejects_registration() {
        let wasm = include_bytes!("../../../tests/fixtures/echo-tool/echo.wasm");
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/echo-tool");
        let manifest = ToolManifest::new(
            ToolInfo {
                id: ToolId::new("echo"),
                version: "0.1.0".into(),
                kind: ToolKind::Wasm,
            },
            &base,
        )
        .with_sha256("deadbeef");

        let mut rt = Runtime::new();
        let err = rt.register(manifest, wasm.to_vec()).unwrap_err();
        assert!(matches!(err, RegisterError::Sha256Mismatch { .. }));
    }

    #[test]
    fn policy_lowered_limit_flows_to_grant_per_axis() {
        // AEG-38 §3.D.1: a rule that lowers ONLY the wall axis must lower wall on
        // the minted grant while memory and output stay at the manifest's limits.
        let yaml = r#"
version: 1
default: allow
rules:
  - id: cap-wall
    action: allow
    tool: capped
    limits: { max_wall_ms: 1000 }
"#;
        let engine = PolicyEngine::from_yaml(yaml).unwrap();
        let tool = ToolId::new("capped");

        let mut resolver = CapabilityResolver::new();
        resolver.register(
            ToolManifest::new(
                ToolInfo {
                    id: tool.clone(),
                    version: "0.1.0".into(),
                    kind: ToolKind::Wasm,
                },
                std::env::temp_dir(),
            )
            .with_limits(ToolLimits {
                max_memory_bytes: 1 << 20,
                max_wall_ms: 10_000,
                max_output_bytes: 4096,
            }),
        );

        // Mirror the production seam exactly: `decision.limits` *is* the ceiling.
        let decision = engine.evaluate(&PolicyRequest::for_tool(&tool));
        let grant = match resolver.resolve_with_ceiling(&tool, decision.limits) {
            CapabilityOutcome::Granted { grant } => grant,
            other => panic!("expected grant, got {other:?}"),
        };

        assert_eq!(grant.max_wall_ms, 1_000, "policy lowers the wall axis");
        assert_eq!(
            grant.max_memory_bytes,
            1 << 20,
            "memory unchanged from manifest"
        );
        assert_eq!(grant.max_output_bytes, 4096, "output unchanged from manifest");
    }

    #[test]
    fn axis_sentinels_survive_policy_to_grant_without_transposition() {
        // AEG-38 §3.D.2: distinct per-axis sentinels (memory=11, wall=22,
        // output=33) must each land on the *matching* grant axis after
        // evaluate → resolve. This fails loudly if any seam maps e.g.
        // `max_wall_ms: decision.limits.max_memory_bytes`.
        let yaml = r#"
version: 1
default: allow
rules:
  - id: sentinels
    action: allow
    tool: sentinel-tool
    limits: { max_memory_bytes: 11, max_wall_ms: 22, max_output_bytes: 33 }
"#;
        let engine = PolicyEngine::from_yaml(yaml).unwrap();
        let tool = ToolId::new("sentinel-tool");

        // Pin the parse → decision map first (catches a transposition in parse).
        let decision = engine.evaluate(&PolicyRequest::for_tool(&tool));
        assert_eq!(decision.limits.max_memory_bytes, Some(11));
        assert_eq!(decision.limits.max_wall_ms, Some(22));
        assert_eq!(decision.limits.max_output_bytes, Some(33));

        // Manifest defaults (64 MiB / 30 s / 1 MiB) all exceed the sentinels, so
        // each sentinel is the tighter bound and flows straight through to grant.
        let mut resolver = CapabilityResolver::new();
        resolver.register(ToolManifest::new(
            ToolInfo {
                id: tool.clone(),
                version: "0.1.0".into(),
                kind: ToolKind::Wasm,
            },
            std::env::temp_dir(),
        ));
        let grant = match resolver.resolve_with_ceiling(&tool, decision.limits) {
            CapabilityOutcome::Granted { grant } => grant,
            other => panic!("expected grant, got {other:?}"),
        };
        assert_eq!(grant.max_memory_bytes, 11, "memory sentinel on memory axis");
        assert_eq!(grant.max_wall_ms, 22, "wall sentinel on wall axis");
        assert_eq!(grant.max_output_bytes, 33, "output sentinel on output axis");
    }
}
