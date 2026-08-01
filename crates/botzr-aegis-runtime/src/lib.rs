//! Library-mode entry point — wires the enforcement pipeline in load-bearing order.

mod build;
mod digest;
mod error;
pub mod host;
mod host_effect;
mod pipeline;

use std::collections::HashMap;

use botzr_aegis_audit::AuditWriter;
use botzr_aegis_capability::{CapabilityResolver, ToolKind, ToolManifest};
use botzr_aegis_core::{AegisError, CapabilityGrant, ExecutionOutcome, ToolId};
use botzr_aegis_policy::{PolicyEngine, PolicyRequest};
#[cfg(feature = "test-utils")]
use botzr_aegis_sandbox::PreparedFixture;
use botzr_aegis_sandbox::{PreparedTool, SandboxEngine, SandboxRun};

use crate::pipeline::ExecutionStep;

pub use build::{BuildError, RuntimeBuilder};
pub use digest::sha256_hex;
pub use error::RegisterError;
pub use host::{HostCallRequest, HostEffectError};
pub use host_effect::{HostEffectContext, HttpStubResponse, LogLevel};

/// A Model B effect, stored in the runtime registry at registration time.
///
/// The handler receives the AEG-43 authority choke point
/// ([`HostEffectContext`]) rather than a raw grant, so every effect it performs
/// goes through structural grant enforcement. Registering the handler up front
/// is what makes Model B registration atomic: authority (manifest) and effect
/// (handler) can no longer be written independently.
pub type HostHandler =
    Box<dyn Fn(&HostEffectContext<'_>, &[u8]) -> Result<Vec<u8>, HostEffectError> + Send + Sync>;

/// The executable artifact a tool is registered with.
///
/// Which variant is legal is decided by the manifest's
/// [`ToolKind`]: `Wasm` accepts [`Self::WasmComponent`] or, under `test-utils`,
/// `Self::WasmFixture`; `Host` accepts [`Self::HostHandler`]. Anything else
/// is a [`RegisterError::KindMismatch`] at registration time.
pub enum ToolExecutable {
    /// A WIT-world component invoked through its `run` export (Model A).
    WasmComponent(Vec<u8>),
    /// A raw WASM component with no WIT world, invoked through `entry_export`
    /// (deny-suite and resource-cap fixtures). Requires the `test-utils`
    /// feature.
    #[cfg(feature = "test-utils")]
    WasmFixture {
        bytes: Vec<u8>,
        entry_export: String,
    },
    /// A host-side effect (Model B) — no sandbox isolation, capability check
    /// and audit only.
    HostHandler(HostHandler),
}

impl ToolExecutable {
    /// Human-readable variant name for [`RegisterError::KindMismatch`].
    fn label(&self) -> &'static str {
        match self {
            Self::WasmComponent(_) => "WasmComponent",
            #[cfg(feature = "test-utils")]
            Self::WasmFixture { .. } => "WasmFixture",
            Self::HostHandler(_) => "HostHandler",
        }
    }
}

/// One tool's entry in the runtime registry — authority kind plus executable.
struct ToolRegistration {
    /// The manifest's declared kind, proven consistent with `slot` by
    /// [`Runtime::register_tool`].
    kind: ToolKind,
    slot: ExecutableSlot,
}

/// The prepared, ready-to-invoke form of a [`ToolExecutable`].
enum ExecutableSlot {
    Wasm(PreparedTool),
    #[cfg(feature = "test-utils")]
    WasmFixture {
        prepared: PreparedFixture,
        export: String,
    },
    Host(HostHandler),
}

/// Runtime configuration.
pub struct Runtime {
    policy: PolicyEngine,
    capabilities: CapabilityResolver,
    sandbox: SandboxEngine,
    audit: AuditWriter,
    /// Single registry: a tool id is present here **iff** its manifest was
    /// written to the capability resolver (AEG-44). Replaces the former
    /// `prepared` + `fixtures` maps, which could disagree with the resolver.
    tools: HashMap<ToolId, ToolRegistration>,
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

    /// Read-only view of the capability resolver (e.g. for introspection).
    ///
    /// Mutation is deliberately not exposed: writing a manifest without its
    /// executable is the split-authority state [`Runtime::register_tool`]
    /// exists to prevent.
    pub fn capabilities(&self) -> &CapabilityResolver {
        &self.capabilities
    }

    /// Crate-internal mutable access — the only writer is `register_tool`.
    pub(crate) fn capabilities_mut(&mut self) -> &mut CapabilityResolver {
        &mut self.capabilities
    }

    /// **The** registration path: atomically associate a tool's manifest
    /// (authority) with its executable artifact.
    ///
    /// Every check runs before any mutation, so a failed registration leaves
    /// the runtime exactly as it was — no manifest without an executable, no
    /// executable without authority. Checks, in order:
    ///
    /// 1. duplicate tool id → [`RegisterError::DuplicateTool`]
    /// 2. manifest [`ToolKind`] vs. [`ToolExecutable`] variant →
    ///    [`RegisterError::KindMismatch`]
    /// 3. `manifest.sha256` pin against the WASM bytes (G10) →
    ///    [`RegisterError::Sha256Mismatch`]; a pin is meaningless for a host
    ///    handler and is ignored there
    /// 4. sandbox prepare → [`RegisterError::SandboxPrepare`]
    ///
    /// Only after all four does it write the manifest and the executable slot,
    /// together.
    pub fn register_tool(
        &mut self,
        manifest: ToolManifest,
        executable: ToolExecutable,
    ) -> Result<(), RegisterError> {
        // 1 — duplicate. Re-registration would let authority and executable be
        // swapped independently; refuse instead of silently replacing.
        if self.tools.contains_key(&manifest.tool.id) {
            return Err(RegisterError::DuplicateTool {
                tool_id: manifest.tool.id.to_string(),
            });
        }

        // 2 — kind match. A Host manifest must never own a prepared component,
        // and a Wasm manifest must never own a host effect.
        let kind = manifest.tool.kind;
        let matches_kind = match (kind, &executable) {
            (ToolKind::Wasm, ToolExecutable::WasmComponent(_)) => true,
            #[cfg(feature = "test-utils")]
            (ToolKind::Wasm, ToolExecutable::WasmFixture { .. }) => true,
            (ToolKind::Host, ToolExecutable::HostHandler(_)) => true,
            _ => false,
        };
        if !matches_kind {
            return Err(RegisterError::KindMismatch {
                declared: format!("{kind:?}"),
                provided: executable.label(),
            });
        }

        // 3 + 4 — digest pin then sandbox prepare, both still before any write.
        let slot = match executable {
            ToolExecutable::WasmComponent(bytes) => {
                verify_sha256(&manifest, &bytes)?;
                let prepared = self
                    .sandbox
                    .prepare(&bytes)
                    .map_err(|e| RegisterError::SandboxPrepare(e.to_string()))?;
                ExecutableSlot::Wasm(prepared)
            }
            #[cfg(feature = "test-utils")]
            ToolExecutable::WasmFixture {
                bytes,
                entry_export,
            } => {
                verify_sha256(&manifest, &bytes)?;
                let prepared = self
                    .sandbox
                    .prepare_fixture(&bytes)
                    .map_err(|e| RegisterError::SandboxPrepare(e.to_string()))?;
                ExecutableSlot::WasmFixture {
                    prepared,
                    export: entry_export,
                }
            }
            // No bytes to pin; `manifest.sha256` (if set) is ignored for Model B.
            ToolExecutable::HostHandler(handler) => ExecutableSlot::Host(handler),
        };

        // 5 — both writes together. Nothing above this line mutated `self`.
        let tool_id = manifest.tool.id.clone();
        // The one sanctioned caller of the deprecated resolver write: this line
        // and the `self.tools.insert` below are the atomic pair that keeps
        // authority and executable from drifting apart (AEG-44).
        #[allow(deprecated)]
        self.capabilities_mut().register(manifest);
        self.tools.insert(tool_id, ToolRegistration { kind, slot });
        Ok(())
    }

    /// Register a tool manifest and its WASM component bytes.
    ///
    /// When `manifest.sha256` is set, the digest must match `component_bytes`
    /// (G10). The component is prepared once and cached for repeat calls.
    /// Thin wrapper over [`Runtime::register_tool`].
    pub fn register(
        &mut self,
        manifest: ToolManifest,
        component_bytes: Vec<u8>,
    ) -> Result<(), RegisterError> {
        self.register_tool(manifest, ToolExecutable::WasmComponent(component_bytes))
    }

    /// Register a raw WASM fixture (no WIT `run` export) for deny-suite and
    /// resource-cap tests. `entry_export` is the component export to invoke.
    /// Thin wrapper over [`Runtime::register_tool`].
    ///
    /// Requires the `test-utils` feature — a default-features build has no
    /// fixture registration path at all.
    #[cfg(feature = "test-utils")]
    pub fn register_fixture(
        &mut self,
        manifest: ToolManifest,
        component_bytes: Vec<u8>,
        entry_export: impl Into<String>,
    ) -> Result<(), RegisterError> {
        self.register_tool(
            manifest,
            ToolExecutable::WasmFixture {
                bytes: component_bytes,
                entry_export: entry_export.into(),
            },
        )
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
    ///
    /// Model A adapter: the shared [`Runtime::drive_pipeline`] owns policy,
    /// capability, output-cap, and audit; this method only supplies the wasmtime
    /// execution step and Model A's caller error string. The audited
    /// `input_digest` is derived from `input` inside the pipeline — callers
    /// cannot supply one.
    ///
    /// A Model B host tool reaching this entry point fails closed: use
    /// [`Runtime::execute_host_call`].
    pub fn execute_tool_call(&self, tool_id: ToolId, input: &[u8]) -> Result<Vec<u8>, AegisError> {
        let policy_request = PolicyRequest::for_tool(&tool_id);
        self.drive_pipeline(
            tool_id.clone(),
            input,
            &policy_request,
            // Execution step: run the prepared component or fixture in the
            // wasmtime sandbox. A tool that was never registered here is a host
            // denial. The sandbox reports metrics on every run (success or trap).
            |grant| match self.tools.get(&tool_id) {
                Some(registration) => {
                    // Routing is on the slot alone; `register_tool` already
                    // proved the slot agrees with the declared kind.
                    debug_assert_eq!(
                        matches!(registration.slot, ExecutableSlot::Host(_)),
                        matches!(registration.kind, ToolKind::Host),
                        "registration kind and executable slot must agree",
                    );
                    match &registration.slot {
                        ExecutableSlot::Wasm(prepared) => {
                            sandbox_step(self.sandbox.execute(prepared, grant, input))
                        }
                        #[cfg(feature = "test-utils")]
                        ExecutableSlot::WasmFixture { prepared, export } => {
                            sandbox_step(self.sandbox.execute_fixture(prepared, grant, export))
                        }
                        ExecutableSlot::Host(_) => ExecutionStep::Failed {
                            outcome: ExecutionOutcome::HostDenied {
                                reason: "host tool must be invoked via execute_host_call".into(),
                            },
                            metrics: None,
                        },
                    }
                }
                None => ExecutionStep::Failed {
                    outcome: ExecutionOutcome::HostDenied {
                        reason: "tool not registered in runtime".into(),
                    },
                    metrics: None,
                },
            },
        )
    }
}

/// Verify a manifest's optional SHA-256 pin against the artifact bytes (G10).
fn verify_sha256(manifest: &ToolManifest, bytes: &[u8]) -> Result<(), RegisterError> {
    let Some(expected) = &manifest.sha256 else {
        return Ok(());
    };
    let actual = sha256_hex(bytes);
    if &actual != expected {
        return Err(RegisterError::Sha256Mismatch {
            expected: expected.clone(),
            actual,
        });
    }
    Ok(())
}

/// Map a sandbox run into the driver's execution step, preserving metrics on
/// both the success and error branches (Model A always meters).
fn sandbox_step(run: SandboxRun) -> ExecutionStep {
    match run.output {
        Ok(bytes) => ExecutionStep::Produced {
            bytes,
            metrics: Some(run.metrics),
        },
        Err(err) => ExecutionStep::Failed {
            outcome: err.to_execution_outcome(),
            metrics: Some(run.metrics),
        },
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            policy: PolicyEngine::allow_all(),
            capabilities: CapabilityResolver::new(),
            sandbox: SandboxEngine::default(),
            audit: AuditWriter::open_temp().expect("temp audit sink must open"),
            tools: HashMap::new(),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use botzr_aegis_capability::{ToolInfo, ToolKind, ToolLimits, ToolManifest};
    use botzr_aegis_core::{AegisError, CapabilityOutcome, PIPELINE_STAGES};
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
            PIPELINE_STAGES,
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
            .execute_tool_call(ToolId::new("smoke"), b"{}")
            .unwrap_err();
        // Policy reason surfaces — proves station 1 rejected, not capability.
        assert_eq!(
            err,
            AegisError::PolicyDenied {
                reason: "blocked in test".into()
            }
        );

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
            .execute_tool_call(ToolId::new("smoke"), b"{}")
            .unwrap_err();
        assert!(
            matches!(err, AegisError::PendingApproval { ref approval_id } if approval_id.starts_with("apr-gate-smoke-smoke-")),
            "unexpected error: {err:?}"
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
            .execute_tool_call(ToolId::new("echo"), input)
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
            .execute_tool_call(ToolId::new("echo"), input)
            .unwrap_err();
        assert_eq!(
            err,
            AegisError::ResourceExceeded {
                kind: "output".into()
            }
        );

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
            .execute_tool_call(ToolId::new("echo"), input)
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
            .execute_tool_call(ToolId::new("echo"), input)
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
        // Exercising the policy → capability seam in isolation; no executable is
        // paired with this throwaway resolver, so split authority is moot.
        #[allow(deprecated)]
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
        assert_eq!(
            grant.max_output_bytes, 4096,
            "output unchanged from manifest"
        );
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
        // Same seam-in-isolation rationale as above: throwaway resolver, no
        // executable, so `Runtime::register_tool` would only add noise.
        #[allow(deprecated)]
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
