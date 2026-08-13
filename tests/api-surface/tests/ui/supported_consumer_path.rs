//! AEG-45: the supported consumer path. If this stops compiling, the
//! contraction went too far.
//!
//! `t.pass()` compiles *and runs* the case, so `main` stays trivial and the
//! API exercise lives in never-called functions.
use botzr_aegis_capability::{CapabilityResolver, ToolInfo, ToolKind, ToolManifest};
use botzr_aegis_core::{AegisError, AuditIntent, CapabilityOutcome, PrevHash, RequestDigest, ToolId};
use botzr_aegis_policy::{PolicyEngine, PolicyRequest, SUPPORTED_POLICY_VERSION};
use botzr_aegis_runtime::{HostCallRequest, Runtime, RuntimeBuilder, ToolExecutable};

/// Manifest construction is public: a consumer declares needs in its own code.
#[allow(dead_code)]
fn manifest(id: &str, kind: ToolKind) -> ToolManifest {
    ToolManifest::new(
        ToolInfo {
            id: ToolId::new(id),
            version: "0.1.0".into(),
            kind,
        },
        std::env::temp_dir(),
    )
}

/// AILAB-628: minting a grant from a manifest **without** registering it, for
/// a surface that is not the WASM tool registry — `aegis wrap --confine`
/// derives its Landlock/seccomp profile from the grant this returns, so the
/// same authority source drives the cell and the native child.
///
/// This moved out from behind `test-utils` in AILAB-628. The case lives here
/// so that promotion is contracted rather than incidental: `register` next
/// door is `#[deprecated]` and has its own `compile_fail` case, and the
/// difference between the two is the whole point — mint without a registry
/// entry is supported, registering a manifest with no executable is not.
#[allow(dead_code)]
fn mint_without_registering(manifest: &ToolManifest) -> CapabilityOutcome {
    CapabilityResolver::new().resolve_manifest(manifest)
}

/// The builder is the sanctioned way to assemble a configured runtime.
#[allow(dead_code)]
fn build() -> Runtime {
    RuntimeBuilder::new().build().expect("default build")
}

#[allow(dead_code)]
fn model_a(rt: &mut Runtime, manifest: ToolManifest, bytes: Vec<u8>) -> Result<Vec<u8>, AegisError> {
    rt.register(manifest, bytes).expect("register");
    rt.execute_tool_call(ToolId::new("echo"), b"hello")
}

#[allow(dead_code)]
fn model_b(rt: &mut Runtime, manifest: ToolManifest) -> Result<Vec<u8>, AegisError> {
    rt.register_tool(
        manifest,
        ToolExecutable::HostHandler(Box::new(|_ctx, input| Ok(input.to_vec()))),
    )
    .expect("register host tool");
    let tool = ToolId::new("host-echo");
    rt.execute_host_call(HostCallRequest::new(
        tool.clone(),
        b"{}",
        PolicyRequest::for_tool(&tool),
    ))
}

#[allow(dead_code)]
fn policy_and_audit() {
    let _engine = PolicyEngine::allow_all();
    let _v = SUPPORTED_POLICY_VERSION;
    let intent = AuditIntent::new(
        "call-1",
        ToolId::new("smoke"),
        RequestDigest::of_request_bytes(b"abc"),
    );
    // Sealed for writes, still readable through the getters — a consumer reads
    // the whole chain position, it just never chooses one.
    assert_eq!(intent.schema_version(), botzr_aegis_core::AUDIT_SCHEMA_VERSION);
    assert_eq!(intent.seq(), 0);
    assert_eq!(*intent.prev_hash(), PrevHash::GENESIS);
}

fn main() {}
