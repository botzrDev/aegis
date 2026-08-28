//! AEG-44 — atomic registration, kind routing, and runtime-derived digests.
//!
//! Every test here pins a property that only holds because manifest authority
//! and the executable artifact are written together by
//! [`Runtime::register_tool`].

use std::path::{Path, PathBuf};

use botzr_aegis_capability::{ToolInfo, ToolKind, ToolManifest};
use botzr_aegis_core::{AegisError, AuditIntent, RequestDigest, ToolId};
use botzr_aegis_policy::CallAxes;
use botzr_aegis_runtime::{
    HostCallRequest, HostEffectError, RegisterError, Runtime, RuntimeBuilder, ToolCallRequest,
    ToolExecutable,
};

const ECHO_WASM: &[u8] = include_bytes!("../../../tests/fixtures/echo-tool/echo.wasm");

fn echo_base() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/echo-tool")
}

fn manifest(id: &str, kind: ToolKind) -> ToolManifest {
    ToolManifest::new(
        ToolInfo {
            id: ToolId::new(id),
            version: "0.1.0".into(),
            kind,
        },
        echo_base(),
    )
}

fn ok_handler() -> ToolExecutable {
    ToolExecutable::HostHandler(Box::new(|_ctx, input| Ok(input.to_vec())))
}

#[test]
fn duplicate_registration_is_rejected() {
    let mut rt = Runtime::new();
    rt.register_tool(
        manifest("echo", ToolKind::Wasm),
        ToolExecutable::WasmComponent(ECHO_WASM.to_vec()),
    )
    .expect("first registration succeeds");

    let err = rt
        .register_tool(
            manifest("echo", ToolKind::Wasm),
            ToolExecutable::WasmComponent(ECHO_WASM.to_vec()),
        )
        .expect_err("second registration of the same id must fail");
    assert!(
        matches!(&err, RegisterError::DuplicateTool { tool_id } if tool_id == "echo"),
        "expected DuplicateTool, got {err:?}"
    );

    // The first registration is still intact — a rejected duplicate must not
    // disturb the tool it collided with.
    let tool = ToolId::new("echo");
    let out = rt
        .execute_tool_call(ToolCallRequest::new(
            tool.clone(),
            b"still-here",
            CallAxes::default(),
        ))
        .expect("original registration survives");
    assert_eq!(out, b"still-here");
}

#[test]
fn wasm_manifest_with_host_handler_is_kind_mismatch_at_register_time() {
    let mut rt = Runtime::new();
    let err = rt
        .register_tool(manifest("echo", ToolKind::Wasm), ok_handler())
        .expect_err("Wasm manifest must refuse a host handler");
    assert!(
        matches!(
            &err,
            RegisterError::KindMismatch { declared, provided }
                if declared == "Wasm" && *provided == "HostHandler"
        ),
        "expected KindMismatch, got {err:?}"
    );
}

#[test]
fn host_manifest_with_wasm_bytes_is_kind_mismatch_at_register_time() {
    let mut rt = Runtime::new();
    let err = rt
        .register_tool(
            manifest("host-echo", ToolKind::Host),
            ToolExecutable::WasmComponent(ECHO_WASM.to_vec()),
        )
        .expect_err("Host manifest must refuse WASM bytes");
    assert!(
        matches!(
            &err,
            RegisterError::KindMismatch { declared, provided }
                if declared == "Host" && *provided == "WasmComponent"
        ),
        "expected KindMismatch, got {err:?}"
    );

    // …and the same for the fixture variant.
    let err = rt
        .register_tool(
            manifest("host-echo", ToolKind::Host),
            ToolExecutable::WasmFixture {
                bytes: ECHO_WASM.to_vec(),
                entry_export: "run".into(),
            },
        )
        .expect_err("Host manifest must refuse a WASM fixture");
    assert!(
        matches!(
            &err,
            RegisterError::KindMismatch { provided, .. } if *provided == "WasmFixture"
        ),
        "expected KindMismatch, got {err:?}"
    );
}

#[test]
fn audit_intent_digest_is_derived_from_the_input_bytes() {
    // No public API accepts a digest any more; the intent line must carry the
    // SHA-256 of the exact bytes that were executed, unmodified.
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    // A persistent sink needs a provisioned signing key (AILAB-620).
    let key_path = dir.path().join("signing.key");
    botzr_aegis_audit::generate_signing_key(&key_path, false).expect("generate signing key");
    let mut rt = RuntimeBuilder::new()
        .audit_file(&audit_path, &key_path)
        .expect("open audit sink")
        .build()
        .expect("build runtime");

    rt.register_tool(
        manifest("echo", ToolKind::Wasm),
        ToolExecutable::WasmComponent(ECHO_WASM.to_vec()),
    )
    .expect("register echo");

    let input = b"digest-must-match-these-exact-bytes";
    let tool = ToolId::new("echo");
    let out = rt
        .execute_tool_call(ToolCallRequest::new(
            tool.clone(),
            input,
            CallAxes::default(),
        ))
        .expect("echo run succeeds");
    assert_eq!(out, input);

    let text = std::fs::read_to_string(&audit_path).expect("audit file");
    let intent_line = text
        .lines()
        .find(|line| line.contains("\"line_type\":\"intent\""))
        .expect("intent line present");
    let intent: AuditIntent = serde_json::from_str(intent_line).expect("intent parses");

    assert_eq!(intent.tool_id, ToolId::new("echo"));
    assert_eq!(
        intent.request_digest,
        RequestDigest::of_request_bytes(input),
        "audited digest must be the runtime-computed hash of the raw input"
    );
    // Sanity: the digest is a real hash, not a placeholder.
    assert_eq!(intent.request_digest.to_hex().len(), 64);
}

#[test]
fn host_tool_via_execute_tool_call_is_denied() {
    let mut rt = Runtime::new();
    rt.register_tool(manifest("host-echo", ToolKind::Host), ok_handler())
        .expect("register host tool");

    let tool = ToolId::new("host-echo");
    let err = rt
        .execute_tool_call(ToolCallRequest::new(
            tool.clone(),
            b"ping",
            CallAxes::default(),
        ))
        .expect_err("Model B tool must not run through the Model A entry point");
    assert_eq!(
        err,
        AegisError::HostDenied {
            reason: "host tool must be invoked via execute_host_call".into()
        }
    );
}

#[test]
fn wasm_tool_via_execute_host_call_is_denied() {
    let mut rt = Runtime::new();
    rt.register_tool(
        manifest("echo", ToolKind::Wasm),
        ToolExecutable::WasmComponent(ECHO_WASM.to_vec()),
    )
    .expect("register echo");

    let tool = ToolId::new("echo");
    let err = rt
        .execute_host_call(HostCallRequest::new(
            tool.clone(),
            b"ping",
            CallAxes::default(),
        ))
        .expect_err("Model A tool must not run through the Model B entry point");
    assert_eq!(
        err,
        AegisError::HostDenied {
            reason: "wasm tool must be invoked via execute_tool_call".into()
        }
    );
}

#[test]
fn failed_registration_leaves_no_partial_state() {
    let mut rt = Runtime::new();

    // (a) kind mismatch — rejected at check 2, before the resolver is touched.
    rt.register_tool(
        manifest("host-echo", ToolKind::Host),
        ToolExecutable::WasmComponent(ECHO_WASM.to_vec()),
    )
    .expect_err("kind mismatch must fail");

    // (b) sandbox prepare failure — rejected at check 4, still before any write.
    rt.register_tool(
        manifest("bad-wasm", ToolKind::Wasm),
        ToolExecutable::WasmComponent(b"not a wasm component".to_vec()),
    )
    .expect_err("garbage component must fail to prepare");

    // (c) sha256 pin mismatch — rejected at check 3.
    rt.register_tool(
        manifest("pinned", ToolKind::Wasm).with_sha256("deadbeef"),
        ToolExecutable::WasmComponent(ECHO_WASM.to_vec()),
    )
    .expect_err("bad digest pin must fail");

    // None of the three wrote a manifest: the capability resolver still denies
    // at station 2, so execution never even reaches the "tool not registered in
    // runtime" adapter branch. That denial *is* the proof of no partial state —
    // a manifest-only write would have minted a grant here instead.
    for id in ["host-echo", "bad-wasm", "pinned"] {
        let tool = ToolId::new(id);
        let err = rt
            .execute_tool_call(ToolCallRequest::new(
                tool.clone(),
                b"{}",
                CallAxes::default(),
            ))
            .expect_err("a tool that failed registration must not execute");
        assert!(
            matches!(&err, AegisError::CapabilityDenied { reason, .. } if reason.contains("tool not registered")),
            "{id}: expected CapabilityDenied(tool not registered), got {err:?}"
        );
    }

    // And each id is still free to register cleanly afterwards.
    rt.register_tool(manifest("host-echo", ToolKind::Host), ok_handler())
        .expect("failed registration must not reserve the id");
}

#[test]
fn host_handler_runs_behind_the_effect_context() {
    // The registered handler receives a HostEffectContext (AEG-43), not a raw
    // grant — a denial it raises flows out as a typed HostDenied.
    let mut rt = Runtime::new();
    rt.register_tool(
        manifest("gated", ToolKind::Host),
        ToolExecutable::HostHandler(Box::new(|ctx, _input| {
            // No fs axis on this grant → the choke point must refuse.
            match ctx.open_read(Path::new("/etc/passwd")) {
                Ok(_) => Err(HostEffectError::Failed {
                    reason: "context handed out an ungranted read".into(),
                }),
                Err(err) => Err(err),
            }
        })),
    )
    .expect("register gated host tool");

    let tool = ToolId::new("gated");
    let err = rt
        .execute_host_call(HostCallRequest::new(
            tool.clone(),
            b"{}",
            CallAxes::default(),
        ))
        .expect_err("ungranted read must deny");
    assert!(
        matches!(&err, AegisError::HostDenied { reason } if reason.contains("read denied")),
        "expected a grant denial from HostEffectContext, got {err:?}"
    );
}
