//! AILAB-809 — a sync entry point called from inside a tokio runtime refuses
//! instead of panicking, and the async entries complete the same call.
//!
//! The bug: `SandboxEngine::execute` built a fresh current-thread tokio runtime
//! per call and blocked on it, so `Runtime::execute_tool_call` from an async
//! embedder died on tokio's "Cannot start a runtime from within a runtime".
//! There was no async entry point to reach for either.
//!
//! These live in `tests/` rather than in the crate's own `#[cfg(test)]` module
//! on purpose: proving the sync entry no longer panics needs `catch_unwind`,
//! and the AILAB-809 §4 gate keeps `catch_unwind` out of the production driver
//! files (`src/lib.rs`, `src/host.rs`, `src/pipeline.rs`) so that AEG-40's
//! fail-closed `CallSession` Drop stays the only panic path in them.
//!
//! `flavor = "multi_thread"` throughout: a current-thread test runtime would
//! also exercise `Handle::try_current`, but the reported bug was an embedder on
//! a multi-thread runtime, so that is the shape under test.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use botzr_aegis_audit::{insecure_dev_key, AuditWriter, MemoryChainSink};
use botzr_aegis_capability::{ToolInfo, ToolKind, ToolManifest};
use botzr_aegis_core::{AegisError, ToolId};
use botzr_aegis_policy::PolicyRequest;
use botzr_aegis_runtime::{sha256_hex, HostCallRequest, Runtime, ToolCallRequest, ToolExecutable};

const ECHO_WASM: &[u8] = include_bytes!("../../../tests/fixtures/echo-tool/echo.wasm");

/// A runtime whose audit Chain the test can read back.
///
/// The default Sink is Volatile and in-memory (ADR-0012) and the writer owns
/// it, so a test that wants the bytes supplies its own [`MemoryChainSink`] and
/// keeps a clone — `Clone` shares the buffer.
fn audited_runtime() -> (Runtime, MemoryChainSink) {
    let store = MemoryChainSink::new();
    let rt = Runtime::new().with_audit(
        AuditWriter::with_sink(Box::new(store.clone()), insecure_dev_key())
            .expect("volatile memory sink must open"),
    );
    (rt, store)
}

/// Every non-empty row of a Chain. Row 0 is the Session `Open` the writer emits
/// on construction, so a call that ran contributes rows 1 (intent) and 2
/// (outcome).
fn chain_lines(store: &MemoryChainSink) -> Vec<String> {
    store
        .to_text()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

/// A refused call must leave the Chain exactly as the writer created it: the
/// Session `Open` line and nothing else.
///
/// Asserting the *shape* of the surviving line, not just the count — a length
/// check alone would pass if a refusal somehow replaced the open line rather
/// than appending to it.
fn assert_chain_is_open_only(store: &MemoryChainSink) {
    let lines = chain_lines(store);
    assert_eq!(
        lines.len(),
        1,
        "a refused call must not be audited: {lines:?}"
    );
    assert!(
        lines[0].contains(r#""line_type":"open""#),
        "the surviving line must be the Session open: {}",
        lines[0]
    );
}

/// Register `echo.wasm` — the same fixture the crate's own
/// `echo_tool_runs_end_to_end` uses — on an audited runtime.
fn echo_runtime() -> (Runtime, MemoryChainSink) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/echo-tool");
    let manifest = ToolManifest::new(
        ToolInfo {
            id: ToolId::new("echo"),
            version: "0.1.0".into(),
            kind: ToolKind::Wasm,
        },
        &base,
    )
    .with_sha256(sha256_hex(ECHO_WASM));

    let (mut rt, audit) = audited_runtime();
    rt.register(manifest, ECHO_WASM.to_vec())
        .expect("register echo");
    (rt, audit)
}

/// Register a host tool that echoes its input back.
fn register_host_echo(rt: &mut Runtime, id: &str) {
    rt.register_tool(
        ToolManifest::new(
            ToolInfo {
                id: ToolId::new(id),
                version: "0.1.0".into(),
                kind: ToolKind::Host,
            },
            std::env::temp_dir(),
        ),
        ToolExecutable::HostHandler(Box::new(|_ctx, input| Ok(input.to_vec()))),
    )
    .expect("register host tool");
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_tool_call_inside_a_runtime_refuses_instead_of_panicking() {
    let (rt, audit) = echo_runtime();
    let tool = ToolId::new("echo");
    let input = b"hello-aegis";

    // `catch_unwind` is the assertion: this is the exact call that used to
    // reach `block_on` inside a runtime and take tokio's panic. The result must
    // be `Ok(Err(NestedRuntime))` — an ordinary typed error — not a payload.
    let caught = catch_unwind(AssertUnwindSafe(|| {
        rt.execute_tool_call(ToolCallRequest::new(
            tool.clone(),
            input,
            PolicyRequest::for_tool(&tool),
        ))
    }));
    let result = match caught {
        Ok(result) => result,
        Err(_) => panic!("execute_tool_call panicked inside a tokio runtime"),
    };
    assert_eq!(
        result.unwrap_err(),
        AegisError::NestedRuntime {
            entry: "execute_tool_call".into()
        }
    );

    // A refusal is not a call that ran. The refusal happens before
    // `CallSession::begin`, so the Chain must still hold nothing but the
    // Session `Open` line — no intent, no outcome (ADR-0007).
    assert_chain_is_open_only(&audit);
}

#[tokio::test(flavor = "multi_thread")]
async fn async_tool_call_completes_inside_a_runtime() {
    let (rt, audit) = echo_runtime();
    let tool = ToolId::new("echo");
    let input = b"hello-aegis";

    let out = rt
        .execute_tool_call_async(ToolCallRequest::new(
            tool.clone(),
            input,
            PolicyRequest::for_tool(&tool),
        ))
        .await
        .expect("echo runs on the caller's runtime");
    assert_eq!(out, input);

    let lines = chain_lines(&audit);
    assert_eq!(lines.len(), 3, "open + intent + outcome, got: {lines:?}");
    assert!(lines[2].contains(r#""status":"success""#), "{}", lines[2]);
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_host_call_refuses_and_async_host_call_completes() {
    // Model B never touched the sandbox and so never panicked here before; it
    // shares the driver now, so it gets the same refusal and the same async
    // twin. Both halves run against one runtime, so the refusal provably is not
    // the handler failing.
    let (mut rt, audit) = audited_runtime();
    register_host_echo(&mut rt, "host-echo");

    let tool = ToolId::new("host-echo");
    let input = b"ping";

    let caught = catch_unwind(AssertUnwindSafe(|| {
        rt.execute_host_call(HostCallRequest::new(
            tool.clone(),
            input,
            PolicyRequest::for_tool(&tool),
        ))
    }));
    let result = match caught {
        Ok(result) => result,
        Err(_) => panic!("execute_host_call panicked inside a tokio runtime"),
    };
    assert_eq!(
        result.unwrap_err(),
        AegisError::NestedRuntime {
            entry: "execute_host_call".into()
        }
    );
    assert_chain_is_open_only(&audit);

    let out = rt
        .execute_host_call_async(HostCallRequest::new(
            tool.clone(),
            input,
            PolicyRequest::for_tool(&tool),
        ))
        .await
        .expect("host echo runs on the caller's runtime");
    assert_eq!(out, input);

    let lines = chain_lines(&audit);
    assert_eq!(lines.len(), 3, "open + intent + outcome, got: {lines:?}");
    assert!(lines[2].contains(r#""status":"success""#), "{}", lines[2]);
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_escape_hatch_refuses_inside_a_runtime() {
    // `execute_host_call_with` also drives the shared async pipeline, so it
    // needs the same guard: without it the escape hatch would be the one sync
    // entry that still panics from tokio. It has no async twin — a research
    // caller inside a runtime registers the handler and uses
    // `execute_host_call_async`.
    let (mut rt, audit) = audited_runtime();
    register_host_echo(&mut rt, "raw");

    let tool = ToolId::new("raw");
    let err = rt
        .execute_host_call_with(
            HostCallRequest::new(tool.clone(), b"raw", PolicyRequest::for_tool(&tool)),
            |_grant, input| Ok(input.to_vec()),
        )
        .unwrap_err();
    assert_eq!(
        err,
        AegisError::NestedRuntime {
            entry: "execute_host_call_with".into()
        }
    );
    assert_chain_is_open_only(&audit);
}

#[tokio::test(flavor = "multi_thread")]
async fn from_spawn_blocking_the_sync_entry_refuses_and_the_async_entry_is_the_route() {
    // The guard is `Handle::try_current()`, which is *broader* than tokio's own
    // rule for `block_on`: a `spawn_blocking` thread carries a runtime handle
    // but is not entered as a driver, so `block_on` would in fact succeed
    // there. This pins that over-refusal as known and deliberate rather than
    // discovered later — `spawn_blocking(|| rt.execute_tool_call(..))` is the
    // textbook sync-from-async bridge and it worked at v0.3.0.
    //
    // It also pins the supported way out, so the refusal is not a dead end.
    let (rt, audit) = echo_runtime();
    let rt = std::sync::Arc::new(rt);
    let input = b"hello-aegis";

    let refused = {
        let rt = std::sync::Arc::clone(&rt);
        tokio::task::spawn_blocking(move || {
            let tool = ToolId::new("echo");
            rt.execute_tool_call(ToolCallRequest::new(
                tool.clone(),
                b"hello-aegis",
                PolicyRequest::for_tool(&tool),
            ))
        })
        .await
        .expect("blocking task ran")
    };
    assert_eq!(
        refused.unwrap_err(),
        AegisError::NestedRuntime {
            entry: "execute_tool_call".into()
        },
        "the sync entry refuses from a blocking thread too"
    );
    assert_chain_is_open_only(&audit);

    // The route out: hand the async entry to the ambient runtime from the
    // blocking thread. `Handle::block_on` is legal there — the thread is not an
    // async execution context — so the call completes normally.
    let out = {
        let rt = std::sync::Arc::clone(&rt);
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let tool = ToolId::new("echo");
            handle.block_on(rt.execute_tool_call_async(ToolCallRequest::new(
                tool.clone(),
                b"hello-aegis",
                PolicyRequest::for_tool(&tool),
            )))
        })
        .await
        .expect("blocking task ran")
        .expect("echo runs through the async entry")
    };
    assert_eq!(out, input);

    let lines = chain_lines(&audit);
    assert_eq!(lines.len(), 3, "open + intent + outcome, got: {lines:?}");
    assert!(lines[2].contains(r#""status":"success""#), "{}", lines[2]);
}
