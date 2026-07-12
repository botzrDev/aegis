//! AEG-18 Stage 3 — proof that `botzr-aegis-sandbox` is a standalone dependency.
//!
//! This crate wires the wasmtime sandbox using **only** `botzr-aegis-sandbox`
//! and `botzr-aegis-core` — nothing from the Aegis orchestrator (runtime,
//! policy, capability, audit). It is the shape an external host would take when
//! it wants sandboxed WASM execution but already owns its own policy/trust model
//! and mints capability grants itself.
//!
//! The whole consumer surface is four calls:
//!
//! 1. [`SandboxEngine::new`] — build the process-wide engine once.
//! 2. Hand-build a [`CapabilityGrant`] (no `CapabilityResolver`) — an external
//!    host that already knows what a call is allowed to touch constructs the
//!    grant directly from core types.
//! 3. [`SandboxEngine::prepare`] — compile + link the WASM component once.
//! 4. [`SandboxEngine::execute`] — run it in a fresh, grant-scoped `Store`.
//!
//! Every store is configured *from the grant*: filesystem preopens (cap-std,
//! escape-proof), network default-deny, a memory cap, and a wall-clock deadline.
//! See `crates/botzr-aegis-sandbox/INTEGRATION.md` for the wiring guide and the
//! Model A vs Model B trust boundary.

use std::path::{Path, PathBuf};

use botzr_aegis_core::{CapabilityGrant, FsGrant, ToolId, DEFAULT_MAX_OUTPUT_BYTES};
use botzr_aegis_sandbox::{SandboxEngine, SandboxRun};

/// The wasip2 path-detector guest, embedded so the example is self-contained.
///
/// Rebuild via `./scripts/build-fixtures.sh`. The guest scans `/ro0/<scan_root>`
/// (the read preopen) and returns `{"findings":[{"path","size"}, …]}`.
const DETECTOR_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/path-detector/path-detector.wasm"
));

/// Host directory handed to the read-only `fs` grant. It contains the `fixtures/`
/// tree the guest walks when asked to scan `{"scan_root":"fixtures"}`.
pub fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/path-detector")
}

/// Hand-mint a read-only grant directly from core types — no `CapabilityResolver`.
///
/// An external consumer that already has a trust model constructs the grant
/// straight from core types: a single read path (mounted at `/ro0`), no write
/// paths, no net, and explicit memory + wall-clock + output ceilings.
/// `write_paths` is deliberately empty — a guest write attempt must be denied,
/// not silently succeed (exercised by the deny smoke test). `max_output_bytes`
/// is the per-call return-size cap the *host* enforces after `execute`; a
/// hand-building consumer must set it (default is 1 MiB).
pub fn read_only_grant(read_root: &Path) -> CapabilityGrant {
    CapabilityGrant {
        grant_id: "sandbox-consumer-demo".to_string(),
        tool_id: ToolId::new("path-detector"),
        fs: Some(FsGrant {
            read_paths: vec![read_root.to_string_lossy().into_owned()],
            write_paths: vec![],
        }),
        net: None,
        max_memory_bytes: 16 * 1024 * 1024,
        max_wall_ms: 1_000,
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
    }
}

/// Run the embedded path-detector guest against `input` under a read-only grant.
///
/// Demonstrates the full standalone sequence: `new` → build grant → `prepare` →
/// `execute`. Returns the [`SandboxRun`] (output bytes on success, a classified
/// [`SandboxError`](botzr_aegis_sandbox::SandboxError) on trap/resource-exceeded,
/// plus observed metrics). The outer `Result` covers engine build / component
/// load failures; the inner `SandboxRun::output` covers the execution itself.
pub fn scan_fixtures(input: &[u8]) -> Result<SandboxRun, botzr_aegis_sandbox::SandboxError> {
    let engine = SandboxEngine::new()?;
    let prepared = engine.prepare(DETECTOR_WASM)?;
    let grant = read_only_grant(&fixtures_root());
    Ok(engine.execute(&prepared, &grant, input))
}
