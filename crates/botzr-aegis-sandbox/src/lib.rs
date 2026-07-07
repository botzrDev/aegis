//! WASM execution sandbox — wasmtime 36.x, per-call Store, cap-std preopens.

use botzr_aegis_core::CapabilityGrant;

/// Pin used in workspace `[workspace.dependencies]` — whole workspace moves as one.
pub const WASMTIME_PIN_MAJOR: u32 = 36;

/// Sandbox engine handle (placeholder until AEG-6).
#[derive(Debug, Default)]
pub struct SandboxEngine;

impl SandboxEngine {
    pub fn new() -> Self {
        Self
    }

    /// Configure a per-call store from the grant, then execute. Stub until AEG-6.
    pub fn execute(&self, _grant: &CapabilityGrant, _input: &[u8]) -> Result<Vec<u8>, String> {
        Err("sandbox not implemented".into())
    }
}
