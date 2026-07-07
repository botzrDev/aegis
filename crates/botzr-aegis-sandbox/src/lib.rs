//! WASM execution sandbox — wasmtime 36.x, component-model-native (`wasip2`).
//!
//! Station 3 of the enforcement pipeline (POLICY → CAPABILITY → **SANDBOX** →
//! AUDIT). The [`SandboxEngine`] is built once and reused; each call gets a
//! fresh [`Store`](wasmtime::Store) configured *from the resolved grant*:
//!
//! - filesystem scoping via cap-std preopens (never hand-rolled path checks),
//! - network default-deny (no socket factory registered),
//! - a per-call memory cap ([`MemoryLimiter`]), and
//! - a wall-clock cap via epoch interruption.
//!
//! Failing exit paths classify into [`SandboxError`], which bridges to the
//! schema-versioned audit `ExecutionOutcome`.

mod engine;
mod error;
mod limits;
mod state;

pub use engine::{PreparedTool, SandboxEngine};
pub use error::SandboxError;
pub use limits::MemoryLimiter;
pub use state::ToolState;

/// Major version of wasmtime this crate is pinned to (LTS through 2027-08-20).
pub const WASMTIME_PIN_MAJOR: u32 = 36;
