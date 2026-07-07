//! Engine and per-call `Store` lifecycle — wasmtime 36.x, component-model-native.
//!
//! The `Engine` is built once per process and reused (it compiles components).
//! The `Store` is per-call and dropped when the call ends — stores never share
//! mutable state. The sandbox is configured *from the resolved grant*, never
//! from the raw request.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use botzr_aegis_core::CapabilityGrant;
use wasmtime::component::{Component, InstancePre, Linker};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder};

use crate::error::SandboxError;
use crate::state::ToolState;

/// Epoch tick period. One tick ≈ one millisecond, so a grant's `max_wall_ms`
/// maps directly onto an epoch deadline in ticks.
const EPOCH_TICK: Duration = Duration::from_millis(1);

/// Process-wide sandbox engine: one wasmtime `Engine`, a WASI-populated
/// component `Linker`, and a background epoch ticker for CPU/wall metering.
pub struct SandboxEngine {
    engine: Engine,
    linker: Linker<ToolState>,
    // Field is never read directly; held so the ticker thread lives as long as
    // the engine and is stopped on drop.
    _epoch: EpochTicker,
}

impl SandboxEngine {
    /// Build the engine (component model + async + epoch interruption), install
    /// WASI host functions into the linker, and start the epoch ticker.
    pub fn new() -> Result<Self, SandboxError> {
        let mut cfg = Config::new();
        cfg.wasm_component_model(true)
            .async_support(true)
            .epoch_interruption(true);
        let engine = Engine::new(&cfg).map_err(SandboxError::EngineInit)?;

        let mut linker = Linker::<ToolState>::new(&engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker).map_err(SandboxError::EngineInit)?;

        let epoch = EpochTicker::spawn(engine.clone());
        Ok(Self {
            engine,
            linker,
            _epoch: epoch,
        })
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Compile a component and cache its `InstancePre`, so repeat calls skip
    /// recompilation. The returned tool is instantiated into a fresh store per
    /// call.
    pub fn prepare(&self, component_bytes: impl AsRef<[u8]>) -> Result<PreparedTool, SandboxError> {
        let component =
            Component::new(&self.engine, component_bytes).map_err(SandboxError::ComponentLoad)?;
        let pre = self
            .linker
            .instantiate_pre(&component)
            .map_err(SandboxError::ComponentLoad)?;
        Ok(PreparedTool { pre })
    }

    /// Build a per-call `Store` **from the grant**. This is the load-bearing
    /// step: filesystem preopens, network deny, memory cap, and wall-clock
    /// deadline are all derived from the resolved grant, not the request.
    pub fn build_store(&self, grant: &CapabilityGrant) -> Result<Store<ToolState>, SandboxError> {
        let ctx = build_wasi_ctx(grant).map_err(SandboxError::StoreConfig)?;
        let mut store = Store::new(&self.engine, ToolState::new(ctx, grant.clone()));

        // Memory limiter borrows into the store data (per-call cap).
        store.limiter(|s| s.limiter_mut() as &mut dyn wasmtime::ResourceLimiter);

        // Wall-clock cap via epoch: 1 tick ≈ 1 ms. `deny_all` (0 ms) still gets
        // a minimal, immediately-expiring budget rather than running unbounded.
        store.set_epoch_deadline(grant.max_wall_ms.max(1));
        store.epoch_deadline_trap();

        Ok(store)
    }

    /// Compatibility entry for the current runtime stub. R1 configures the
    /// store from the grant (the load-bearing step) and proves it builds; full
    /// component invocation is wired by the runtime orchestrator (AEG-23) once
    /// tools are registered and the WIT world bindings + host imports land.
    pub fn execute(&self, grant: &CapabilityGrant, _input: &[u8]) -> Result<Vec<u8>, String> {
        let _store = self.build_store(grant).map_err(|e| e.to_string())?;
        Err(
            "sandbox R1: no tool prepared — use prepare() + run; invocation wired in AEG-23"
                .to_string(),
        )
    }
}

impl std::fmt::Debug for SandboxEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxEngine").finish_non_exhaustive()
    }
}

impl Default for SandboxEngine {
    fn default() -> Self {
        // The config is static and valid; `Engine::new` only fails on an
        // internal wasmtime invariant break, which is not recoverable here.
        Self::new().expect("static wasmtime config must build a valid Engine")
    }
}

/// A compiled, link-resolved tool ready to instantiate into per-call stores.
pub struct PreparedTool {
    pre: InstancePre<ToolState>,
}

impl PreparedTool {
    /// Instantiate into a fresh per-call store and invoke a `func() -> ()`
    /// export.
    ///
    /// This is the minimal typed entry used by the deny-suite and the
    /// forthcoming orchestrator; the full `run(list<u8>) -> result<...>` world
    /// binding lands with the Stage-2 tool and its Model B host imports.
    pub async fn call_unit(
        &self,
        engine: &SandboxEngine,
        grant: &CapabilityGrant,
        export: &str,
    ) -> Result<(), SandboxError> {
        let mut store = engine.build_store(grant)?;
        let instance = self
            .pre
            .instantiate_async(&mut store)
            .await
            .map_err(SandboxError::from_wasmtime)?;
        let func = instance
            .get_typed_func::<(), ()>(&mut store, export)
            .map_err(|_| SandboxError::MissingExport(export.to_string()))?;
        func.call_async(&mut store, ())
            .await
            .map_err(SandboxError::from_wasmtime)?;
        func.post_return_async(&mut store)
            .await
            .map_err(SandboxError::from_wasmtime)?;
        Ok(())
    }

    /// Instantiate and invoke a `func() -> s32` export, returning the value.
    /// Used to exercise the memory limiter (a guest that grows memory past its
    /// cap sees `memory.grow` return `-1`).
    pub async fn call_i32(
        &self,
        engine: &SandboxEngine,
        grant: &CapabilityGrant,
        export: &str,
    ) -> Result<i32, SandboxError> {
        let mut store = engine.build_store(grant)?;
        let instance = self
            .pre
            .instantiate_async(&mut store)
            .await
            .map_err(SandboxError::from_wasmtime)?;
        let func = instance
            .get_typed_func::<(), (i32,)>(&mut store, export)
            .map_err(|_| SandboxError::MissingExport(export.to_string()))?;
        let (value,) = func
            .call_async(&mut store, ())
            .await
            .map_err(SandboxError::from_wasmtime)?;
        func.post_return_async(&mut store)
            .await
            .map_err(SandboxError::from_wasmtime)?;
        Ok(value)
    }
}

/// Configure a WASI context from a grant. Filesystem preopens use cap-std under
/// the hood (via `WasiCtxBuilder::preopened_dir`), which is capability-relative
/// and cannot be escaped by `..`, symlinks, or TOCTOU races. Network gets
/// nothing registered — default-deny is free.
fn build_wasi_ctx(grant: &CapabilityGrant) -> anyhow::Result<WasiCtx> {
    let mut b = WasiCtxBuilder::new();

    if let Some(fs) = &grant.fs {
        for (i, path) in fs.read_paths.iter().enumerate() {
            b.preopened_dir(path, format!("/ro{i}"), DirPerms::READ, FilePerms::READ)?;
        }
        for (i, path) in fs.write_paths.iter().enumerate() {
            b.preopened_dir(
                path,
                format!("/rw{i}"),
                DirPerms::READ | DirPerms::MUTATE,
                FilePerms::READ | FilePerms::WRITE,
            )?;
        }
    }

    // net: register no socket factory → no network. Allow-list wiring from
    // `grant.net` lands with the net capability work; absence is a full deny.

    Ok(b.build())
}

/// Background thread that increments the engine epoch on a fixed tick so
/// per-store epoch deadlines fire. Stopped and joined on drop.
struct EpochTicker {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl EpochTicker {
    fn spawn(engine: Engine) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    thread::sleep(EPOCH_TICK);
                    engine.increment_epoch();
                }
            })
        };
        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
