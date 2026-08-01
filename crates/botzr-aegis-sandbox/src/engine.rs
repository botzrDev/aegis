//! Engine and per-call `Store` lifecycle — wasmtime 36.x, component-model-native.
//!
//! The `Engine` is built once per process and reused (it compiles components).
//! The `Store` is per-call and dropped when the call ends — stores never share
//! mutable state. The sandbox is configured *from the resolved grant*, never
//! from the raw request.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use botzr_aegis_core::CallMetrics;
use botzr_aegis_core::CapabilityGrant;
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder};

use crate::bindings::{Tool, ToolPre};
use crate::error::SandboxError;
use crate::state::ToolState;

/// Epoch tick period. One tick ≈ one millisecond, so a grant's `max_wall_ms`
/// maps directly onto an epoch deadline in ticks.
const EPOCH_TICK: Duration = Duration::from_millis(1);

/// Result of a sandbox invocation, including observed resource usage (R5).
#[derive(Debug)]
pub struct SandboxRun {
    pub output: Result<Vec<u8>, SandboxError>,
    pub metrics: CallMetrics,
}

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
        Tool::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .map_err(SandboxError::EngineInit)?;

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

    pub fn linker(&self) -> &Linker<ToolState> {
        &self.linker
    }

    /// Compile a WIT `tool` world component and cache its `ToolPre`.
    pub fn prepare(&self, component_bytes: impl AsRef<[u8]>) -> Result<PreparedTool, SandboxError> {
        let component =
            Component::new(&self.engine, component_bytes).map_err(SandboxError::ComponentLoad)?;
        let pre = self
            .linker
            .instantiate_pre(&component)
            .map_err(SandboxError::ComponentLoad)?;
        let tool_pre = ToolPre::new(pre).map_err(SandboxError::ComponentLoad)?;
        Ok(PreparedTool { tool_pre })
    }

    /// Compile a raw component fixture (no WIT exports required). Used by the
    /// deny-suite and resource-metering tests. Requires the `test-utils`
    /// feature.
    #[cfg(feature = "test-utils")]
    pub fn prepare_fixture(
        &self,
        component_bytes: impl AsRef<[u8]>,
    ) -> Result<PreparedFixture, SandboxError> {
        let component =
            Component::new(&self.engine, component_bytes).map_err(SandboxError::ComponentLoad)?;
        let pre = self
            .linker
            .instantiate_pre(&component)
            .map_err(SandboxError::ComponentLoad)?;
        Ok(PreparedFixture { pre })
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

    /// Invoke a prepared tool's WIT `run` export with the grant-scoped store.
    pub fn execute(
        &self,
        tool: &PreparedTool,
        grant: &CapabilityGrant,
        input: &[u8],
    ) -> SandboxRun {
        block_on_async(tool.run(self, grant, input))
    }

    /// Invoke a raw fixture export (deny-suite / resource-cap tests). Requires
    /// the `test-utils` feature.
    #[cfg(feature = "test-utils")]
    pub fn execute_fixture(
        &self,
        fixture: &PreparedFixture,
        grant: &CapabilityGrant,
        export: &str,
    ) -> SandboxRun {
        block_on_async(fixture.call_unit(self, grant, export))
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

/// A compiled, link-resolved WIT tool ready to instantiate into per-call stores.
pub struct PreparedTool {
    tool_pre: ToolPre<ToolState>,
}

/// A raw component fixture for deny-suite / resource tests (no WIT exports).
/// Requires the `test-utils` feature.
#[cfg(feature = "test-utils")]
pub struct PreparedFixture {
    pre: wasmtime::component::InstancePre<ToolState>,
}

#[cfg(feature = "test-utils")]
impl PreparedFixture {
    /// Instantiate into a fresh per-call store and invoke a `func() -> ()`
    /// export.
    pub async fn call_unit(
        &self,
        engine: &SandboxEngine,
        grant: &CapabilityGrant,
        export: &str,
    ) -> SandboxRun {
        let started = Instant::now();
        let mut store = match engine.build_store(grant) {
            Ok(store) => store,
            Err(err) => {
                return SandboxRun {
                    output: Err(err),
                    metrics: CallMetrics {
                        wall_ms: started.elapsed().as_millis() as u64,
                        peak_memory_bytes: 0,
                    },
                };
            }
        };
        let run = async {
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
            Ok(Vec::new())
        };
        let output = reclassify_memory_trap(run.await, &store);
        SandboxRun {
            output,
            metrics: metrics_from_store(&store, started),
        }
    }

    /// Instantiate and invoke a `func() -> s32` export, returning the value.
    pub async fn call_i32(
        &self,
        engine: &SandboxEngine,
        grant: &CapabilityGrant,
        export: &str,
    ) -> SandboxRun {
        let started = Instant::now();
        let mut store = match engine.build_store(grant) {
            Ok(store) => store,
            Err(err) => {
                return SandboxRun {
                    output: Err(err),
                    metrics: CallMetrics {
                        wall_ms: started.elapsed().as_millis() as u64,
                        peak_memory_bytes: 0,
                    },
                };
            }
        };
        let run = async {
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
            Ok(value.to_le_bytes().to_vec())
        };
        let output = reclassify_memory_trap(run.await, &store);
        SandboxRun {
            output,
            metrics: metrics_from_store(&store, started),
        }
    }
}

impl PreparedTool {
    /// Instantiate into a fresh per-call store and invoke WIT `run`.
    pub async fn run(
        &self,
        engine: &SandboxEngine,
        grant: &CapabilityGrant,
        input: &[u8],
    ) -> SandboxRun {
        let started = Instant::now();
        let mut store = match engine.build_store(grant) {
            Ok(store) => store,
            Err(err) => {
                return SandboxRun {
                    output: Err(err),
                    metrics: CallMetrics {
                        wall_ms: started.elapsed().as_millis() as u64,
                        peak_memory_bytes: 0,
                    },
                };
            }
        };
        let run = async {
            let tool = self
                .tool_pre
                .instantiate_async(&mut store)
                .await
                .map_err(SandboxError::from_wasmtime)?;
            match tool
                .call_run(&mut store, input)
                .await
                .map_err(SandboxError::from_wasmtime)?
            {
                Ok(bytes) => Ok(bytes),
                Err(err) => Err(SandboxError::Trap {
                    message: format!("{}: {}", err.code, err.message),
                }),
            }
        };
        let output = reclassify_memory_trap(run.await, &store);
        SandboxRun {
            output,
            metrics: metrics_from_store(&store, started),
        }
    }
}

fn metrics_from_store(store: &Store<ToolState>, started: Instant) -> CallMetrics {
    CallMetrics {
        wall_ms: started.elapsed().as_millis() as u64,
        peak_memory_bytes: store.data().limiter().peak_bytes(),
    }
}

/// Reclassify a post-cap trap as a memory resource exhaustion.
///
/// When the memory limiter refused a `memory.grow` (or the initial allocation)
/// at the grant's cap and the guest then trapped — typically an out-of-bounds
/// access on the memory it assumed it received — the proximate cause is the
/// memory limit, not arbitrary guest logic. The audit then records
/// `resource_exceeded{memory}` rather than an opaque trap, matching how the
/// wall-clock cap surfaces. A clean run, an in-band `-1` the guest handled, or a
/// trap with no cap-denied grow is left untouched.
fn reclassify_memory_trap(
    output: Result<Vec<u8>, SandboxError>,
    store: &Store<ToolState>,
) -> Result<Vec<u8>, SandboxError> {
    match output {
        Err(SandboxError::Trap { .. }) if store.data().limiter().denied_growth() => {
            Err(SandboxError::ResourceExceeded {
                kind: "memory".to_string(),
            })
        }
        other => other,
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

fn block_on_async<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current-thread runtime must build")
        .block_on(future)
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
