//! Engine and per-call `Store` lifecycle — wasmtime 36.x, component-model-native.
//!
//! The `Engine` is built once per process and reused (it compiles components).
//! The `Store` is per-call and dropped when the call ends — stores never share
//! mutable state. The sandbox is configured *from the resolved grant*, never
//! from the raw request.
//!
//! The tokio runtime that polls the guest future is built once alongside the
//! `Engine`, not per call: it carries no guest state, so amortizing it is not
//! a relaxation of the per-call `Store` rule (AILAB-809).

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use botzr_aegis_core::CallMetrics;
use botzr_aegis_core::CapabilityGrant;
use tokio::runtime::Runtime as TokioRuntime;
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
    /// One tokio runtime for the life of the engine, built in
    /// [`SandboxEngine::new`].
    ///
    /// wasmtime's component API is async, so *something* has to poll the guest
    /// future on the sync entry points. That something used to be a brand-new
    /// current-thread runtime per call, which cost a runtime construction on
    /// every invocation and — worse — panicked outright when the caller was
    /// already inside a tokio runtime (AILAB-809).
    ///
    /// **This is not a wasmtime `Store`.** The per-call rule this module opens
    /// with is about `Store`: mutable guest state, never shared across calls.
    /// A tokio runtime holds no guest state, so amortizing it costs no
    /// isolation — the `Store` is still built per call in
    /// [`SandboxEngine::build_store`].
    ///
    /// `std::sync::Mutex` is the deliberate choice: the guard serializes the
    /// **sync** entry points' `block_on` calls, and it must never be held
    /// across an `.await`. The async entry points never take it — they poll
    /// the same futures on the caller's runtime.
    ///
    /// `Option` exists only so [`Drop`] can move the runtime out and shut it
    /// down in the background. Dropping a tokio runtime the ordinary way
    /// *blocks* to join its blocking pool, and tokio panics if that happens
    /// inside an async context — which is exactly where an embedder that hit
    /// AILAB-809 in the first place would be dropping this engine. It is
    /// `Some` for the whole observable life of the engine.
    runtime: Mutex<Option<TokioRuntime>>,
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

        // One runtime, built here rather than per call. `enable_all` keeps the
        // time and I/O drivers available to WASI host functions that need them.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| SandboxError::EngineInit(e.into()))?;

        let epoch = EpochTicker::spawn(engine.clone());
        Ok(Self {
            engine,
            linker,
            runtime: Mutex::new(Some(runtime)),
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

    /// Run `future` to completion on the engine's own tokio runtime.
    ///
    /// This is the one place the sandbox blocks. It **panics if called from
    /// inside a tokio runtime** — that is tokio's rule for `block_on`, not a
    /// policy of this crate — so every sync public entry point above it is
    /// responsible for refusing a nested runtime *before* it gets here. The
    /// runtime crate does that check on all three of its sync entries
    /// (`execute_tool_call`, `execute_host_call`, `execute_host_call_with`) and
    /// returns `AegisError::NestedRuntime`, so no call arrives here from an
    /// async context by that route. A consumer calling this method directly
    /// owns the same check.
    ///
    /// The lock is taken and released inside this call and is never held across
    /// an `.await`. It is a plain `std::sync::Mutex` and therefore **not
    /// reentrant**: reaching this method again on the same engine from inside
    /// the future it is already driving deadlocks rather than panicking. No
    /// path in `botzr-aegis-runtime` can do that — Model A's execution step
    /// uses [`SandboxEngine::execute_async`], which takes no lock — but a
    /// consumer wiring this crate directly must not call `execute` from inside
    /// an effect that `execute` invoked.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        let guard = self.runtime();
        guard
            .as_ref()
            .expect("engine runtime is taken only in Drop")
            .block_on(future)
    }

    /// The engine's tokio runtime, recovering from poisoning.
    ///
    /// A guest panic unwinds through `block_on` and poisons the mutex. The
    /// runtime itself is not left in a broken state by that — the panic came
    /// from the future, not from tokio — so the guard is recovered rather than
    /// turning one panicking call into a permanently dead engine.
    fn runtime(&self) -> MutexGuard<'_, Option<TokioRuntime>> {
        self.runtime.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Invoke a prepared tool's WIT `run` export with the grant-scoped store.
    ///
    /// Synchronous: blocks on the engine's runtime. A caller that is already
    /// inside a tokio runtime must use [`SandboxEngine::execute_async`].
    pub fn execute(
        &self,
        tool: &PreparedTool,
        grant: &CapabilityGrant,
        input: &[u8],
    ) -> SandboxRun {
        self.block_on(tool.run(self, grant, input))
    }

    /// [`SandboxEngine::execute`] for a caller that already has a runtime.
    ///
    /// Same store, same grant configuration, same metering — the only
    /// difference is that the guest future is polled by the caller's executor
    /// instead of the engine's. Takes no lock.
    pub async fn execute_async(
        &self,
        tool: &PreparedTool,
        grant: &CapabilityGrant,
        input: &[u8],
    ) -> SandboxRun {
        tool.run(self, grant, input).await
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
        self.block_on(fixture.call_unit(self, grant, export))
    }

    /// [`SandboxEngine::execute_fixture`] for a caller that already has a
    /// runtime. Requires the `test-utils` feature.
    #[cfg(feature = "test-utils")]
    pub async fn execute_fixture_async(
        &self,
        fixture: &PreparedFixture,
        grant: &CapabilityGrant,
        export: &str,
    ) -> SandboxRun {
        fixture.call_unit(self, grant, export).await
    }
}

impl Drop for SandboxEngine {
    /// Shut the owned tokio runtime down **without blocking**.
    ///
    /// `Runtime`'s own `Drop` waits for the blocking pool to join, and tokio
    /// panics when that wait happens inside an async context. An engine built
    /// by an embedder that lives on tokio is dropped exactly there, so relying
    /// on the default drop would trade AILAB-809's call-time panic for a
    /// drop-time one.
    ///
    /// **What this gives up.** No *call* can still be running — `Drop` takes
    /// `&mut self` — but abandoned `spawn_blocking` work can be: wasmtime-wasi
    /// runs p2 file I/O on the blocking pool, and a guest trapped mid-write
    /// leaves a task whose `abort()` is a no-op once it is running. The
    /// per-call runtime this replaced joined that pool at the end of every
    /// call, so those bytes landed before `execute` returned; they may now land
    /// after it, and a process that exits promptly may lose them. Joining here
    /// is not an option — it is the blocking wait that panics.
    fn drop(&mut self) {
        if let Some(runtime) = self
            .runtime
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            runtime.shutdown_background();
        }
    }
}

impl std::fmt::Debug for SandboxEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxEngine").finish_non_exhaustive()
    }
}

impl Default for SandboxEngine {
    fn default() -> Self {
        // The wasmtime config is static and valid, so `Engine::new` only fails
        // on an internal wasmtime invariant break. `new` also builds the
        // engine's tokio runtime, which can fail on a genuinely exhausted host
        // (file descriptors, threads). Neither is recoverable here — a caller
        // that needs to handle the second should use `SandboxEngine::new`.
        Self::new().expect("wasmtime config and tokio runtime must both build")
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The engine owns a tokio runtime, and a tokio runtime's own `Drop` blocks
    /// to join its blocking pool — which tokio refuses to do inside an async
    /// context. An embedder on tokio drops the engine exactly there, so without
    /// [`SandboxEngine`]'s non-blocking `Drop` this test panics with "Cannot
    /// drop a runtime in a context where blocking is not allowed", trading
    /// AILAB-809's call-time panic for a drop-time one.
    #[tokio::test]
    async fn engine_drops_inside_a_tokio_context() {
        let engine = SandboxEngine::new().expect("engine builds");
        drop(engine);
    }

    /// Two engines in the same async context: the shutdown is per-engine and
    /// leaves nothing behind that would trip the next one.
    #[tokio::test]
    async fn engines_drop_independently_inside_a_tokio_context() {
        let first = SandboxEngine::new().expect("first engine builds");
        let second = SandboxEngine::new().expect("second engine builds");
        drop(first);
        drop(second);
    }
}
