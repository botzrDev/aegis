//! Per-call guest state carried in the wasmtime `Store<ToolState>`.
//!
//! One `ToolState` per call; never shared across calls. Model B host functions
//! read [`ToolState::grant`] and enforce it host-side *before* the effect — the
//! sandbox gives zero protection for host-side effects.

use botzr_aegis_core::CapabilityGrant;
use wasmtime::component::ResourceTable;
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

use crate::limits::MemoryLimiter;

/// State stored per call: WASI context, resource table, memory limiter, and the
/// resolved grant that configured this call.
pub struct ToolState {
    ctx: WasiCtx,
    table: ResourceTable,
    limiter: MemoryLimiter,
    grant: CapabilityGrant,
}

impl ToolState {
    pub(crate) fn new(ctx: WasiCtx, grant: CapabilityGrant) -> Self {
        let limiter = MemoryLimiter::new(grant.max_memory_bytes);
        Self {
            ctx,
            table: ResourceTable::new(),
            limiter,
            grant,
        }
    }

    pub(crate) fn limiter(&self) -> &MemoryLimiter {
        &self.limiter
    }

    pub(crate) fn limiter_mut(&mut self) -> &mut MemoryLimiter {
        &mut self.limiter
    }

    /// The grant that configured this call. Model B host functions enforce this
    /// before performing an effect.
    pub fn grant(&self) -> &CapabilityGrant {
        &self.grant
    }
}

impl WasiView for ToolState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}
