//! Sandbox error taxonomy, and the bridge into the audit contract.
//!
//! Every failing exit path classifies into a [`SandboxError`], which maps onto
//! a schema-versioned [`ExecutionOutcome`] so the audit record reflects what
//! actually happened (trap vs. resource-exceeded vs. denial).

use botzr_aegis_core::ExecutionOutcome;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("engine initialization failed: {0}")]
    EngineInit(#[source] anyhow::Error),

    #[error("component load failed: {0}")]
    ComponentLoad(#[source] anyhow::Error),

    #[error("store configuration failed: {0}")]
    StoreConfig(#[source] anyhow::Error),

    #[error("component export not found: {0}")]
    MissingExport(String),

    #[error("guest trapped: {message}")]
    Trap { message: String },

    #[error("resource limit exceeded: {kind}")]
    ResourceExceeded { kind: String },
}

impl SandboxError {
    /// Bridge into the schema-versioned audit outcome — one record per call,
    /// including on trap and resource-exceeded.
    pub fn to_execution_outcome(&self) -> ExecutionOutcome {
        match self {
            SandboxError::ResourceExceeded { kind } => {
                ExecutionOutcome::ResourceExceeded { kind: kind.clone() }
            }
            SandboxError::Trap { message } => ExecutionOutcome::Trap {
                message: message.clone(),
            },
            other => ExecutionOutcome::Trap {
                message: other.to_string(),
            },
        }
    }

    /// Classify a wasmtime error from instantiation or a guest call into a
    /// sandbox outcome. An epoch-deadline interrupt is a wall-clock resource
    /// exhaustion, fuel exhaustion is its own resource axis, and everything
    /// else is a plain trap.
    pub(crate) fn from_wasmtime(err: anyhow::Error) -> Self {
        if let Some(&trap) = err.downcast_ref::<wasmtime::Trap>() {
            return match trap {
                wasmtime::Trap::Interrupt => SandboxError::ResourceExceeded {
                    kind: "wall_clock".to_string(),
                },
                wasmtime::Trap::OutOfFuel => SandboxError::ResourceExceeded {
                    kind: "fuel".to_string(),
                },
                other => SandboxError::Trap {
                    message: other.to_string(),
                },
            };
        }
        SandboxError::Trap {
            message: format!("{err:#}"),
        }
    }
}
