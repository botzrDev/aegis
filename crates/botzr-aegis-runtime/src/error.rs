//! Runtime registration errors (tool registry + component integrity).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegisterError {
    #[error("component bytes required for registration")]
    MissingComponent,

    #[error("sha256 mismatch: expected {expected}, got {actual}")]
    Sha256Mismatch { expected: String, actual: String },

    #[error("sandbox prepare failed: {0}")]
    SandboxPrepare(String),

    /// A tool id may be registered exactly once — re-registration would swap
    /// authority (manifest) and executable independently, which is the split
    /// state AEG-44 exists to remove.
    #[error("tool {tool_id} is already registered")]
    DuplicateTool { tool_id: String },

    /// The manifest's declared [`ToolKind`](botzr_aegis_capability::ToolKind)
    /// disagrees with the supplied [`ToolExecutable`](crate::ToolExecutable)
    /// — e.g. a Model B host tool handed WASM bytes.
    #[error("kind mismatch: manifest declares {declared} but executable is {provided}")]
    KindMismatch {
        declared: String,
        provided: &'static str,
    },
}
