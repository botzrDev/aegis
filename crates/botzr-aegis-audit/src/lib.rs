//! Audit trail — schema-versioned records, JSONL persistence (AEG-10).
//!
//! G3 durability default: synchronous append + fsync, fail-closed on write
//! failure. Two-phase lines (`intent` then `outcome`) share a `call_id`.

mod error;
mod session;
mod writer;

pub use error::AuditError;
pub use session::CallSession;
pub use writer::{to_json_line, AuditWriter};
