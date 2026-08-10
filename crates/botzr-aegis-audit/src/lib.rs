//! Audit trail — schema-versioned, hash-chained, signed records (AEG-10,
//! AILAB-619).
//!
//! G3 durability default: synchronous append + fsync, fail-closed on write
//! failure. One [`AuditWriter`] is one Session: it emits the `Open` line on
//! construction and the `Close` line on `Drop`, and owns the chain state
//! (`seq`, tail hash) behind the same lock as the file handle.
//!
//! Every appended line is hashed into the chain; `Open`, `Outcome`, `Decision`
//! and `Close` are also signed. `Intent` is not — it is fsynced ahead of
//! execution, and signing must stay off the pre-execution critical path.

mod error;
mod line;
mod session;
mod signing;
mod verdict;
mod writer;

pub use error::AuditError;
pub use line::{ChainLine, SignedChainLine};
pub use session::CallSession;
pub use signing::{insecure_dev_key, verify_line, SigningKey, VerifyError};
pub use verdict::{
    verify_chain, verify_chain_file, IndeterminateReason, Position, TamperedReason, Verdict,
    Verification,
};
pub use writer::{line_hash, to_json_line, AuditWriter};
