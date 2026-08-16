//! Audit trail — schema-versioned, hash-chained, signed records (AEG-10,
//! AILAB-619).
//!
//! One [`AuditWriter`] is one Session: it emits the `Open` line on
//! construction and the `Close` line on `Drop`, and owns the chain rule —
//! `seq`, tail hash and the sink handle behind one lock. Appends are
//! synchronous and fail-closed: a write error is returned, never swallowed.
//!
//! **The G3 durability default is the sink's, not this crate's.** Synchronous
//! append plus fsync is what [`FileChainSink`] does; another [`ChainSink`] may
//! do less, and says which by declaring its [`Retention`]. A Chain appended to
//! an in-memory sink and a Chain fsynced to disk are byte-identical, so that
//! declaration — checked against the signing key at construction, where a
//! Durable Sink refuses [`insecure_dev_key`] — is the only thing that
//! distinguishes evidence from a rehearsal (ADR-0012).
//!
//! Every appended line is hashed into the chain; `Open`, `Outcome`, `Decision`
//! and `Close` are also signed. `Intent` is not — it is fsynced ahead of
//! execution, and signing must stay off the pre-execution critical path.
//!
//! The signing key's lifecycle — a hex seed file, owner-only, generated
//! explicitly and loaded fail-closed — is [`generate_signing_key`] /
//! [`load_signing_key`] (AILAB-620). [`insecure_dev_key`] signs temp sinks and
//! tests only, and no configuration reaches it.

mod error;
mod keyfile;
mod line;
mod session;
mod signing;
mod sink;
mod verdict;
mod writer;

pub use error::AuditError;
pub use keyfile::{generate_signing_key, load_signing_key};
pub use line::{ChainLine, SignedChainLine};
pub use session::CallSession;
pub use signing::{insecure_dev_key, verify_line, SigningKey, VerifyError};
pub use sink::{ChainSink, FileChainSink, MemoryChainSink, Retention};
pub use verdict::{
    verify_chain, verify_chain_file, verify_chain_file_with_trust, verify_chain_with_trust,
    IndeterminateReason, Position, TamperedReason, TrustLabel, Verdict, Verification,
};
pub use writer::{line_hash, to_json_line, AuditWriter};
