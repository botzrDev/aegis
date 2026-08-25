//! Transparent stdio MCP interposer — client ↔ `aegis wrap` ↔ child server.
//!
//! Wrap sits in the middle of an existing MCP stdio session and relays it in
//! both directions, writing a schema-v2 chained audit record for every
//! `tools/call` it carries.
//!
//! **Framing, precisely.** A frame is the bytes up to and not including the
//! `\n` that delimited it. Within a frame the bytes are relayed verbatim: a
//! trailing `\r` is preserved, invalid UTF-8 is preserved, and the request and
//! response digests cover exactly those bytes and not the delimiter. The only
//! normalization is at the framing layer — the `\n` is re-emitted, so a final
//! frame that arrived without one gains one, and a frame that is empty or all
//! whitespace is dropped rather than forwarded.
//!
//! **A `tools/call` inside a JSON-RPC batch array is recorded like one sent in
//! a frame of its own**, and the array is still relayed whole and unsplit. The
//! N calls in one batch therefore share one `request_digest` and one
//! `response_digest`: a batched element never was a frame, so the digests cover
//! the arrays that actually crossed the wire. The README's "Batched calls"
//! carries the whole of it.
//!
//! **Wrap confines only when `WrapConfig::confinement` is `Some`**, which the
//! CLI sets from `--confine` (AILAB-628). Without it there is no policy
//! evaluation, no argument matching, and no filesystem or network restriction
//! on the child — the child is an ordinary OS process with whatever authority
//! the operator's own account has. Read `README.md` before describing this
//! crate as a sandbox by default, because it is not one.
//!
//! Nothing here drives the enforcement pipeline. Wrap's only station is AUDIT:
//! do not reach for `PolicyEngine`, `RuntimeBuilder`, or `execute_tool_call`
//! from this crate — capability resolution arrives with AILAB-626/628.

mod config;
mod error;
mod record;
mod relay;

pub use config::{WrapConfig, WrapStreams};
pub use error::WrapError;
pub use record::WRAP_PASSTHROUGH_POLICY_SET_ID;
pub use relay::{run_wrap, run_wrap_with_streams};
