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
//! a frame of its own**, and the array is still relayed whole and unsplit — by
//! default, and under [`WrapMode::Enforce`] when the gate allows every
//! `tools/call` in the frame. One refused element drops the **whole** frame
//! instead, never a filtered array: re-serializing a parsed value onto the
//! child's stdin is the thing wrap does not do (ADR-0015). The N calls in one
//! batch therefore share one `request_digest` and one `response_digest`: a
//! batched element never was a frame, so the digests cover the arrays that
//! actually crossed the wire. The README's "Batched calls" carries the whole of
//! it.
//!
//! **What a session does is [`WrapMode`], and the default is
//! [`WrapMode::Record`]:** relay everything, record every `tools/call`, block
//! nothing. The CLI selects it when the operator passes neither `--confine` nor
//! `--policy`, and a default session is byte-for-byte the child's on the client
//! stream. Read `README.md` before describing this crate as a sandbox by
//! default, because it is not one.
//!
//! [`WrapMode::Confine`] adds OS confinement of the child from `--confine`
//! (AILAB-628) and changes nothing about which calls are relayed.
//! [`WrapMode::Enforce`] is opt-in per-call enforcement from `--policy <YAML>`:
//! every well-formed `tools/call` is put to a [`CallGate`] first, and one the
//! gate refuses never reaches the child — the client gets the ADR-0015 `-32042`
//! error instead, and the record carries the real Policy Set hash rather than
//! the pass-through stand-in. Without `--policy` there is no policy evaluation
//! and no synthesized frame at all.
//!
//! **The enforcement pipeline still does not run in this crate.** A
//! [`CallGate`] is a seam, not a `PolicyEngine`: do not reach for
//! `PolicyEngine`, `RuntimeBuilder` or `execute_tool_call` from here — the CLI
//! owns `botzr_aegis_policy` and implements the gate over it. Capability
//! resolution is not coming here either: argument matchers were canceled in
//! AILAB-626, and `--confine` confines at the OS level without minting a grant,
//! so even an enforced call records the `deny_all` pass-through grant.

mod config;
mod error;
mod record;
mod relay;

pub use config::{CallGate, GateVerdict, WrapConfig, WrapMode, WrapStreams};
pub use error::WrapError;
pub use record::WRAP_PASSTHROUGH_POLICY_SET_ID;
pub use relay::{run_wrap, run_wrap_with_streams};
