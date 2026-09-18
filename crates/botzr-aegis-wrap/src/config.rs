//! What a wrap session is configured with, and where its four streams come
//! from.

use std::fmt;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use botzr_aegis_core::{PolicyAction, PolicySetHash, ToolId};

/// One wrap session: a child to interpose on, and the record file to write.
///
/// Both paths are required. There is no temp-sink mode and no dev-key fallback
/// — a persistent record file an operator may later pin must never be signed by
/// the seed compiled into the published audit crate (AILAB-620).
#[derive(Debug, Clone)]
pub struct WrapConfig {
    /// `[0]` is the program, the rest are its arguments. Must be non-empty;
    /// an empty argv is [`crate::WrapError::EmptyArgv`].
    pub child_argv: Vec<String>,
    pub audit_path: PathBuf,
    pub signing_key_path: PathBuf,
    /// What this session does with the frames it carries — see [`WrapMode`].
    /// [`WrapMode::Record`] is the transparent default the CLI selects when the
    /// operator passes neither `--confine` nor `--policy`.
    pub mode: WrapMode,
}

/// What a wrap session does with the `tools/call`s it carries.
///
/// **Three variants, not two `Option`s.** Confinement and enforcement used to
/// be one optional field, and adding a second optional field for the gate would
/// have made four states out of three facts — including "a gate with no
/// confinement profile and no way to tell that apart from a profile with no
/// gate", which nothing in the relay knows what to do with. The illegal state
/// is unrepresentable here instead of being checked for later.
///
/// `Confine(p)` and `Enforce { confinement: Some(p), .. }` both confine. The
/// one reader of that fact is `spawn_child`, and it goes through
/// [`WrapMode::confinement`] so the four-state shape cannot reappear at the
/// call site.
#[derive(Clone)]
pub enum WrapMode {
    /// Relay every frame and record every `tools/call`. No policy evaluation,
    /// no confinement, and no frame wrap authored itself: the client stream is
    /// byte-for-byte the child's. This is the default and it is what
    /// `botzr-aegis-wrap` has always done.
    Record,
    /// [`WrapMode::Record`], plus OS confinement of the child (AILAB-628). The
    /// child is spawned as `current_exe() __confine-exec -- <original argv>`
    /// with the profile in `AEGIS_CONFINE_PROFILE`. Still no policy
    /// evaluation: a confined child's `tools/call`s are all relayed.
    Confine(botzr_aegis_confine::ConfinementProfile),
    /// Put every well-formed `tools/call` to `gate` before it may reach the
    /// child, and refuse the ones the gate does not allow (ADR-0015).
    ///
    /// Opt-in only. The CLI selects it from `--policy <YAML>` and from nothing
    /// else, so an `aegis wrap` invocation can never fall into enforcement.
    Enforce {
        /// Where the decision comes from. Wrap does not make it — see
        /// [`CallGate`].
        gate: Arc<dyn CallGate + Send + Sync>,
        /// `--confine` is orthogonal to `--policy`: an enforcing session may or
        /// may not also confine the child at the OS level.
        confinement: Option<botzr_aegis_confine::ConfinementProfile>,
    },
}

impl WrapMode {
    /// The OS confinement profile this mode carries, if any.
    ///
    /// The single reader is `spawn_child`. Matching on the enum there instead
    /// would re-open exactly the shape this enum exists to close.
    pub fn confinement(&self) -> Option<&botzr_aegis_confine::ConfinementProfile> {
        match self {
            Self::Record => None,
            Self::Confine(profile) => Some(profile),
            Self::Enforce { confinement, .. } => confinement.as_ref(),
        }
    }

    /// The gate every `tools/call` is put to, or `None` when this session
    /// evaluates nothing.
    ///
    /// `None` is the whole of the default contract: no gate, no refusal, no
    /// synthesized frame, and the pass-through `policy_set_hash` on every
    /// record.
    pub fn gate(&self) -> Option<&(dyn CallGate + Send + Sync)> {
        match self {
            Self::Record | Self::Confine(_) => None,
            Self::Enforce { gate, .. } => Some(gate.as_ref()),
        }
    }
}

impl fmt::Debug for WrapMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Record => f.write_str("Record"),
            Self::Confine(profile) => f.debug_tuple("Confine").field(profile).finish(),
            Self::Enforce { confinement, .. } => f
                .debug_struct("Enforce")
                // A trait object carries no `Debug`, and requiring one of every
                // gate implementation would put a formatting concern into the
                // enforcement seam. The type name is the honest amount a wrap
                // config can say about a gate a caller supplied.
                .field("gate", &"CallGate")
                .field("confinement", confinement)
                .finish(),
        }
    }
}

/// The per-call decision wrap **asks for** and does not make.
///
/// Wrap's crate graph is `audit` + `core` + `confine`, and this trait is how it
/// stays that way: `botzr_aegis_policy` lives one layer up, in the CLI, which
/// implements this over `PolicyEngine::evaluate`. The relay tests implement it
/// over a fixed table. Nothing here names a policy engine — [`PolicyAction`]
/// and [`PolicySetHash`] are already `botzr-aegis-core` types, so the seam
/// costs no dependency (ADR-0015 *Consequences*).
///
/// A gate is asked about a tool **identity** and nothing else. Wrap has no
/// caller role to assert and does not look at `params.arguments` — argument
/// matchers were canceled in AILAB-626 — so `tool_id` is the whole request.
pub trait CallGate: Send + Sync {
    /// Decide one `tools/call`. Called on the relay's main thread, once per
    /// well-formed `tools/call`, before the frame may reach the child.
    fn decide(&self, tool_id: &ToolId) -> GateVerdict;
}

/// One gate answer, with the evidence the record must carry.
///
/// `policy_set_hash` is **not** optional and has no default. A verdict whose
/// ruleset is unknown cannot be rechecked, and a record that named
/// [`crate::WRAP_PASSTHROUGH_POLICY_SET_ID`] for a call a real engine governed
/// would be the pass-through lie in the one field that is supposed to make the
/// verdict reproducible (ADR-0015).
#[derive(Debug, Clone)]
pub struct GateVerdict {
    /// Content hash of the Policy Set that produced `action`.
    pub policy_set_hash: PolicySetHash,
    /// The verdict. Anything but [`PolicyAction::Allow`] refuses the call —
    /// including `PendingApproval`, which is a refusal here and not a park:
    /// parking is AILAB-629 and wrap has no line type for it.
    pub action: PolicyAction,
    /// Id of the rule that decided it, for `decision_axes.matched_rule`.
    /// `None` when the set's default action decided.
    pub matched_rule: Option<String>,
}

/// The client-facing ends of a wrap session.
///
/// `run_wrap` fills these from the process's own stdio. They are a parameter at
/// all because the relay has to be testable against a **real** child process
/// without an in-process pipe: `std::io::pipe` is 1.87 and the workspace MSRV
/// is 1.86. This is a testability seam, not a narrowing of the product surface.
///
/// `child_err` is the sink the child's stderr is teed to — never swallowed, and
/// never merged into `client_out`, which carries JSON-RPC only. The tee is
/// byte-for-byte and imposes no encoding of its own: a server that emits a
/// progress bar, an ANSI escape or a stray non-UTF-8 byte still gets every
/// following byte through. Wrap's own lifecycle diagnostics share this sink.
pub struct WrapStreams {
    pub client_in: Box<dyn Read + Send>,
    pub client_out: Box<dyn Write + Send>,
    pub child_err: Box<dyn Write + Send>,
}
