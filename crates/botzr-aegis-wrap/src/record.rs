//! What wrap records, and — just as load-bearing — what it does not.
//!
//! **`tools/call` only.** `initialize`, `tools/list`, `ping`, notifications and
//! every method this build has never heard of are relayed with zero
//! interception: no session, no audit line, and never a response wrap wrote
//! itself. Wrap is an interposer, not a second server, and a `-32601` invented
//! at this layer would be wrap answering for a child that was never asked —
//! forbidden here and under every mode, enforcement included.
//!
//! **The one frame wrap may author** is the JSON-RPC `error` answering a
//! `tools/call` that an opted-in [`CallGate`] refused before the request
//! reached the child (ADR-0015). Default wrap has no gate, so it synthesizes
//! nothing and its client stream is byte-for-byte the child's.
//!
//! A recorded call is two lines, in this order: an **intent** fsynced before the
//! request reaches the child, and an **outcome** written after the child's
//! matching response is already on its way to the client. The intent-first rule
//! is what makes a wrap process that dies mid-call still say a call was in
//! flight; `CallSession`'s fail-closed `Drop` supplies the outcome. A refused
//! call has no child response to wait for, so its two lines are written back to
//! back and it never enters the pending map.
//!
//! Everything here works on **frames of bytes**, never `String`: a frame is the
//! bytes up to and not including the `\n` that delimited it, and it is parsed
//! with `serde_json::from_slice` and digested verbatim. A frame that is not
//! valid UTF-8 is simply a frame that is not a `tools/call` — it is relayed,
//! not dropped, and never mistaken for end-of-stream.

use std::time::Instant;

use botzr_aegis_audit::{AuditError, AuditWriter, CallSession};
use botzr_aegis_core::{
    CallAxes, CallMetrics, CapabilityGrant, CapabilityOutcome, DecisionAxes, ExecutionOutcome,
    GrantId, PolicyAction, PolicyOutcome, PolicySetHash, RequestDigest, ResponseDigest, ToolId,
};
use serde_json::Value;

use crate::config::{CallGate, GateVerdict};

/// The bytes hashed into a pass-through record's `policy_set_hash`.
///
/// Not a real Policy Set: a wrap session with no [`CallGate`] runs **no** policy
/// engine, and naming a set it did not evaluate would be the more dishonest
/// option. This constant is a stable, documented stand-in that says "relayed
/// under the wrap pass-through regime, version 0".
///
/// It is the hash of a **pass-through**, and only of a pass-through. An
/// enforcing session hashes [`GateVerdict::policy_set_hash`] into every call the
/// gate governed, because a call a real engine decided must name the set that
/// decided it or the verdict cannot be rechecked (ADR-0015).
pub const WRAP_PASSTHROUGH_POLICY_SET_ID: &[u8] = b"aegis-wrap-passthrough-v0";

/// `tool_id` for a `tools/call` that never named a tool.
const UNKNOWN_TOOL_ID: &str = "<unknown>";

/// Why a malformed `tools/call` is recorded as a deny across every axis.
const MALFORMED_REASON: &str = "tools/call without a string params.name";

/// The JSON-RPC error code ADR-0015 reserves for a wrap refusal.
///
/// Inside JSON-RPC 2.0's implementation-defined server-error range
/// (`-32000`..`-32099`), and not `-32601` (the method-not-found lie wrap never
/// tells) nor `-32000` (the slot the fixture child and every real server reach
/// for first). It does not vary — a client integrates against it.
const REFUSAL_CODE: i64 = -32042;

/// The `error.message` on every refusal. Fixed for the same reason the code is.
const REFUSAL_MESSAGE: &str = "aegis wrap refused this tools/call";

/// `data.aegis.layer`: the frame names the layer that authored it, rather than
/// leaving a reader to infer authorship from a number.
const REFUSAL_LAYER: &str = "wrap";

// `data.aegis.code` — the gateway's string table at
// `botzr-aegis-mcp/src/mcp.rs`, duplicated here rather than imported. Wrap does
// not depend on `botzr-aegis-mcp` and must not start: from wrap's point of view
// the gateway is just another unmodified stdio server. Four short strings are
// the cheaper coupling, and ADR-0015 asks only that a wrap refusal and a
// gateway denial name the same cause with the same word.
const CODE_POLICY_DENIED: &str = "POLICY_DENIED";
const CODE_RATE_LIMITED: &str = "RATE_LIMITED";
const CODE_PENDING_APPROVAL: &str = "PENDING_APPROVAL";
const CODE_HOST_DENIED: &str = "HOST_DENIED";

/// What the capability axis says when policy refused before it ever ran.
/// Spelled the same as `botzr_aegis_runtime`'s pipeline, deliberately: one
/// refusal, one wording, wherever it is enforced.
const BLOCKED_BEFORE_CAPABILITY: &str = "policy blocked before capability";

/// What the execution axis says for a call that never reached the child.
const NOT_EXECUTED: &str = "not executed";

/// What an **allowed** call is told, and recorded as, when it rode in a frame
/// that wrap dropped.
///
/// A batch cannot be filtered: the array is the frame, and forwarding a subset
/// would mean re-serializing a parsed value onto the child's stdin, which this
/// crate never does. So one refused element refuses the frame, and its allowed
/// siblings are refused *with* it — told so in their own client error and said
/// so in their own record, rather than left to look like calls that failed.
const SIBLING_REFUSED: &str = "not executed: sibling call in this batch was refused";

/// A `tools/call` that has been recorded as intent and is waiting for the
/// child's response.
pub(crate) struct PendingCall<'a> {
    session: CallSession<'a>,
    /// Kept because the grant minted at completion is scoped to it, and
    /// `CallSession::begin` consumed the original.
    tool_id: ToolId,
    started: Instant,
}

/// What one client frame turned out to be.
pub(crate) enum Observed<'a> {
    /// Nothing to track. Not JSON, not a `tools/call`, a notification, a batch
    /// carrying none of those, or a malformed `tools/call` that has *already*
    /// been recorded as a completed deny here.
    Ignored,
    /// A well-formed `tools/call`: recorded as intent, keyed by the id its
    /// response will carry.
    ///
    /// Boxed because a `CallSession` is ~680 bytes and `Ignored` is empty, so
    /// an unboxed enum would make every relayed frame — most of them not
    /// `tools/call` at all — pay for the one that is
    /// (`clippy::large_enum_variant`). The allocation happens once per recorded
    /// call, against two fsyncs.
    Pending(String, Box<PendingCall<'a>>),
    /// Every well-formed `tools/call` carried by one JSON-RPC **batch array**,
    /// in the order its elements appeared.
    ///
    /// Never empty: a batch with no call to account for is [`Observed::Ignored`],
    /// so the caller has one thing to do with each variant rather than two.
    Many(Vec<(String, Box<PendingCall<'a>>)>),
    /// **Do not forward the client frame.** Write these bytes to `client_out`
    /// instead — each element is one complete JSON-RPC frame wrap authored.
    ///
    /// One client frame in, one client frame out: an object request is answered
    /// by an object, and a **batch** by a single array carrying one error per
    /// call it contained (JSON-RPC 2.0 §6). Splitting one refused array into N
    /// object frames would hand the client a framing its own request did not
    /// have, and is the mirror of the split this crate refuses on the way to
    /// the child.
    ///
    /// Only an enforcing session produces this, and only for a frame carrying a
    /// `tools/call` its [`CallGate`] refused. Every call the frame carried is
    /// already recorded **and completed** by the time this returns: a refused
    /// call must never enter the pending map, because [`complete_relayed`]
    /// would then overwrite its deny with `Allowed` / `deny_all` / `Success`
    /// the moment anything carrying that id arrived.
    ///
    /// Not `Ignored` with a side channel, and not a `Pending` that is never
    /// answered: the relay has exactly one thing to do with each variant, and
    /// "the frame stops here" is a different instruction from "the frame goes
    /// through untracked".
    Refused(Vec<Vec<u8>>),
}

/// Why a still-pending call is being closed without the child's answer.
///
/// Two different facts, two different reason strings, deliberately not merged.
/// An audit record is a signed statement: saying a process exited when it is
/// still running is a false one, and "the child is slow" and "the child is
/// gone" are exactly the two states an operator reads this file to tell apart.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Unanswered {
    /// The child's stdout reached EOF — the process is gone.
    ChildExited,
    /// The client closed stdin and the child neither answered nor produced any
    /// other output before the shutdown grace ran out. The child was **still
    /// alive** at this point; wrap is about to reap and kill it.
    ShutdownGraceExpired,
}

impl Unanswered {
    fn reason(self) -> &'static str {
        match self {
            Self::ChildExited => "child exited before responding",
            Self::ShutdownGraceExpired => {
                "client closed stdin; child did not answer within the shutdown grace"
            }
        }
    }
}

/// Inspect one client frame and open a session for every well-formed
/// `tools/call` it carries.
///
/// `gate` is `None` for a pass-through session — [`crate::WrapMode::Record`] and
/// [`crate::WrapMode::Confine`] — and then **the caller still relays the frame
/// verbatim, whole and unsplit, in every case**. Wrap blocks nothing; a child
/// that dislikes the request answers with its own `-32602`.
///
/// `gate` is `Some` only under [`crate::WrapMode::Enforce`], and then a frame
/// carrying a refused `tools/call` comes back as [`Observed::Refused`] and does
/// **not** reach the child. That is the one sentence this function's contract
/// gained in AILAB-793, and the reason it is a parameter rather than a mode
/// read off a config: the recorder needs the decision, not the profile.
///
/// # Batches
///
/// A JSON-RPC **batch** — a top-level array — is walked element by element, and
/// each well-formed `tools/call` inside it is recorded exactly as one sent in a
/// frame of its own: an intent before the frame reaches the child, an outcome
/// when the child's answer comes back. An element that is not a `tools/call` is
/// skipped the way a whole `initialize` frame is, and one that cannot name a
/// tool takes the same immediate three-axis deny a malformed object frame
/// takes.
///
/// **N calls in one batch share one `request_digest`.** A batched element never
/// was a frame, so the digest covers the array the client actually wrote;
/// re-serializing an element to give it a digest of its own would commit the
/// record to bytes that crossed no wire (`digest.rs` verbatim rule). The mirror
/// of that holds coming back — see [`complete_relayed`].
///
/// Recording a batched call **like a single** is the shape this crate chose,
/// and on the pass-through path the two alternatives were both worse. Dropping
/// the frame so it never reaches the child would need wrap to answer the client
/// with a JSON-RPC error, which a pass-through does not author. Relaying the
/// frame while recording the call `Denied` / `not executed` would sign a
/// refusal of a call the child really ran — a record stating something other
/// than what was enforced, which is the defect `e92450a` exists for.
///
/// Under a gate the first of those becomes the *correct* answer, because wrap
/// is now permitted to author exactly that error (ADR-0015): one refused
/// element refuses the whole frame. See [`observe_gated`].
pub(crate) fn observe_client_line<'a>(
    writer: &'a AuditWriter,
    frame: &[u8],
    gate: Option<&(dyn CallGate + Send + Sync)>,
) -> Result<Observed<'a>, AuditError> {
    let Ok(message) = serde_json::from_slice::<Value>(frame) else {
        return Ok(Observed::Ignored);
    };
    match gate {
        Some(gate) => observe_gated(writer, frame, &message, gate),
        None => observe_passthrough(writer, frame, &message),
    }
}

/// The always-relay path: today's behaviour, unchanged, and the only one a
/// default `aegis wrap` can reach.
fn observe_passthrough<'a>(
    writer: &'a AuditWriter,
    frame: &[u8],
    message: &Value,
) -> Result<Observed<'a>, AuditError> {
    if let Some(elements) = message.as_array() {
        let mut calls = Vec::new();
        for element in elements {
            // `?` rather than a per-element recovery: an audit write that
            // fails takes the whole session down, exactly as it does on the
            // object path. The frame reaches the child only once every intent
            // it carries is durable.
            if let Some(call) = observe_tools_call(writer, frame, element)? {
                calls.push(call);
            }
        }
        return Ok(if calls.is_empty() {
            Observed::Ignored
        } else {
            Observed::Many(calls)
        });
    }
    Ok(match observe_tools_call(writer, frame, message)? {
        Some((id_key, call)) => Observed::Pending(id_key, call),
        None => Observed::Ignored,
    })
}

/// Open a session for one `tools/call` message — or account for it here and
/// return `None`.
///
/// `frame` is the whole client frame the message arrived in. For a batched
/// element that is the enclosing array, because the array is the only run of
/// bytes that ever existed as a frame.
///
/// `None` covers three facts that share one consequence — no response left to
/// match: this is not a `tools/call`; it is a notification no response can ever
/// answer; or it is a `tools/call` that cannot name a tool, which is recorded
/// here as a completed deny before returning.
fn observe_tools_call<'a>(
    writer: &'a AuditWriter,
    frame: &[u8],
    message: &Value,
) -> Result<Option<(String, Box<PendingCall<'a>>)>, AuditError> {
    match classify(message) {
        Element::Untouched => Ok(None),
        Element::Malformed { .. } => {
            record_malformed(writer, frame)?;
            Ok(None)
        }
        Element::Gated { id_key, tool_id, .. } => {
            // VERBATIM: the digest covers the frame bytes as they arrived — a
            // trailing `\r` included, the `\n` delimiter excluded — never a
            // re-encoding of the parsed value (`digest.rs` verbatim rule). A
            // batched element has no frame of its own, so it commits to the
            // array's bytes along with its siblings.
            let request_digest = RequestDigest::of_request_bytes(frame);
            let policy_set_hash =
                PolicySetHash::of_canonical_bytes(WRAP_PASSTHROUGH_POLICY_SET_ID);
            let session =
                CallSession::begin(writer, tool_id.clone(), request_digest, policy_set_hash)?;
            Ok(Some((
                id_key,
                Box::new(PendingCall {
                    session,
                    tool_id,
                    started: Instant::now(),
                }),
            )))
        }
    }
}

/// The enforcing path: ask the gate about every `tools/call` in the frame, then
/// let the frame through or refuse it whole.
///
/// **Two passes, and the split is the point.** A batch is refused as a whole or
/// not at all, and that is not known until the last element has been asked — so
/// pass one asks the gate and writes nothing, and pass two writes the records
/// the frame's fate calls for. Recording as we went and then discovering a deny
/// in the final element would leave allowed siblings already signed as pending
/// calls the child will never answer.
///
/// The gate is asked about **every** element either way, including the siblings
/// of a call that is already going to refuse the frame. An engine-governed call
/// whose record says nothing about the rule that governed it is the same defect
/// as a pass-through hash, one field over.
fn observe_gated<'a>(
    writer: &'a AuditWriter,
    frame: &[u8],
    message: &Value,
    gate: &(dyn CallGate + Send + Sync),
) -> Result<Observed<'a>, AuditError> {
    let is_batch = message.is_array();
    let elements: Vec<&Value> = match message.as_array() {
        Some(elements) => elements.iter().collect(),
        None => vec![message],
    };

    // Pass one: decide, record nothing.
    let decided: Vec<(Element, Option<GateVerdict>)> = elements
        .iter()
        .map(|element| {
            let element = classify(element);
            let verdict = match &element {
                Element::Gated { tool_id, .. } => Some(gate.decide(tool_id)),
                Element::Malformed { .. } | Element::Untouched => None,
            };
            (element, verdict)
        })
        .collect();

    // A malformed `tools/call` does not vote. It names no tool, so there was
    // nothing for the gate to evaluate and no verdict to refuse the frame over
    // — its immediate three-axis deny is already the honest record, and it has
    // always relayed.
    let refused = decided
        .iter()
        .filter_map(|(_, verdict)| verdict.as_ref())
        .any(|verdict| !matches!(PolicyOutcome::from(&verdict.action), PolicyOutcome::Allowed));

    if refused {
        return refuse_frame(writer, frame, decided, is_batch);
    }

    // Pass two, allowed: record intents exactly as the pass-through path does,
    // but against the set that actually governed each call.
    let mut calls = Vec::new();
    for (element, verdict) in decided {
        match (element, verdict) {
            (Element::Gated { id_key, tool_id, .. }, Some(verdict)) => {
                let session = begin_governed(writer, frame, tool_id.clone(), &verdict)?;
                calls.push((
                    id_key,
                    Box::new(PendingCall {
                        session,
                        tool_id,
                        started: Instant::now(),
                    }),
                ));
            }
            (Element::Malformed { .. }, _) => record_malformed(writer, frame)?,
            (Element::Untouched | Element::Gated { .. }, _) => {}
        }
    }

    Ok(match calls.len() {
        0 => Observed::Ignored,
        _ if is_batch => Observed::Many(calls),
        // Exactly one, and the frame was an object: the single-call shape.
        _ => {
            let (id_key, call) = calls.remove(0);
            Observed::Pending(id_key, call)
        }
    })
}

/// The frame stops here. Record and close every `tools/call` it carried, and
/// author the client's answer to each.
///
/// The frame is **not** forwarded and **not** rewritten. Filtering a batch down
/// to its allowed elements would mean re-serializing a parsed value onto the
/// child's stdin, and this crate relays bytes it did not author or it does not
/// relay them at all (`DECISIONS.md`, *The relay is byte-oriented*).
///
/// `is_batch` decides the client's **framing**, not its content: a refused
/// array is answered by one array of errors, an object by one object. The
/// client gets back the shape it sent.
///
/// Every call is completed here rather than left pending: there is no child
/// response coming, and a refused call sitting in the pending map would have
/// its deny overwritten by [`complete_relayed`] the moment any frame carrying
/// that id arrived.
fn refuse_frame<'a>(
    writer: &'a AuditWriter,
    frame: &[u8],
    decided: Vec<(Element, Option<GateVerdict>)>,
    is_batch: bool,
) -> Result<Observed<'a>, AuditError> {
    let mut errors: Vec<Value> = Vec::new();
    for (element, verdict) in decided {
        match (element, verdict) {
            (Element::Gated { id, tool_id, .. }, Some(verdict)) => {
                let outcome = PolicyOutcome::from(&verdict.action);
                let mut session = begin_governed(writer, frame, tool_id, &verdict)?;
                session.set_policy(outcome.clone());
                if matches!(outcome, PolicyOutcome::Allowed) {
                    // The gate allowed this call; the frame it rode in was
                    // refused anyway. Policy says `allowed` because that is
                    // what the engine said, and the capability seed
                    // (`not evaluated`) stands because no capability station
                    // ran — wrap minted nothing for a call that never left it.
                    session.set_execution(ExecutionOutcome::HostDenied {
                        reason: SIBLING_REFUSED.into(),
                    });
                } else {
                    session.set_capability(CapabilityOutcome::Denied {
                        reason: BLOCKED_BEFORE_CAPABILITY.into(),
                        denied_capability: None,
                    });
                    session.set_execution(ExecutionOutcome::HostDenied {
                        reason: NOT_EXECUTED.into(),
                    });
                }
                session.complete()?;
                errors.push(refusal(&id, refusal_code(&verdict.action)));
            }
            (Element::Malformed { id }, _) => {
                // Already a completed deny wherever it appears, and it still
                // says `not executed` — which is now true twice over. It is
                // answered because the frame is not going anywhere: leaving a
                // stranded id unanswered would hang the client, which is the
                // one thing ADR-0015 exists to prevent.
                record_malformed(writer, frame)?;
                errors.push(refusal(&id, CODE_HOST_DENIED));
            }
            // Not a `tools/call`, or a `tools/call` notification. A
            // notification is answerable by nothing — JSON-RPC says it has no
            // id — so it is dropped with the frame and nothing waits on it.
            (Element::Untouched | Element::Gated { .. }, _) => {}
        }
    }
    Ok(Observed::Refused(frame_answers(errors, is_batch)))
}

/// Frame the authored errors the way the client framed its request.
///
/// `serde_json::to_vec` is infallible for a value built here: every part of it
/// was just constructed from owned JSON, with no non-string map key and no
/// float to reject. An empty result is unreachable — a refusal happens only
/// when some element carried an answerable id — and would simply relay nothing,
/// never forward the frame.
fn frame_answers(errors: Vec<Value>, is_batch: bool) -> Vec<Vec<u8>> {
    let frames = if is_batch {
        vec![Value::Array(errors)]
    } else {
        errors
    };
    frames
        .iter()
        .filter_map(|frame| serde_json::to_vec(frame).ok())
        .collect()
}

/// Open a session for a call a [`CallGate`] governed, naming the set that
/// governed it and the rule that decided it.
///
/// Both halves matter. The hash is what makes the verdict recheckable, and
/// `matched_rule` is what makes it explainable — an engine-governed record with
/// empty `decision_axes` is the pass-through lie in another field. They are set
/// in the same order as `botzr_aegis_runtime`'s pipeline: the caller-asserted
/// axes first, then `matched_rule` layered on, because that is the verdict's own
/// output rather than something a caller asserted.
///
/// Wrap asserts **no** axes. It has no caller role, no session scope and no
/// capability axis to offer, so `from_call_axes` of an empty [`CallAxes`] is the
/// honest `{}` and the rule id is the only axis a wrap record can carry.
/// Inventing a role here would put a fabricated matcher input into a signed
/// record.
fn begin_governed<'a>(
    writer: &'a AuditWriter,
    frame: &[u8],
    tool_id: ToolId,
    verdict: &GateVerdict,
) -> Result<CallSession<'a>, AuditError> {
    let request_digest = RequestDigest::of_request_bytes(frame);
    let mut session =
        CallSession::begin(writer, tool_id, request_digest, verdict.policy_set_hash)?;
    let mut axes = DecisionAxes::from_call_axes(CallAxes::default());
    if let Some(matched_rule) = verdict.matched_rule.clone() {
        axes = axes.with_matched_rule(matched_rule);
    }
    session.set_decision_axes(axes);
    Ok(session)
}

/// Record a `tools/call` that cannot name a tool: denied on every axis and
/// closed immediately.
///
/// **The pass-through hash is correct here even under a gate.** No tool was
/// named, so no gate was asked and no Policy Set governed this call; naming one
/// would claim an evaluation that never happened, which is the same defect as
/// naming a stand-in for a call an engine really did decide.
fn record_malformed(writer: &AuditWriter, frame: &[u8]) -> Result<(), AuditError> {
    let mut session = CallSession::begin(
        writer,
        ToolId::new(UNKNOWN_TOOL_ID),
        RequestDigest::of_request_bytes(frame),
        PolicySetHash::of_canonical_bytes(WRAP_PASSTHROUGH_POLICY_SET_ID),
    )?;
    session.set_policy(PolicyOutcome::Denied {
        reason: MALFORMED_REASON.into(),
    });
    session.set_capability(CapabilityOutcome::Denied {
        reason: MALFORMED_REASON.into(),
        denied_capability: None,
    });
    session.set_execution(ExecutionOutcome::HostDenied {
        reason: NOT_EXECUTED.into(),
    });
    session.complete()
}

/// What one element of a client frame is, as far as the recorder is concerned.
///
/// One classifier for both paths: the pass-through recorder and the gate walk
/// have to agree on what a `tools/call` is, and two copies of that question
/// would be two chances to answer it differently.
enum Element {
    /// A well-formed `tools/call` with an answerable id.
    Gated {
        /// Pending-map key — the *serialized* id, so `1` and `"1"` stay the
        /// distinct keys JSON-RPC says they are.
        id_key: String,
        /// The id itself, kept so a refusal can echo it as JSON. A request that
        /// sent the number `1` must be answered with the number `1`; echoing
        /// `id_key` would answer with the string `"1"`, which JSON-RPC says is
        /// a different id.
        id: Value,
        tool_id: ToolId,
    },
    /// A `tools/call` with an answerable id and no `params.name`.
    Malformed { id: Value },
    /// Not a `tools/call`, or a `tools/call` notification.
    ///
    /// A notification has no id, so no response can ever be matched to it and
    /// no outcome could ever be written. Recording an intent that is
    /// structurally unanswerable would manufacture a permanent in-flight call.
    Untouched,
}

fn classify(message: &Value) -> Element {
    if message.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Element::Untouched;
    }
    let Some(id) = message.get("id").filter(|id| !id.is_null()) else {
        return Element::Untouched;
    };
    let Ok(id_key) = serde_json::to_string(id) else {
        return Element::Untouched;
    };
    match message.pointer("/params/name").and_then(Value::as_str) {
        Some(name) => Element::Gated {
            id_key,
            id: id.clone(),
            tool_id: ToolId::new(name),
        },
        None => Element::Malformed { id: id.clone() },
    }
}

/// The one frame wrap is ever permitted to author (ADR-0015).
///
/// `id` is echoed **as JSON**: a number stays a number. `error.code`,
/// `data.aegis.layer` and the `error`-rather-than-`result` envelope are fixed —
/// they are the shape a client integrates against, and a mode that varied them
/// would be a mode nothing could be written against. Only `data.aegis.code`
/// varies, across the gateway's existing string table.
///
/// A JSON-RPC `error` rather than the gateway's `result` with `isError: true`:
/// a `result` is wrap speaking *as the child*, which is the impersonation the
/// flat ban existed to prevent. An `error` is wrap speaking as the interposer.
fn refusal(id: &Value, code: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": REFUSAL_CODE,
            "message": REFUSAL_MESSAGE,
            "data": { "aegis": { "layer": REFUSAL_LAYER, "code": code } }
        }
    })
}

/// `data.aegis.code` for one verdict.
///
/// `Allow` is reachable: it is the allowed sibling of a refused call, whose
/// frame wrap dropped. Wrap denied it at the host, not the policy station, and
/// `HOST_DENIED` is the gateway's word for exactly that.
fn refusal_code(action: &PolicyAction) -> &'static str {
    match action {
        PolicyAction::Allow => CODE_HOST_DENIED,
        PolicyAction::Deny { .. } => CODE_POLICY_DENIED,
        PolicyAction::RateLimited { .. } => CODE_RATE_LIMITED,
        // A refusal, not a park. Parking the request is AILAB-629 and is
        // unspecced; wrap has no line type for a call that is neither answered
        // nor closed, and inventing one here would leave a signed intent with
        // no outcome for as long as the approval took.
        PolicyAction::PendingApproval { .. } => CODE_PENDING_APPROVAL,
    }
}

/// Close a call the child answered.
///
/// `raw_response` is the child frame as it arrived. When that frame is a batch
/// array it closes one call per response-shaped element, so N outcomes share
/// one `response_digest` — the mirror of the N intents that shared one
/// `request_digest`, and for the same reason: an element inside an array never
/// was a frame.
///
/// **A JSON-RPC `error` object from the child is still [`ExecutionOutcome::Success`].**
/// The call ran; the tool erred. `HostDenied` is reserved for the child
/// *process* failing to answer at all — see [`complete_unanswered`]. Collapsing
/// the two would make "the tool returned an error" indistinguishable from "the
/// runtime refused to run it", which is precisely the distinction an audit trail
/// exists to keep.
///
/// This is the allow-and-relay path, under a gate exactly as without one, and
/// it does not branch on the mode. The Policy Set was named at `begin` and the
/// decision axes were set there; a refused call never reaches here at all.
pub(crate) fn complete_relayed(
    pending: PendingCall<'_>,
    raw_response: &[u8],
) -> Result<(), AuditError> {
    let PendingCall {
        mut session,
        tool_id,
        started,
    } = pending;

    let grant_id = GrantId::new(format!("wrap-passthrough-{}", session.call_id()));
    session.set_policy(PolicyOutcome::Allowed);
    session.set_grant_id(grant_id.clone());
    // `deny_all` is the honest grant whether or not a gate allowed the call:
    // wrap confined nothing and minted nothing, so it must not record fs or net
    // authority it never had. A gate decides *whether* a call may go; it
    // resolves no capability, and `--confine` confines at the OS level without
    // minting a grant — so a confined or enforced run records `deny_all` too.
    session.set_capability(CapabilityOutcome::Granted {
        grant: CapabilityGrant::deny_all(tool_id, grant_id),
    });
    // Verbatim response frame, delimiter excluded — the same rule the request
    // digest follows.
    session.set_response_digest(ResponseDigest::of_response_bytes(raw_response));
    session.set_metrics(CallMetrics {
        // Round trip through wrap, not the child's own accounting.
        wall_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        // Wrap does not meter the child process — it is an ordinary OS process
        // outside any resource ceiling — so 0 is "not measured", not "used
        // nothing". Confinement shipped and metering did not follow it: wrap
        // does not meter, and no ticket currently promises that it will.
        peak_memory_bytes: 0,
    });
    session.set_execution(ExecutionOutcome::Success);
    // `decision_axes` is whatever `begin` set: `{}` on the pass-through path,
    // where no policy and no capability station ran, and the governing rule
    // under a gate. Not overwritten here — the verdict was reached before the
    // frame went out, not after it came back.
    session.complete()
}

/// Close a call the child never answered, saying **which** of the two ways it
/// went unanswered.
pub(crate) fn complete_unanswered(
    pending: PendingCall<'_>,
    why: Unanswered,
) -> Result<(), AuditError> {
    let PendingCall { mut session, .. } = pending;
    session.set_execution(ExecutionOutcome::HostDenied {
        reason: why.reason().into(),
    });
    // Policy and capability keep their default-deny seeds: neither station ran,
    // and nothing about this call was ever allowed.
    session.complete()
}

/// The pending-map keys a child frame closes, in the order they appear in it.
///
/// Empty when the frame is not a response at all — which includes the child
/// making a request of its own. An object frame yields at most one key; a batch
/// array yields one per **response-shaped** element, and a method-bearing
/// element inside it contributes nothing, exactly as it would contribute
/// nothing on its own. The bidirectional-MCP guard below is per element, not
/// per frame: a server→client request riding in the same array as a real
/// response must not close anything.
pub(crate) fn response_id_keys(frame: &[u8]) -> Vec<String> {
    let Ok(message) = serde_json::from_slice::<Value>(frame) else {
        return Vec::new();
    };
    match message.as_array() {
        Some(elements) => elements.iter().filter_map(response_key).collect(),
        None => response_key(&message).into_iter().collect(),
    }
}

/// The pending-map key one message closes, if it is a response at all.
fn response_key(message: &Value) -> Option<String> {
    if !is_response_shaped(message) {
        return None;
    }
    id_key(message)
}

/// Is this child frame a *response*, or a request the server is making of its
/// own client?
///
/// LOAD-BEARING. **MCP is bidirectional.** A server issues its own requests to
/// the client — `sampling/createMessage`, `elicitation/create`, `roots/list` —
/// numbered from the *server's* id space, which shares no namespace with the
/// client's and collides with it routinely (both usually start at 1).
///
/// Keying a completion on `id` alone would let one of those close a pending
/// `tools/call`: wrap would sign an `Allowed` / `Granted` / `Success` outcome
/// whose `response_digest` covers a **request the tool never answered**, and the
/// real response, arriving later, would match nothing and be recorded nowhere.
/// A false signed record is strictly worse than a missing one.
///
/// JSON-RPC 2.0 §5: a response carries `result` **or** `error` and never a
/// `method`. That shape is the gate; anything else is relayed with no recording
/// effect.
fn is_response_shaped(message: &Value) -> bool {
    message.get("method").is_none()
        && (message.get("result").is_some() || message.get("error").is_some())
}

/// Key a request and its response agree on.
///
/// The serialized `id` rather than the raw text, so that `1` and `"1"` stay
/// distinct keys the way JSON-RPC says they are, and so whitespace in the
/// client's framing cannot fork one call into two.
fn id_key(message: &Value) -> Option<String> {
    let id = message.get("id").filter(|id| !id.is_null())?;
    serde_json::to_string(id).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_set_id_is_the_documented_constant() {
        // Spec §5.6: these exact bytes, and a change to them is a change to
        // every record's `policy_set_hash`.
        assert_eq!(WRAP_PASSTHROUGH_POLICY_SET_ID, b"aegis-wrap-passthrough-v0");
    }

    #[test]
    fn ids_of_different_json_types_do_not_collide() {
        let number = response_id_keys(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#);
        let string = response_id_keys(br#"{"jsonrpc":"2.0","id":"1","result":{}}"#);
        assert_eq!(number.len(), 1, "{number:?}");
        assert_ne!(number, string);
    }

    #[test]
    fn a_null_or_absent_id_is_a_notification() {
        assert!(response_id_keys(br#"{"jsonrpc":"2.0","method":"x"}"#).is_empty());
        assert!(response_id_keys(br#"{"jsonrpc":"2.0","id":null,"result":{}}"#).is_empty());
        assert!(response_id_keys(b"not json").is_empty());
    }

    /// The bidirectional-MCP guard, at the unit level: a server→client
    /// *request* must never key a completion, however familiar its id looks.
    #[test]
    fn a_server_initiated_request_is_not_a_response() {
        assert!(response_id_keys(
            br#"{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{}}"#
        )
        .is_empty());
        assert!(response_id_keys(br#"{"jsonrpc":"2.0","id":1,"method":"roots/list"}"#).is_empty());
        // A response shape with the same id *does* complete.
        assert_eq!(
            response_id_keys(br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#).len(),
            1
        );
        assert_eq!(
            response_id_keys(br#"{"jsonrpc":"2.0","id":1,"error":{"code":-1}}"#).len(),
            1
        );
        // A `null` result is still a result: `get` sees the key, not the value.
        assert_eq!(
            response_id_keys(br#"{"jsonrpc":"2.0","id":1,"result":null}"#).len(),
            1
        );
    }

    /// A batch array closes calls too — but only through its response-shaped
    /// elements. The bidirectional-MCP guard is per element, not per frame.
    #[test]
    fn a_batch_array_completes_through_response_shaped_elements_only() {
        assert_eq!(
            response_id_keys(
                br#"[{"jsonrpc":"2.0","id":1,"result":{}},{"jsonrpc":"2.0","id":2,"error":{"code":-1}}]"#
            ),
            vec!["1".to_owned(), "2".to_owned()],
            "both response elements key their own completion"
        );
        assert!(
            response_id_keys(
                br#"[{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage"},{"jsonrpc":"2.0","id":2,"method":"roots/list"}]"#
            )
            .is_empty(),
            "an array of server-initiated requests closes nothing"
        );
        assert_eq!(
            response_id_keys(
                br#"[{"jsonrpc":"2.0","id":1,"method":"roots/list"},{"jsonrpc":"2.0","id":1,"result":{}}]"#
            ),
            vec!["1".to_owned()],
            "a server request riding beside a real response must not close a call of its own"
        );
        assert!(
            response_id_keys(b"[]").is_empty(),
            "an empty array carries no answer"
        );
    }

    /// Invalid UTF-8 is a frame that is not a response, not an error and never
    /// an end-of-stream.
    #[test]
    fn invalid_utf8_is_merely_unmatched() {
        assert!(response_id_keys(&[0xff, 0xfe, b'{']).is_empty());
    }

    /// The one frame wrap may author, asserted against ADR-0015's own sketch.
    ///
    /// Three of its four parts do not vary — `error.code`, `data.aegis.layer`,
    /// and `error` rather than `result` — so they are pinned here rather than
    /// only where a relay test happens to look at a client stream.
    #[test]
    fn a_refusal_frame_has_the_adr_0015_shape() {
        let parsed = refusal(&serde_json::json!(7), CODE_POLICY_DENIED);

        assert_eq!(parsed["jsonrpc"], "2.0", "{parsed}");
        assert_eq!(parsed["error"]["code"], -32042, "{parsed}");
        assert_eq!(parsed["error"]["message"], REFUSAL_MESSAGE, "{parsed}");
        assert_eq!(parsed["error"]["data"]["aegis"]["layer"], "wrap", "{parsed}");
        assert_eq!(
            parsed["error"]["data"]["aegis"]["code"], "POLICY_DENIED",
            "{parsed}"
        );
        // Wrap speaks as the interposer, never as the child: an `error`
        // envelope, and never the gateway's `result` with `isError`.
        assert!(parsed.get("result").is_none(), "{parsed}");
        // The `-32601` ban is not relaxed by enforcement.
        assert_ne!(parsed["error"]["code"], -32601, "{parsed}");
    }

    /// The id is echoed as **JSON**, not as its pending-map key.
    ///
    /// `id_key` is the *serialized* id, so a client that sent the number `1`
    /// would be answered with the string `"1"` if the key were echoed — which
    /// JSON-RPC says is a different id, and which a strict client is entitled
    /// to treat as an answer to a call it never made.
    #[test]
    fn a_refused_id_keeps_its_json_type() {
        for id in [
            serde_json::json!(1),
            serde_json::json!("1"),
            serde_json::json!(null),
        ] {
            assert_eq!(refusal(&id, CODE_HOST_DENIED)["id"], id);
        }
    }

    /// One client frame in, one client frame out — and in the shape the client
    /// used. A refused batch is answered by an array, never by N object frames.
    #[test]
    fn a_refused_batch_is_answered_by_one_array_frame() {
        let errors = vec![
            refusal(&serde_json::json!(1), CODE_POLICY_DENIED),
            refusal(&serde_json::json!(2), CODE_HOST_DENIED),
        ];

        let batched = frame_answers(errors.clone(), true);
        assert_eq!(batched.len(), 1, "a batch is answered by one frame");
        let parsed: Value = serde_json::from_slice(&batched[0]).expect("the frame is JSON");
        let elements = parsed.as_array().expect("an array answers an array");
        assert_eq!(elements.len(), 2, "{parsed}");
        assert_eq!(elements[0]["id"], 1, "{parsed}");
        assert_eq!(elements[1]["id"], 2, "{parsed}");

        // An object request keeps the object shape it sent.
        let single = frame_answers(vec![errors[0].clone()], false);
        assert_eq!(single.len(), 1);
        let parsed: Value = serde_json::from_slice(&single[0]).expect("the frame is JSON");
        assert!(parsed.is_object(), "{parsed}");
    }

    /// Every verdict maps to a code, and the allowed-sibling arm is reachable.
    #[test]
    fn every_verdict_names_a_gateway_code() {
        assert_eq!(refusal_code(&PolicyAction::Allow), CODE_HOST_DENIED);
        assert_eq!(
            refusal_code(&PolicyAction::Deny {
                reason: "x".into()
            }),
            CODE_POLICY_DENIED
        );
        assert_eq!(
            refusal_code(&PolicyAction::RateLimited {
                reason: "x".into()
            }),
            CODE_RATE_LIMITED
        );
        assert_eq!(
            refusal_code(&PolicyAction::PendingApproval {
                approval_id: "x".into()
            }),
            CODE_PENDING_APPROVAL
        );
    }

    /// `classify` is the single answer to "what is this element", and the two
    /// recorder paths both read it.
    #[test]
    fn classify_separates_a_gated_call_from_a_malformed_one() {
        let gated = serde_json::from_str::<Value>(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}"#,
        )
        .expect("json");
        match classify(&gated) {
            Element::Gated { id_key, id, tool_id } => {
                assert_eq!(id_key, "1");
                assert_eq!(id, serde_json::json!(1));
                assert_eq!(tool_id.as_str(), "echo");
            }
            _ => panic!("a named tools/call is gated"),
        }

        let malformed = serde_json::from_str::<Value>(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}}"#,
        )
        .expect("json");
        assert!(matches!(classify(&malformed), Element::Malformed { .. }));

        // A `tools/call` notification is unanswerable, so it is untouched even
        // under a gate: there is no id to refuse to.
        let notification =
            serde_json::from_str::<Value>(r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo"}}"#)
                .expect("json");
        assert!(matches!(classify(&notification), Element::Untouched));

        let other =
            serde_json::from_str::<Value>(r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#)
                .expect("json");
        assert!(matches!(classify(&other), Element::Untouched));
    }
}
