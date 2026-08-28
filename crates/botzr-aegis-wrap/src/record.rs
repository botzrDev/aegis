//! What wrap records, and — just as load-bearing — what it does not.
//!
//! **`tools/call` only.** `initialize`, `tools/list`, `ping`, notifications and
//! every method this build has never heard of are relayed with zero
//! interception: no session, no audit line, no locally synthesized response.
//! Wrap is an interposer, not a second server, and a `-32601` invented at this
//! layer would be wrap answering for a child that was never asked.
//!
//! A recorded call is two lines, in this order: an **intent** fsynced before the
//! request reaches the child, and an **outcome** written after the child's
//! matching response is already on its way to the client. The intent-first rule
//! is what makes a wrap process that dies mid-call still say a call was in
//! flight; `CallSession`'s fail-closed `Drop` supplies the outcome.
//!
//! Everything here works on **frames of bytes**, never `String`: a frame is the
//! bytes up to and not including the `\n` that delimited it, and it is parsed
//! with `serde_json::from_slice` and digested verbatim. A frame that is not
//! valid UTF-8 is simply a frame that is not a `tools/call` — it is relayed,
//! not dropped, and never mistaken for end-of-stream.

use std::time::Instant;

use botzr_aegis_audit::{AuditError, AuditWriter, CallSession};
use botzr_aegis_core::{
    CallMetrics, CapabilityGrant, CapabilityOutcome, ExecutionOutcome, GrantId, PolicyOutcome,
    PolicySetHash, RequestDigest, ResponseDigest, ToolId,
};
use serde_json::Value;

/// The bytes hashed into every wrap record's `policy_set_hash`.
///
/// Not a real Policy Set: wrap runs **no** policy engine, and naming a set it
/// did not evaluate would be the more dishonest option. This constant is a
/// stable, documented stand-in that says "relayed under the wrap pass-through
/// regime, version 0". Nothing is scheduled to replace it with the hash of an
/// actual set: argument matchers were canceled in AILAB-626.
pub const WRAP_PASSTHROUGH_POLICY_SET_ID: &[u8] = b"aegis-wrap-passthrough-v0";

/// `tool_id` for a `tools/call` that never named a tool.
const UNKNOWN_TOOL_ID: &str = "<unknown>";

/// Why a malformed `tools/call` is recorded as a deny across every axis.
const MALFORMED_REASON: &str = "tools/call without a string params.name";

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
/// In every case the caller still relays the frame verbatim, whole and unsplit.
/// Wrap does not block; a child that dislikes the request answers with its own
/// `-32602`.
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
/// and the two alternatives were both worse. Dropping the frame so it never
/// reaches the child would need wrap to answer the client with a JSON-RPC error
/// the child never produced, which wrap does not do (AILAB-789). Relaying the
/// frame while recording the call `Denied` / `not executed` would sign a
/// refusal of a call the child really ran — a record stating something other
/// than what was enforced, which is the defect `e92450a` exists for.
pub(crate) fn observe_client_line<'a>(
    writer: &'a AuditWriter,
    frame: &[u8],
) -> Result<Observed<'a>, AuditError> {
    let Ok(message) = serde_json::from_slice::<Value>(frame) else {
        return Ok(Observed::Ignored);
    };
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
    Ok(match observe_tools_call(writer, frame, &message)? {
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
    if message.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Ok(None);
    }
    // A notification has no id, so no response can ever be matched to it and no
    // outcome could ever be written. Recording an intent that is structurally
    // unanswerable would manufacture a permanent in-flight call.
    let Some(id_key) = id_key(message) else {
        return Ok(None);
    };

    // VERBATIM: the digest covers the frame bytes as they arrived — a trailing
    // `\r` included, the `\n` delimiter excluded — never a re-encoding of the
    // parsed value (`digest.rs` verbatim rule). A batched element has no frame
    // of its own, so it commits to the array's bytes along with its siblings.
    let request_digest = RequestDigest::of_request_bytes(frame);
    let policy_set_hash = PolicySetHash::of_canonical_bytes(WRAP_PASSTHROUGH_POLICY_SET_ID);
    let tool_id = message
        .pointer("/params/name")
        .and_then(Value::as_str)
        .map(ToolId::new);

    let Some(tool_id) = tool_id else {
        // Fail closed *and* stay transparent: the call is recorded as denied on
        // every axis and closed immediately, and the frame still goes to the
        // child. It is not added to the pending map, so the child's answer
        // matches nothing and cannot produce a second outcome.
        let mut session = CallSession::begin(
            writer,
            ToolId::new(UNKNOWN_TOOL_ID),
            request_digest,
            policy_set_hash,
        )?;
        session.set_policy(PolicyOutcome::Denied {
            reason: MALFORMED_REASON.into(),
        });
        session.set_capability(CapabilityOutcome::Denied {
            reason: MALFORMED_REASON.into(),
            denied_capability: None,
        });
        session.set_execution(ExecutionOutcome::HostDenied {
            reason: "not executed".into(),
        });
        session.complete()?;
        return Ok(None);
    };

    let session = CallSession::begin(writer, tool_id.clone(), request_digest, policy_set_hash)?;
    Ok(Some((
        id_key,
        Box::new(PendingCall {
            session,
            tool_id,
            started: Instant::now(),
        }),
    )))
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
pub(crate) fn complete_relayed(
    pending: PendingCall<'_>,
    raw_response: &[u8],
) -> Result<(), AuditError> {
    let PendingCall {
        mut session,
        tool_id,
        started,
    } = pending;

    let grant_id = format!("wrap-passthrough-{}", session.call_id());
    session.set_policy(PolicyOutcome::Allowed);
    session.set_grant_id(GrantId::new(grant_id.clone()));
    // `deny_all` is the honest grant for a pass-through: wrap confined nothing,
    // so it must not record fs or net authority it never minted. Nothing
    // replaces it with a resolved grant: argument matchers were canceled in
    // AILAB-626, and `--confine` confines at the OS level without minting a
    // capability grant — this function does not branch on it, so a confined run
    // records `deny_all` too.
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
    // `decision_axes` stays `{}`: no policy and no capability station ran, so
    // there are no inputs a verdict turned on to record.
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
}
