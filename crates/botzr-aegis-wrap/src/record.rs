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
/// regime, version 0" — AILAB-626 replaces it with the hash of an actual set.
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
    /// Nothing to track. Not JSON, not a `tools/call`, a notification, or a
    /// malformed `tools/call` that has *already* been recorded as a completed
    /// deny here.
    Ignored,
    /// A well-formed `tools/call`: recorded as intent, keyed by the id its
    /// response will carry.
    ///
    /// Boxed because a `CallSession` is ~680 bytes and the other two variants
    /// are empty, so an unboxed enum would make every relayed frame — most of
    /// them not `tools/call` at all — pay for the one that is
    /// (`clippy::large_enum_variant`). The allocation happens once per recorded
    /// call, against two fsyncs.
    Pending(String, Box<PendingCall<'a>>),
    /// A JSON-RPC **batch array**. Relayed like everything else and recorded by
    /// nothing — see [`observe_client_line`].
    Batch,
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

/// Inspect one client frame and, when it is a well-formed `tools/call`, open a
/// session for it.
///
/// In every case the caller still relays the frame verbatim. Wrap does not
/// block; a child that dislikes the request answers with its own `-32602`.
///
/// # The batch gap
///
/// A JSON-RPC **batch** — a top-level array — is relayed and **not recorded**,
/// including any `tools/call` inside it. Recording one would mean opening a
/// session per element, matching an array response element by element, and
/// digesting a "request" that never existed as its own frame; none of that is
/// built (AILAB-625 is pass-through + recording only). Reporting it is the
/// honest alternative to hiding it, so this returns [`Observed::Batch`] and the
/// relay names the bypass on the child-stderr sink.
pub(crate) fn observe_client_line<'a>(
    writer: &'a AuditWriter,
    frame: &[u8],
) -> Result<Observed<'a>, AuditError> {
    let Ok(message) = serde_json::from_slice::<Value>(frame) else {
        return Ok(Observed::Ignored);
    };
    if message.is_array() {
        return Ok(Observed::Batch);
    }
    if message.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Ok(Observed::Ignored);
    }
    // A notification has no id, so no response can ever be matched to it and no
    // outcome could ever be written. Recording an intent that is structurally
    // unanswerable would manufacture a permanent in-flight call.
    let Some(id_key) = id_key(&message) else {
        return Ok(Observed::Ignored);
    };

    // VERBATIM: the digest covers the frame bytes as they arrived — a trailing
    // `\r` included, the `\n` delimiter excluded — never a re-encoding of the
    // parsed value (`digest.rs` verbatim rule).
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
        return Ok(Observed::Ignored);
    };

    let session = CallSession::begin(writer, tool_id.clone(), request_digest, policy_set_hash)?;
    Ok(Observed::Pending(
        id_key,
        Box::new(PendingCall {
            session,
            tool_id,
            started: Instant::now(),
        }),
    ))
}

/// Close a call the child answered.
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
    // so it must not record fs or net authority it never minted. AILAB-626/628
    // replace this with a resolved grant once wrap can actually confine.
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
        // nothing". Metering lands with confinement (AILAB-628).
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

/// The pending-map key for a child **response** frame, or `None` when the frame
/// is not a response — which includes the child making a request of its own.
pub(crate) fn response_id_key(frame: &[u8]) -> Option<String> {
    let message = serde_json::from_slice::<Value>(frame).ok()?;
    if !is_response_shaped(&message) {
        return None;
    }
    id_key(&message)
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
        let number = response_id_key(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#).unwrap();
        let string = response_id_key(br#"{"jsonrpc":"2.0","id":"1","result":{}}"#).unwrap();
        assert_ne!(number, string);
    }

    #[test]
    fn a_null_or_absent_id_is_a_notification() {
        assert_eq!(response_id_key(br#"{"jsonrpc":"2.0","method":"x"}"#), None);
        assert_eq!(
            response_id_key(br#"{"jsonrpc":"2.0","id":null,"result":{}}"#),
            None
        );
        assert_eq!(response_id_key(b"not json"), None);
    }

    /// The bidirectional-MCP guard, at the unit level: a server→client
    /// *request* must never key a completion, however familiar its id looks.
    #[test]
    fn a_server_initiated_request_is_not_a_response() {
        assert_eq!(
            response_id_key(
                br#"{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{}}"#
            ),
            None
        );
        assert_eq!(
            response_id_key(br#"{"jsonrpc":"2.0","id":1,"method":"roots/list"}"#),
            None
        );
        // A response shape the same id *does* complete.
        assert!(response_id_key(br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#).is_some());
        assert!(response_id_key(br#"{"jsonrpc":"2.0","id":1,"error":{"code":-1}}"#).is_some());
        // A `null` result is still a result: `get` sees the key, not the value.
        assert!(response_id_key(br#"{"jsonrpc":"2.0","id":1,"result":null}"#).is_some());
    }

    /// A batch response is not matched either — the batch gap is symmetric.
    #[test]
    fn an_array_frame_is_never_a_response() {
        assert_eq!(
            response_id_key(br#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#),
            None
        );
    }

    /// Invalid UTF-8 is a frame that is not a response, not an error and never
    /// an end-of-stream.
    #[test]
    fn invalid_utf8_is_merely_unmatched() {
        assert_eq!(response_id_key(&[0xff, 0xfe, b'{']), None);
    }
}
