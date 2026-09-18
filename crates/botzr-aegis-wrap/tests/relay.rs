//! Integration: drive `run_wrap_with_streams` against a **real** child process.
//!
//! Every case runs the relay on a worker thread behind a `recv_timeout` guard.
//! The property under test is as much "wrap terminates" as "wrap relays": a
//! deadlock in the pump would otherwise stall CI instead of failing a test, and
//! the child-death case exists precisely to catch a hang.
//!
//! Two cases here are deliberately slow (~8 s each). They are the only way to
//! observe wrap's 5 s post-EOF shutdown grace from the outside: one proves the
//! grace is **extended** by a child that is still working, the other proves it
//! **expires** on a child that has gone silent — and that the two are recorded
//! as different facts.

use std::io::{self, Cursor, Read, Write};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use botzr_aegis_audit::{verify_chain_file, Verdict};
use botzr_aegis_core::{PolicyAction, PolicySetHash, RequestDigest, ResponseDigest, ToolId};
use botzr_aegis_wrap::{
    run_wrap_with_streams, CallGate, GateVerdict, WrapConfig, WrapError, WrapMode, WrapStreams,
    WRAP_PASSTHROUGH_POLICY_SET_ID,
};
use serde_json::Value;
use tempfile::TempDir;

/// A relay that has not returned by now is a hang, and a hang is a failure.
///
/// Generous because two cases legitimately run for ~8 s (wrap's own shutdown
/// grace is 5 s, and its reap adds up to 5 s more). The guard is a deadlock
/// detector, not a latency budget.
const HANG_GUARD: Duration = Duration::from_secs(40);

/// An in-memory `Write` sink the test can read back after the relay returns.
///
/// Cloneable so one handle can go into `WrapStreams` (which takes ownership)
/// while the test keeps another. Bytes, not text: the stderr tee is byte-exact
/// and one case feeds it invalid UTF-8 on purpose.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Sink {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes()).into_owned()
    }

    fn lines(&self) -> Vec<String> {
        self.text()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .collect()
    }
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A client stream that plays its script and then **stays open**, the way a
/// live client sitting at a prompt does.
///
/// A `Cursor` client reports EOF the instant its script runs out, so `client_open`
/// is already false by the time anything can happen to the child. This reader
/// blocks instead, which is the only way to reach the "child quit under a live
/// client" branch. It unblocks when the test drops its sender.
struct HeldOpen {
    script: Cursor<Vec<u8>>,
    release: mpsc::Receiver<()>,
    released: bool,
}

impl Read for HeldOpen {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.script.read(buf)?;
        if read > 0 {
            return Ok(read);
        }
        if !self.released {
            self.released = true;
            let _ = self.release.recv_timeout(HANG_GUARD);
        }
        Ok(0)
    }
}

/// Everything one scripted wrap session produced.
struct Driven {
    result: Result<u8, WrapError>,
    client_out: Sink,
    child_err: Sink,
    audit: String,
    audit_path: PathBuf,
    /// Removes the audit file and the signing key on drop.
    _dir: TempDir,
}

impl Driven {
    /// Every `outcome` line, parsed. Rows on disk are canonical (key-sorted), so
    /// they are read as JSON rather than substring-matched.
    fn outcomes(&self) -> Vec<Value> {
        self.audit
            .lines()
            .filter(|line| line.contains("\"line_type\":\"outcome\""))
            .map(|line| serde_json::from_str(line).expect("every audit row is JSON"))
            .collect()
    }

    fn line_types(&self) -> Vec<String> {
        self.audit
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let row: Value = serde_json::from_str(line).expect("every audit row is JSON");
                row["line_type"].as_str().expect("line_type").to_owned()
            })
            .collect()
    }

    /// One relayed response, parsed.
    fn response(&self, index: usize) -> Value {
        let out = self.client_out.lines();
        serde_json::from_str(&out[index])
            .unwrap_or_else(|e| panic!("response {index}: {e}: {out:?}"))
    }
}

/// Run one wrap session: the mirror child, a scripted client, and a fresh
/// signed audit sink.
///
/// Default mode — [`WrapMode::Record`] — so every case written before
/// AILAB-793 drives the pass-through relay it was written against, unchanged.
fn drive(script: &[&str]) -> Driven {
    drive_bytes(framed(script))
}

/// The client's bytes for a scripted session: one frame per line.
fn framed(script: &[&str]) -> Vec<u8> {
    let mut input = Vec::new();
    for line in script {
        input.extend_from_slice(line.as_bytes());
        input.push(b'\n');
    }
    input
}

/// [`drive`], with the client's bytes supplied exactly — including framing.
fn drive_bytes(input: Vec<u8>) -> Driven {
    drive_client(Box::new(Cursor::new(input)))
}

/// [`drive`], with the client stream supplied whole.
fn drive_client(client_in: Box<dyn Read + Send>) -> Driven {
    drive_mode(WrapMode::Record, client_in)
}

/// [`drive`], under an opted-in enforcement gate.
///
/// The extension rather than a second copy of the fifty lines below: the point
/// of these cases is that enforcement runs through the *same* relay, against
/// the same real child process, so a divergence would be a divergence in the
/// product and not in two test harnesses.
fn drive_enforced(gate: Arc<dyn CallGate + Send + Sync>, script: &[&str]) -> Driven {
    drive_mode(
        WrapMode::Enforce {
            gate,
            confinement: None,
        },
        Box::new(Cursor::new(framed(script))),
    )
}

/// [`drive`], with both the mode and the client stream supplied.
fn drive_mode(mode: WrapMode, client_in: Box<dyn Read + Send>) -> Driven {
    let dir = tempfile::tempdir().expect("temp dir");
    let audit_path = dir.path().join("audit.jsonl");
    let key_path = dir.path().join("signing.key");
    // A persistent sink has no dev-key fallback (AILAB-620): mint a real one.
    botzr_aegis_audit::generate_signing_key(&key_path, false).expect("signing key");

    let config = WrapConfig {
        child_argv: vec![env!("CARGO_BIN_EXE_aegis-wrap-mirror-child").to_owned()],
        audit_path: audit_path.clone(),
        signing_key_path: key_path,
        mode,
    };

    let client_out = Sink::default();
    let child_err = Sink::default();
    let streams = WrapStreams {
        client_in,
        client_out: Box::new(client_out.clone()),
        child_err: Box::new(child_err.clone()),
    };

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(run_wrap_with_streams(&config, streams));
    });
    let result = rx
        .recv_timeout(HANG_GUARD)
        .expect("run_wrap_with_streams must return; a hang is the failure this guard catches");

    // Read after the relay returned: the `AuditWriter` drops on the way out, and
    // its `Drop` is what writes the signed `close` line.
    let audit = std::fs::read_to_string(&audit_path).unwrap_or_default();

    Driven {
        result,
        client_out,
        child_err,
        audit,
        audit_path,
        _dir: dir,
    }
}

/// 1. Pass-through happy path: three methods in, three responses out, one
///    recorded call.
#[test]
fn relays_a_whole_session_and_records_only_the_tools_call() {
    let driven = drive(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}"#,
    ]);

    assert_eq!(driven.result.as_ref().ok(), Some(&0), "{:?}", driven.result);

    let out = driven.client_out.lines();
    assert_eq!(out.len(), 3, "one response per request: {out:?}");
    assert!(out[0].contains(r#""mirrored":"initialize""#), "{out:?}");
    assert!(out[1].contains(r#""mirrored":"tools/list""#), "{out:?}");
    assert!(out[2].contains(r#""text":"echo""#), "{out:?}");

    // `initialize` and `tools/list` are relayed with zero interception, so the
    // whole file is open + one intent + one outcome + close.
    assert_eq!(
        driven.line_types(),
        vec!["open", "intent", "outcome", "close"],
        "{}",
        driven.audit
    );
    let outcome = &driven.outcomes()[0];
    assert_eq!(outcome["schema_version"], 2, "{outcome}");
    assert_eq!(outcome["tool_id"], "echo", "{outcome}");
    assert_eq!(outcome["execution"]["status"], "success", "{outcome}");
    assert_eq!(outcome["policy"]["status"], "allowed", "{outcome}");
    assert_eq!(outcome["capability"]["status"], "granted", "{outcome}");
    // The pass-through grant confines nothing and must not claim otherwise.
    let grant = &outcome["capability"]["grant"];
    assert!(grant.get("fs").is_none(), "{outcome}");
    assert!(grant.get("net").is_none(), "{outcome}");
}

/// 2. An unknown method reaches the child. `mirrored` is unforgeable by a local
///    short-circuit, which is the whole point of the fixture.
#[test]
fn an_unknown_method_is_relayed_and_never_locally_refused() {
    let driven = drive(&[r#"{"jsonrpc":"2.0","id":1,"method":"aegis/definitely-not-a-method"}"#]);

    let out = driven.client_out.text();
    assert!(
        out.contains(r#""mirrored":"aegis/definitely-not-a-method""#),
        "the child, not wrap, must have answered: {out}"
    );
    assert!(
        !out.contains("-32601"),
        "wrap must never synthesize method-not-found: {out}"
    );
    // Not a `tools/call`, so nothing was recorded.
    assert_eq!(
        driven.line_types(),
        vec!["open", "close"],
        "{}",
        driven.audit
    );
}

/// 3. The child dies mid-call. Wrap must not hang, must exit non-zero, and must
///    close the in-flight call fail-closed.
#[test]
fn a_child_that_dies_mid_call_exits_non_zero_and_records_host_denied() {
    let driven =
        drive(&[r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test/exit"}}"#]);

    let code = *driven.result.as_ref().expect("relay returned");
    assert_ne!(code, 0, "a child that exits 3 must not report success");
    assert_eq!(code, 3, "the child's own exit code is what wrap reports");

    let outcomes = driven.outcomes();
    assert_eq!(outcomes.len(), 1, "{}", driven.audit);
    assert_eq!(outcomes[0]["execution"]["status"], "host_denied");
    assert_eq!(
        outcomes[0]["execution"]["reason"], "child exited before responding",
        "the child really did exit, so this is the true reason"
    );
    // Nothing about this call was ever allowed: the default-deny seeds stand.
    assert_eq!(outcomes[0]["policy"]["status"], "denied");
    assert_eq!(outcomes[0]["capability"]["status"], "denied");
}

/// 4. The child's stderr is teed, not swallowed — and never merged into the
///    JSON-RPC stream.
#[test]
fn child_stderr_is_teed_and_kept_off_the_json_rpc_stream() {
    let driven = drive(&[r#"{"jsonrpc":"2.0","id":1,"method":"test/stderr"}"#]);

    assert!(
        driven.child_err.text().contains("distinctive stderr line"),
        "child stderr: {:?}",
        driven.child_err.text()
    );
    let out = driven.client_out.text();
    assert!(
        out.contains(r#""mirrored":"test/stderr""#),
        "the request must still be answered: {out}"
    );
    assert!(
        !out.contains("distinctive stderr line"),
        "stdout carries JSON-RPC only: {out}"
    );
}

/// 5. Two calls, one Session, one unbroken chain.
#[test]
fn two_calls_share_one_verified_chain() {
    let driven = drive(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"first"}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"second"}}"#,
    ]);

    let outcomes = driven.outcomes();
    assert_eq!(outcomes.len(), 2, "{}", driven.audit);
    assert_eq!(outcomes[0]["tool_id"], "first");
    assert_eq!(outcomes[1]["tool_id"], "second");
    assert!(
        outcomes[0]["seq"].as_u64() < outcomes[1]["seq"].as_u64(),
        "seq must advance: {outcomes:?}"
    );
    // Distinct calls, distinct grants — no id reuse across the Session.
    assert_ne!(outcomes[0]["call_id"], outcomes[1]["call_id"]);
    assert_ne!(outcomes[0]["grant_id"], outcomes[1]["grant_id"]);
    // Distinctness alone would hold for any two ids. Pin the spelling: a
    // pass-through grant id is the literal prefix plus that call's own id, so
    // a reader can tell a wrap pass-through from a minted grant by eye.
    for outcome in &outcomes {
        assert_eq!(
            outcome["grant_id"].as_str().expect("a grant id"),
            format!(
                "wrap-passthrough-{}",
                outcome["call_id"].as_str().expect("a call id")
            ),
            "{}",
            driven.audit
        );
    }

    // `Verified` requires a signed `close` as the last line, which only lands
    // when the `AuditWriter` drops — so this also asserts wrap shut down
    // cleanly rather than merely stopping.
    let verification = verify_chain_file(&driven.audit_path).expect("audit readable");
    assert_eq!(
        verification.verdict,
        Verdict::Verified,
        "{:?}",
        verification.verdict
    );
}

/// 6. A notification produces no response and no record, and does not disturb
///    the call that follows it.
#[test]
fn a_notification_is_relayed_without_a_response_or_a_record() {
    let driven = drive(&[
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"after"}}"#,
    ]);

    let out = driven.client_out.lines();
    assert_eq!(out.len(), 1, "only the tools/call is answered: {out:?}");
    assert!(out[0].contains(r#""text":"after""#), "{out:?}");
    assert_eq!(
        driven.line_types(),
        vec!["open", "intent", "outcome", "close"],
        "the notification must add no rows: {}",
        driven.audit
    );
}

/// 7. A JSON-RPC `error` from the child is the **tool** erring, not the host
///    denying — the call ran, so execution is `success`.
#[test]
fn a_child_json_rpc_error_is_recorded_as_a_successful_execution() {
    let driven = drive(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test/error"}}"#,
    ]);

    let out = driven.client_out.text();
    assert!(out.contains("mirror child tool error"), "{out}");

    let outcomes = driven.outcomes();
    assert_eq!(outcomes.len(), 1, "{}", driven.audit);
    assert_eq!(
        outcomes[0]["execution"]["status"], "success",
        "documented mapping: the tool erred, the host did not deny: {}",
        outcomes[0]
    );
    assert!(
        outcomes[0]["response_digest"].is_string(),
        "the error response is still digested: {}",
        outcomes[0]
    );
}

/// 8. A `tools/call` with no `params.name` is recorded as a deny — and is still
///    relayed, so the child gets to answer with its own `-32602`.
#[test]
fn a_malformed_tools_call_is_recorded_denied_and_still_reaches_the_child() {
    let driven = drive(&[r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#]);

    let out = driven.client_out.lines();
    assert_eq!(out.len(), 1, "wrap must not answer for the child: {out:?}");
    let response: Value = serde_json::from_str(&out[0]).expect("response JSON");
    assert_eq!(response["id"], 1, "the child answered: {out:?}");

    let outcomes = driven.outcomes();
    assert_eq!(outcomes.len(), 1, "exactly one outcome: {}", driven.audit);
    assert_eq!(outcomes[0]["tool_id"], "<unknown>");
    assert_eq!(outcomes[0]["policy"]["status"], "denied");
    assert_eq!(
        outcomes[0]["policy"]["reason"],
        "tools/call without a string params.name"
    );
    assert_eq!(outcomes[0]["capability"]["status"], "denied");
    assert_eq!(outcomes[0]["execution"]["status"], "host_denied");
    assert_eq!(outcomes[0]["execution"]["reason"], "not executed");
}

/// 9. **MCP is bidirectional.** A server→client *request* that happens to carry
///    the client's id must not be mistaken for the client's response.
///
/// The mirror child answers `test/server-request` with two frames: first a
/// `sampling/createMessage` **request** reusing id 1, then the real result. An
/// interposer that keys completion on `id` alone closes the call on the first
/// frame — signing `Allowed`/`Success` over bytes the tool never answered with,
/// and leaving the real response matching nothing.
#[test]
fn a_server_initiated_request_never_completes_a_pending_call() {
    let driven = drive(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test/server-request"}}"#,
    ]);

    // Both frames reached the client: the server's request is relayed like
    // anything else, because wrap answers for nobody.
    let out = driven.client_out.lines();
    assert_eq!(out.len(), 2, "both child frames must be relayed: {out:?}");
    assert_eq!(
        driven.response(0)["method"],
        "sampling/createMessage",
        "the server's own request, relayed verbatim: {out:?}"
    );
    assert!(
        driven.response(1)["result"].is_object(),
        "the real response: {out:?}"
    );

    let outcomes = driven.outcomes();
    assert_eq!(outcomes.len(), 1, "exactly one outcome: {}", driven.audit);
    assert_eq!(outcomes[0]["execution"]["status"], "success");

    // Which bytes the record committed to is the whole question. Recomputed
    // here rather than eyeballed: a hex string cannot be argued with.
    let recorded = outcomes[0]["response_digest"]
        .as_str()
        .expect("a response digest");
    assert_eq!(
        recorded,
        ResponseDigest::of_response_bytes(out[1].as_bytes()).to_hex(),
        "the digest must cover the child's real response"
    );
    assert_ne!(
        recorded,
        ResponseDigest::of_response_bytes(out[0].as_bytes()).to_hex(),
        "the digest must NOT cover the server's own request"
    );
}

/// 10. Blocker: the post-EOF grace bounds **silence**, not work.
///
/// Forty `test/slow` calls take ~8 s of child time, and the client's `Cursor`
/// reaches EOF in the first few hundred milliseconds — so almost all of that
/// work happens after the 5 s shutdown grace is armed. A grace that is never
/// re-armed truncates the session at 5 s and signs "child exited before
/// responding" about a process that is alive and answering.
#[test]
fn a_child_still_working_after_client_eof_is_not_cut_off() {
    const CALLS: usize = 40;

    let script: Vec<String> = (1..=CALLS)
        .map(|id| {
            format!(
                r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"test/slow"}}}}"#
            )
        })
        .collect();
    let refs: Vec<&str> = script.iter().map(String::as_str).collect();
    let driven = drive(&refs);

    assert_eq!(driven.result.as_ref().ok(), Some(&0), "{:?}", driven.result);
    assert_eq!(
        driven.client_out.lines().len(),
        CALLS,
        "every call must still be answered"
    );

    let outcomes = driven.outcomes();
    assert_eq!(
        outcomes.len(),
        CALLS,
        "every call must still be recorded: {}",
        driven.audit
    );
    for outcome in &outcomes {
        assert_eq!(
            outcome["execution"]["status"], "success",
            "no call may be truncated by the shutdown grace: {outcome}"
        );
    }
}

/// 11. …and when the grace really does expire, the reason says so. A child that
///     is alive but silent is **never** recorded as having exited.
#[test]
fn a_silent_child_expires_the_grace_without_being_called_dead() {
    let driven =
        drive(&[r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test/hang"}}"#]);

    let outcomes = driven.outcomes();
    assert_eq!(outcomes.len(), 1, "{}", driven.audit);
    assert_eq!(outcomes[0]["execution"]["status"], "host_denied");
    assert_eq!(
        outcomes[0]["execution"]["reason"],
        "client closed stdin; child did not answer within the shutdown grace",
        "the child had not exited, and the record must not say it had: {}",
        outcomes[0]
    );
    assert_ne!(
        outcomes[0]["execution"]["reason"], "child exited before responding",
        "attributing an exit to a live process is a false signed statement"
    );
}

/// 12. A non-UTF-8 frame is a frame, not an end-of-stream.
///
/// `BufRead::lines()` yields `Err(InvalidData)` here, and a reader that reports
/// a read error as EOF would end the session on the junk frame — so the
/// `tools/call` that follows it is the observable.
#[test]
fn an_invalid_utf8_frame_does_not_end_the_client_stream() {
    let mut input = Vec::new();
    input.extend_from_slice(&[0xff, 0xfe, 0x00, b'{', 0x80]);
    input.push(b'\n');
    input.extend_from_slice(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"after-junk"}}"#,
    );
    input.push(b'\n');

    let driven = drive_bytes(input);

    let out = driven.client_out.lines();
    assert_eq!(
        out.len(),
        1,
        "the junk frame is unanswerable, the call after it is not: {out:?}"
    );
    assert!(out[0].contains(r#""text":"after-junk""#), "{out:?}");
    assert_eq!(
        driven.line_types(),
        vec!["open", "intent", "outcome", "close"],
        "the call after the junk frame must still be recorded: {}",
        driven.audit
    );
}

/// 13. CRLF framing survives: the `\r` is content, only the `\n` is framing.
///
/// Two observables, one on each side of the relay. The child reports the byte
/// length of the frame it received, so a stripped `\r` shows up as a shorter
/// frame; and the recorded `request_digest` is recomputed here over the exact
/// bytes the client wrote, delimiter excluded.
#[test]
fn a_crlf_frame_keeps_its_carriage_return_end_to_end() {
    const CRLF_FRAME: &str = r#"{"jsonrpc":"2.0","id":1,"method":"test/frame"}"#;
    const LF_FRAME: &str = r#"{"jsonrpc":"2.0","id":2,"method":"test/frame"}"#;
    const CALL_FRAME: &str =
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"crlf"}}"#;

    let mut input = Vec::new();
    input.extend_from_slice(format!("{CRLF_FRAME}\r\n").as_bytes());
    input.extend_from_slice(format!("{LF_FRAME}\n").as_bytes());
    input.extend_from_slice(format!("{CALL_FRAME}\r\n").as_bytes());

    let driven = drive_bytes(input);

    // The two mirrored frames differ by exactly the carriage return.
    let with_cr = driven.response(0)["result"]["frame_len"]
        .as_u64()
        .expect("frame_len");
    let without_cr = driven.response(1)["result"]["frame_len"]
        .as_u64()
        .expect("frame_len");
    assert_eq!(
        (with_cr, without_cr),
        ((CRLF_FRAME.len() + 1) as u64, LF_FRAME.len() as u64),
        "the child must receive the `\\r` and not the `\\n`: {:?}",
        driven.client_out.lines()
    );

    // And the digest commits to exactly those bytes: `\r` in, `\n` out.
    let outcomes = driven.outcomes();
    assert_eq!(outcomes.len(), 1, "{}", driven.audit);
    let recorded = outcomes[0]["request_digest"]
        .as_str()
        .expect("a request digest");
    assert_eq!(
        recorded,
        RequestDigest::of_request_bytes(format!("{CALL_FRAME}\r").as_bytes()).to_hex(),
        "the digest covers the frame including its carriage return"
    );
    assert_ne!(
        recorded,
        RequestDigest::of_request_bytes(CALL_FRAME.as_bytes()).to_hex(),
        "a stripped `\\r` would be a different, quieter bug"
    );
    assert_ne!(
        recorded,
        RequestDigest::of_request_bytes(format!("{CALL_FRAME}\r\n").as_bytes()).to_hex(),
        "the `\\n` delimiter is framing and is not digested"
    );
}

/// 14. The stderr tee is byte-oriented: one invalid byte must not swallow
///     everything after it.
///
/// This is the crate's one unconditional promise about stderr, and a `lines()`
/// tee breaks it for any server that ever emits a progress bar or a stray
/// binary byte.
#[test]
fn child_stderr_survives_a_non_utf8_byte() {
    let driven = drive(&[r#"{"jsonrpc":"2.0","id":1,"method":"test/stderr-binary"}"#]);

    let err = driven.child_err.bytes();
    assert!(
        err.windows(2).any(|pair| pair == [0xff, 0xfe]),
        "the raw bytes must pass through: {err:?}"
    );
    assert!(
        String::from_utf8_lossy(&err).contains("stderr survived the invalid byte"),
        "everything after the invalid byte must still arrive: {}",
        String::from_utf8_lossy(&err)
    );
    assert!(
        driven
            .client_out
            .text()
            .contains(r#""mirrored":"test/stderr-binary""#),
        "and the session carries on: {}",
        driven.client_out.text()
    );
}

/// 15. A `tools/call` inside a JSON-RPC batch array is recorded exactly like
///     one sent in a frame of its own — and the frame still reaches the child
///     whole (AILAB-788).
#[test]
fn a_batched_tools_call_is_recorded_like_a_single_and_still_relayed() {
    const BATCH_FRAME: &str =
        r#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"batched"}}]"#;

    let driven = drive(&[BATCH_FRAME]);

    // Relayed, unsplit: the child answered with a batch of its own, which it
    // could only do if it received the array rather than N object frames.
    let out = driven.client_out.lines();
    assert_eq!(out.len(), 1, "one batch response frame: {out:?}");
    assert!(
        driven.response(0).is_array(),
        "a batch answers as an array: {out:?}"
    );
    assert!(out[0].contains("batched"), "{out:?}");

    // Recorded: the same four lines a single-frame call produces.
    assert_eq!(
        driven.line_types(),
        vec!["open", "intent", "outcome", "close"],
        "a batched call is recorded like a single: {}",
        driven.audit
    );
    let outcome = &driven.outcomes()[0];
    assert_eq!(outcome["tool_id"], "batched", "{outcome}");
    assert_eq!(outcome["policy"]["status"], "allowed", "{outcome}");
    assert_eq!(outcome["capability"]["status"], "granted", "{outcome}");
    assert_eq!(outcome["execution"]["status"], "success", "{outcome}");

    // The digest commits to the array the client actually wrote. A batched
    // element never was a frame, so re-serializing it to give it a digest of
    // its own would commit the record to bytes that crossed no wire.
    assert_eq!(
        outcome["request_digest"]
            .as_str()
            .expect("a request digest"),
        RequestDigest::of_request_bytes(BATCH_FRAME.as_bytes()).to_hex(),
        "the digest covers the batch frame verbatim"
    );

    // The old bypass diagnostic is gone, not merely quieter: the record file is
    // the evidence now, so there is nothing left for wrap to confess.
    let err = driven.child_err.text();
    assert!(
        !err.contains("aegis wrap: relayed a JSON-RPC batch array"),
        "the superseded diagnostic must not survive: {err:?}"
    );
    assert!(!err.contains("known gap"), "{err:?}");
}

/// 15b. Two `tools/call`s in **one** batch array: two records, one frame.
///
/// The AC Linear named separately from the single-call case. N intents share
/// one `request_digest` and N outcomes share one `response_digest`, because on
/// each wire there was exactly one frame — that shared-digest fact is the whole
/// difference between a batched call and a single one, so it is asserted rather
/// than described.
#[test]
fn a_batch_of_two_calls_produces_two_records_over_one_frame() {
    const BATCH_FRAME: &str = r#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"first"}},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"second"}}]"#;

    let driven = drive(&[BATCH_FRAME]);

    let out = driven.client_out.lines();
    assert_eq!(out.len(), 1, "one batch response frame: {out:?}");
    assert_eq!(
        driven.response(0).as_array().map(Vec::len),
        Some(2),
        "the child answered both elements: {out:?}"
    );

    assert_eq!(
        driven.line_types(),
        vec!["open", "intent", "intent", "outcome", "outcome", "close"],
        "every call in the batch is accounted for: {}",
        driven.audit
    );

    let outcomes = driven.outcomes();
    assert_eq!(outcomes[0]["tool_id"], "first", "{}", driven.audit);
    assert_eq!(outcomes[1]["tool_id"], "second", "{}", driven.audit);
    assert_eq!(outcomes[0]["execution"]["status"], "success");
    assert_eq!(outcomes[1]["execution"]["status"], "success");
    assert!(
        outcomes[0]["seq"].as_u64() < outcomes[1]["seq"].as_u64(),
        "seq must advance across a batch as it does across frames: {outcomes:?}"
    );
    // Distinct calls, distinct grants — sharing a frame is not sharing an
    // identity.
    assert_ne!(outcomes[0]["call_id"], outcomes[1]["call_id"]);
    assert_ne!(outcomes[0]["grant_id"], outcomes[1]["grant_id"]);

    // One frame in, one frame out — so one request digest and one response
    // digest, each shared by both calls.
    assert_eq!(
        outcomes[0]["request_digest"], outcomes[1]["request_digest"],
        "both calls arrived in the same frame"
    );
    assert_eq!(
        outcomes[0]["request_digest"]
            .as_str()
            .expect("a request digest"),
        RequestDigest::of_request_bytes(BATCH_FRAME.as_bytes()).to_hex(),
    );
    assert_eq!(
        outcomes[0]["response_digest"], outcomes[1]["response_digest"],
        "both calls were answered by the same frame"
    );
    assert_eq!(
        outcomes[0]["response_digest"]
            .as_str()
            .expect("a response digest"),
        ResponseDigest::of_response_bytes(out[0].as_bytes()).to_hex(),
        "the digest covers the child's array frame as it was relayed"
    );

    let verification = verify_chain_file(&driven.audit_path).expect("audit readable");
    assert_eq!(
        verification.verdict,
        Verdict::Verified,
        "{:?}",
        verification.verdict
    );
}

/// 16. The child quits while the client is **still open** — the branch a
///     `Cursor` client can never reach, because it reports EOF first.
///
/// Spec §3.1: a clear error on wrap's stderr and a non-zero exit.
#[test]
fn a_child_that_dies_under_a_live_client_says_so_and_exits_non_zero() {
    let (release_tx, release) = mpsc::channel();
    let client = HeldOpen {
        script: Cursor::new(
            format!(
                "{}\n",
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test/exit"}}"#
            )
            .into_bytes(),
        ),
        release,
        released: false,
    };

    let driven = drive_client(Box::new(client));

    let code = *driven.result.as_ref().expect("relay returned");
    assert_ne!(code, 0, "a session whose child quit is not a success");

    assert!(
        driven
            .child_err
            .text()
            .contains("child process exited before the client closed stdin"),
        "the operator must be told why the session ended: {:?}",
        driven.child_err.text()
    );

    let outcomes = driven.outcomes();
    assert_eq!(outcomes.len(), 1, "{}", driven.audit);
    assert_eq!(outcomes[0]["execution"]["status"], "host_denied");
    assert_eq!(
        outcomes[0]["execution"]["reason"],
        "child exited before responding"
    );

    // Held open until here on purpose: dropping the sender earlier would let the
    // client stream report EOF and the branch under test would not be reached.
    drop(release_tx);
}

// ---------------------------------------------------------------------------
// AILAB-793 — opt-in enforcement. Everything above this line drives
// `WrapMode::Record` and is unchanged by it.
// ---------------------------------------------------------------------------

/// The Policy Set a stub gate names, and the whole of the hash assertion.
///
/// Deliberately **not** `WRAP_PASSTHROUGH_POLICY_SET_ID`: telling those two
/// hexes apart in a record is how a reader knows whether a real engine governed
/// the call, and it is the acceptance criterion ADR-0015 left to this ticket.
const TEST_POLICY_SET_ID: &[u8] = b"wrap-test-policy-v0";

fn fixture_hash() -> String {
    PolicySetHash::of_canonical_bytes(TEST_POLICY_SET_ID).to_hex()
}

fn passthrough_hash() -> String {
    PolicySetHash::of_canonical_bytes(WRAP_PASSTHROUGH_POLICY_SET_ID).to_hex()
}

/// A [`CallGate`] over a fixed table.
///
/// **Not a `PolicyEngine`.** `botzr-aegis-wrap` does not depend on
/// `botzr-aegis-policy`, and a test that reached for one would be testing the
/// engine rather than the seam — and would quietly make the dependency this
/// ticket exists to avoid look necessary. What wrap owes the record is the
/// hash, the action and the rule id a gate hands it; a table supplies all
/// three.
struct StubGate {
    /// Tool ids this gate allows. Everything else gets `otherwise`.
    allowed: &'static [&'static str],
    /// The verdict every other tool gets.
    otherwise: PolicyAction,
}

impl StubGate {
    /// Allow these tools, deny the rest.
    fn allowing(allowed: &'static [&'static str]) -> Arc<dyn CallGate + Send + Sync> {
        Arc::new(Self {
            allowed,
            otherwise: PolicyAction::Deny {
                reason: "stub gate denies this tool".to_owned(),
            },
        })
    }

    /// Allow nothing, and refuse with this action — for the verdicts that are
    /// refusals without being denials.
    fn refusing_with(otherwise: PolicyAction) -> Arc<dyn CallGate + Send + Sync> {
        Arc::new(Self {
            allowed: &[],
            otherwise,
        })
    }
}

impl CallGate for StubGate {
    fn decide(&self, tool_id: &ToolId) -> GateVerdict {
        let allowed = self.allowed.contains(&tool_id.as_str());
        GateVerdict {
            policy_set_hash: PolicySetHash::of_canonical_bytes(TEST_POLICY_SET_ID),
            action: if allowed {
                PolicyAction::Allow
            } else {
                self.otherwise.clone()
            },
            matched_rule: Some(if allowed { "stub-allow" } else { "stub-refuse" }.to_owned()),
        }
    }
}

/// 18. A denied `tools/call` never reaches the child, and the client is told so
///     rather than left blocked on an id (ADR-0015).
#[test]
fn a_denied_tools_call_is_refused_and_never_reaches_the_child() {
    let driven = drive_enforced(
        StubGate::allowing(&[]),
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}"#,
        ],
    );

    assert_eq!(driven.result.as_ref().ok(), Some(&0), "{:?}", driven.result);

    // The child never saw it. Both markers are unforgeable by wrap: `mirrored`
    // is the fixture's unknown-method answer, and the echo body is what a
    // relayed `tools/call` comes back as.
    let out = driven.client_out.text();
    assert!(!out.contains("mirrored"), "{out}");
    assert!(
        !out.contains(r#""text":"echo""#),
        "a refused call must not have been answered by the child: {out}"
    );

    // ADR-0015's frame, and only it.
    let lines = driven.client_out.lines();
    assert_eq!(lines.len(), 1, "one refusal, one frame: {lines:?}");
    let refusal = driven.response(0);
    assert_eq!(refusal["error"]["code"], -32042, "{refusal}");
    assert!(
        out.contains(r#""layer":"wrap""#),
        "the frame names the layer that authored it: {out}"
    );
    assert_eq!(
        refusal["error"]["data"]["aegis"]["code"], "POLICY_DENIED",
        "{refusal}"
    );
    // The id is echoed as JSON: the client sent the number 1, not the string.
    assert_eq!(refusal["id"], 1, "{refusal}");
    assert!(
        refusal["id"].is_number(),
        "echoing the pending-map key would answer with \"1\": {refusal}"
    );
    // Wrap speaks as the interposer, never as the child.
    assert!(refusal.get("result").is_none(), "{refusal}");

    // Recorded as a deny on every axis below policy — the wording the runtime
    // pipeline uses for the same refusal.
    assert_eq!(
        driven.line_types(),
        vec!["open", "intent", "outcome", "close"],
        "{}",
        driven.audit
    );
    let outcome = &driven.outcomes()[0];
    assert_eq!(outcome["tool_id"], "echo", "{outcome}");
    assert_eq!(outcome["policy"]["status"], "denied", "{outcome}");
    assert_eq!(outcome["capability"]["status"], "denied", "{outcome}");
    assert_eq!(
        outcome["capability"]["reason"], "policy blocked before capability",
        "{outcome}"
    );
    assert_eq!(outcome["execution"]["status"], "host_denied", "{outcome}");
    assert_eq!(outcome["execution"]["reason"], "not executed", "{outcome}");

    // Against the set that actually decided it. The pass-through stand-in on a
    // call a real gate governed is the lie this ticket exists to remove.
    assert_eq!(
        outcome["policy_set_hash"].as_str().expect("a hash"),
        fixture_hash(),
        "{outcome}"
    );
    assert_ne!(
        outcome["policy_set_hash"].as_str().expect("a hash"),
        passthrough_hash(),
        "an engine-governed call must not carry the pass-through stand-in"
    );
    // An engine-governed record with empty `decision_axes` is that same lie one
    // field over: the rule that decided it is named.
    assert_eq!(
        outcome["decision_axes"]["matched_rule"], "stub-refuse",
        "{outcome}"
    );

    let verification = verify_chain_file(&driven.audit_path).expect("audit readable");
    assert_eq!(
        verification.verdict,
        Verdict::Verified,
        "{:?}",
        verification.verdict
    );
}

/// 19. An **allowed** `tools/call` is still relayed verbatim — and still
///     records `deny_all`, because a gate mints no capability.
#[test]
fn an_allowed_tools_call_is_relayed_verbatim_under_a_gate() {
    let driven = drive_enforced(
        StubGate::allowing(&["echo"]),
        &[r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}"#],
    );

    assert_eq!(driven.result.as_ref().ok(), Some(&0), "{:?}", driven.result);

    let out = driven.client_out.text();
    assert!(
        out.contains(r#""text":"echo""#),
        "the child, not wrap, must have answered: {out}"
    );
    assert!(
        !out.contains("-32042"),
        "an allowed call is not refused: {out}"
    );

    let outcome = &driven.outcomes()[0];
    assert_eq!(outcome["policy"]["status"], "allowed", "{outcome}");
    assert_eq!(outcome["capability"]["status"], "granted", "{outcome}");
    assert_eq!(outcome["execution"]["status"], "success", "{outcome}");
    // A gate decides *whether* a call may go. It resolves no capability, so the
    // grant is still the pass-through `deny_all` — wrap must not record fs or
    // net authority it never minted.
    let grant = &outcome["capability"]["grant"];
    assert!(grant.get("fs").is_none(), "{outcome}");
    assert!(grant.get("net").is_none(), "{outcome}");
    // The hash and the rule are the engine's on an allow too: an allowed call
    // carrying the pass-through stand-in is the same defect as a denied one.
    assert_eq!(
        outcome["policy_set_hash"].as_str().expect("a hash"),
        fixture_hash(),
        "{outcome}"
    );
    assert_ne!(
        outcome["policy_set_hash"].as_str().expect("a hash"),
        passthrough_hash(),
        "{outcome}"
    );
    assert_eq!(
        outcome["decision_axes"]["matched_rule"], "stub-allow",
        "{outcome}"
    );
}

/// 20. Enforcement spends transparency on exactly one frame. An unknown method
///     still reaches the child, and `-32601` stays forbidden (ADR-0015 *What
///     enforcement still relays*).
///
/// A duplicate of `an_unknown_method_is_relayed_and_never_locally_refused` and
/// deliberately not an edit of it: the original owns the default-mode claim,
/// and a mode that quietly started refusing unknown methods has to redden a
/// test of its own.
#[test]
fn an_unknown_method_is_relayed_under_enforcement_too() {
    let driven = drive_enforced(
        StubGate::allowing(&[]),
        &[r#"{"jsonrpc":"2.0","id":1,"method":"aegis/definitely-not-a-method"}"#],
    );

    let out = driven.client_out.text();
    assert!(
        out.contains(r#""mirrored":"aegis/definitely-not-a-method""#),
        "the child, not wrap, must have answered: {out}"
    );
    assert!(
        !out.contains("-32601"),
        "wrap must never synthesize method-not-found, gate or no gate: {out}"
    );
    assert!(
        !out.contains("-32042"),
        "a refusal answers a refused tools/call, not an unknown method: {out}"
    );
    // Not a `tools/call`, so the gate was never asked and nothing was recorded.
    assert_eq!(
        driven.line_types(),
        vec!["open", "close"],
        "{}",
        driven.audit
    );
}

/// 21. A batch carrying a denied `tools/call` is not forwarded at all.
///
/// A batch cannot be filtered: the array is the frame, and forwarding a subset
/// would mean re-serializing a parsed value onto the child's stdin. So one
/// refused element refuses the frame.
#[test]
fn a_batch_carrying_a_denied_call_is_not_forwarded() {
    const BATCH: &str =
        r#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}]"#;

    let driven = drive_enforced(StubGate::allowing(&[]), &[BATCH]);

    let out = driven.client_out.text();
    assert!(!out.contains("mirrored"), "{out}");
    assert!(
        !out.contains(r#""text":"echo""#),
        "the child must not have answered a frame it never received: {out}"
    );

    // One client frame in, one client frame out — and in the shape the client
    // sent, the way the child itself answers a batch.
    let lines = driven.client_out.lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let answer = driven.response(0);
    let elements = answer.as_array().expect("a batch answers as an array");
    assert_eq!(elements.len(), 1, "{answer}");
    assert_eq!(elements[0]["id"], 1, "{answer}");
    assert_eq!(elements[0]["error"]["code"], -32042, "{answer}");
    assert_eq!(
        elements[0]["error"]["data"]["aegis"]["code"], "POLICY_DENIED",
        "{answer}"
    );

    // The call is still accounted for, as a deny.
    assert_eq!(
        driven.line_types(),
        vec!["open", "intent", "outcome", "close"],
        "{}",
        driven.audit
    );
    let outcome = &driven.outcomes()[0];
    assert_eq!(outcome["tool_id"], "echo", "{outcome}");
    assert_eq!(outcome["policy"]["status"], "denied", "{outcome}");
    assert_eq!(outcome["execution"]["status"], "host_denied", "{outcome}");
    assert_eq!(
        outcome["policy_set_hash"].as_str().expect("a hash"),
        fixture_hash(),
        "{outcome}"
    );
}

/// 22. One deny in a batch takes its allowed siblings with it — and says so,
///     to the client and in the record.
///
/// The alternative is re-encoding the array minus the refused element onto the
/// child's stdin, which this crate does not do with any frame. The cost is
/// named rather than hidden: an allowed sibling is refused, told `HOST_DENIED`,
/// and recorded `allowed` at the policy station it actually passed.
#[test]
fn a_denied_sibling_refuses_the_whole_batch() {
    const BATCH: &str = r#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"blocked"}},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"permitted"}}]"#;

    let driven = drive_enforced(StubGate::allowing(&["permitted"]), &[BATCH]);

    let out = driven.client_out.text();
    assert!(!out.contains("mirrored"), "{out}");
    assert!(
        !out.contains(r#""text":"blocked""#) && !out.contains(r#""text":"permitted""#),
        "neither element may have reached the child: {out}"
    );

    // Both ids are answered, in the order they appeared, in one array frame.
    let lines = driven.client_out.lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let answer = driven.response(0);
    let elements = answer.as_array().expect("a batch answers as an array");
    assert_eq!(elements.len(), 2, "both ids are answered: {answer}");
    assert_eq!(elements[0]["id"], 1, "{answer}");
    assert_eq!(elements[0]["error"]["code"], -32042, "{answer}");
    assert_eq!(
        elements[0]["error"]["data"]["aegis"]["code"], "POLICY_DENIED",
        "the denied call names policy: {answer}"
    );
    assert_eq!(elements[1]["id"], 2, "{answer}");
    assert_eq!(elements[1]["error"]["code"], -32042, "{answer}");
    assert_eq!(
        elements[1]["error"]["data"]["aegis"]["code"], "HOST_DENIED",
        "the allowed sibling was refused by the host, not by policy: {answer}"
    );

    // Both have outcomes, and each says what was true of *it*.
    assert_eq!(
        driven.line_types(),
        vec!["open", "intent", "outcome", "intent", "outcome", "close"],
        "{}",
        driven.audit
    );
    let outcomes = driven.outcomes();
    assert_eq!(outcomes.len(), 2, "{}", driven.audit);
    assert_eq!(outcomes[0]["tool_id"], "blocked", "{}", driven.audit);
    assert_eq!(outcomes[0]["policy"]["status"], "denied");
    assert_eq!(outcomes[0]["execution"]["reason"], "not executed");

    assert_eq!(outcomes[1]["tool_id"], "permitted", "{}", driven.audit);
    assert_eq!(
        outcomes[1]["policy"]["status"], "allowed",
        "the gate really did allow it, and the record must not say otherwise"
    );
    assert_eq!(outcomes[1]["execution"]["status"], "host_denied");
    assert_eq!(
        outcomes[1]["execution"]["reason"],
        "not executed: sibling call in this batch was refused",
        "{}",
        driven.audit
    );
    // It never ran, so no grant was minted for it: the `not evaluated` seed
    // stands rather than the `granted` a relayed call would have got.
    assert_eq!(outcomes[1]["capability"]["status"], "denied");

    let verification = verify_chain_file(&driven.audit_path).expect("audit readable");
    assert_eq!(
        verification.verdict,
        Verdict::Verified,
        "{:?}",
        verification.verdict
    );
}

/// 23. `PendingApproval` is a **refusal**, not a park.
///
/// Parking the request is AILAB-629 and is unspecced. Wrap has no line type for
/// a call that is neither answered nor closed, so a verdict it cannot act on is
/// a verdict it refuses — named `PENDING_APPROVAL` so the client can tell it
/// from a flat denial.
#[test]
fn a_pending_approval_verdict_refuses_rather_than_parks() {
    let driven = drive_enforced(
        StubGate::refusing_with(PolicyAction::PendingApproval {
            approval_id: "appr-1".to_owned(),
        }),
        &[r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}"#],
    );

    let refusal = driven.response(0);
    assert_eq!(refusal["error"]["code"], -32042, "{refusal}");
    assert_eq!(
        refusal["error"]["data"]["aegis"]["code"], "PENDING_APPROVAL",
        "{refusal}"
    );

    // Closed, not left in flight: an intent with no outcome is exactly what a
    // park would look like on disk, and this is not one.
    assert_eq!(
        driven.line_types(),
        vec!["open", "intent", "outcome", "close"],
        "{}",
        driven.audit
    );
    let outcome = &driven.outcomes()[0];
    assert_eq!(outcome["policy"]["status"], "pending_approval", "{outcome}");
    assert_eq!(outcome["execution"]["status"], "host_denied", "{outcome}");
}
