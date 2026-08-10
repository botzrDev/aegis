//! Verdict acceptance tests — Coverage plus Anchor presence, three states only
//! (ADR-0002).
//!
//! Two fixture styles on purpose. Anything an emitter can produce is produced by
//! the real [`AuditWriter`], so the test cannot drift from the writer. Anything
//! it **cannot** produce — a reserved `Checkpoint`, a line type from a newer
//! emitter — is hand-built by [`FixtureChain`], which is the only thing in this
//! repo that writes those bytes. No code path may emit a `Checkpoint`.

use botzr_aegis_audit::{
    insecure_dev_key, verify_chain, verify_chain_file, AuditWriter, IndeterminateReason, Position,
    SigningKey, TamperedReason, Verdict, VerifyError,
};
use botzr_aegis_core::{
    to_canonical_json, AuditRecord, CapabilityOutcome, ExecutionOutcome, PolicyOutcome,
    PolicySetHash, PrevHash, PublicKey, RequestDigest, ToolId,
};
use serde_json::{json, Map, Value};

// ---- fixtures ------------------------------------------------------------

/// Hand-builds a Chain by the same rule the writer follows: stamp `seq` and
/// `prev_hash`, sign the canonical form with `signature` omitted and `key_id`
/// present, then hash the complete canonical line including the signature.
///
/// It exists for the lines no emitter is allowed to write. Keeping it a
/// separate, deliberate implementation is the point — if it and the writer ever
/// disagree, the format has two spellings, and `verifier_agrees_with_the_writer`
/// below fails.
struct FixtureChain {
    key: SigningKey,
    lines: Vec<String>,
    seq: u64,
    tail: PrevHash,
}

impl FixtureChain {
    /// Open a Session, optionally back-referencing a previous Session's tail.
    fn new(prev_session_tail: Option<PrevHash>) -> Self {
        let key = insecure_dev_key();
        let mut chain = Self {
            key,
            lines: Vec::new(),
            seq: 0,
            tail: PrevHash::GENESIS,
        };
        let mut open = Map::new();
        open.insert("line_type".into(), json!("open"));
        open.insert("public_key".into(), json!(chain.key.public_key().to_hex()));
        if let Some(tail) = prev_session_tail {
            open.insert("prev_session_tail".into(), json!(tail.to_hex()));
        }
        chain.push(open, Signed::Yes);
        chain
    }

    fn push(&mut self, mut body: Map<String, Value>, signed: Signed) {
        body.insert("schema_version".into(), json!(2));
        body.insert("seq".into(), json!(self.seq));
        body.insert("prev_hash".into(), json!(self.tail.to_hex()));
        if signed == Signed::Yes {
            body.insert("key_id".into(), json!(self.key.key_id().to_hex()));
            let signing_input = to_canonical_json(&Value::Object(body.clone())).unwrap();
            let signature = self.key.sign(signing_input.as_bytes());
            body.insert("signature".into(), json!(signature.to_hex()));
        }
        let canonical = to_canonical_json(&Value::Object(body)).unwrap();
        self.tail = PrevHash::of_line(canonical.as_bytes());
        self.seq += 1;
        self.lines.push(canonical);
    }

    fn line(&mut self, line_type: &str, signed: Signed) {
        let mut body = Map::new();
        body.insert("line_type".into(), json!(line_type));
        self.push(body, signed);
    }

    fn close(&mut self) {
        self.line("close", Signed::Yes);
    }

    fn text(&self) -> String {
        let mut text = self.lines.join("\n");
        text.push('\n');
        text
    }

    fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Signed {
    Yes,
    No,
}

fn outcome(call_id: &str) -> AuditRecord {
    AuditRecord::new(
        call_id,
        ToolId::new("echo"),
        RequestDigest::of_request_bytes(b"{}"),
        PolicySetHash::of_canonical_bytes(b"policy"),
        PolicyOutcome::Allowed,
        CapabilityOutcome::Denied {
            reason: "not evaluated".into(),
            denied_capability: None,
        },
        ExecutionOutcome::Success,
    )
}

/// Write one closed Session through the real writer and hand back its text.
fn written_session(calls: usize) -> String {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    {
        let writer = AuditWriter::open(&path, insecure_dev_key()).unwrap();
        for call in 0..calls {
            let call_id = format!("call-{call}");
            let mut intent = botzr_aegis_core::AuditIntent::new(
                call_id.clone(),
                ToolId::new("echo"),
                RequestDigest::of_request_bytes(b"{}"),
            );
            writer.emit_intent(&mut intent).unwrap();
            writer.emit_outcome(&mut outcome(&call_id)).unwrap();
        }
    }
    std::fs::read_to_string(&path).unwrap()
}

fn rows(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

fn rejoin(rows: &[String]) -> String {
    let mut text = rows.join("\n");
    text.push('\n');
    text
}

// ---- the happy path ------------------------------------------------------

#[test]
fn a_closed_session_verifies_and_coverage_reaches_its_last_line() {
    let text = written_session(2);
    let result = verify_chain(&text);
    assert_eq!(result.verdict, Verdict::Verified);
    assert_eq!(
        result.coverage,
        Some(Position {
            session_index: 0,
            seq: rows(&text).len() as u64 - 1
        }),
        "the Close line is the anchor, so Coverage reaches it"
    );
}

/// The fixture builder and the writer must produce chains the same verifier
/// accepts, or every hand-built fixture below is testing its own reimplementation.
#[test]
fn verifier_agrees_with_the_writer_on_a_hand_built_chain() {
    let mut chain = FixtureChain::new(None);
    chain.line("intent", Signed::No);
    chain.close();
    assert_eq!(verify_chain(&chain.text()).verdict, Verdict::Verified);
}

#[test]
fn the_committed_golden_session_verifies_end_to_end() {
    // The golden snapshots are one Session, in chain order — so the verdict
    // primitive is the sharpest possible check that they were not hand-edited.
    let names = [
        "session_open",
        "intent",
        "policy_deny",
        "rate_limit",
        "pending_approval",
        "capability_denied",
        "trap",
        "resource_exceeded",
        "panic",
        "abandoned_session",
        "decision",
        "session_close",
    ];
    let text: String = names
        .iter()
        .map(|name| {
            let line = std::fs::read_to_string(format!("tests/golden/{name}.json")).unwrap();
            format!("{}\n", line.trim())
        })
        .collect();
    assert_eq!(verify_chain(&text).verdict, Verdict::Verified);
}

// ---- unknown types and Checkpoint cap at Indeterminate -------------------

#[test]
fn a_reserved_checkpoint_parses_hashes_and_caps_the_verdict_at_indeterminate() {
    let mut chain = FixtureChain::new(None);
    chain.line("checkpoint", Signed::Yes);
    chain.close();
    let result = verify_chain(&chain.text());

    // Capped, not failed: a Checkpoint is a signed line and the chain is intact.
    assert_eq!(
        result.verdict,
        Verdict::Indeterminate {
            reason: IndeterminateReason::ReservedCheckpoint {
                at: Position {
                    session_index: 0,
                    seq: 1
                }
            }
        }
    );
    // Hashed: the walk continued past it and the Close still chained, which it
    // could not do if the Checkpoint had not been hashed identically.
    assert_eq!(
        result.coverage,
        Some(Position {
            session_index: 0,
            seq: 2
        })
    );
}

#[test]
fn a_checkpoint_extends_coverage_even_though_it_caps_the_verdict() {
    // Coverage is about signatures; the cap is about comprehension. A
    // Checkpoint is signed, so it does move Coverage — ADR-0002 says so, and a
    // verifier that refused to count it would under-report how much of the file
    // is authenticated.
    let mut chain = FixtureChain::new(None);
    chain.line("checkpoint", Signed::Yes);
    let result = verify_chain(&chain.text());
    assert_eq!(
        result.coverage,
        Some(Position {
            session_index: 0,
            seq: 1
        })
    );
    assert!(matches!(
        result.verdict,
        Verdict::Indeterminate {
            reason: IndeterminateReason::ReservedCheckpoint { .. }
        }
    ));
}

#[test]
fn an_unknown_line_type_parses_hashes_and_caps_the_verdict_at_indeterminate() {
    let mut chain = FixtureChain::new(None);
    chain.line("anchor", Signed::Yes);
    chain.close();
    let result = verify_chain(&chain.text());

    // The raw token survives into the reason: an operator gets "unknown line
    // type `anchor`", not "parse error".
    assert_eq!(
        result.verdict,
        Verdict::Indeterminate {
            reason: IndeterminateReason::UnknownLineType {
                at: Position {
                    session_index: 0,
                    seq: 1
                },
                line_type: "anchor".into(),
            }
        }
    );
    assert!(result
        .verdict
        .to_string_if_indeterminate()
        .contains("newer emitter"));
    assert_eq!(
        result.coverage,
        Some(Position {
            session_index: 0,
            seq: 2
        }),
        "an unrecognised line still hashes, so the chain walks past it"
    );
}

#[test]
fn an_unknown_line_type_never_reports_verified_even_when_everything_else_holds() {
    // The whole extensibility story: if an old auditor said `Verified` here, a
    // newer emitter could smuggle any content past it.
    let mut chain = FixtureChain::new(None);
    chain.line("intent", Signed::No);
    chain.line("something-from-2027", Signed::Yes);
    chain.close();
    assert_ne!(verify_chain(&chain.text()).verdict, Verdict::Verified);
}

#[test]
fn a_detected_forgery_outranks_a_capped_verdict() {
    // Tampered wins: an unreadable line is a reason to withhold `Verified`, not
    // a reason to soften a contradiction the file already gave up.
    let mut chain = FixtureChain::new(None);
    chain.line("anchor", Signed::Yes);
    chain.close();
    let mut rows = rows(&chain.text());
    let last = rows.len() - 1;
    let mut close: Value = serde_json::from_str(&rows[last]).unwrap();
    close["prev_hash"] = json!("f".repeat(64));
    rows[last] = to_canonical_json(&close).unwrap();
    assert!(matches!(
        verify_chain(&rejoin(&rows)).verdict,
        Verdict::Tampered {
            reason: TamperedReason::ChainBroken { .. }
        }
    ));
}

// ---- the unverified tail -------------------------------------------------

#[test]
fn an_outcome_in_the_unverified_tail_is_a_stripped_signature_not_a_crash() {
    // ADR-0002: the tail may hold intent lines and at most one torn final line.
    // Every outcome line is signed, so an unsigned one in the tail is a
    // signature someone removed — and removing it from the *last* line does not
    // break any `prev_hash`, which is exactly why this rule has to exist.
    let text = written_session(1);
    let mut rows = rows(&text);
    rows.pop(); // drop the Close, making the outcome the tail
    let last = rows.len() - 1;
    let mut record: Value = serde_json::from_str(&rows[last]).unwrap();
    assert_eq!(record["line_type"], json!("outcome"));
    record.as_object_mut().unwrap().remove("signature");
    rows[last] = to_canonical_json(&record).unwrap();

    let result = verify_chain(&rejoin(&rows));
    assert_eq!(
        result.verdict,
        Verdict::Tampered {
            reason: TamperedReason::BadSignature {
                at: Position {
                    session_index: 0,
                    seq: 2
                },
                source: VerifyError::Unsigned,
            }
        }
    );
}

#[test]
fn a_trailing_unparseable_line_is_a_torn_write_with_its_own_reason() {
    // Distinct from "no close record": a torn write says a line was being
    // appended when the process died, and that is a different operator story
    // from a Session that simply has not closed yet.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    let writer = AuditWriter::open(&path, insecure_dev_key()).unwrap();
    let mut intent = botzr_aegis_core::AuditIntent::new(
        "call-0",
        ToolId::new("echo"),
        RequestDigest::of_request_bytes(b"{}"),
    );
    writer.emit_intent(&mut intent).unwrap();
    std::mem::forget(writer); // no Close, as after a SIGKILL
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str("{\"line_type\":\"outcome\",\"seq\"");
    std::fs::write(&path, &text).unwrap();

    let result = verify_chain_file(&path).unwrap();
    assert_eq!(
        result.verdict,
        Verdict::Indeterminate {
            reason: IndeterminateReason::TornFinalLine { line: 3 }
        }
    );
    // Everything before the torn line stays covered — a torn tail is not a
    // reason to disown the Session's verified prefix.
    assert_eq!(
        result.coverage,
        Some(Position {
            session_index: 0,
            seq: 0
        })
    );
    // The writer, a different consumer, refuses to *append* onto this file. The
    // verdict path classifies it instead of refusing to answer.
    assert!(AuditWriter::open(&path, insecure_dev_key()).is_err());
}

#[test]
fn an_intent_tail_is_indeterminate_and_names_the_calls_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    let writer = AuditWriter::open(&path, insecure_dev_key()).unwrap();
    for call_id in ["call-a", "call-b"] {
        let mut intent = botzr_aegis_core::AuditIntent::new(
            call_id,
            ToolId::new("net.post"),
            RequestDigest::of_request_bytes(b"{}"),
        );
        writer.emit_intent(&mut intent).unwrap();
    }
    std::mem::forget(writer);

    let result = verify_chain_file(&path).unwrap();
    assert_eq!(
        result.verdict,
        Verdict::Indeterminate {
            reason: IndeterminateReason::UnanchoredTail {
                session_index: 0,
                in_flight_calls: vec!["call-a".into(), "call-b".into()],
            }
        }
    );
}

#[test]
fn an_empty_chain_is_indeterminate_not_verified() {
    let result = verify_chain("");
    assert_eq!(
        result.verdict,
        Verdict::Indeterminate {
            reason: IndeterminateReason::EmptyChain
        }
    );
    assert_eq!(result.coverage, None);
}

// ---- malformed input -----------------------------------------------------

#[test]
fn garbage_before_the_final_line_is_tampering_not_a_torn_write() {
    // The writer refuses to append onto a torn tail, so unparseable bytes with
    // valid lines after them were put there after the fact.
    let text = written_session(1);
    let mut rows = rows(&text);
    rows.insert(2, "not json at all".into());
    assert!(matches!(
        verify_chain(&rejoin(&rows)).verdict,
        Verdict::Tampered {
            reason: TamperedReason::MalformedLine { line: 3, .. }
        }
    ));
}

#[test]
fn a_chain_that_does_not_begin_with_an_open_line_is_rejected() {
    let text = written_session(1);
    let rows = rows(&text);
    assert!(matches!(
        verify_chain(&rejoin(&rows[1..])).verdict,
        Verdict::Tampered {
            reason: TamperedReason::MalformedLine { line: 1, .. }
        }
    ));
}

#[test]
fn a_repeated_seq_is_tampering() {
    // What a forked chain looks like from the file: two lines claiming one
    // position. The writer cannot produce it — `seq` is taken under the same
    // lock as the append — so seeing it means the file was edited. The hash link
    // is left intact on purpose, so `seq` is the only thing that gives it away.
    let mut chain = FixtureChain::new(None);
    chain.line("intent", Signed::No);
    let mut rows = rows(&chain.text());
    let mut duplicate: Value = serde_json::from_str(&rows[1]).unwrap();
    duplicate["prev_hash"] = json!(PrevHash::of_line(rows[1].as_bytes()).to_hex());
    rows.push(to_canonical_json(&duplicate).unwrap());
    assert!(matches!(
        verify_chain(&rejoin(&rows)).verdict,
        Verdict::Tampered {
            reason: TamperedReason::SeqOutOfOrder {
                expected: 2,
                found: 1,
                ..
            }
        }
    ));
}

#[test]
fn a_seq_gap_over_an_intact_chain_is_a_lost_write_not_a_forgery() {
    // The writer takes `seq` before the append and advances its tail only after
    // the write lands, so a failed append leaves a gap with the chain intact.
    // Removing a line instead would break the next `prev_hash`, and re-signing
    // the remainder needs the key — so an intact link means nothing was taken
    // out. Reporting forgery on a full disk is the alarm ADR-0002 exists to
    // avoid.
    let mut chain = FixtureChain::new(None);
    chain.line("intent", Signed::No);
    let mut rows = rows(&chain.text());
    let mut skipped: Value = serde_json::from_str(&rows[1]).unwrap();
    skipped["seq"] = json!(7);
    skipped["prev_hash"] = json!(PrevHash::of_line(rows[1].as_bytes()).to_hex());
    rows.push(to_canonical_json(&skipped).unwrap());
    assert_eq!(
        verify_chain(&rejoin(&rows)).verdict,
        Verdict::Indeterminate {
            reason: IndeterminateReason::MissingLine {
                session_index: 0,
                expected: 2,
                found: 7,
            }
        }
    );
}

#[test]
fn a_line_signed_by_another_key_is_tampering() {
    // Key rotation is legal only when a Session `Open` introduces the new key.
    // A `key_id` change mid-Session lands here as a key mismatch.
    let chain = FixtureChain::new(None);
    let foreign = SigningKey::from_seed([9u8; 32]);
    assert_ne!(foreign.key_id(), chain.key.key_id());
    let mut body = Map::new();
    body.insert("line_type".into(), json!("outcome"));
    body.insert("schema_version".into(), json!(2));
    body.insert("seq".into(), json!(1));
    body.insert("prev_hash".into(), json!(chain.tail.to_hex()));
    body.insert("key_id".into(), json!(foreign.key_id().to_hex()));
    let signature = foreign.sign(
        to_canonical_json(&Value::Object(body.clone()))
            .unwrap()
            .as_bytes(),
    );
    body.insert("signature".into(), json!(signature.to_hex()));
    let mut rows = rows(&chain.text());
    rows.push(to_canonical_json(&Value::Object(body)).unwrap());

    assert!(matches!(
        verify_chain(&rejoin(&rows)).verdict,
        Verdict::Tampered {
            reason: TamperedReason::BadSignature {
                source: VerifyError::KeyMismatch { .. },
                ..
            }
        }
    ));
    // Sanity: the Session did publish the other key.
    assert_ne!(chain.public_key(), foreign.public_key());
}

#[test]
fn the_verdict_is_deterministic_over_the_same_bytes() {
    // Asserted as a property, not a case: same bytes, same verdict, always.
    let text = written_session(3);
    let first = verify_chain(&text);
    for _ in 0..8 {
        assert_eq!(verify_chain(&text), first);
    }
}

/// Small helper so an assertion can read the human-facing reason text without
/// every test unwrapping the enum.
trait VerdictText {
    fn to_string_if_indeterminate(&self) -> String;
}

impl VerdictText for Verdict {
    fn to_string_if_indeterminate(&self) -> String {
        match self {
            Verdict::Indeterminate { reason } => reason.to_string(),
            other => panic!("expected an indeterminate verdict, got {other:?}"),
        }
    }
}
