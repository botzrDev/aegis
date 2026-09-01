//! Published `Indeterminate` vectors — one committed Chain file per class in
//! `spec/SPEC.md` §8.2.
//!
//! The sibling of `tests/tampered.rs`, and it exists for the same reason: a
//! third party building a verifier from the specification needs files they can
//! download and run. Without these six, §8.2 is prose. An implementation that
//! collapses `Indeterminate` into `Verified` or into `Tampered` passes every
//! `Tampered` vector and every golden — which is exactly the two-state verifier
//! §8 spends four paragraphs arguing against.
//!
//! **One file is one whole Chain, not one Line**, and the extension is `.aarl`
//! (ADR-0014), the same shape as `tests/tampered/`. Every vector is read back
//! from disk here: a vector nothing reads is an unverified artifact sitting in
//! a directory the specification points strangers at.
//!
//! Every vector is signed by the fixed-seed [`insecure_dev_key`], the same key
//! §11.2 publishes, so a reader checks one `key_id` across the whole document —
//! except `empty_chain.aarl`, which has no lines to sign at all. That key forces
//! a [`MemoryChainSink`]: a Durable Sink refuses it (ADR-0012). Each vector
//! builds its **own** Session rather than reusing the golden one, because the
//! goldens are an ordered chain where inserting a case rewrites every later
//! snapshot.
//!
//! # What the writer built, and what it could not
//!
//! Four of the six need nothing assembled by hand. `missing_line` comes out of
//! the writer exactly as it stands, over a sink that refuses one append;
//! `torn_final_line` and `unanchored_tail` are writer-built Chains with whole
//! lines added or removed afterwards, adding no field and re-signing nothing;
//! and `empty_chain` has no writer to run at all. The remaining two classes
//! describe lines **no emitter in this repo produces**, so for those the last
//! line is assembled by hand onto a writer-built Chain:
//!
//! - `unknown_line_type.aarl` carries a `line_type` token this build does not
//!   know. `AuditLineType::Unknown` is parse-only and nothing constructs one.
//!   The hand-assembled line carries **no signature**, so nothing about a
//!   signature is being reimplemented here: only `seq` and `prev_hash`, both
//!   read straight off the writer's own last line.
//! - `reserved_checkpoint.aarl` is **the one vector whose signature this file
//!   produces rather than the writer.** There is deliberately no
//!   `emit_checkpoint` — `AuditLineType::Checkpoint` is reserved so that adding
//!   it later breaks no downstream `match`, and adding an emitter to satisfy a
//!   test would be product surface invented for a fixture. So the line is built
//!   as a `serde_json::Value` and signed with the product's own primitives:
//!   `to_canonical_json` for the JCS bytes and `SigningKey::sign` over them,
//!   applying the signing-input rule (`crates/botzr-aegis-core/src/audit.rs`
//!   `SignedLine::signing_input`) — this line's canonical form with `signature`
//!   omitted and `key_id` present. Never a hand-rolled canonicalizer.
//!
//! That admission is the point of writing it down: `tests/tampered.rs` warns
//! that "a vector that reimplements chain and signature construction could only
//! ever agree with itself", and this is the single place in either suite where
//! any part of that happens. Its signature **must verify** — a `checkpoint`
//! whose signature does not is `Tampered` (§8.4), and publishing one by accident
//! would document the opposite class.
//!
//! Call ids here are named for the class rather than numbered, unlike
//! `tests/tampered.rs`'s `call-vector-N`: `unanchored_tail`'s reason payload
//! *publishes* its in-flight call id in `spec/SPEC.md` §11.5, and a class name
//! reads there where an ordinal would need a decoder.
//!
//! Refresh: `cargo test -p botzr-aegis-audit --test indeterminate write_indeterminate_vectors -- --ignored`

use std::path::Path;

use botzr_aegis_audit::{
    insecure_dev_key, verify_chain, AuditError, AuditWriter, ChainSink, IndeterminateReason,
    MemoryChainSink, Position, Retention, Verdict,
};
use botzr_aegis_core::{
    to_canonical_json, AuditIntent, AuditRecord, CapabilityOutcome, ExecutionOutcome,
    PolicyOutcome, PolicySetHash, PrevHash, RequestDigest, ToolId, AUDIT_SCHEMA_VERSION,
};
use serde_json::{json, Value};

/// Vector names, each one a §8.2 class, in the order §8.2 lists them. Named for
/// the class rather than for the mechanism: a reader arriving from the
/// specification is looking up a class.
const INDETERMINATE_VECTORS: &[&str] = &[
    "unknown_line_type",
    "reserved_checkpoint",
    "torn_final_line",
    "unanchored_tail",
    "missing_line",
    "empty_chain",
];

/// The token in the unknown-line-type vector. A plausible future line type
/// rather than noise: the class is "a newer emitter wrote something this build
/// has no struct for", not "a corrupt field".
const UNKNOWN_TOKEN: &str = "attestation";

/// The torn tail: a line cut off mid-write, which is what a torn write actually
/// leaves behind. It stops inside a string literal, so no parser recovers it.
const TORN_TAIL: &str = r#"{"call_id":"call-torn-final-line","line_type":"outc"#;

fn vector_path(name: &str) -> String {
    format!("tests/indeterminate/{name}.aarl")
}

/// Read a committed vector. Reading from disk is the point: these tests must
/// fail when the artifact drifts, not when a builder does.
fn read_vector(name: &str) -> String {
    let path = vector_path(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing indeterminate vector: {path}"))
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

fn vector_outcome(call_id: &str) -> AuditRecord {
    AuditRecord::new(
        call_id,
        ToolId::new("echo"),
        RequestDigest::of_request_bytes(b"{}"),
        PolicySetHash::of_canonical_bytes(b"indeterminate-vector-policy-set"),
        PolicyOutcome::Allowed,
        CapabilityOutcome::Denied {
            reason: "not evaluated".into(),
            denied_capability: None,
        },
        ExecutionOutcome::Success,
    )
}

fn intent_for(call_id: &str) -> AuditIntent {
    AuditIntent::new(
        call_id,
        ToolId::new("echo"),
        RequestDigest::of_request_bytes(b"{}"),
    )
}

fn one_call(writer: &AuditWriter, call_id: &str) {
    let mut intent = intent_for(call_id);
    writer.emit_intent(&mut intent).expect("intent");
    writer
        .emit_outcome(&mut vector_outcome(call_id))
        .expect("outcome");
}

/// One closed Session — `open`, `intent`, `outcome`, `close` — emitted through
/// the real writer. Built by the writer rather than assembled by hand: a vector
/// that reimplements chain and signature construction could only ever agree
/// with itself.
fn closed_session(call_id: &str) -> Vec<String> {
    let store = MemoryChainSink::new();
    {
        let writer = AuditWriter::with_sink(Box::new(store.clone()), insecure_dev_key())
            .expect("open session");
        one_call(&writer, call_id);
        // Drop closes the Session.
    }
    rows(&store.to_text())
}

/// The chain position a line appended after `rows` would occupy: the next `seq`
/// and the hash of the current tail.
///
/// Read off the writer's own output, never recomputed from a private rule — the
/// two hand-assembled vectors need somewhere to chain onto, and this is the only
/// arithmetic either of them does.
fn next_position(rows: &[String]) -> (u64, String) {
    let last = rows.last().expect("a session has lines");
    let value: Value = serde_json::from_str(last).expect("the last line parses");
    let seq = value.get("seq").and_then(Value::as_u64).expect("last seq") + 1;
    (seq, PrevHash::of_line(last.as_bytes()).to_hex())
}

// ---- the six vectors -----------------------------------------------------

/// §8.2 class 1 — a `line_type` token this build does not know, **unsigned**.
///
/// Unsigned is load-bearing, not incidental. A signature that is present and
/// does not verify is a decidable forgery even over a line nobody can read, and
/// the verifier reports that as `Tampered` (§8.1). It is the *absence* of a
/// signature that leaves the verifier with nothing to contradict and only
/// something it cannot interpret — which is the class.
fn unknown_line_type_vector() -> String {
    let mut rows = closed_session("call-unknown-line-type");
    let (seq, prev_hash) = next_position(&rows);
    let line = json!({
        "line_type": UNKNOWN_TOKEN,
        "prev_hash": prev_hash,
        "schema_version": AUDIT_SCHEMA_VERSION,
        "seq": seq,
    });
    rows.push(to_canonical_json(&line).expect("canonical"));
    rejoin(&rows)
}

/// §8.2 class 2 — a reserved `checkpoint`, **validly signed**.
///
/// The one vector this suite signs itself; see the module doc for why no
/// `emit_checkpoint` exists and why adding one would be product surface
/// invented for a test. The signing input is built by the product's own rule —
/// canonical form, `signature` omitted, `key_id` present — and signed by the
/// product's own key type.
fn reserved_checkpoint_vector() -> String {
    let mut rows = closed_session("call-reserved-checkpoint");
    let (seq, prev_hash) = next_position(&rows);
    let key = insecure_dev_key();
    let mut line = json!({
        "key_id": key.key_id().to_hex(),
        "line_type": "checkpoint",
        "prev_hash": prev_hash,
        "schema_version": AUDIT_SCHEMA_VERSION,
        "seq": seq,
    });
    let signing_input = to_canonical_json(&line).expect("signing input");
    line["signature"] = json!(key.sign(signing_input.as_bytes()).to_hex());
    rows.push(to_canonical_json(&line).expect("canonical"));
    rejoin(&rows)
}

/// §8.2 class 3 — the file's last Line does not parse.
///
/// The deliberate contrast with `tampered/malformed_line.aarl`, which puts
/// unparseable bytes *before* the final Line and is `Tampered`. Only the last
/// Line can be torn, because a correct writer refuses to append onto a torn
/// tail — so garbage with valid Lines after it was put there after the fact.
/// The distinguishing property is **position, not content**, which
/// `torn_final_line_vector_is_indeterminate` proves against these same bytes.
///
/// No trailing newline: a torn write ends mid-line, and a record separator the
/// process never got to write should not be in the published artifact.
fn torn_final_line_vector() -> String {
    let mut text = rejoin(&closed_session("call-torn-final-line"));
    text.push_str(TORN_TAIL);
    text
}

/// §8.2 class 4 — the final Session has no `close` and nothing anchors beyond
/// its tail.
///
/// The `outcome` is dropped along with the `close`, not just the `close`: with
/// the `outcome` present its signature covers the `intent` transitively, the
/// Call is no longer in flight, and `in_flight_calls` comes back empty — which
/// would under-document a class whose whole report is *which Calls* were
/// unresolved. This is the SIGKILL shape, and the live-file shape.
fn unanchored_tail_vector() -> String {
    let mut rows = closed_session("call-unanchored-tail");
    rows.pop().expect("close");
    rows.pop().expect("outcome");
    rejoin(&rows)
}

/// §8.2 class 5 — `seq` jumped forward with the chain still intact.
///
/// Produced the only way it can honestly be produced: through the real writer,
/// over a sink that refuses exactly one append. `ChainState::take_seq` hands out
/// the position *before* the write and `write_line` advances the tail only after
/// `sink.append` returns `Ok`, so a refused write leaves the position consumed
/// and the chain unbroken. That is the durability incident §8.2 describes, and
/// hand-forging it by re-signing a line at a jumped `seq` would prove nothing
/// about the writer that produced it.
fn missing_line_vector() -> String {
    let store = MemoryChainSink::new();
    {
        let sink = FailOneAppend {
            inner: store.clone(),
            appends: 0,
            // 0 is the `open`, 1 the `intent`, 2 the `outcome`. The outcome is
            // the write that does not land; the Session then closes cleanly at
            // the next position, leaving the gap.
            refuse: 2,
        };
        let writer =
            AuditWriter::with_sink(Box::new(sink), insecure_dev_key()).expect("open session");
        let mut intent = intent_for("call-missing-line");
        writer.emit_intent(&mut intent).expect("intent");
        let refused = writer
            .emit_outcome(&mut vector_outcome("call-missing-line"))
            .expect_err("the sink refuses this append");
        assert!(
            matches!(refused, AuditError::Io(_)),
            "the refusal must reach the caller, not be swallowed: {refused:?}"
        );
        // Drop closes the Session at the position after the one consumed.
    }
    rejoin(&rows(&store.to_text()))
}

/// §8.2 class 6 — no Lines at all. A zero-byte file.
///
/// Published rather than left implicit because it is the class an implementer
/// is most likely to collapse into `Verified`: nothing in the file contradicts
/// anything, and a verifier that answers "no findings" has answered a question
/// nobody asked. There is nothing here to verify.
fn empty_chain_vector() -> String {
    String::new()
}

/// A [`ChainSink`] that refuses exactly one append and otherwise behaves like
/// the in-memory sink underneath it.
///
/// A test double for a full disk. It owns bytes and nothing else, as the trait
/// requires — `seq`, `prev_hash`, the signature and the line hash are all chosen
/// by the writer before `append` is called, which is why refusing the call is
/// enough to leave a gap the writer itself stamped.
struct FailOneAppend {
    inner: MemoryChainSink,
    appends: usize,
    refuse: usize,
}

impl ChainSink for FailOneAppend {
    fn retention(&self) -> Retention {
        // The inner sink's own declaration, read back verbatim. Volatile, so
        // the dev key is legal here (ADR-0012).
        self.inner.retention()
    }

    fn existing_tail(&self) -> Result<Option<PrevHash>, AuditError> {
        self.inner.existing_tail()
    }

    fn append(&mut self, line: &[u8]) -> Result<(), AuditError> {
        let seen = self.appends;
        self.appends += 1;
        if seen == self.refuse {
            return Err(AuditError::Io(std::io::Error::other(
                "simulated durability failure: no space left on device",
            )));
        }
        self.inner.append(line)
    }

    fn path(&self) -> Option<&Path> {
        None
    }
}

fn build_vector(name: &str) -> String {
    match name {
        "unknown_line_type" => unknown_line_type_vector(),
        "reserved_checkpoint" => reserved_checkpoint_vector(),
        "torn_final_line" => torn_final_line_vector(),
        "unanchored_tail" => unanchored_tail_vector(),
        "missing_line" => missing_line_vector(),
        "empty_chain" => empty_chain_vector(),
        other => panic!("no builder for indeterminate vector: {other}"),
    }
}

#[test]
#[ignore = "run once to refresh indeterminate vectors: cargo test -p botzr-aegis-audit --test indeterminate write_indeterminate_vectors -- --ignored"]
fn write_indeterminate_vectors() {
    std::fs::create_dir_all("tests/indeterminate").unwrap();
    for name in INDETERMINATE_VECTORS {
        std::fs::write(vector_path(name), build_vector(name)).unwrap();
    }
}

// ---- one test per published vector ---------------------------------------

/// The reason under an `Indeterminate` verdict, or a panic naming what came
/// back instead.
///
/// `IndeterminateReason` is `#[non_exhaustive]` and this is a separate crate, so
/// every `match` on it here carries a wildcard. That is the constraint working
/// as intended rather than an obstacle: a reason added upstream must not make
/// this file stop compiling, it must make the specific assertion below fail.
fn indeterminate_reason(text: &str) -> IndeterminateReason {
    let verification = verify_chain(text);
    match verification.verdict {
        Verdict::Indeterminate { reason } => reason,
        other => panic!("expected Indeterminate, got {other:?}"),
    }
}

#[test]
fn unknown_line_type_vector_is_indeterminate() {
    let reason = indeterminate_reason(&read_vector("unknown_line_type"));
    assert_eq!(
        reason,
        IndeterminateReason::UnknownLineType {
            at: Position {
                session_index: 0,
                seq: 4
            },
            // The emitter's own token, preserved rather than normalised: the
            // only useful half of "unknown line type `x` at seq N".
            line_type: UNKNOWN_TOKEN.to_owned(),
        }
    );
}

#[test]
fn reserved_checkpoint_vector_is_indeterminate_and_its_signature_verifies() {
    let text = read_vector("reserved_checkpoint");
    assert_eq!(
        indeterminate_reason(&text),
        IndeterminateReason::ReservedCheckpoint {
            at: Position {
                session_index: 0,
                seq: 4
            }
        }
    );

    // The load-bearing half, and the reason this vector is riskier to publish
    // than the other five: a `checkpoint` whose signature does not verify is
    // `Tampered` (§8.4), so a vector that quietly lost its signature would
    // document the opposite class while still reading `Indeterminate` here —
    // `require_signature` runs *before* the cap is set, so the only proof that
    // the signature held is that the verdict is not `Tampered`. Strip it and
    // this same call reports BadSignature.
    let stripped = {
        let mut rows = rows(&text);
        let last = rows.len() - 1;
        let mut line: Value = serde_json::from_str(&rows[last]).expect("checkpoint parses");
        assert_eq!(line["line_type"], json!("checkpoint"));
        line.as_object_mut()
            .expect("checkpoint is an object")
            .remove("signature");
        rows[last] = to_canonical_json(&line).expect("canonical");
        rejoin(&rows)
    };
    assert!(
        matches!(verify_chain(&stripped).verdict, Verdict::Tampered { .. }),
        "an unsigned checkpoint must not hide behind the cap"
    );
}

#[test]
fn torn_final_line_vector_is_indeterminate() {
    let text = read_vector("torn_final_line");
    assert_eq!(
        indeterminate_reason(&text),
        // 1-based, over non-empty rows: four writer Lines and the torn fifth.
        IndeterminateReason::TornFinalLine { line: 5 }
    );

    // Position decides this class, not content. The same bytes with any Line
    // after them are `Tampered` — which is `tampered/malformed_line.aarl`. A
    // reader who diffs the two files sees different garbage in different places
    // and could reasonably conclude the content mattered; it does not.
    let not_final = format!("{text}\n{{}}\n");
    assert!(
        matches!(
            verify_chain(&not_final).verdict,
            Verdict::Tampered {
                reason: botzr_aegis_audit::TamperedReason::MalformedLine { line: 5, .. }
            }
        ),
        "the same torn bytes are Tampered once they are not the final Line"
    );
}

#[test]
fn unanchored_tail_vector_is_indeterminate() {
    let reason = indeterminate_reason(&read_vector("unanchored_tail"));
    assert_eq!(
        reason,
        IndeterminateReason::UnanchoredTail {
            session_index: 0,
            // The report names the Calls, not a count: three intents for
            // workspace reads is a shrug where one for a network POST is where
            // an operator starts looking.
            in_flight_calls: vec!["call-unanchored-tail".to_owned()],
        }
    );
}

#[test]
fn missing_line_vector_is_indeterminate() {
    let reason = indeterminate_reason(&read_vector("missing_line"));
    assert_eq!(
        reason,
        IndeterminateReason::MissingLine {
            session_index: 0,
            // The refused `outcome` consumed seq 2; the `close` landed at 3.
            expected: 2,
            found: 3,
        }
    );
}

#[test]
fn empty_chain_vector_is_indeterminate() {
    let text = read_vector("empty_chain");
    assert!(
        text.is_empty(),
        "the empty chain vector is a zero-byte file"
    );
    assert_eq!(indeterminate_reason(&text), IndeterminateReason::EmptyChain);
}

// ---- the vectors as artifacts --------------------------------------------

/// Every published vector is byte-reproducible from the builder above.
///
/// The analogue of `every_committed_tamper_vector_is_byte_reproducible`: a
/// vector edited by hand fails here rather than passing as "expected output".
/// Without it the committed bytes and the builders could drift apart silently,
/// and the file a third party downloads would stop being the file this suite
/// checks.
#[test]
fn every_committed_indeterminate_vector_is_byte_reproducible() {
    for name in INDETERMINATE_VECTORS {
        assert_eq!(
            read_vector(name),
            build_vector(name),
            "committed indeterminate vector {name} is not what the builder produces"
        );
    }
}

/// Nothing in the directory is unreachable. `INDETERMINATE_VECTORS` is a
/// hardcoded list, so a file dropped beside these would otherwise be read by
/// nothing — the exact failure that keeps stray files out of a vector directory.
#[test]
fn the_directory_holds_exactly_the_published_vectors() {
    let mut found: Vec<String> = std::fs::read_dir("tests/indeterminate")
        .expect("tests/indeterminate exists")
        .map(|entry| entry.expect("readable entry").file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    found.sort();
    let mut expected: Vec<String> = INDETERMINATE_VECTORS
        .iter()
        .map(|name| format!("{name}.aarl"))
        .collect();
    expected.sort();
    assert_eq!(found, expected);
}
