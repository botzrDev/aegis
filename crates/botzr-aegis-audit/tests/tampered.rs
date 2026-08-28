//! Published tamper vectors — one committed Chain file per `Tampered` class in
//! `spec/SPEC.md` §8.1.
//!
//! These test the **published artifacts**, not the verifier. The in-code tamper
//! tests in `verdict.rs` build their damaged input in memory and throw it away;
//! a third party building a verifier from the specification cannot run those.
//! So each class also gets a committed file they can download, and each of those
//! files is read from disk here — a vector nothing reads is an unverified
//! artifact sitting in a directory the specification points strangers at.
//!
//! **One file is one whole Chain, not one Line.** That is the shape difference
//! from `tests/golden/`, where each file is a single canonical Line. Seven of
//! the eight classes are only meaningful in the context of the Lines around
//! them, and the session-boundary class needs two Sessions in one file.
//!
//! The extension is `.aarl` (ADR-0014): these are whole Agent Action Record
//! files, which is exactly what that extension names. The goldens keep `.json`
//! because a single Line is not a record file.
//!
//! Every vector is signed by the fixed-seed [`insecure_dev_key`], the same key
//! §11.2 publishes, so a reader checks one `key_id` across the whole document.
//! That key forces a [`MemoryChainSink`]: a Durable Sink refuses it (ADR-0012).
//! Each vector builds its **own** Session rather than reusing the golden one,
//! because the goldens are an ordered chain where inserting a case rewrites
//! every later snapshot.
//!
//! Refresh: `cargo test -p botzr-aegis-audit --test tampered write_tamper_vectors -- --ignored`

use botzr_aegis_audit::{
    insecure_dev_key, verify_chain, verify_chain_with_trust, AuditWriter, MemoryChainSink,
    Position, SigningKey, TamperedReason, TrustLabel, Verdict, VerifyError,
};
use botzr_aegis_core::{
    to_canonical_json, ApprovalId, ApprovalVerdict, AuditDecision, AuditIntent, AuditRecord,
    CapabilityOutcome, ExecutionOutcome, PolicyOutcome, PolicySetHash, PrevHash, RequestDigest,
    ToolId,
};
use serde_json::{json, Value};

/// Vector names, each one a §8.1 class. Named for the class rather than for the
/// mechanism: a reader arriving from the specification is looking up a class.
const TAMPER_VECTORS: &[&str] = &[
    "prev_hash_mismatch",
    "seq_out_of_order",
    "bad_signature",
    "key_id_mismatch",
    "session_boundary_broken",
    "malformed_line",
    "untrusted_key",
    "duplicate_decision",
];

/// The overwritten `prev_hash` in the class 1 vector. A value no hash function
/// produces, so the damage is unmistakable in the published bytes.
fn broken_prev_hash() -> String {
    "f".repeat(64)
}

/// A fixed seed that is **not** the dev key's. Only its `key_id` is used, as the
/// fingerprint the class 4 vector names, and its public key is the trust slice
/// the class 7 vector is checked against.
fn foreign_key() -> SigningKey {
    SigningKey::from_seed([9u8; 32])
}

fn vector_path(name: &str) -> String {
    format!("tests/tampered/{name}.aarl")
}

/// Read a committed vector. Reading from disk is the point: these tests must
/// fail when the artifact drifts, not when a builder does.
fn read_vector(name: &str) -> String {
    let path = vector_path(name);
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing tamper vector: {path}"))
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
        PolicySetHash::of_canonical_bytes(b"tamper-vector-policy-set"),
        PolicyOutcome::Allowed,
        CapabilityOutcome::Denied {
            reason: "not evaluated".into(),
            denied_capability: None,
        },
        ExecutionOutcome::Success,
    )
}

fn one_call(writer: &AuditWriter, call_id: &str) {
    let mut intent = AuditIntent::new(
        call_id,
        ToolId::new("echo"),
        RequestDigest::of_request_bytes(b"{}"),
    );
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

// ---- the eight vectors ---------------------------------------------------

/// Class 1 (§8.1) — the `close` Line's `prev_hash` is overwritten, so it no
/// longer hashes to the Line before it. The chain check precedes the signature
/// check on the same Line, so this reports as a broken chain rather than as a
/// forged signature.
fn prev_hash_mismatch_vector() -> String {
    let mut rows = closed_session("call-vector-1");
    let last = rows.len() - 1;
    let mut close: Value = serde_json::from_str(&rows[last]).expect("close parses");
    close["prev_hash"] = json!(broken_prev_hash());
    rows[last] = to_canonical_json(&close).expect("canonical");
    rejoin(&rows)
}

/// Class 2 (§8.1) — the unsigned `intent` Line is replayed at the end of the
/// Session, keeping its original `seq`. Its hash link is repaired so `seq` is
/// the only thing that gives it away; the Line is unsigned, so repairing the
/// link costs the forger nothing.
fn seq_out_of_order_vector() -> String {
    let mut rows = closed_session("call-vector-2");
    let mut replay: Value = serde_json::from_str(&rows[1]).expect("intent parses");
    let tail = PrevHash::of_line(rows[rows.len() - 1].as_bytes());
    replay["prev_hash"] = json!(tail.to_hex());
    rows.push(to_canonical_json(&replay).expect("canonical"));
    rejoin(&rows)
}

/// Class 3 (§8.1) — the Session's `close` is dropped and the `outcome` Line it
/// exposed loses its `signature`. Stripping the signature from the *last* Line
/// breaks no `prev_hash`, which is exactly why §8.3 has to name this case.
fn bad_signature_vector() -> String {
    let mut rows = closed_session("call-vector-3");
    rows.pop();
    let last = rows.len() - 1;
    let mut record: Value = serde_json::from_str(&rows[last]).expect("outcome parses");
    assert_eq!(record["line_type"], json!("outcome"));
    record
        .as_object_mut()
        .expect("outcome is an object")
        .remove("signature");
    rows[last] = to_canonical_json(&record).expect("canonical");
    rejoin(&rows)
}

/// Class 4 (§8.1) — the `close` Line's `key_id` is swapped for another key's
/// fingerprint, and its signature is left untouched. The last Line is chosen so
/// the file carries this defect and no other: rewriting an interior Line would
/// break the next Line's `prev_hash` too, and a vector with two defects
/// documents neither.
fn key_id_mismatch_vector() -> String {
    let mut rows = closed_session("call-vector-4");
    let last = rows.len() - 1;
    let mut close: Value = serde_json::from_str(&rows[last]).expect("close parses");
    close["key_id"] = json!(foreign_key().key_id().to_hex());
    rows[last] = to_canonical_json(&close).expect("canonical");
    rejoin(&rows)
}

/// Class 5 (§8.1) — two Sessions in one file with the first Session's `close`
/// removed. The truncated Session is internally consistent on its own; the
/// detection comes entirely from the second Session's signed `Open`, which
/// still back-references the Line that was taken out.
fn session_boundary_broken_vector() -> String {
    let store = MemoryChainSink::new();
    for session in 0..2 {
        let writer = AuditWriter::with_sink(Box::new(store.clone()), insecure_dev_key())
            .expect("open session");
        one_call(&writer, &format!("call-vector-5-s{session}"));
    }
    let mut rows = rows(&store.to_text());
    assert_eq!(rows.len(), 8, "two Sessions of open+intent+outcome+close");
    rows.remove(3);
    rejoin(&rows)
}

/// Class 6 (§8.1) — bytes that are not JSON, placed *before* the final Line. The
/// writer refuses to append onto a torn tail, so unparseable bytes with valid
/// Lines after them were put there after the fact.
fn malformed_line_vector() -> String {
    let mut rows = closed_session("call-vector-6");
    rows.insert(2, "not json at all".into());
    rejoin(&rows)
}

/// Class 7 (§8.1) — **an undamaged file.** The defect is not in the bytes: the
/// caller supplied a trust slice, and the Session published a key that is not in
/// it. Published as a vector because a verifier that reports `Verified
/// (unpinned)` here has ignored the key it was gated on.
fn untrusted_key_vector() -> String {
    rejoin(&closed_session("call-vector-7"))
}

/// Class 8 (§8.1) — two `decision` Lines for one `approval_id`. Both are validly
/// signed and the chain is intact: this is a rule about the record, not about
/// the crypto, and no signature check would catch it.
fn duplicate_decision_vector() -> String {
    let store = MemoryChainSink::new();
    {
        let writer = AuditWriter::with_sink(Box::new(store.clone()), insecure_dev_key())
            .expect("open session");
        for _ in 0..2 {
            let mut decision = AuditDecision::new(
                ApprovalId::new("apr-vector-8"),
                ApprovalVerdict::Denied {
                    reason: "operator said no".into(),
                },
            );
            writer.emit_decision(&mut decision).expect("decision");
        }
    }
    rejoin(&rows(&store.to_text()))
}

fn build_vector(name: &str) -> String {
    match name {
        "prev_hash_mismatch" => prev_hash_mismatch_vector(),
        "seq_out_of_order" => seq_out_of_order_vector(),
        "bad_signature" => bad_signature_vector(),
        "key_id_mismatch" => key_id_mismatch_vector(),
        "session_boundary_broken" => session_boundary_broken_vector(),
        "malformed_line" => malformed_line_vector(),
        "untrusted_key" => untrusted_key_vector(),
        "duplicate_decision" => duplicate_decision_vector(),
        other => panic!("no builder for tamper vector: {other}"),
    }
}

#[test]
#[ignore = "run once to refresh tamper vectors: cargo test -p botzr-aegis-audit --test tampered write_tamper_vectors -- --ignored"]
fn write_tamper_vectors() {
    std::fs::create_dir_all("tests/tampered").unwrap();
    for name in TAMPER_VECTORS {
        std::fs::write(vector_path(name), build_vector(name)).unwrap();
    }
}

// ---- one test per published vector ---------------------------------------

#[test]
fn prev_hash_mismatch_vector_is_tampered() {
    let result = verify_chain(&read_vector("prev_hash_mismatch"));
    let Verdict::Tampered {
        reason:
            TamperedReason::ChainBroken {
                at,
                expected,
                found,
            },
    } = result.verdict
    else {
        panic!("expected ChainBroken, got {:?}", result.verdict);
    };
    assert_eq!(
        at,
        Position {
            session_index: 0,
            seq: 3
        }
    );
    assert_eq!(found.to_hex(), broken_prev_hash());
    // Both halves are published in `spec/SPEC.md` §11.4, and §11's preamble
    // claims every vector there is checked by CI. Pinning the literal is what
    // makes that true: a vector that drifts fails here rather than quietly
    // leaving the specification stating a hash nothing produces.
    assert_eq!(
        expected.to_hex(),
        "9a2c3c9f6c9f58effd1636bbb31c30fad2fcbcbd25ea5d2679c835740370cb9c"
    );
}

#[test]
fn seq_out_of_order_vector_is_tampered() {
    let result = verify_chain(&read_vector("seq_out_of_order"));
    assert_eq!(
        result.verdict,
        Verdict::Tampered {
            reason: TamperedReason::SeqOutOfOrder {
                session_index: 0,
                expected: 4,
                found: 1,
            }
        }
    );
}

#[test]
fn bad_signature_vector_is_tampered() {
    let result = verify_chain(&read_vector("bad_signature"));
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
fn key_id_mismatch_vector_is_tampered() {
    let result = verify_chain(&read_vector("key_id_mismatch"));
    assert_eq!(
        result.verdict,
        Verdict::Tampered {
            reason: TamperedReason::BadSignature {
                at: Position {
                    session_index: 0,
                    seq: 3
                },
                source: VerifyError::KeyMismatch {
                    expected: insecure_dev_key().key_id(),
                    found: foreign_key().key_id(),
                },
            }
        }
    );
}

#[test]
fn session_boundary_broken_vector_is_tampered() {
    let result = verify_chain(&read_vector("session_boundary_broken"));
    let Verdict::Tampered {
        reason: TamperedReason::SessionBoundaryBroken { session_index, .. },
    } = result.verdict
    else {
        panic!("expected SessionBoundaryBroken, got {:?}", result.verdict);
    };
    assert_eq!(session_index, 1, "the second Session names the broken link");
}

#[test]
fn malformed_line_vector_is_tampered() {
    let result = verify_chain(&read_vector("malformed_line"));
    let Verdict::Tampered {
        reason: TamperedReason::MalformedLine { line, .. },
    } = result.verdict
    else {
        panic!("expected MalformedLine, got {:?}", result.verdict);
    };
    assert_eq!(line, 3, "the unparseable Line is the third, 1-based");
}

#[test]
fn untrusted_key_vector_is_tampered_only_against_a_trust_slice() {
    let text = read_vector("untrusted_key");

    // The premise, and the reason this vector is unlike the other seven: the
    // bytes are clean. A verifier that reports `Tampered` here without being
    // given a trust slice has a different bug.
    let unpinned = verify_chain(&text);
    assert_eq!(unpinned.verdict, Verdict::Verified);
    assert_eq!(unpinned.trust, TrustLabel::Unpinned);

    let result = verify_chain_with_trust(&text, Some(&[foreign_key().public_key()]));
    assert_eq!(
        result.verdict,
        Verdict::Tampered {
            reason: TamperedReason::UntrustedKey {
                at: Position {
                    session_index: 0,
                    seq: 0
                },
                key_id: insecure_dev_key().key_id(),
            }
        },
        "the reason names the key the file published, not the one that was expected"
    );
    assert_eq!(result.trust, TrustLabel::Unpinned);
}

#[test]
fn duplicate_decision_vector_is_tampered() {
    let result = verify_chain(&read_vector("duplicate_decision"));
    assert_eq!(
        result.verdict,
        Verdict::Tampered {
            reason: TamperedReason::DuplicateDecision {
                at: Position {
                    session_index: 0,
                    seq: 2
                },
                approval_id: "apr-vector-8".into(),
            }
        }
    );
}

// ---- the vectors as artifacts --------------------------------------------

/// Every published vector is byte-reproducible from the builder above.
///
/// This is the analogue of `every_committed_golden_line_verifies_and_chains`: a
/// vector edited by hand fails here rather than passing as "expected output".
/// Without it the committed bytes and the builders could drift apart silently,
/// and the file a third party downloads would stop being the file this suite
/// checks.
#[test]
fn every_committed_tamper_vector_is_byte_reproducible() {
    for name in TAMPER_VECTORS {
        assert_eq!(
            read_vector(name),
            build_vector(name),
            "committed tamper vector {name} is not what the builder produces"
        );
    }
}

/// Nothing in the directory is unreachable. `TAMPER_VECTORS` is a hardcoded
/// list, so a file dropped beside these would otherwise be read by nothing —
/// the exact failure that keeps tamper vectors out of `tests/golden/`.
#[test]
fn the_directory_holds_exactly_the_published_vectors() {
    let mut found: Vec<String> = std::fs::read_dir("tests/tampered")
        .expect("tests/tampered exists")
        .map(|entry| entry.expect("readable entry").file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    found.sort();
    let mut expected: Vec<String> = TAMPER_VECTORS
        .iter()
        .map(|name| format!("{name}.aarl"))
        .collect();
    expected.sort();
    assert_eq!(found, expected);
}
