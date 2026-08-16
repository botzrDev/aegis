//! Session boundaries — what `prev_session_tail` buys, and what it does not.
//!
//! The headline property (ADR-0002): **the undecidable set is one Session, not
//! every Session.** A later `Open` line back-references the previous Session's
//! final hash and is signed, so truncating any *non-final* Session contradicts
//! that signature — `Tampered`, detected from the file alone, with no external
//! witness. Only the final Session's tail, with nothing anchored beyond it, is
//! undecidable. That is a materially better thing to publish than "we cannot
//! detect truncation", and it is why these two cases are tested side by side.

use botzr_aegis_audit::{
    verify_chain, verify_chain_file, AuditWriter, IndeterminateReason, SigningKey, Verdict,
};
use botzr_aegis_core::{
    AuditRecord, CapabilityOutcome, ExecutionOutcome, PolicyOutcome, PolicySetHash, PrevHash,
    RequestDigest, ToolId,
};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// A fixed seed that is **not** the dev key's.
///
/// These fixtures write real Chain files, and a Durable Sink refuses
/// `insecure_dev_key` (ADR-0012). Fixed rather than random so a failing case
/// reproduces byte for byte.
fn provisioned_key() -> SigningKey {
    SigningKey::from_seed([0x2a; 32])
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

fn rows(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .expect("chain file readable")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

fn write_rows(path: &Path, rows: &[String]) {
    let mut text = rows.join("\n");
    text.push('\n');
    std::fs::write(path, text).unwrap();
}

/// Two closed Sessions appended to one file, each with one call.
fn two_sessions(path: &Path) {
    for session in 0..2 {
        let writer = AuditWriter::open(path, provisioned_key()).unwrap();
        writer
            .emit_outcome(&mut outcome(&format!("call-s{session}")))
            .unwrap();
        // Drop closes this Session before the next one opens.
    }
}

fn temp_chain() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    (dir, path)
}

#[test]
fn two_sessions_in_one_file_chain_across_the_boundary() {
    let (_dir, path) = temp_chain();
    two_sessions(&path);
    let rows = rows(&path);
    assert_eq!(rows.len(), 6, "open+outcome+close, twice");

    let first_session_tail = PrevHash::of_line(rows[2].as_bytes());
    let second_open: Value = serde_json::from_str(&rows[3]).unwrap();
    assert_eq!(second_open["line_type"], Value::from("open"));
    assert_eq!(
        second_open["prev_session_tail"],
        Value::from(first_session_tail.to_hex()),
        "the second Open must back-reference the first Session's final line hash"
    );
    // Genesis, not the tail: one fact gets one spelling, and a verifier already
    // special-cases `Open` because that is where the public key lives.
    assert_eq!(
        second_open["prev_hash"],
        Value::from("0".repeat(64)),
        "an Open line always anchors on genesis"
    );
    // `seq` restarts per Session — which is exactly why Coverage is a
    // (session_index, seq) pair and not a bare `seq`.
    assert_eq!(second_open["seq"], Value::from(0u64));

    let result = verify_chain_file(&path).unwrap();
    assert_eq!(result.verdict, Verdict::Verified);
    assert_eq!(result.coverage.unwrap().session_index, 1);
    assert_eq!(result.coverage.unwrap().seq, 2);

    // The first Session's own `Open` carries no back-reference: the file was
    // empty when it was written.
    let first_open: Value = serde_json::from_str(&rows[0]).unwrap();
    assert!(
        first_open.get("prev_session_tail").is_none(),
        "{first_open}"
    );
}

#[test]
fn truncating_a_non_final_session_is_detected() {
    let (_dir, path) = temp_chain();
    two_sessions(&path);
    let mut rows = rows(&path);

    // Drop the first Session's `Close`. The truncated Session is still an
    // internally consistent chain on its own — nothing inside it is missing a
    // predecessor. Detection comes entirely from the later signed `Open`.
    rows.remove(2);
    write_rows(&path, &rows);

    let result = verify_chain_file(&path).unwrap();
    assert!(
        matches!(
            result.verdict,
            Verdict::Tampered {
                reason: botzr_aegis_audit::TamperedReason::SessionBoundaryBroken { .. }
            }
        ),
        "truncating a non-final Session must be Tampered, got {:?}",
        result.verdict
    );

    // The premise: on its own, the truncated Session verifies clean apart from
    // its missing anchor. So the boundary check is doing the work, not luck.
    let orphan = {
        let mut text = rows[..2].join("\n");
        text.push('\n');
        text
    };
    assert!(matches!(
        verify_chain(&orphan).verdict,
        Verdict::Indeterminate {
            reason: IndeterminateReason::UnanchoredTail { .. }
        }
    ));
}

#[test]
fn truncating_the_final_session_is_undecidable_not_tampered() {
    // The honest half of the property. Nothing in the file asserts content
    // beyond the last Session's tail, so removing it leaves an internally
    // consistent chain — a verifier that called this `Tampered` would be
    // guessing, and one that called it `Verified` would be lying.
    let (_dir, path) = temp_chain();
    two_sessions(&path);
    let mut rows = rows(&path);
    rows.pop();
    write_rows(&path, &rows);

    let result = verify_chain_file(&path).unwrap();
    assert!(
        matches!(
            result.verdict,
            Verdict::Indeterminate {
                reason: IndeterminateReason::UnanchoredTail {
                    session_index: 1,
                    ..
                }
            }
        ),
        "the final Session's tail is undecidable, got {:?}",
        result.verdict
    );
}

#[test]
fn close_is_written_on_drop_for_clean_exit_and_for_unwind() {
    let (_dir, base) = temp_chain();
    let dir = base.parent().unwrap();

    let clean = dir.join("clean.jsonl");
    {
        let writer = AuditWriter::open(&clean, provisioned_key()).unwrap();
        writer.emit_outcome(&mut outcome("call-clean")).unwrap();
    }
    assert_eq!(
        verify_chain_file(&clean).unwrap().verdict,
        Verdict::Verified
    );

    let unwound = dir.join("unwound.jsonl");
    let result = std::panic::catch_unwind({
        let unwound = unwound.clone();
        move || {
            let writer = AuditWriter::open(&unwound, provisioned_key()).unwrap();
            writer.emit_outcome(&mut outcome("call-unwound")).unwrap();
            panic!("simulated host panic");
        }
    });
    assert!(result.is_err());
    assert_eq!(
        verify_chain_file(&unwound).unwrap().verdict,
        Verdict::Verified,
        "unwinding still closes the Session, so the file still anchors"
    );
}

#[test]
fn a_session_that_never_dropped_is_indeterminate_which_is_the_sigkill_gap() {
    // DOCUMENTED, NOT ENGINEERED AROUND: `Drop` does not run on SIGKILL, so a
    // killed process leaves a Session with no `Close`. `mem::forget` reproduces
    // exactly that file state in-process — the lines already written are
    // durable (append + flush + fsync per line), and no `Close` follows.
    //
    // The gap is real and it is precisely what produces `Indeterminate` rather
    // than a false `Verified` or a false alarm. Closing it needs an external
    // Anchor, which is not this ticket.
    let (_dir, path) = temp_chain();
    let writer = AuditWriter::open(&path, provisioned_key()).unwrap();
    writer.emit_outcome(&mut outcome("call-killed")).unwrap();
    std::mem::forget(writer);

    let rows = rows(&path);
    assert_eq!(rows.len(), 2, "open + outcome, no close");
    let result = verify_chain_file(&path).unwrap();
    assert!(
        matches!(
            result.verdict,
            Verdict::Indeterminate {
                reason: IndeterminateReason::UnanchoredTail { .. }
            }
        ),
        "got {:?}",
        result.verdict
    );
    // Coverage still reaches the last signed line: the outcome is authentic,
    // and only what may lie *beyond* it is unknown.
    assert_eq!(result.coverage.unwrap().seq, 1);
}

#[test]
fn a_later_session_reopening_the_file_anchors_the_killed_one() {
    // The other half of ADR-0002's consequence: once a *later* Session opens on
    // the same file, the killed Session stops being the final one, and its tail
    // becomes anchored by a signature.
    let (_dir, path) = temp_chain();
    let writer = AuditWriter::open(&path, provisioned_key()).unwrap();
    writer.emit_outcome(&mut outcome("call-killed")).unwrap();
    std::mem::forget(writer);

    {
        let writer = AuditWriter::open(&path, provisioned_key()).unwrap();
        writer.emit_outcome(&mut outcome("call-after")).unwrap();
    }
    assert_eq!(verify_chain_file(&path).unwrap().verdict, Verdict::Verified);

    // And now truncating the killed Session is detectable, where a moment ago
    // it was not.
    let mut rows = rows(&path);
    rows.remove(1);
    write_rows(&path, &rows);
    assert!(matches!(
        verify_chain_file(&path).unwrap().verdict,
        Verdict::Tampered { .. }
    ));
}
