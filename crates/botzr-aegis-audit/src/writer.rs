//! The Session owner: it stamps `seq` and `prev_hash`, signs, hashes the signed
//! form and appends — with the hash chain behind the same lock as the sink
//! handle.
//!
//! **Durability is the sink's claim, not this module's.** The fsync lives in
//! [`FileChainSink`], which declares [`Retention::Durable`]; what this module
//! guarantees is order and failing closed — a write error is returned, never
//! swallowed, and the tail advances only after the sink accepted the line. What
//! the bytes are worth afterwards is whatever the sink's [`Retention`] says
//! (ADR-0012).
//!
//! One `AuditWriter` is one Session — `Open` on construction, `Close` on
//! `Drop`. Chain state (`seq`, tail hash) lives *inside* the sink mutex rather
//! than in a sibling object: two threads that read the chain head outside the
//! lock get the same `prev_hash` and fork the chain, and splitting ordering
//! authority across two objects is how that race gets reintroduced. A Chain may
//! hold many Sessions; `prev_session_tail` on the `Open` line is what links
//! them.
//!
//! **`Drop` does not run on SIGKILL.** Close-on-drop covers clean exit and
//! unwind only. That gap is documented rather than engineered around: a Session
//! with no `Close` and no later `Open` beyond it is exactly what makes a tail
//! undecidable, and a verifier reports it as `Indeterminate` (ADR-0002).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use botzr_aegis_core::{
    to_canonical_json, AuditClose, AuditDecision, AuditIntent, AuditOpen, AuditRecord, KeyId,
    PrevHash, PublicKey, AUDIT_SCHEMA_VERSION,
};

use crate::error::AuditError;
use crate::line::{ChainLine, SignedChainLine};
use crate::signing::{insecure_dev_key, SigningKey};
use crate::sink::{ChainSink, FileChainSink, Retention};

/// Everything the chain rule needs, under one lock.
///
/// Bundled deliberately: `seq`, the tail hash, and the sink handle have to move
/// together or the append order and the chain order can disagree.
struct ChainState {
    /// `Send` is load-bearing, not stylistic: an `AuditWriter` shared across
    /// threads is only `Sync` because everything inside this mutex is `Send`.
    sink: Box<dyn ChainSink + Send>,
    /// Next position to hand out. Per appended **line**, per Session — not per
    /// Call, because concurrent Calls interleave and a Call's intent and
    /// outcome lines are not adjacent.
    next_seq: u64,
    /// Hash of the last line written; the next line's `prev_hash`.
    tail: PrevHash,
}

impl ChainState {
    /// Consume the next chain position. Only ever called with the lock held.
    ///
    /// The counter advances even when the write that follows fails: a gap says
    /// a line was meant to exist and does not, which is the honest reading.
    /// Handing the same number out twice after a partial write would forge a
    /// position instead.
    fn take_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }
}

/// Append-only audit sink and Session owner. Fail-closed: callers must treat
/// write errors as fatal.
pub struct AuditWriter {
    /// Cached from the sink at construction, deliberately *outside* the chain
    /// lock. `path()` is a printer's question, and a printer must not be able to
    /// queue behind an in-flight fsync to learn a value that never changes.
    path: Option<PathBuf>,
    chain: Mutex<ChainState>,
    signing_key: SigningKey,
    /// Names Calls; it does **not** order the chain, so it stays outside the
    /// chain lock. Chain position is `seq`, and only `seq` — a call id is a
    /// label two threads may take in either order without consequence.
    call_seq: AtomicU64,
    /// Whether the `Open` line made it to disk. `Drop` writes `Close` only if
    /// it did, so a writer whose construction failed does not leave a Session
    /// that closes without ever having opened.
    open_emitted: AtomicBool,
}

impl AuditWriter {
    /// Begin a Session over any [`ChainSink`].
    ///
    /// Three things happen, in this order, and the order is the point:
    ///
    /// 1. The sink's declared [`Retention`] is checked against the key. A
    ///    Durable Sink signed by [`insecure_dev_key`] is refused before the
    ///    store is touched at all, so a library embedder inherits the pairing
    ///    rule without going through anyone's argument parsing.
    /// 2. The previous tail is read, for this Session's `prev_session_tail`.
    /// 3. The `Open` line is appended, publishing the public key every later
    ///    line in this Session is verified against (ADR-0004).
    pub fn with_sink(
        sink: Box<dyn ChainSink + Send>,
        signing_key: SigningKey,
    ) -> Result<Self, AuditError> {
        if sink.retention() == Retention::Durable
            && signing_key.key_id() == insecure_dev_key().key_id()
        {
            return Err(AuditError::DurableSinkNeedsProvisionedKey);
        }
        // Uniform across both retentions, deliberately. For a Durable Sink this
        // is the torn-tail refusal: chaining onto bytes nobody can hash twice
        // turns a recoverable `Indeterminate` into a permanent break. For a
        // Volatile one the error is not a chain-integrity claim — but a sink
        // that cannot read the store it is about to write is broken either way,
        // and starting a Session on it would only move the failure to the first
        // append, after an `Open` line had already been emitted.
        let prev_session_tail = sink.existing_tail()?;
        let path = sink.path().map(Path::to_path_buf);
        let writer = Self {
            path,
            chain: Mutex::new(ChainState {
                sink,
                next_seq: 0,
                tail: PrevHash::GENESIS,
            }),
            signing_key,
            call_seq: AtomicU64::new(1),
            open_emitted: AtomicBool::new(false),
        };
        let mut open = AuditOpen::new(writer.signing_key.public_key(), prev_session_tail);
        writer.append_signed(&mut open)?;
        writer.open_emitted.store(true, Ordering::Relaxed);
        Ok(writer)
    }

    /// Open (or create) a Chain file and begin a Session.
    ///
    /// [`AuditWriter::with_sink`] over a [`FileChainSink`], which declares
    /// [`Retention::Durable`] — so this constructor refuses
    /// [`insecure_dev_key`]. A retained file is one somebody will later pin a
    /// `Verified (pinned)` label to, and the dev seed ships in every published
    /// artifact.
    ///
    /// Appending to a non-empty file recovers the previous Session's final line
    /// hash into this Session's `Open` line as `prev_session_tail`. The `Open`
    /// line's own `prev_hash` stays genesis — a verifier already special-cases
    /// `Open`, since that is where the public key is, and duplicating the tail
    /// into `prev_hash` would give one fact two spellings.
    pub fn open(path: impl AsRef<Path>, signing_key: SigningKey) -> Result<Self, AuditError> {
        Self::with_sink(Box::new(FileChainSink::open(path)?), signing_key)
    }

    /// Ephemeral sink for tests and dev defaults — a real temp JSONL file,
    /// signed by [`insecure_dev_key`]. Not a production sink, and not a
    /// production key.
    ///
    /// The temp directory is removed when the writer drops, so the sink
    /// declares [`Retention::Volatile`]: the bytes are fsynced but do not
    /// outlive the process, which is exactly the pairing the dev key is allowed.
    pub fn open_temp() -> Result<Self, AuditError> {
        Self::with_sink(Box::new(FileChainSink::temp()?), insecure_dev_key())
    }

    /// Where this Session's bytes live, when that is a meaningful question.
    ///
    /// `None` for a sink with nothing to point an operator at — an in-memory
    /// Chain has no path, and printing one for it would name a file that does
    /// not exist.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// The public key this Session's `Open` line published — what a verifier
    /// checks every signed line in the file against.
    pub fn public_key(&self) -> PublicKey {
        self.signing_key.public_key()
    }

    /// Fingerprint of the signing key, stamped on every signed line.
    pub fn key_id(&self) -> KeyId {
        self.signing_key.key_id()
    }

    pub fn next_call_id(&self) -> String {
        format!("call-{}", self.call_seq.fetch_add(1, Ordering::Relaxed))
    }

    /// Append the pre-execution intent line. Hashed into the chain and
    /// deliberately not signable — [`AuditIntent`] does not implement
    /// [`SignedChainLine`], because this line is fsynced ahead of execution and
    /// signing must stay off the pre-execution critical path.
    pub fn emit_intent(&self, intent: &mut AuditIntent) -> Result<(), AuditError> {
        self.append_unsigned(intent)
    }

    pub fn emit_outcome(&self, record: &mut AuditRecord) -> Result<(), AuditError> {
        self.append_signed(record)
    }

    /// Append a human approval verdict (ADR-0005). A resumed call is a *new*
    /// Call with its own intent and outcome, linked by `approval_id` — this
    /// line has no intent and no execution of its own.
    pub fn emit_decision(&self, decision: &mut AuditDecision) -> Result<(), AuditError> {
        self.append_signed(decision)
    }

    // There is deliberately no `emit_checkpoint`. `AuditLineType::Checkpoint`
    // is reserved so that adding it later is not a breaking change for every
    // downstream `match`; no emitter in this repo produces one.

    fn lock_chain(&self) -> MutexGuard<'_, ChainState> {
        // A poisoned lock means a previous append panicked mid-write. The chain
        // is append-only and the tail is only advanced after a successful
        // write, so recovering the guard resumes from the last durable line
        // rather than abandoning the sink — an audit writer that stops writing
        // is the failure mode this crate exists to prevent.
        self.chain
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn append_unsigned<L: ChainLine>(&self, line: &mut L) -> Result<(), AuditError> {
        validate_schema(line.schema_version())?;
        let mut state = self.lock_chain();
        // Chain position is chosen *here*, holding the same lock that performs
        // the write. Reading the head outside this lock is what forks a chain.
        let seq = state.take_seq();
        line.stamp_chain(seq, state.tail);
        write_line(&mut state, line)
    }

    fn append_signed<L: SignedChainLine>(&self, line: &mut L) -> Result<(), AuditError> {
        validate_schema(line.schema_version())?;
        let key_id = self.signing_key.key_id();
        let mut state = self.lock_chain();
        // Same lock, same order as `append_unsigned`: stamp position, sign what
        // that produced, hash the signed result, write.
        let seq = state.take_seq();
        line.stamp_chain(seq, state.tail);
        let signature = self
            .signing_key
            .sign(line.signing_input(&key_id)?.as_bytes());
        line.stamp_signature(signature, key_id);
        write_line(&mut state, line)
    }
}

/// Steps 4–6 of the chain rule: hash the complete line, write it, then advance
/// the tail.
///
/// The `line_hash` covers the signature. Stripping a signature therefore
/// changes the hash and breaks the *next* line's `prev_hash`; hashing the
/// pre-signature form instead would let signature-stripping leave a clean
/// chain.
fn write_line<L: serde::Serialize>(state: &mut ChainState, line: &L) -> Result<(), AuditError> {
    // The row on disk is the canonical form, so the bytes a verifier reads are
    // the bytes that were hashed — no re-canonicalization step where the two
    // implementations can disagree, and one serialization instead of two on the
    // fsync path.
    let canonical = to_canonical_json(line)?;
    let line_hash = PrevHash::of_line(canonical.as_bytes());
    state.sink.append(canonical.as_bytes())?;
    // Only after the sink accepted the line: a failed write leaves the next
    // line chained to the last one that actually landed.
    state.tail = line_hash;
    Ok(())
}

impl Drop for AuditWriter {
    fn drop(&mut self) {
        // Nothing to close if the `Open` line never landed.
        if !self.open_emitted.load(Ordering::Relaxed) {
            return;
        }
        // `CallSession<'a>` borrows `&'a AuditWriter`, so the borrow checker
        // already guarantees no Call is in flight here — the `Close` line
        // structurally cannot be written mid-Call.
        //
        // Best-effort: a write failure at drop has nowhere left to go. A
        // Session with no `Close` reads as `Indeterminate`, which is the
        // truthful verdict.
        let _ = self.append_signed(&mut AuditClose::new());
    }
}

impl std::fmt::Debug for AuditWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditWriter")
            .field("path", &self.path)
            .field("key_id", &self.signing_key.key_id())
            .finish_non_exhaustive()
    }
}

fn validate_schema(version: u32) -> Result<(), AuditError> {
    if version != AUDIT_SCHEMA_VERSION {
        return Err(AuditError::UnsupportedSchema {
            found: version,
            supported: AUDIT_SCHEMA_VERSION,
        });
    }
    Ok(())
}

/// Serialize a value to a JSON line (no trailing newline).
pub fn to_json_line<T: serde::Serialize>(value: &T) -> Result<String, AuditError> {
    Ok(serde_json::to_string(value)?)
}

/// SHA-256 over a line's canonical form — what the *next* line carries as its
/// `prev_hash`, and what a verifier recomputes to walk the chain.
pub fn line_hash<T: serde::Serialize>(line: &T) -> Result<PrevHash, AuditError> {
    Ok(PrevHash::of_line(to_canonical_json(line)?.as_bytes()))
}

#[cfg(test)]
mod tests {
    use botzr_aegis_core::{
        AuditLineType, CapabilityOutcome, ExecutionOutcome, PolicyOutcome, PolicySetHash,
        RequestDigest, ToolId,
    };
    use serde_json::Value;

    use super::*;
    use crate::signing::{verify_line, VerifyError};
    use crate::sink::MemoryChainSink;

    /// A fixed seed that is *not* the dev key's, for fixtures that need a
    /// Durable file sink — which refuses [`insecure_dev_key`] (ADR-0012).
    /// Fixed rather than random so a failing test reproduces byte for byte.
    fn provisioned_key() -> SigningKey {
        SigningKey::from_seed([0x2a; 32])
    }

    /// The Session's file. Every writer below is a file sink, so `None` here
    /// would be a bug in the test rather than a case to handle.
    fn file_of(writer: &AuditWriter) -> &Path {
        writer.path().expect("a file sink names its path")
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

    fn lines(path: &Path) -> Vec<Value> {
        std::fs::read_to_string(path)
            .expect("audit file readable")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("every row is JSON"))
            .collect()
    }

    fn raw_lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .expect("audit file readable")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn each_line_chains_to_the_hash_of_the_one_before_it() {
        let writer = AuditWriter::open_temp().unwrap();
        let mut intent = AuditIntent::new(
            "call-1",
            ToolId::new("echo"),
            RequestDigest::of_request_bytes(b"{}"),
        );
        writer.emit_intent(&mut intent).unwrap();
        writer.emit_outcome(&mut outcome("call-1")).unwrap();

        let rows = raw_lines(file_of(&writer));
        assert_eq!(rows.len(), 3, "open + intent + outcome");
        // The Open line anchors on genesis; the back-reference to a previous
        // Session lives in `prev_session_tail`, not here.
        let parsed = lines(file_of(&writer));
        assert_eq!(parsed[0]["prev_hash"], Value::from("0".repeat(64)));
        for index in 1..rows.len() {
            let expected = PrevHash::of_line(rows[index - 1].as_bytes());
            assert_eq!(
                parsed[index]["prev_hash"],
                Value::from(expected.to_hex()),
                "line {index} must chain to line {}",
                index - 1
            );
        }
        // `seq` is per line, per Session, starting at the Open line.
        for (index, row) in parsed.iter().enumerate() {
            assert_eq!(row["seq"], Value::from(index as u64));
        }
    }

    #[test]
    fn a_signed_line_verifies_against_the_public_key_in_the_open_line() {
        let writer = AuditWriter::open_temp().unwrap();
        writer.emit_outcome(&mut outcome("call-1")).unwrap();

        let rows = raw_lines(file_of(&writer));
        let open: AuditOpen = serde_json::from_str(&rows[0]).unwrap();
        let record: AuditRecord = serde_json::from_str(&rows[1]).unwrap();
        assert_eq!(*open.line_type(), AuditLineType::Open);
        assert_eq!(verify_line(&open, &open.public_key), Ok(()));
        assert_eq!(verify_line(&record, &open.public_key), Ok(()));
        assert_eq!(record.key_id(), Some(&writer.key_id()));
    }

    #[test]
    fn tampering_with_any_field_makes_the_signature_fail() {
        let writer = AuditWriter::open_temp().unwrap();
        writer.emit_outcome(&mut outcome("call-1")).unwrap();
        let rows = raw_lines(file_of(&writer));
        let open: AuditOpen = serde_json::from_str(&rows[0]).unwrap();

        for (field, replacement) in [
            ("call_id", Value::from("call-2")),
            ("tool_id", Value::from("rm")),
            ("seq", Value::from(99u64)),
            ("prev_hash", Value::from("f".repeat(64))),
            (
                "policy",
                serde_json::json!({ "status": "denied", "reason": "after the fact" }),
            ),
            ("decision_axes", serde_json::json!({ "role": "admin" })),
        ] {
            let mut value: Value = serde_json::from_str(&rows[1]).unwrap();
            let previous = value[field].clone();
            value[field] = replacement;
            assert_ne!(value[field], previous, "{field} must actually change");
            let tampered: AuditRecord = serde_json::from_value(value).unwrap();
            assert_eq!(
                verify_line(&tampered, &open.public_key),
                Err(VerifyError::BadSignature),
                "editing {field} must break the signature"
            );
        }
    }

    #[test]
    fn stripping_a_signature_changes_the_line_hash() {
        let writer = AuditWriter::open_temp().unwrap();
        writer.emit_outcome(&mut outcome("call-1")).unwrap();
        let rows = raw_lines(file_of(&writer));
        let signed = PrevHash::of_line(rows[1].as_bytes());

        let mut value: Value = serde_json::from_str(&rows[1]).unwrap();
        assert!(value.as_object_mut().unwrap().remove("signature").is_some());
        let stripped = PrevHash::of_line(to_canonical_json(&value).unwrap().as_bytes());
        // The chain, not just the signature check, is what catches this: the
        // next line's `prev_hash` no longer matches.
        assert_ne!(signed, stripped);
    }

    #[test]
    fn a_fresh_file_opens_without_a_back_reference_and_a_reopen_chains_to_the_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.jsonl");

        {
            let writer = AuditWriter::open(&path, provisioned_key()).unwrap();
            let first = &lines(&path)[0];
            assert!(
                first.get("prev_session_tail").is_none(),
                "a fresh file has no previous Session: {first}"
            );
            writer.emit_outcome(&mut outcome("call-1")).unwrap();
        }

        let first_session = raw_lines(&path);
        let tail = PrevHash::of_line(first_session.last().unwrap().as_bytes());

        let _second = AuditWriter::open(&path, provisioned_key()).unwrap();
        let rows = lines(&path);
        let reopened = &rows[first_session.len()];
        assert_eq!(reopened["line_type"], Value::from("open"));
        assert_eq!(
            reopened["prev_session_tail"],
            Value::from(tail.to_hex()),
            "the new Open must back-reference the previous Session's final line"
        );
        // Genesis, not the tail — the tail is not duplicated into `prev_hash`.
        assert_eq!(reopened["prev_hash"], Value::from("0".repeat(64)));
        assert_eq!(
            reopened["seq"],
            Value::from(0u64),
            "seq restarts per Session"
        );
    }

    #[test]
    fn close_is_written_on_drop_for_clean_exit_and_for_unwind() {
        let dir = tempfile::tempdir().unwrap();

        let clean = dir.path().join("clean.jsonl");
        {
            let _writer = AuditWriter::open(&clean, provisioned_key()).unwrap();
        }
        let rows = lines(&clean);
        assert_eq!(rows.last().unwrap()["line_type"], Value::from("close"));

        let unwound = dir.path().join("unwound.jsonl");
        let result = std::panic::catch_unwind({
            let unwound = unwound.clone();
            move || {
                let _writer = AuditWriter::open(&unwound, provisioned_key()).unwrap();
                panic!("simulated host panic");
            }
        });
        assert!(result.is_err());
        let rows = lines(&unwound);
        assert_eq!(
            rows.last().unwrap()["line_type"],
            Value::from("close"),
            "unwinding still closes the Session"
        );
        // Documented gap, asserted nowhere: SIGKILL skips `Drop` entirely, and
        // the missing Close is what a verifier reports as `Indeterminate`.
    }

    #[test]
    fn intent_lines_carry_no_signature() {
        let writer = AuditWriter::open_temp().unwrap();
        let mut intent = AuditIntent::new(
            "call-1",
            ToolId::new("echo"),
            RequestDigest::of_request_bytes(b"{}"),
        );
        writer.emit_intent(&mut intent).unwrap();
        let row = &lines(file_of(&writer))[1];
        assert_eq!(row["line_type"], Value::from("intent"));
        assert!(row.get("signature").is_none(), "{row}");
        assert!(row.get("key_id").is_none(), "{row}");
        // Still hashed into the chain: the next line points at it.
        writer.emit_outcome(&mut outcome("call-1")).unwrap();
        let rows = raw_lines(file_of(&writer));
        let next: AuditRecord = serde_json::from_str(&rows[2]).unwrap();
        assert_eq!(*next.prev_hash(), PrevHash::of_line(rows[1].as_bytes()));
    }

    #[test]
    fn concurrent_appends_produce_one_unforked_chain() {
        let writer = AuditWriter::open_temp().unwrap();
        std::thread::scope(|scope| {
            for thread in 0..8 {
                scope.spawn({
                    let writer = &writer;
                    move || {
                        for call in 0..4 {
                            writer
                                .emit_outcome(&mut outcome(&format!("call-{thread}-{call}")))
                                .unwrap();
                        }
                    }
                });
            }
        });

        let rows = raw_lines(file_of(&writer));
        assert_eq!(rows.len(), 1 + 8 * 4);
        let parsed = lines(file_of(&writer));
        for (index, row) in parsed.iter().enumerate() {
            assert_eq!(row["seq"], Value::from(index as u64), "seq must not repeat");
            if index > 0 {
                assert_eq!(
                    row["prev_hash"],
                    Value::from(PrevHash::of_line(rows[index - 1].as_bytes()).to_hex()),
                    "line {index} forked off the chain"
                );
            }
        }
    }

    #[test]
    fn rejects_unsupported_schema() {
        // The field is sealed against direct mutation (AEG-45), so the only way
        // an unsupported version reaches the writer is a foreign/tampered record
        // deserialized from the wire — exactly what this guard is for.
        let writer = AuditWriter::open_temp().unwrap();
        let mut intent: AuditIntent = serde_json::from_str(
            r#"{"schema_version":999,"line_type":"intent","seq":0,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","call_id":"call-1","tool_id":"smoke","request_digest":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}"#,
        )
        .expect("intent with a foreign schema version still deserializes");
        assert_eq!(intent.schema_version(), 999);
        let err = writer.emit_intent(&mut intent).unwrap_err();
        assert!(matches!(err, AuditError::UnsupportedSchema { .. }));
    }

    #[test]
    fn a_torn_tail_refuses_to_open_rather_than_chaining_onto_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("torn.jsonl");
        drop(AuditWriter::open(&path, provisioned_key()).unwrap());
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"line_type\":\"outcome\",\"seq\"");
        std::fs::write(&path, text).unwrap();

        let err = AuditWriter::open(&path, provisioned_key()).unwrap_err();
        assert!(matches!(err, AuditError::TornTail { .. }), "{err:?}");
    }

    /// A sink that claims [`Retention::Durable`] while holding its bytes in
    /// memory. The pairing rule is about the *declaration*, so the refusal is
    /// checkable without a filesystem — and "nothing was written" is then a
    /// statement about a buffer rather than about a stat call.
    struct DurableStub(MemoryChainSink);

    impl ChainSink for DurableStub {
        fn retention(&self) -> Retention {
            Retention::Durable
        }
        fn existing_tail(&self) -> Result<Option<PrevHash>, AuditError> {
            self.0.existing_tail()
        }
        fn append(&mut self, line: &[u8]) -> Result<(), AuditError> {
            self.0.append(line)
        }
        fn path(&self) -> Option<&Path> {
            None
        }
    }

    #[test]
    fn a_durable_sink_refuses_the_dev_key_and_leaves_no_open_line() {
        let store = MemoryChainSink::new();
        let err = AuditWriter::with_sink(
            Box::new(DurableStub(store.clone())),
            crate::signing::insecure_dev_key(),
        )
        .unwrap_err();
        assert!(
            matches!(err, AuditError::DurableSinkNeedsProvisionedKey),
            "{err:?}"
        );
        // The negative half is the point: a refused construction must not leave
        // a Session that opened and will never close.
        assert!(
            store.bytes().is_empty(),
            "refused construction wrote: {}",
            store.to_text()
        );

        // `open` is `with_sink` over a Durable file sink, so it inherits the
        // refusal — and writes no `Open` line either.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("refused.jsonl");
        let err = AuditWriter::open(&path, crate::signing::insecure_dev_key()).unwrap_err();
        assert!(
            matches!(err, AuditError::DurableSinkNeedsProvisionedKey),
            "{err:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap_or_default(),
            "",
            "a refused Durable sink must hold no Open line"
        );

        // The same key over a Volatile sink is allowed — that pairing is what
        // keeps `open_temp` and the runtime's default sink working.
        assert!(
            AuditWriter::with_sink(
                Box::new(MemoryChainSink::new()),
                crate::signing::insecure_dev_key()
            )
            .is_ok(),
            "only Durable sinks refuse the dev key"
        );
    }

    #[test]
    fn an_in_memory_session_round_trips_and_verifies() {
        let store = MemoryChainSink::new();
        {
            let writer =
                AuditWriter::with_sink(Box::new(store.clone()), crate::signing::insecure_dev_key())
                    .unwrap();
            assert_eq!(writer.path(), None, "an in-memory Chain names no file");
            let mut intent = AuditIntent::new(
                "call-1",
                ToolId::new("echo"),
                RequestDigest::of_request_bytes(b"{}"),
            );
            writer.emit_intent(&mut intent).unwrap();
            writer.emit_outcome(&mut outcome("call-1")).unwrap();
            // Dropped here, so the `Close` line is part of what is read back.
        }

        let text = store.to_text();
        let rows: Vec<&str> = text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert_eq!(rows.len(), 4, "open + intent + outcome + close: {text}");
        // The bytes, not the writer, are what a verifier sees — so this is the
        // assertion that the seam did not change them.
        let verification = crate::verify_chain(&text);
        assert_eq!(
            verification.verdict,
            crate::Verdict::Verified,
            "{verification:?}"
        );
        for (index, row) in rows.iter().enumerate().skip(1) {
            let parsed: Value = serde_json::from_str(row).unwrap();
            assert_eq!(
                parsed["prev_hash"],
                Value::from(PrevHash::of_line(rows[index - 1].as_bytes()).to_hex()),
                "line {index} forked off the chain"
            );
        }
    }

    /// A Durable sink that cannot read its own tail. `append` panics because
    /// reaching it at all would mean a Session opened on a store the writer
    /// could not chain onto.
    struct UnreadableDurableSink;

    impl ChainSink for UnreadableDurableSink {
        fn retention(&self) -> Retention {
            Retention::Durable
        }
        fn existing_tail(&self) -> Result<Option<PrevHash>, AuditError> {
            Err(AuditError::TornTail { line: 7 })
        }
        fn append(&mut self, _line: &[u8]) -> Result<(), AuditError> {
            unreachable!("construction must fail before any line is appended")
        }
        fn path(&self) -> Option<&Path> {
            None
        }
    }

    #[test]
    fn a_durable_sink_that_cannot_read_its_tail_fails_construction() {
        let err = AuditWriter::with_sink(Box::new(UnreadableDurableSink), provisioned_key())
            .expect_err("a Durable sink with an unreadable tail must fail closed");
        assert!(matches!(err, AuditError::TornTail { line: 7 }), "{err:?}");
    }
}
