//! The three-state verdict a Chain file gets, computed from Coverage plus
//! Anchor presence (ADR-0002).
//!
//! **This is the library primitive only.** AILAB-621's `aegis verify` CLI wraps
//! it: that ticket owns the output format and the exit codes ADR-0002 pins
//! (0 verified, 1 tampered, 2 could-not-read, 3 indeterminate). Nothing here
//! parses arguments or prints anything, and nothing here should start to.
//!
//! Why not a boolean: content beyond the last signature is unverifiable by
//! construction, and truncating a Chain leaves an internally consistent Chain.
//! A gate that fails on every in-progress file is noise within a week; a gate
//! that passes with a warning is exit 0 to every `if aegis verify; then`. So the
//! answer is `Verified`, `Indeterminate` with a typed reason, or `Tampered`.
//!
//! What this walk can and cannot decide:
//!
//! - Truncating a **non-final** Session is `Tampered`. The next Session's `Open`
//!   line carries `prev_session_tail`, so the truncation contradicts a later
//!   signature — detected, with no external witness. That is a materially
//!   better property than "we cannot detect truncation."
//! - Only the **final** Session's tail is undecidable, and only when nothing
//!   anchors beyond it. That is what `Drop`-not-running-on-SIGKILL produces.
//! - A line type this build does not recognise caps the verdict at
//!   `Indeterminate`. A verifier must never report `Verified` over content it
//!   does not understand, or a future emitter can smuggle anything past an old
//!   auditor. `Checkpoint` is reserved and unemitted by v0, so a v0 verifier
//!   meeting one treats it the same way — it is a signed line, so it extends
//!   Coverage, but it still caps the verdict.
//!
//! The walk also takes an optional **trust slice** of `PublicKey`s the caller
//! anchored out of band (ADR-0004). Pinning is *identity checking, not a second
//! signature path*: signatures always verify against the key the Session `Open`
//! line publishes, and the slice only answers "is that key one of mine?". With
//! no slice the answer is `Unpinned` — some Aegis build wrote this file, and
//! nothing in the file says whose build.

use std::path::Path;

use botzr_aegis_core::{
    line_type_field, to_canonical_json, AuditLineType, KeyId, PrevHash, PublicKey, SessionCounter,
};
use serde_json::Value;

use crate::error::AuditError;
use crate::signing::{verify_json_line, VerifyError};

/// A line's address in a Chain file.
///
/// **Coverage is `(session_index, seq)`, not `seq`.** ADR-0002 defines Coverage
/// as "the highest `seq` covered by a valid signature", which reads file-global;
/// `seq` in fact restarts at 0 per Session (amendment §2.1, "per appended line,
/// per Session"). Those disagree the moment one file holds two Sessions — `seq`
/// 5 is two different lines — so the position that Coverage names has to carry
/// the Session with it. `session_index` is the Session's ordinal within the
/// file, counted from the first `Open` line by [`SessionCounter`], which is
/// also what `aegis recheck` counts with — so an address printed by one verb
/// names the same Session as an address printed by the other (ADR-0013).
/// SPEC.md (AILAB-623) must state this; the ADR's wording is under-specified
/// rather than wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position {
    pub session_index: usize,
    pub seq: u64,
}

impl std::fmt::Display for Position {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session {} seq {}", self.session_index, self.seq)
    }
}

/// Why a Chain could not be fully verified, though nothing contradicted it.
///
/// `#[non_exhaustive]`: new reasons are new knowledge about files in the wild,
/// and adding one must not break a downstream `match`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndeterminateReason {
    /// A line type this build does not recognise, with the emitter's own token
    /// preserved so the message can name it.
    UnknownLineType { at: Position, line_type: String },
    /// A reserved `Checkpoint`. It is a signed line, so it extends Coverage —
    /// but v0 does not know what a Checkpoint asserts, and a verifier does not
    /// pass content it cannot read.
    ReservedCheckpoint { at: Position },
    /// The file's **final** line does not parse — a torn write, distinct from
    /// "no close record". Note `AuditWriter::open` refuses to append onto a
    /// torn tail; a verdict is a different consumer and classifies instead.
    TornFinalLine { line: usize },
    /// The final Session has no `Close` and nothing anchors beyond its tail, so
    /// content may have been truncated after the last signature and no evidence
    /// in the file can say. This is the SIGKILL case, and the live-file case.
    UnanchoredTail {
        session_index: usize,
        /// Calls with an intent line and no outcome — the tail is always a set
        /// of in-flight Calls, and three intents for workspace reads is a shrug
        /// where one for `net.post` is where an operator starts looking.
        in_flight_calls: Vec<String>,
    },
    /// `seq` jumped forward while `prev_hash` still matched — a line was meant
    /// to exist and does not.
    ///
    /// Only the writer can produce this: it takes `seq` before the append and
    /// advances the tail only after the write lands, so a failed write leaves a
    /// gap with the chain intact. An attacker cannot: removing a line breaks the
    /// next line's `prev_hash`, and re-signing the remainder needs the key. So
    /// this is a durability incident, not a forgery, and calling it `Tampered`
    /// would be the "alarms on healthy systems" failure ADR-0002 exists to
    /// avoid.
    MissingLine {
        session_index: usize,
        expected: u64,
        found: u64,
    },
    /// No lines at all. Nothing contradicts the file; there is also nothing in
    /// it to verify.
    EmptyChain,
}

impl std::fmt::Display for IndeterminateReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownLineType { at, line_type } => {
                write!(f, "unknown line type `{line_type}` at {at}, newer emitter")
            }
            Self::ReservedCheckpoint { at } => {
                write!(f, "reserved checkpoint line at {at}, not defined by v0")
            }
            Self::TornFinalLine { line } => {
                write!(f, "final line {line} does not parse; torn write")
            }
            Self::UnanchoredTail {
                session_index,
                in_flight_calls,
            } => write!(
                f,
                "session {session_index} has no close record and nothing anchors beyond it; {} call(s) in flight",
                in_flight_calls.len()
            ),
            Self::MissingLine {
                session_index,
                expected,
                found,
            } => write!(
                f,
                "session {session_index} skips seq {expected}..{found} with the chain intact; a write did not land"
            ),
            Self::EmptyChain => f.write_str("no lines to verify"),
        }
    }
}

/// Why a Chain contradicts itself. Any one of these is evidence of an edit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TamperedReason {
    /// A line's `prev_hash` is not the hash of the line before it — an edit, a
    /// removed line, or a forked chain.
    ChainBroken {
        at: Position,
        expected: PrevHash,
        found: PrevHash,
    },
    /// `seq` repeated or went backwards. Two lines at one position is what a
    /// chain fork looks like from the file, and no writer can produce it — the
    /// position is taken under the same lock as the append.
    ///
    /// A `seq` that jumps *forward* over an intact chain is a different thing
    /// entirely: see [`IndeterminateReason::MissingLine`].
    SeqOutOfOrder {
        session_index: usize,
        expected: u64,
        found: u64,
    },
    /// A line that must be signed carries no signature, or one that does not
    /// verify against the key its Session published. A stripped signature on an
    /// outcome line lands here — the unverified tail may hold intent lines and
    /// at most one torn final line, never an outcome. A `key_id` that changes
    /// mid-Session also lands here, as [`VerifyError::KeyMismatch`]: a new key
    /// is legal only when a Session `Open` introduces it.
    BadSignature { at: Position, source: VerifyError },
    /// A Session's `prev_session_tail` does not match the previous Session's
    /// final line. **This is how truncating a non-final Session is caught.**
    SessionBoundaryBroken {
        session_index: usize,
        expected: PrevHash,
        found: Option<PrevHash>,
    },
    /// A line outside the format: not JSON (and not the final line), not an
    /// object, missing or ill-typed `line_type` / `seq` / `prev_hash`, or
    /// outside the JCS value space so it has no reproducible hash. Not
    /// `Indeterminate`: the file is decidably not a valid Chain.
    MalformedLine { line: usize, detail: String },
    /// A Session published a key the caller's trust slice does not contain.
    ///
    /// Not `Unpinned`: the caller said which keys it accepts, and this file
    /// answers with another one. Rotation is legal — every `Open` in the file
    /// must be in the store, not one of them — so several distinct keys pass
    /// and one unknown key fails.
    UntrustedKey { at: Position, key_id: KeyId },
    /// A second `Decision` line for an `approval_id` already decided in this
    /// file. One park, one verdict: a re-decision would let a denial be
    /// overwritten by an approval with both lines validly signed.
    DuplicateDecision { at: Position, approval_id: String },
}

impl std::fmt::Display for TamperedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChainBroken {
                at,
                expected,
                found,
            } => write!(
                f,
                "line at {at} chains to {found}, but the line before it hashes to {expected}"
            ),
            Self::SeqOutOfOrder {
                session_index,
                expected,
                found,
            } => write!(
                f,
                "session {session_index} expected seq {expected}, found {found}"
            ),
            Self::BadSignature { at, source } => write!(f, "line at {at}: {source}"),
            Self::SessionBoundaryBroken {
                session_index,
                expected,
                found,
            } => match found {
                Some(found) => write!(
                    f,
                    "session {session_index} back-references {found}, but the previous session ends at {expected}"
                ),
                None => write!(
                    f,
                    "session {session_index} carries no prev_session_tail, but the previous session ends at {expected}"
                ),
            },
            Self::MalformedLine { line, detail } => write!(f, "line {line}: {detail}"),
            // The printed value is the *fingerprint*, and it has to say so:
            // `key_id` and `PublicKey` are both 64 lowercase hex, so an
            // operator who pastes this value into `--key` would otherwise be
            // told the file publishes exactly the string they just supplied.
            Self::UntrustedKey { at, key_id } => write!(
                f,
                "session opened at {at} publishes a key with fingerprint {key_id}, which is not in the supplied trust store (--key takes the 64-hex public key, not this fingerprint)"
            ),
            Self::DuplicateDecision { at, approval_id } => write!(
                f,
                "line at {at} decides approval {approval_id} a second time"
            ),
        }
    }
}

/// The three states, and only three (ADR-0002).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Verified,
    Indeterminate { reason: IndeterminateReason },
    Tampered { reason: TamperedReason },
}

/// Whether a verdict's key was anchored out of band (ADR-0004).
///
/// `Unpinned` is the honest default and not a soft failure: a valid signature
/// proves *some* Aegis build wrote the file, and only a key the caller supplied
/// from outside the file can say whose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLabel {
    Unpinned,
    Pinned,
}

/// A verdict plus how far a valid signature reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub verdict: Verdict,
    /// Coverage: the highest position covered by a valid signature, or `None`
    /// when nothing was. See [`Position`] for why this is a pair.
    pub coverage: Option<Position>,
    /// Every key a Session `Open` published, in first-seen order, de-duplicated.
    /// More than one is legal rotation, not a finding.
    pub key_ids: Vec<KeyId>,
    /// `Pinned` only when a trust slice was supplied **and** the verdict is
    /// `Verified`. Pinning a file that does not verify would name a key for a
    /// chain nobody should be reading in the first place.
    pub trust: TrustLabel,
}

impl Verification {
    pub fn is_verified(&self) -> bool {
        matches!(self.verdict, Verdict::Verified)
    }
}

/// Read a Chain file and compute its verdict.
///
/// An I/O failure is `Err` rather than a verdict: "could not read" is a
/// different answer from any of the three, and ADR-0002 gives it its own exit
/// code.
pub fn verify_chain_file(path: impl AsRef<Path>) -> Result<Verification, AuditError> {
    verify_chain_file_with_trust(path, None)
}

/// Compute the verdict for a Chain file's contents.
///
/// Deterministic: same bytes, same verdict, always.
pub fn verify_chain(text: &str) -> Verification {
    verify_chain_with_trust(text, None)
}

/// [`verify_chain_file`], against keys the caller anchored out of band.
///
/// See [`verify_chain_with_trust`] for what supplying a slice does and does not
/// mean.
pub fn verify_chain_file_with_trust(
    path: impl AsRef<Path>,
    trust: Option<&[PublicKey]>,
) -> Result<Verification, AuditError> {
    Ok(verify_chain_with_trust(
        &std::fs::read_to_string(path)?,
        trust,
    ))
}

/// [`verify_chain`], against keys the caller anchored out of band (ADR-0004).
///
/// **Pinning is identity, not a second crypto path.** Signatures are checked
/// against the key each Session `Open` publishes either way; the slice only
/// decides whether that key is one the caller accepts. So `Some(keys)` cannot
/// make a broken chain verify, and it cannot make a sound one verify "more
/// strongly" — it upgrades the *label* from `Unpinned` to `Pinned`.
///
/// A supplied slice that is missing an `Open` key is `Tampered`, never
/// `Unpinned`: the caller stated which keys it accepts and the file answered
/// with another one. Every `Open` must be in the slice, so rotation across
/// Sessions stays legal while an unknown key does not.
pub fn verify_chain_with_trust(text: &str, trust: Option<&[PublicKey]>) -> Verification {
    Walk {
        trust,
        ..Default::default()
    }
    .run(text)
}

/// Chain state while walking. Mirrors what the writer holds under its lock —
/// position and tail — plus the Session's published key.
#[derive(Default)]
struct Walk<'a> {
    /// Session ordinals, counted by the rule `aegis recheck` also counts by
    /// (ADR-0013) rather than by a local expression the two have to be kept in
    /// agreement by hand.
    sessions: SessionCounter,
    expected_seq: u64,
    tail: Option<PrevHash>,
    public_key: Option<PublicKey>,
    coverage: Option<Position>,
    /// First cap wins: the earliest thing a verifier could not read is the one
    /// worth reporting.
    cap: Option<IndeterminateReason>,
    in_flight_calls: Vec<String>,
    ends_with_verified_close: bool,
    /// Keys the caller anchored out of band, or `None` for an unpinned walk.
    trust: Option<&'a [PublicKey]>,
    /// Observed `Open` keys, first-seen order — a `Vec` and not a set because
    /// the order is reported.
    key_ids: Vec<KeyId>,
    /// Every `approval_id` this file has already decided.
    seen_approvals: std::collections::HashSet<String>,
}

impl Walk<'_> {
    fn run(mut self, text: &str) -> Verification {
        let rows: Vec<&str> = text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        if rows.is_empty() {
            return self.finish(Verdict::Indeterminate {
                reason: IndeterminateReason::EmptyChain,
            });
        }
        for (index, row) in rows.iter().enumerate() {
            let line_number = index + 1;
            let is_final = index + 1 == rows.len();
            match self.step(row, line_number, is_final) {
                Ok(()) => {}
                Err(Stop::Tampered(reason)) => {
                    return self.finish(Verdict::Tampered { reason });
                }
                // A torn final line stops the walk without contradicting
                // anything before it: everything already covered stays covered.
                Err(Stop::Torn(reason)) => {
                    self.cap.get_or_insert(reason);
                    break;
                }
            }
        }
        if let Some(reason) = self.cap.take() {
            return self.finish(Verdict::Indeterminate { reason });
        }
        if self.ends_with_verified_close {
            return self.finish(Verdict::Verified);
        }
        let reason = IndeterminateReason::UnanchoredTail {
            session_index: self.sessions.current(),
            in_flight_calls: std::mem::take(&mut self.in_flight_calls),
        };
        self.finish(Verdict::Indeterminate { reason })
    }

    fn finish(self, verdict: Verdict) -> Verification {
        let trust = match (self.trust, &verdict) {
            (Some(_), Verdict::Verified) => TrustLabel::Pinned,
            _ => TrustLabel::Unpinned,
        };
        Verification {
            verdict,
            coverage: self.coverage,
            key_ids: self.key_ids,
            trust,
        }
    }

    fn step(&mut self, row: &str, line_number: usize, is_final: bool) -> Result<(), Stop> {
        let value: Value = match serde_json::from_str(row) {
            Ok(value) => value,
            // Only the *last* line can be a torn write: the writer refuses to
            // append onto a torn tail, so garbage anywhere else was put there
            // after the fact.
            Err(_) if is_final => {
                return Err(Stop::Torn(IndeterminateReason::TornFinalLine {
                    line: line_number,
                }))
            }
            Err(error) => return Err(malformed(line_number, format!("not JSON: {error}"))),
        };
        // Hash the canonical form, not the raw bytes: that is what the writer
        // hashed, and a foreign emitter's spacing must not change a line hash.
        let canonical = to_canonical_json(&value).map_err(|error| {
            Stop::Tampered(TamperedReason::MalformedLine {
                line: line_number,
                detail: format!(
                    "outside the canonical value space, so it has no reproducible hash: {error}"
                ),
            })
        })?;
        let line_hash = PrevHash::of_line(canonical.as_bytes());

        // LOAD-BEARING: the *field*, never the schema-v1 `phase` fallback. A
        // verifier that routed on `line_type_from_value` would start finding a
        // routable line type on v1 records — which carry no chain, no `seq` and
        // no signature — and this walk's whole subject is the chain. Refusing
        // them here is the deliberate half of ADR-0013's asymmetry: `aegis
        // recheck` reads v1, `aegis verify` does not, and neither reading is
        // reachable from the other's call site.
        let line_type = line_type_field(&value)
            .ok_or_else(|| malformed_reason(line_number, "no line_type"))
            .map_err(Stop::Tampered)?;
        let seq = value
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| malformed_reason(line_number, "no seq"))
            .map_err(Stop::Tampered)?;
        let prev_hash = value
            .get("prev_hash")
            .and_then(Value::as_str)
            .and_then(|hex| PrevHash::from_hex(hex).ok())
            .ok_or_else(|| malformed_reason(line_number, "no prev_hash"))
            .map_err(Stop::Tampered)?;

        self.ends_with_verified_close = false;
        if line_type == AuditLineType::Open {
            self.open_session(&value, line_number, seq, prev_hash)?;
        } else {
            self.continue_session(line_number, seq, prev_hash)?;
        }
        let at = Position {
            session_index: self.sessions.current(),
            seq,
        };

        match line_type {
            // The Open line publishes the key and signs itself. Checking it
            // against its own key is what "Verified (unpinned)" means: some
            // Aegis build wrote this, and the file says which key, but nothing
            // in the file says that key is yours (ADR-0004).
            AuditLineType::Open | AuditLineType::Outcome => {
                self.require_signature(&value, at)?;
            }
            AuditLineType::Decision => {
                self.require_signature(&value, at)?;
                // One park, one verdict. `approval_id` is a bare JSON string on
                // the wire (`ApprovalId` is `#[serde(transparent)]`). A second
                // Decision for the same park would let a denial be overwritten
                // by an approval with both lines validly signed, so the chain
                // being intact is not enough to accept it.
                if let Some(approval_id) = value.get("approval_id").and_then(Value::as_str) {
                    if !self.seen_approvals.insert(approval_id.to_owned()) {
                        return Err(Stop::Tampered(TamperedReason::DuplicateDecision {
                            at,
                            approval_id: approval_id.to_owned(),
                        }));
                    }
                }
            }
            AuditLineType::Close => {
                self.require_signature(&value, at)?;
                self.ends_with_verified_close = true;
            }
            AuditLineType::Intent => {
                // Never signed — fsynced ahead of execution, so signing stays
                // off the pre-execution path. It is still hashed into the
                // chain, and the next signature covers it transitively.
                if let Some(call_id) = value.get("call_id").and_then(Value::as_str) {
                    self.in_flight_calls.push(call_id.to_owned());
                }
            }
            AuditLineType::Checkpoint => {
                // Signed, so it is in the signed set and its signature has to
                // hold — discarding the result here would let a forged
                // Checkpoint hide behind the cap (SPEC.md §8.4). It still caps
                // the verdict, because v0 does not know what it asserts.
                self.require_signature(&value, at)?;
                self.cap
                    .get_or_insert(IndeterminateReason::ReservedCheckpoint { at });
            }
            AuditLineType::Unknown(ref token) => {
                // Hashes like any other bytes, so the chain survives it. The
                // verdict does not: reporting `Verified` over content this
                // build cannot read is how a newer emitter smuggles a line past
                // an old auditor.
                //
                // Whether an unknown type *must* be signed is unknowable here,
                // so an unsigned one only caps. A signature that is present and
                // does not verify is a different claim: forgery is decidable
                // without understanding the line, and it outranks the cap.
                //
                // LOAD-BEARING: "present" is read off the JSON, not inferred
                // from the error. `verify_json_line` reports `Unsigned` when
                // *either* `signature` or `key_id` is missing, so keying the
                // benign arm on the error variant would let a forger delete
                // `key_id` and turn a decidable forgery back into "we could not
                // read it" — capping at `Indeterminate` over a line that
                // carries a signature which does not authenticate.
                let carries_signature = value.get("signature").is_some();
                match self.try_signature(&value, at) {
                    Ok(()) => {}
                    Err(VerifyError::Unsigned) if !carries_signature => {}
                    Err(source) => {
                        return Err(Stop::Tampered(TamperedReason::BadSignature { at, source }))
                    }
                }
                self.cap
                    .get_or_insert(IndeterminateReason::UnknownLineType {
                        at,
                        line_type: token.clone(),
                    });
            }
            // `AuditLineType` is `#[non_exhaustive]`; a variant added upstream
            // reaches here and must not be treated as understood.
            ref other => {
                self.cap
                    .get_or_insert(IndeterminateReason::UnknownLineType {
                        at,
                        line_type: other.to_string(),
                    });
            }
        }

        self.tail = Some(line_hash);
        self.expected_seq = seq + 1;
        Ok(())
    }

    /// Start a Session and check that it joins the one before it.
    fn open_session(
        &mut self,
        value: &Value,
        line_number: usize,
        seq: u64,
        prev_hash: PrevHash,
    ) -> Result<(), Stop> {
        // Peeked, not taken: this Open is still entitled to be refused below,
        // and every refusal names the Session it would have been.
        let session_index = self.sessions.next_index();
        if seq != 0 {
            return Err(Stop::Tampered(TamperedReason::SeqOutOfOrder {
                session_index,
                expected: 0,
                found: seq,
            }));
        }
        // The back-reference lives in `prev_session_tail`; `prev_hash` on an
        // Open is always genesis, so the tail is not given two spellings.
        if prev_hash != PrevHash::GENESIS {
            return Err(malformed(
                line_number,
                "open line does not anchor on the genesis digest",
            ));
        }
        let back_reference = value
            .get("prev_session_tail")
            .and_then(Value::as_str)
            .and_then(|hex| PrevHash::from_hex(hex).ok());
        if let Some(previous_tail) = self.tail {
            // LOAD-BEARING: this single comparison is what makes truncating a
            // non-final Session detectable. Drop lines off the end of Session
            // N and its tail changes, so Session N+1's signed `Open` no longer
            // agrees with it — `Tampered`, from the file alone, with no
            // external witness.
            if back_reference != Some(previous_tail) {
                return Err(Stop::Tampered(TamperedReason::SessionBoundaryBroken {
                    session_index,
                    expected: previous_tail,
                    found: back_reference,
                }));
            }
        }
        let public_key = value
            .get("public_key")
            .and_then(Value::as_str)
            .and_then(|hex| PublicKey::from_hex(hex).ok())
            .ok_or_else(|| malformed_reason(line_number, "open line carries no public key"))
            .map_err(Stop::Tampered)?;
        let key_id = KeyId::of_public_key(&public_key);
        if !self.key_ids.contains(&key_id) {
            self.key_ids.push(key_id);
        }
        // LOAD-BEARING: *every* Open must be in the store, not merely one of
        // them. Rotation is legal and an unknown key is not, so a file that
        // rotates into a key the caller never anchored has to fail here — the
        // remaining Sessions' signatures would otherwise verify happily against
        // a key the file supplied to itself.
        if let Some(keys) = self.trust {
            if !keys.contains(&public_key) {
                return Err(Stop::Tampered(TamperedReason::UntrustedKey {
                    at: Position { session_index, seq },
                    key_id,
                }));
            }
        }
        self.sessions.note_open();
        self.public_key = Some(public_key);
        self.in_flight_calls.clear();
        Ok(())
    }

    fn continue_session(
        &mut self,
        line_number: usize,
        seq: u64,
        prev_hash: PrevHash,
    ) -> Result<(), Stop> {
        // `index()` and not `current()`: "no Session yet" is the finding here,
        // and the address column's 0 would answer a headless file with a
        // plausible Session number instead.
        let Some(session_index) = self.sessions.index() else {
            return Err(malformed(
                line_number,
                "chain does not begin with an open line",
            ));
        };
        // The hash link is checked first: it is what a forger has to break, and
        // it is what tells a `seq` gap apart from a removed line. Removing a
        // line always breaks the *next* line's `prev_hash`, and re-signing the
        // remainder needs the key — so an intact link means nothing was taken
        // out.
        let expected = self.tail.expect("a session with an open line has a tail");
        if prev_hash != expected {
            return Err(Stop::Tampered(TamperedReason::ChainBroken {
                at: Position { session_index, seq },
                expected,
                found: prev_hash,
            }));
        }
        match seq.cmp(&self.expected_seq) {
            std::cmp::Ordering::Equal => {}
            // Forward over an intact chain: the writer takes `seq` before the
            // append and advances its tail only after the write lands, so a
            // failed write leaves exactly this. A durability incident, not a
            // forgery — calling it `Tampered` would alarm on a full disk.
            std::cmp::Ordering::Greater => {
                self.cap.get_or_insert(IndeterminateReason::MissingLine {
                    session_index,
                    expected: self.expected_seq,
                    found: seq,
                });
            }
            std::cmp::Ordering::Less => {
                return Err(Stop::Tampered(TamperedReason::SeqOutOfOrder {
                    session_index,
                    expected: self.expected_seq,
                    found: seq,
                }));
            }
        }
        Ok(())
    }

    /// A line type that must be signed. A missing signature here is a stripped
    /// signature, not an absence.
    fn require_signature(&mut self, value: &Value, at: Position) -> Result<(), Stop> {
        self.try_signature(value, at)
            .map_err(|source| Stop::Tampered(TamperedReason::BadSignature { at, source }))
    }

    /// Verify a signature if there is one, advancing Coverage when it holds.
    fn try_signature(&mut self, value: &Value, at: Position) -> Result<(), VerifyError> {
        let public_key = self.public_key.ok_or(VerifyError::Unsigned)?;
        verify_json_line(value, &public_key)?;
        self.coverage = Some(at);
        // Every intent before this signature is now covered transitively: the
        // signature commits to `prev_hash`, and `prev_hash` chains back to them.
        self.in_flight_calls.clear();
        Ok(())
    }
}

/// How a walk stops early.
enum Stop {
    Tampered(TamperedReason),
    Torn(IndeterminateReason),
}

fn malformed_reason(line: usize, detail: &str) -> TamperedReason {
    TamperedReason::MalformedLine {
        line,
        detail: detail.to_owned(),
    }
}

fn malformed(line: usize, detail: impl Into<String>) -> Stop {
    Stop::Tampered(TamperedReason::MalformedLine {
        line,
        detail: detail.into(),
    })
}
