//! ed25519 signing and verification for audit lines.
//!
//! This is the only module in the workspace that holds a private key —
//! `botzr-aegis-core` carries signature *bytes* and cannot verify anything, so
//! every crate that merely reads records stays free of a crypto dependency.
//!
//! Scope: the *primitive*. Where a key file lives, what permissions it has, and
//! whether it is generated on first run are AILAB-620. This module signs with a
//! key it is handed at construction, and verifies with a public key a caller
//! supplies — normally the one the Session `Open` line carries (ADR-0004).

use std::fmt;

use botzr_aegis_core::{to_canonical_json, JcsError, KeyId, PublicKey, Signature};
use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey, VerifyingKey};
use serde_json::Value;

use crate::line::SignedChainLine;

/// The key an [`crate::AuditWriter`] signs its Session with.
///
/// `key_id` and the public key are derived once at construction: they are on
/// the per-line critical path, and recomputing a SHA-256 per signed line to
/// learn a value that cannot change is waste inside the writer lock.
pub struct SigningKey {
    inner: Ed25519SigningKey,
    public_key: PublicKey,
    key_id: KeyId,
}

impl SigningKey {
    /// Build a key from its 32-byte ed25519 seed.
    ///
    /// The seed is the private key. Nothing here reads it from disk or writes
    /// it anywhere — supplying it is the caller's problem, and AILAB-620's.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let inner = Ed25519SigningKey::from_bytes(&seed);
        let public_key = PublicKey::from_bytes(inner.verifying_key().to_bytes());
        Self {
            inner,
            key_id: KeyId::of_public_key(&public_key),
            public_key,
        }
    }

    /// The public key this Session's `Open` line publishes.
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// This key's fingerprint — SHA-256 of the 32-byte public key. Stamped on
    /// every signed line so a verifier can select a key and rotation is
    /// expressible (ADR-0004).
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Sign a line's canonical form.
    pub fn sign(&self, signing_input: &[u8]) -> Signature {
        Signature::from_bytes(self.inner.sign(signing_input).to_bytes())
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Fingerprint only — a `Debug` that prints key material puts it in
        // every log line that ever formats a writer.
        f.debug_struct("SigningKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Seed for [`insecure_dev_key`]. Fixed, published, and worthless — spelled out
/// here so nobody has to look it up to know it is not a secret.
const INSECURE_DEV_SEED: [u8; 32] = *b"aegis-insecure-dev-key-not-real!";

/// **INSECURE — tests and dev defaults only. Never a production key.**
///
/// A fixed seed compiled into this crate, so its private bytes ship in every
/// published artifact and its `key_id` is identical on every machine. A line it
/// signs proves that *some* Aegis build wrote it, never *which* — a verifier
/// can only report `Verified (unpinned)` over it (ADR-0004).
///
/// It exists because [`crate::AuditWriter::open_temp`] and the runtime's
/// default sink need *some* key before AILAB-620 ships key lifecycle, and a
/// stable `key_id` across the whole test suite is worth more than a fresh
/// random key per test. Do not add a config option that reaches this function.
pub fn insecure_dev_key() -> SigningKey {
    SigningKey::from_seed(INSECURE_DEV_SEED)
}

/// Why a signed line failed to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The line carries no `signature` / `key_id`, so there is nothing to
    /// check. A missing signature on a line type that must be signed is
    /// tampering, not an absence — the caller decides which it is looking at.
    Unsigned,
    /// The line was signed under a different key than the one supplied.
    /// Distinct from [`VerifyError::BadSignature`] so a verifier can say
    /// "wrong key" rather than "forged".
    KeyMismatch { expected: KeyId, found: KeyId },
    /// The supplied public key is not a valid ed25519 point.
    MalformedPublicKey,
    /// The line could not be canonicalized, so the signed bytes are unknowable.
    Canonicalize(JcsError),
    /// The signature does not authenticate this line's canonical form.
    BadSignature,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned => f.write_str("line carries no signature"),
            Self::KeyMismatch { expected, found } => {
                write!(f, "line was signed under key {found}, not {expected}")
            }
            Self::MalformedPublicKey => f.write_str("not a valid ed25519 public key"),
            Self::Canonicalize(source) => write!(f, "canonical form unavailable: {source}"),
            Self::BadSignature => f.write_str("signature does not match this line"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Check a signed line against a public key — normally the one carried by the
/// Session `Open` line.
///
/// Uses ed25519 *strict* verification, which rejects small-order and malleable
/// signatures. A record format wants one signature to have one verdict
/// everywhere; the permissive rule lets the same bytes verify here and fail in
/// a batch verifier.
pub fn verify_line<L: SignedChainLine>(
    line: &L,
    public_key: &PublicKey,
) -> Result<(), VerifyError> {
    let (signature, key_id) = match (line.signature(), line.key_id()) {
        (Some(signature), Some(key_id)) => (signature, key_id),
        _ => return Err(VerifyError::Unsigned),
    };
    let expected = KeyId::of_public_key(public_key);
    if *key_id != expected {
        return Err(VerifyError::KeyMismatch {
            expected,
            found: *key_id,
        });
    }
    let verifying_key = VerifyingKey::from_bytes(&public_key.to_bytes())
        .map_err(|_| VerifyError::MalformedPublicKey)?;
    // `key_id` comes from the line, not from `expected`, so a line that names a
    // key it was not signed under fails here rather than silently verifying
    // against a substituted fingerprint.
    let signing_input = line
        .signing_input(key_id)
        .map_err(VerifyError::Canonicalize)?;
    verify_strict(&verifying_key, &signing_input, signature)
}

/// Check a signed line a verifier could not give a type to.
///
/// A verifier meets lines this build has no struct for — a reserved
/// `Checkpoint`, or a type a newer emitter introduced — and still has to say
/// whether they are authentic. So the signed bytes are reconstructed from the
/// JSON itself, by exactly the rule [`botzr_aegis_core::AuditRecord::signing_input`]
/// implements: the canonical form with `signature` removed and `key_id` left in
/// place. A test pins the two against each other, because two spellings of
/// "what the signature covers" is the drift ADR-0003 exists to prevent.
pub(crate) fn verify_json_line(value: &Value, public_key: &PublicKey) -> Result<(), VerifyError> {
    let object = value
        .as_object()
        .ok_or(VerifyError::Canonicalize(JcsError::Serialize(
            "line is not a JSON object".into(),
        )))?;
    let (Some(signature), Some(key_id)) = (object.get("signature"), object.get("key_id")) else {
        return Err(VerifyError::Unsigned);
    };
    let signature = signature
        .as_str()
        .and_then(|hex| Signature::from_hex(hex).ok())
        .ok_or(VerifyError::BadSignature)?;
    // `key_id` is read off the line, never substituted from the supplied key: a
    // line that names a key it was not signed under must fail rather than
    // quietly verify against a fingerprint it never carried.
    let key_id = key_id
        .as_str()
        .and_then(|hex| KeyId::from_hex(hex).ok())
        .ok_or(VerifyError::BadSignature)?;
    let expected = KeyId::of_public_key(public_key);
    if key_id != expected {
        return Err(VerifyError::KeyMismatch {
            expected,
            found: key_id,
        });
    }
    let verifying_key = VerifyingKey::from_bytes(&public_key.to_bytes())
        .map_err(|_| VerifyError::MalformedPublicKey)?;
    let mut unsigned = object.clone();
    unsigned.remove("signature");
    let signing_input =
        to_canonical_json(&Value::Object(unsigned)).map_err(VerifyError::Canonicalize)?;
    verify_strict(&verifying_key, &signing_input, &signature)
}

fn verify_strict(
    verifying_key: &VerifyingKey,
    signing_input: &str,
    signature: &Signature,
) -> Result<(), VerifyError> {
    verifying_key
        .verify_strict(
            signing_input.as_bytes(),
            &ed25519_dalek::Signature::from_bytes(&signature.to_bytes()),
        )
        .map_err(|_| VerifyError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dev_key_id_is_stable_across_the_suite() {
        // Tests in other modules pin expectations against this key; a key_id
        // that moved per process would make every one of them flaky.
        assert_eq!(insecure_dev_key().key_id(), insecure_dev_key().key_id());
        assert_eq!(
            insecure_dev_key().public_key(),
            SigningKey::from_seed(INSECURE_DEV_SEED).public_key()
        );
    }

    #[test]
    fn key_id_is_the_fingerprint_of_the_published_public_key() {
        let key = insecure_dev_key();
        assert_eq!(key.key_id(), KeyId::of_public_key(&key.public_key()));
    }

    #[test]
    fn the_typed_and_untyped_verifiers_agree_on_what_the_signature_covers() {
        // LOAD-BEARING: `verify_json_line` reconstructs the signed bytes from
        // JSON so a verifier can check a line it has no struct for. If it ever
        // disagrees with `signing_input`, the same line verifies one way and
        // fails the other — the drift ADR-0003 exists to prevent.
        use botzr_aegis_core::{
            AuditRecord, CapabilityOutcome, ExecutionOutcome, PolicyOutcome, PolicySetHash,
            PrevHash, RequestDigest, ToolId,
        };

        let key = insecure_dev_key();
        let mut record = AuditRecord::new(
            "call-1",
            ToolId::new("echo"),
            RequestDigest::of_request_bytes(b"{}"),
            PolicySetHash::of_canonical_bytes(b"policy"),
            PolicyOutcome::Allowed,
            CapabilityOutcome::Denied {
                reason: "not evaluated".into(),
                denied_capability: None,
            },
            ExecutionOutcome::Success,
        );
        record.stamp_chain(4, PrevHash::of_line(b"prev"));
        let signature = key.sign(record.signing_input(&key.key_id()).unwrap().as_bytes());
        record.stamp_signature(signature, key.key_id());

        let value: Value = serde_json::from_str(&to_canonical_json(&record).unwrap()).unwrap();
        assert_eq!(verify_line(&record, &key.public_key()), Ok(()));
        assert_eq!(verify_json_line(&value, &key.public_key()), Ok(()));

        // And they agree on a rejection, not only on an acceptance.
        let mut tampered = value.clone();
        tampered["call_id"] = Value::from("call-2");
        assert_eq!(
            verify_json_line(&tampered, &key.public_key()),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn an_unsigned_json_line_reports_unsigned_rather_than_forged() {
        let key = insecure_dev_key();
        let value = serde_json::json!({ "line_type": "intent", "seq": 1 });
        assert_eq!(
            verify_json_line(&value, &key.public_key()),
            Err(VerifyError::Unsigned)
        );
    }

    #[test]
    fn signatures_are_deterministic_for_the_same_input() {
        // ed25519 is deterministic; the same line signed twice must produce the
        // same bytes, or goldens over a signed line could never be stable.
        let key = insecure_dev_key();
        assert_eq!(key.sign(b"line"), key.sign(b"line"));
        assert_ne!(key.sign(b"line"), key.sign(b"line "));
    }
}
