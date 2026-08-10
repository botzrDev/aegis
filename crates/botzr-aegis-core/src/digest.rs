//! Content digests, and the newtypes that make transposing them a compile error.
//!
//! Three bare `[u8; 32]` fields in one constructor cannot catch a swap, and a
//! chain that hashes the policy set into `prev_hash` verifies clean while being
//! wrong (ADR-0001). Every digest on the wire therefore gets its own type, and
//! there is deliberately **no** conversion between them — no `From`, no `Into`,
//! no public `Digest -> Newtype`. The only way to build one is from its own
//! domain input, so a transposition cannot be spelled.
//!
//! This module holds key and signature *bytes* too. It holds no crypto: signing
//! and verification live in `botzr-aegis-audit`, which is where the private key
//! is.

use std::fmt;

use sha2::{Digest as _, Sha256};

/// Raw SHA-256 output. Wire form is 64 lowercase hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    /// The all-zero digest. Genesis predecessor for a Session's first line —
    /// an `Open` line has no predecessor inside its own Session, and its
    /// back-reference to the previous Session travels in `prev_session_tail`
    /// instead.
    pub const ZERO: Self = Self([0u8; 32]);

    /// SHA-256 over the given bytes.
    pub fn sha256(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// The raw 32 digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The canonical wire form: 64 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    /// Parse the canonical wire form.
    ///
    /// Strict by design: exactly 64 characters, `0-9a-f` only. Uppercase is
    /// **rejected rather than normalized** — one digest must have exactly one
    /// spelling, or two canonical forms of the same line hash differently and
    /// a third-party verifier disagrees with us for no visible reason.
    pub fn from_hex(s: &str) -> Result<Self, DigestParseError> {
        hex_decode::<32>(s).map(Self)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl serde::Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_hex(&raw).map_err(serde::de::Error::custom)
    }
}

/// Why a fixed-width hex field failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestParseError {
    /// Wrong number of characters for the field width.
    Length { expected: usize, actual: usize },
    /// A byte outside `0-9a-f` — including uppercase `A-F`, which is rejected
    /// so that one digest has one spelling.
    NotLowercaseHex { position: usize },
}

impl fmt::Display for DigestParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { expected, actual } => {
                write!(f, "expected {expected} hex characters, got {actual}")
            }
            Self::NotLowercaseHex { position } => {
                write!(f, "not a lowercase hex character at position {position}")
            }
        }
    }
}

impl std::error::Error for DigestParseError {}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        out.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode<const N: usize>(s: &str) -> Result<[u8; N], DigestParseError> {
    let bytes = s.as_bytes();
    if bytes.len() != N * 2 {
        return Err(DigestParseError::Length {
            expected: N * 2,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        out[index] = (nibble(pair[0], index * 2)? << 4) | nibble(pair[1], index * 2 + 1)?;
    }
    Ok(out)
}

fn nibble(byte: u8, position: usize) -> Result<u8, DigestParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(DigestParseError::NotLowercaseHex { position }),
    }
}

/// Declares a digest newtype with no conversion to or from its siblings.
macro_rules! digest_newtype {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        ///
        /// Wire form: 64 lowercase hex characters. There is deliberately no
        /// conversion to or from any sibling digest type — a transposition must
        /// be a compile error, not a chain that verifies clean while being wrong.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(Digest);

        impl $name {
            /// Parse the canonical wire form: exactly 64 lowercase hex characters.
            pub fn from_hex(s: &str) -> Result<Self, DigestParseError> {
                Digest::from_hex(s).map(Self)
            }

            /// The canonical wire form.
            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }

            /// The raw 32 digest bytes.
            pub fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serde::Serialize::serialize(&self.0, serializer)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                <Digest as serde::Deserialize>::deserialize(deserializer).map(Self)
            }
        }
    };
}

digest_newtype! {
    /// Hash of the predecessor line's canonical form — the chain link.
    ///
    /// The separation is not documentation, it is enforcement — hashing the
    /// policy set into `prev_hash` would produce a chain that verifies clean
    /// while being wrong, so the swap must not compile:
    ///
    /// ```compile_fail
    /// use botzr_aegis_core::{PolicySetHash, PrevHash};
    /// let policy_set = PolicySetHash::of_canonical_bytes(b"rules");
    /// let _transposed: PrevHash = policy_set;
    /// ```
    PrevHash
}

digest_newtype! {
    /// Content hash of the Policy Set that governed a call.
    PolicySetHash
}

digest_newtype! {
    /// Hash of the verbatim request bytes.
    RequestDigest
}

digest_newtype! {
    /// Hash of the verbatim response bytes.
    ResponseDigest
}

digest_newtype! {
    /// Fingerprint of the signing key — SHA-256 of the 32-byte ed25519 public
    /// key. Without it a verifier cannot select a key and rotation is
    /// inexpressible (ADR-0004).
    KeyId
}

impl PrevHash {
    /// Genesis: what a Session's first line points at. An `Open` line always
    /// carries this, never the previous Session's tail — the back-reference
    /// lives in `prev_session_tail`, because a verifier already special-cases
    /// `Open` (it is where the public key is).
    pub const GENESIS: Self = Self(Digest::ZERO);

    /// SHA-256 over the **complete** canonical form of the predecessor line,
    /// signature included.
    ///
    /// Covering the signature is load-bearing: strip a signature and the line
    /// hash changes, which breaks the next line's `prev_hash` and reports
    /// `Tampered`. Hash the pre-signature form instead and signature-stripping
    /// leaves a clean chain.
    pub fn of_line(canonical_bytes: &[u8]) -> Self {
        Self(Digest::sha256(canonical_bytes))
    }
}

impl PolicySetHash {
    /// SHA-256 over the canonical bytes of a parsed Policy Set.
    ///
    /// Not `PolicySet::digest`, which is FNV-1a over YAML *text* and
    /// self-documented as "not a security digest"; and not the YAML text
    /// itself, so that a whitespace or comment edit does not change the
    /// identity of a semantically identical set.
    pub fn of_canonical_bytes(canonical_bytes: &[u8]) -> Self {
        Self(Digest::sha256(canonical_bytes))
    }
}

impl RequestDigest {
    /// SHA-256 over the **raw** request bytes, exactly as they arrived.
    ///
    /// Never canonicalize, pretty-print, or re-encode the input first. This
    /// digest is what content-addresses the Envelope, so a writer that
    /// reformats the payload silently breaks the link — and the break is
    /// invisible until someone runs a formatter.
    pub fn of_request_bytes(raw: &[u8]) -> Self {
        Self(Digest::sha256(raw))
    }
}

impl ResponseDigest {
    /// SHA-256 over the raw response bytes, under the same verbatim rule as
    /// [`RequestDigest::of_request_bytes`].
    pub fn of_response_bytes(raw: &[u8]) -> Self {
        Self(Digest::sha256(raw))
    }
}

impl KeyId {
    /// SHA-256 of the 32-byte ed25519 public key.
    pub fn of_public_key(public_key: &PublicKey) -> Self {
        Self(Digest::sha256(&public_key.0))
    }
}

/// ed25519 public key bytes, as carried by a Session `Open` line.
///
/// Bytes only — core does not depend on a crypto library, so this type cannot
/// verify anything. That is deliberate: the verifier owns key handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// The canonical wire form: 64 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    /// Parse the canonical wire form.
    pub fn from_hex(s: &str) -> Result<Self, DigestParseError> {
        hex_decode::<32>(s).map(Self)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_hex(&raw).map_err(serde::de::Error::custom)
    }
}

/// ed25519 signature bytes. Wire form is 128 lowercase hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature([u8; 64]);

impl Signature {
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(self) -> [u8; 64] {
        self.0
    }

    /// The canonical wire form: 128 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    /// Parse the canonical wire form.
    pub fn from_hex(s: &str) -> Result<Self, DigestParseError> {
        hex_decode::<64>(s).map(Self)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl serde::Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_hex(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn sha256_matches_the_published_empty_string_vector() {
        assert_eq!(Digest::sha256(b"").to_hex(), EMPTY_SHA256);
    }

    #[test]
    fn genesis_is_all_zero() {
        assert_eq!(PrevHash::GENESIS.to_hex(), "0".repeat(64));
        assert_eq!(PrevHash::GENESIS.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn hex_round_trips_through_the_wire_form() {
        let digest = Digest::sha256(b"aegis");
        assert_eq!(Digest::from_hex(&digest.to_hex()).unwrap(), digest);
        let prev = PrevHash::of_line(b"aegis");
        assert_eq!(PrevHash::from_hex(&prev.to_hex()).unwrap(), prev);
    }

    #[test]
    fn uppercase_hex_is_rejected_not_normalized() {
        let upper = EMPTY_SHA256.to_uppercase();
        assert_eq!(
            Digest::from_hex(&upper),
            Err(DigestParseError::NotLowercaseHex { position: 0 })
        );
    }

    #[test]
    fn wrong_length_and_non_hex_are_rejected() {
        assert_eq!(
            Digest::from_hex("abc"),
            Err(DigestParseError::Length {
                expected: 64,
                actual: 3
            })
        );
        let mut bad = EMPTY_SHA256.to_string();
        bad.replace_range(63..64, "z");
        assert_eq!(
            Digest::from_hex(&bad),
            Err(DigestParseError::NotLowercaseHex { position: 63 })
        );
    }

    #[test]
    fn same_bytes_under_different_newtypes_stay_distinct_types() {
        // The values coincide; the types do not, which is the whole point —
        // assigning one to the other does not compile.
        let prev = PrevHash::of_line(b"x");
        let policy = PolicySetHash::of_canonical_bytes(b"x");
        assert_eq!(prev.to_hex(), policy.to_hex());
    }

    #[test]
    fn key_id_is_sha256_of_the_public_key() {
        let key = PublicKey::from_bytes([7u8; 32]);
        assert_eq!(
            KeyId::of_public_key(&key).to_hex(),
            Digest::sha256(&[7u8; 32]).to_hex()
        );
    }

    #[test]
    fn signature_is_128_hex_characters() {
        let sig = Signature::from_bytes([0xab; 64]);
        assert_eq!(sig.to_hex().len(), 128);
        assert_eq!(Signature::from_hex(&sig.to_hex()).unwrap(), sig);
        assert!(Signature::from_hex(&"ab".repeat(63)).is_err());
    }

    #[test]
    fn serde_uses_the_hex_wire_form() {
        let prev = PrevHash::of_line(b"line");
        let json = serde_json::to_string(&prev).unwrap();
        assert_eq!(json, format!("\"{}\"", prev.to_hex()));
        assert_eq!(serde_json::from_str::<PrevHash>(&json).unwrap(), prev);
        let key = PublicKey::from_bytes([1u8; 32]);
        assert_eq!(
            serde_json::from_str::<PublicKey>(&serde_json::to_string(&key).unwrap()).unwrap(),
            key
        );
    }

    #[test]
    fn deserializing_a_malformed_digest_fails_loudly() {
        assert!(serde_json::from_str::<PrevHash>("\"deadbeef\"").is_err());
        assert!(serde_json::from_str::<PrevHash>("7").is_err());
    }
}
