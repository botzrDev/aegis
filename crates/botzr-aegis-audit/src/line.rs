//! What the writer needs from a line in order to put it in the chain.
//!
//! Two traits rather than one, so that "the intent line is never signed" is a
//! property of the type system instead of a rule the writer has to remember:
//! [`AuditIntent`] implements [`ChainLine`] only, and there is no way to hand
//! it to the signing path. The intent line is fsynced ahead of execution, so
//! anything added there lands on the pre-execution critical path — signing
//! must stay off it.
//!
//! [`AuditLineType::Checkpoint`] is reserved and has no line type of its own to
//! implement: nothing in this repo can emit one.

use botzr_aegis_core::{
    AuditClose, AuditDecision, AuditIntent, AuditOpen, AuditRecord, AuditSchemaVersion, JcsError,
    KeyId, PrevHash, Signature,
};

/// A line that occupies a position in the hash chain.
///
/// Every appended line implements this. `stamp_chain` is called by
/// [`crate::AuditWriter`] inside the same lock as the append, never by a
/// caller — see [`AuditRecord::stamp_chain`].
pub trait ChainLine: serde::Serialize {
    fn schema_version(&self) -> AuditSchemaVersion;
    fn stamp_chain(&mut self, seq: u64, prev_hash: PrevHash);
}

/// A chain line that is also signed: `Open`, `Outcome`, `Decision`, `Close`.
///
/// A signature covers `prev_hash`, so one signed line transitively
/// authenticates every unsigned line before it back to the previous signature.
pub trait SignedChainLine: ChainLine {
    /// The exact bytes the signature covers — the canonical form with
    /// `signature` omitted and `key_id` present.
    fn signing_input(&self, key_id: &KeyId) -> Result<String, JcsError>;
    fn stamp_signature(&mut self, signature: Signature, key_id: KeyId);
    fn signature(&self) -> Option<&Signature>;
    fn key_id(&self) -> Option<&KeyId>;
}

macro_rules! impl_chain_line {
    ($ty:ty) => {
        impl ChainLine for $ty {
            fn schema_version(&self) -> AuditSchemaVersion {
                <$ty>::schema_version(self)
            }

            fn stamp_chain(&mut self, seq: u64, prev_hash: PrevHash) {
                <$ty>::stamp_chain(self, seq, prev_hash)
            }
        }
    };
}

macro_rules! impl_signed_chain_line {
    ($ty:ty) => {
        impl_chain_line!($ty);

        impl SignedChainLine for $ty {
            fn signing_input(&self, key_id: &KeyId) -> Result<String, JcsError> {
                <$ty>::signing_input(self, key_id)
            }

            fn stamp_signature(&mut self, signature: Signature, key_id: KeyId) {
                <$ty>::stamp_signature(self, signature, key_id)
            }

            fn signature(&self) -> Option<&Signature> {
                <$ty>::signature(self)
            }

            fn key_id(&self) -> Option<&KeyId> {
                <$ty>::key_id(self)
            }
        }
    };
}

// Hashed into the chain, deliberately not signable.
impl_chain_line!(AuditIntent);

impl_signed_chain_line!(AuditOpen);
impl_signed_chain_line!(AuditRecord);
impl_signed_chain_line!(AuditDecision);
impl_signed_chain_line!(AuditClose);
