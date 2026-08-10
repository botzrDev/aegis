//! AILAB-619: the chain position and the signature are the writer's, not the
//! caller's.
//!
//! A caller that can pick its own `seq` or `prev_hash` forges a position the
//! line never occupied, or hands two lines the same one — which is what a forked
//! chain is. A caller that can set `signature` / `key_id` writes an unverified
//! claim about authorship straight into evidence. The seal is what makes those
//! structural rather than a comment, so it is locked here as a compile error.
use botzr_aegis_core::{
    AuditIntent, AuditRecord, CapabilityOutcome, ExecutionOutcome, KeyId, PolicyOutcome,
    PolicySetHash, PrevHash, PublicKey, RequestDigest, Signature, ToolId,
};

fn main() {
    let mut record = AuditRecord::new(
        "call-1",
        ToolId::new("smoke"),
        RequestDigest::of_request_bytes(b"abc"),
        PolicySetHash::of_canonical_bytes(b"rules"),
        PolicyOutcome::Allowed,
        CapabilityOutcome::Denied {
            reason: "not evaluated".into(),
            denied_capability: None,
        },
        ExecutionOutcome::Success,
    );
    record.seq = 99;
    record.prev_hash = PrevHash::GENESIS;
    record.signature = Some(Signature::from_bytes([0u8; 64]));
    record.key_id = Some(KeyId::of_public_key(&PublicKey::from_bytes([0u8; 32])));

    let mut intent = AuditIntent::new(
        "call-1",
        ToolId::new("smoke"),
        RequestDigest::of_request_bytes(b"abc"),
    );
    intent.seq = 99;
    intent.prev_hash = PrevHash::GENESIS;
}
