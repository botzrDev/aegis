//! AILAB-845: the intent line is never signed, and the compiler is what says so.
//!
//! The intent line is appended, flushed and fsynced *before* sandbox work
//! begins, so signing it would put key material and an ed25519 signing
//! operation on the pre-execution critical path. Before this ticket the
//! property was "`AuditIntent` does not implement `SignedLine`"; now it is
//! "`IntentPayload` does not implement `Signable`", and every path that could
//! attach a signature is bounded on that marker.
//!
//! This is an **absent trait impl**, not a seal, so the error is a trait-bound
//! failure rather than E0616. A bare "it does not compile" would also pass on a
//! typo; the committed `.stderr` is what pins the reason.
use botzr_aegis_core::{AuditIntent, KeyId, PublicKey, RequestDigest, Signature, ToolId};

fn main() {
    let mut intent = AuditIntent::new(
        "call-1",
        ToolId::new("smoke"),
        RequestDigest::of_request_bytes(b"abc"),
    );
    // `IntentPayload: Signable` does not hold, so `stamp_signature` is not
    // reachable on this line at all — it is not an unused method, it is absent.
    intent.stamp_signature(
        Signature::from_bytes([0u8; 64]),
        KeyId::of_public_key(&PublicKey::from_bytes([0u8; 32])),
    );
}
