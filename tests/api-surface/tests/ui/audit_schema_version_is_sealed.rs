//! AEG-45: the schema version is stamped by the constructor, never chosen by a
//! caller — a record that could be stamped with an arbitrary version is a
//! forgeable audit trail.
//!
//! AILAB-845 moved the field onto `LineHeader`, so the seal is the private
//! `header` on `Envelope`. This must stay **E0616 private field**, not E0609.
use botzr_aegis_core::{AuditIntent, RequestDigest, ToolId};

fn main() {
    let mut intent = AuditIntent::new(
        "call-1",
        ToolId::new("smoke"),
        RequestDigest::of_request_bytes(b"abc"),
    );
    intent.header.schema_version = 99;
}
