use botzr_aegis_core::{AuditIntent, RequestDigest, ToolId};

fn main() {
    let mut intent = AuditIntent::new(
        "call-1",
        ToolId::new("smoke"),
        RequestDigest::of_request_bytes(b"abc"),
    );
    // AEG-45: private field — only the constructor stamps the version.
    intent.schema_version = 99;
}
