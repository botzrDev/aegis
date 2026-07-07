//! Audit trail — schema-versioned records, JSONL + OTel export (AEG-10).

use botzr_aegis_core::{AuditRecord, AUDIT_SCHEMA_VERSION};

/// Emit an audit record. Stub: validates schema version until AEG-10 persistence lands.
pub fn emit(record: &AuditRecord) -> Result<(), String> {
    if record.schema_version != AUDIT_SCHEMA_VERSION {
        return Err(format!(
            "unsupported audit schema version {}",
            record.schema_version
        ));
    }
    Ok(())
}
