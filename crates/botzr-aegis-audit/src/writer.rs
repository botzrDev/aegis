//! Synchronous JSONL append + fsync (G3 durability default).

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use botzr_aegis_core::{AuditIntent, AuditRecord, AUDIT_SCHEMA_VERSION};

use crate::error::AuditError;

/// Append-only audit sink. Fail-closed: callers must treat write errors as fatal.
pub struct AuditWriter {
    path: PathBuf,
    file: Mutex<BufWriter<File>>,
    call_seq: AtomicU64,
    _temp: Option<tempfile::TempDir>,
}

impl AuditWriter {
    /// Open (or create) a JSONL file for append-only writes with per-line fsync.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            file: Mutex::new(BufWriter::new(file)),
            call_seq: AtomicU64::new(1),
            _temp: None,
        })
    }

    /// Ephemeral sink for tests and dev defaults — writes to a temp JSONL file.
    pub fn open_temp() -> Result<Self, AuditError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit.jsonl");
        let mut writer = Self::open(path)?;
        writer._temp = Some(dir);
        Ok(writer)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn next_call_id(&self) -> String {
        format!("call-{}", self.call_seq.fetch_add(1, Ordering::Relaxed))
    }

    pub fn emit_intent(&self, intent: &AuditIntent) -> Result<(), AuditError> {
        validate_schema(intent.schema_version())?;
        self.append_line(intent)
    }

    pub fn emit_outcome(&self, record: &AuditRecord) -> Result<(), AuditError> {
        validate_schema(record.schema_version())?;
        self.append_line(record)
    }

    fn append_line<T: serde::Serialize>(&self, value: &T) -> Result<(), AuditError> {
        let mut guard = self
            .file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        serde_json::to_writer(&mut *guard, value)?;
        guard.write_all(b"\n")?;
        guard.flush()?;
        guard.get_ref().sync_all()?;
        Ok(())
    }
}

impl std::fmt::Debug for AuditWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditWriter")
            .field("path", &self.path)
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

/// Serialize a value to a canonical JSON line (no trailing newline).
pub fn to_json_line<T: serde::Serialize>(value: &T) -> Result<String, AuditError> {
    Ok(serde_json::to_string(value)?)
}

#[cfg(test)]
mod tests {
    use botzr_aegis_core::AuditIntent;

    use super::*;

    #[test]
    fn rejects_unsupported_schema() {
        // The field is sealed against direct mutation (AEG-45), so the only way
        // an unsupported version reaches the writer is a foreign/tampered record
        // deserialized from the wire — exactly what this guard is for.
        let writer = AuditWriter::open_temp().unwrap();
        let intent: AuditIntent = serde_json::from_str(
            r#"{"schema_version":999,"phase":"intent","call_id":"call-1","tool_id":"smoke","input_digest":"abc"}"#,
        )
        .expect("intent with a foreign schema version still deserializes");
        assert_eq!(intent.schema_version(), 999);
        let err = writer.emit_intent(&intent).unwrap_err();
        assert!(matches!(err, AuditError::UnsupportedSchema { .. }));
    }
}
