//! Where a Chain's bytes land — the seam underneath the chain rule (ADR-0012).
//!
//! [`crate::AuditWriter`] keeps owning the chain rule: stamp `seq` and
//! `prev_hash` under one lock, sign, hash the signed form, append. This module
//! owns only the storage medium underneath it, which is why the fsync lives
//! here and not in the writer.
//!
//! **Retention is declared, never inferred.** A Chain appended to an in-memory
//! sink and a Chain fsynced to disk are byte-identical and indistinguishable to
//! a verifier, so the only thing that can say which one is holding evidence is
//! the adapter's own [`Retention`] declaration — checked once, against the
//! signing key, in [`crate::AuditWriter::with_sink`]. A boolean durability flag
//! on the writer was rejected outright for the same reason ADR-0007 gives about
//! records: a guarantee you can switch off in production is not a guarantee,
//! and a flag would let one be asked for and not enforced.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use botzr_aegis_core::{to_canonical_json, PrevHash};

use crate::error::AuditError;

/// Whether bytes written to a [`ChainSink`] survive the process.
///
/// A declaration, not a knob: the adapter states which it is, and the writer
/// checks that statement against the signing key at construction. **A Durable
/// Sink requires a provisioned key; only a Volatile one may be signed by
/// [`crate::insecure_dev_key`]** — a retained file signed by a seed compiled
/// into every published artifact is exactly the Session a `Verified (pinned)`
/// label must never be able to describe (ADR-0004).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    /// Bytes outlive the process and are evidence. A verifier can be pointed at
    /// them afterwards, and a later Session can anchor to their tail.
    Durable,
    /// Bytes die with the process. Not evidence, and says so. Sessions written
    /// here leave no Anchor for a later Session to back-reference (ADR-0002).
    Volatile,
}

/// Where a Chain's bytes land. The chain rule stays in [`crate::AuditWriter`].
///
/// An implementor owns bytes and nothing else. `seq`, `prev_hash`, the
/// signature and the line hash are all chosen by the writer, under its lock,
/// before [`ChainSink::append`] is ever called — a sink that reordered,
/// rewrote or deduplicated lines would break the chain, not participate in it.
///
/// `Send` is required rather than stylistic: the writer keeps the sink inside
/// the same mutex as `seq` and the tail hash, and an `AuditWriter` shared
/// across threads is only `Sync` if that state is `Send`.
///
/// # A sink can lie, and nothing here detects it
///
/// A sink may declare [`Retention::Durable`] and return `Ok(None)` from
/// [`ChainSink::existing_tail`] over a store that is not empty. Every Session
/// after that point is silently unanchored: its `Open` line carries no
/// `prev_session_tail`, so a verifier cannot tell a fresh file from a file
/// whose earlier Sessions were dropped on the floor.
///
/// One trait plus a runtime check cannot catch that — the honest answer to
/// "was this really the tail?" is another read of the same untrusted sink, so a
/// probe would only ask the liar twice. It is documented rather than
/// engineered around, and it is the cost accepted in ADR-0012 for one trait
/// instead of a subtrait hierarchy that would have made retention a bound. A
/// sink that declares `Durable` and *errors* on `existing_tail` is a different
/// case and does fail closed at construction, matching the torn-tail refusal.
pub trait ChainSink: Send {
    /// Declared, not inferred. Checked at construction against the signing key.
    fn retention(&self) -> Retention;

    /// The hash of the last line already in the store — what the new Session's
    /// `Open` line carries as `prev_session_tail`.
    ///
    /// `Ok(None)` means a fresh or empty store. `Err` means the store could not
    /// be read as a Chain, which fails construction rather than starting a
    /// Session chained onto bytes nobody can hash the same way twice.
    fn existing_tail(&self) -> Result<Option<PrevHash>, AuditError>;

    /// Append one canonical line plus its newline, and make it as durable as
    /// [`ChainSink::retention`] claims.
    ///
    /// `line` is the canonical (JCS) form with no trailing newline: the exact
    /// bytes the writer hashed into the chain, so the row a verifier reads is
    /// the row that was hashed. Adding the newline is the sink's job because
    /// the record separator belongs to the storage format.
    fn append(&mut self, line: &[u8]) -> Result<(), AuditError>;

    /// Where these bytes live, if that is a meaningful question. `None` is the
    /// truthful answer for a sink with nothing to point an operator at.
    fn path(&self) -> Option<&Path>;
}

/// The hash of the last non-empty line in `reader`, or `None` for an empty
/// store.
///
/// Canonicalizes what it reads rather than hashing the raw bytes, because that
/// is what a verifier does; we write canonical rows, so the round trip is an
/// identity and a divergence would be a bug worth failing on.
///
/// Shared by both shipped adapters so the torn-tail rule has exactly one
/// implementation. An adapter supplies bytes; it does not get its own opinion
/// about what a tail is.
fn tail_of_lines(reader: impl BufRead) -> Result<Option<PrevHash>, AuditError> {
    let mut last: Option<(usize, String)> = None;
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if !line.trim().is_empty() {
            last = Some((index + 1, line));
        }
    }
    let Some((number, line)) = last else {
        return Ok(None);
    };
    // A tail that does not parse is a torn write. Refusing to open is the
    // fail-closed answer: continuing would chain a new Session onto bytes
    // nobody can hash the same way twice, turning a recoverable
    // `Indeterminate` into a permanent chain break.
    let value: serde_json::Value =
        serde_json::from_str(&line).map_err(|_| AuditError::TornTail { line: number })?;
    let canonical = to_canonical_json(&value).map_err(|_| AuditError::TornTail { line: number })?;
    Ok(Some(PrevHash::of_line(canonical.as_bytes())))
}

/// A JSONL file on disk: synchronous append plus fsync per line, fail-closed on
/// write failure. This adapter is where the G3 durability default lives.
///
/// Always [`Retention::Durable`], and deliberately not via a stored field.
/// [`FileChainSink::open`] is the only constructor, so there is no second file
/// shape a declaration could distinguish — and a field only invites something
/// to set it, which is the durability knob ADR-0012 refused. The retention is a
/// property of this type, so it is written where the type is.
pub struct FileChainSink {
    path: PathBuf,
    file: BufWriter<File>,
}

impl FileChainSink {
    /// Open (or create) a Chain file at a caller-named path. Declares
    /// [`Retention::Durable`], so the writer will refuse to sign it with
    /// [`crate::insecure_dev_key`].
    ///
    /// Missing parent directories are created; the file is opened for append
    /// and never truncated, so an existing Chain is continued rather than
    /// replaced.
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
            file: BufWriter::new(file),
        })
    }
}

impl ChainSink for FileChainSink {
    fn retention(&self) -> Retention {
        Retention::Durable
    }

    fn existing_tail(&self) -> Result<Option<PrevHash>, AuditError> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        tail_of_lines(BufReader::new(file))
    }

    fn append(&mut self, line: &[u8]) -> Result<(), AuditError> {
        self.file.write_all(line)?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.file.get_ref().sync_all()?;
        Ok(())
    }

    fn path(&self) -> Option<&Path> {
        Some(&self.path)
    }
}

impl std::fmt::Debug for FileChainSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileChainSink")
            .field("path", &self.path)
            .field("retention", &self.retention())
            .finish_non_exhaustive()
    }
}

/// A Chain in memory. Declares [`Retention::Volatile`]: nothing is written
/// anywhere, so nothing is evidence.
///
/// Its bytes are the same canonical JSONL a [`FileChainSink`] would hold —
/// [`MemoryChainSink::to_text`] feeds [`crate::verify_chain`] directly, which is
/// what makes it usable as a test double without the test double having to
/// reimplement anything the writer does.
///
/// **`Clone` shares the buffer.** That is the point: the writer takes the sink
/// by value, so a caller keeps a clone to read the bytes back afterwards —
/// including the `Close` line the writer's own `Drop` appends.
#[derive(Clone, Debug, Default)]
pub struct MemoryChainSink {
    lines: Arc<Mutex<Vec<u8>>>,
}

impl MemoryChainSink {
    /// An empty in-memory Chain.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every byte appended so far, newlines included.
    pub fn bytes(&self) -> Vec<u8> {
        self.lock().clone()
    }

    /// The same bytes as JSONL text, ready for [`crate::verify_chain`].
    ///
    /// Lossy only in theory: the writer appends canonical JSON, which is always
    /// valid UTF-8, so a replacement character here would mean something other
    /// than the writer wrote to this sink.
    pub fn to_text(&self) -> String {
        String::from_utf8_lossy(&self.bytes()).into_owned()
    }

    fn lock(&self) -> MutexGuard<'_, Vec<u8>> {
        // Same rule as the writer's chain lock: a poisoned buffer means a
        // previous append panicked, and the honest recovery is to resume from
        // the bytes that landed rather than to stop recording.
        self.lines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl ChainSink for MemoryChainSink {
    fn retention(&self) -> Retention {
        Retention::Volatile
    }

    fn existing_tail(&self) -> Result<Option<PrevHash>, AuditError> {
        // Read the same way the file adapter does, so a buffer shared with an
        // earlier Session anchors instead of silently restarting the Chain.
        tail_of_lines(BufReader::new(self.bytes().as_slice()))
    }

    fn append(&mut self, line: &[u8]) -> Result<(), AuditError> {
        let mut buffer = self.lock();
        buffer.extend_from_slice(line);
        buffer.push(b'\n');
        Ok(())
    }

    fn path(&self) -> Option<&Path> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_named_file_is_durable_and_names_the_path_it_was_opened_at() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("chain.jsonl");
        let named = FileChainSink::open(&path).expect("open");
        // The only file sink there is: bytes on disk, retained, and pointable
        // at afterwards — which is why it refuses the dev key upstream.
        assert_eq!(named.retention(), Retention::Durable);
        assert_eq!(named.path(), Some(path.as_path()));
    }

    #[test]
    fn a_memory_sink_has_no_path_and_recovers_its_own_tail() {
        let mut sink = MemoryChainSink::new();
        assert_eq!(sink.retention(), Retention::Volatile);
        assert_eq!(sink.path(), None);
        assert_eq!(sink.existing_tail().expect("empty store"), None);

        let line = br#"{"a":1}"#;
        sink.append(line).expect("append");
        assert_eq!(sink.to_text(), "{\"a\":1}\n");
        assert_eq!(
            sink.existing_tail().expect("tail"),
            Some(PrevHash::of_line(line)),
            "the tail is the hash of the canonical last line"
        );
    }

    #[test]
    fn a_torn_final_line_refuses_rather_than_hashing_garbage() {
        let mut sink = MemoryChainSink::new();
        sink.append(br#"{"a":1}"#).expect("append");
        sink.append(br#"{"b":"#).expect("append");
        let error = sink.existing_tail().expect_err("a torn tail must refuse");
        assert!(
            matches!(error, AuditError::TornTail { line: 2 }),
            "{error:?}"
        );
    }

    #[test]
    fn a_clone_shares_the_buffer_so_a_caller_can_read_back() {
        let reader = MemoryChainSink::new();
        let mut writer = reader.clone();
        writer.append(br#"{"a":1}"#).expect("append");
        assert_eq!(reader.to_text(), "{\"a\":1}\n");
    }
}
