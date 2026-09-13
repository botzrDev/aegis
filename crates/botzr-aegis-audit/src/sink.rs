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
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::ops::Range;
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

/// How much of a store one backward step pulls in.
///
/// Sized to hold a whole record in a single read, not to bound anything: a row
/// longer than this simply costs another chunk. A cap would turn a large but
/// perfectly good tail into a refusal, and a refusal is reserved for bytes
/// nobody can hash reproducibly.
const TAIL_CHUNK: usize = 8 * 1024;

/// The hash of the last non-empty line in `reader`, or `None` for an empty
/// store.
///
/// Locates that line by seeking to the end and scanning backwards, so opening a
/// Session on a long-lived Chain costs one chunk rather than a read of every
/// row. The rows it reports are the rows [`std::io::BufRead::lines`] reported
/// before it: one trailing newline terminates the last row instead of starting
/// a blank one, blank rows are skipped for the hash but still advance the
/// number a torn tail reports, a trailing carriage return is stripped, and
/// bytes that are not UTF-8 are an `io::Error` rather than a torn tail.
///
/// Canonicalizes what it reads rather than hashing the raw bytes, because that
/// is what a verifier does; we write canonical rows, so the round trip is an
/// identity and a divergence would be a bug worth failing on.
///
/// Shared by both shipped adapters — one `Read + Seek` over a file, one over a
/// buffer — so the torn-tail rule has exactly one implementation. An adapter
/// supplies bytes; it does not get its own opinion about what a tail is.
///
/// Only a torn tail reads anything ahead of the row it hashed, and then only to
/// count newlines for the line number. The verifier walk in
/// [`crate::verify_chain`] still reads every row on purpose: its job is the
/// whole Chain, not its tail, and torn-tail policy is per-consumer (ADR-0013).
fn tail_of_lines(mut reader: impl Read + Seek) -> Result<Option<PrevHash>, AuditError> {
    let end = reader.seek(SeekFrom::End(0))?;
    if end == 0 {
        return Ok(None);
    }

    // `window` holds the store's bytes from `origin` to the end, widened
    // towards the front only while the last non-empty row's first byte is
    // still outside it. On the happy path that is one chunk.
    let mut window: Vec<u8> = Vec::new();
    let mut origin = end;
    let row = loop {
        if let Some(row) = last_non_empty_row(&window, origin)? {
            break row;
        }
        if origin == 0 {
            // Every row is blank. The forward walk this replaced kept no line
            // here either, so there is no tail to chain onto.
            return Ok(None);
        }
        let front = origin.saturating_sub(TAIL_CHUNK as u64);
        let mut chunk = vec![0u8; (origin - front) as usize];
        reader.seek(SeekFrom::Start(front))?;
        reader.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&window);
        window = chunk;
        origin = front;
    };
    let start = origin + row.start as u64;

    let line = std::str::from_utf8(&window[row]).map_err(|_| not_utf8())?;
    let line = line.strip_suffix('\r').unwrap_or(line);

    // A tail that does not parse is a torn write. Refusing to open is the
    // fail-closed answer: continuing would chain a new Session onto bytes
    // nobody can hash the same way twice, turning a recoverable
    // `Indeterminate` into a permanent chain break.
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return Err(AuditError::TornTail {
            line: row_number(&mut reader, start)?,
        });
    };
    let Ok(canonical) = to_canonical_json(&value) else {
        return Err(AuditError::TornTail {
            line: row_number(&mut reader, start)?,
        });
    };
    Ok(Some(PrevHash::of_line(canonical.as_bytes())))
}

/// The last non-empty row lying wholly inside `window`, which holds the store's
/// bytes from `origin` to the end.
///
/// `Ok(None)` means the window is not yet wide enough to answer — unless
/// `origin` is already 0, in which case it means every row in the store is
/// blank. The caller distinguishes the two, because only it knows whether
/// there is anything left to read.
fn last_non_empty_row(window: &[u8], origin: u64) -> Result<Option<Range<usize>>, std::io::Error> {
    let Some(&final_byte) = window.last() else {
        return Ok(None);
    };
    // One trailing newline terminates the final row rather than starting a
    // blank one — and exactly one, so "A\n\n" is still two rows.
    let mut end = window.len() - usize::from(final_byte == b'\n');
    loop {
        let start = match window[..end].iter().rposition(|&byte| byte == b'\n') {
            Some(newline) => newline + 1,
            // The row's first byte is outside the window; widen it.
            None if origin > 0 => return Ok(None),
            None => 0,
        };
        if !std::str::from_utf8(&window[start..end])
            .map_err(|_| not_utf8())?
            .trim()
            .is_empty()
        {
            return Ok(Some(start..end));
        }
        if start == 0 {
            return Ok(None);
        }
        end = start - 1;
    }
}

/// The 1-based number of the row beginning at `start`, counted the way the
/// forward walk's `enumerate` counted it: blank rows advance it.
///
/// Only the torn-tail path pays for this, and it counts newlines rather than
/// parsing anything, so a clean open still never looks at the prefix.
fn row_number<R: Read + Seek>(reader: &mut R, start: u64) -> Result<usize, std::io::Error> {
    reader.seek(SeekFrom::Start(0))?;
    let mut buffer = vec![0u8; TAIL_CHUNK];
    let mut remaining = start;
    let mut rows = 1;
    while remaining > 0 {
        let want = remaining.min(TAIL_CHUNK as u64) as usize;
        reader.read_exact(&mut buffer[..want])?;
        rows += buffer[..want].iter().filter(|&&byte| byte == b'\n').count();
        remaining -= want as u64;
    }
    Ok(rows)
}

/// What `BufRead::lines` returns for bytes that are not text: an `io::Error`,
/// not a torn tail. A torn tail is a *parse* verdict on a row we could read;
/// bytes that are not UTF-8 never got that far, and calling them torn would
/// report a chain break where there is an encoding fault.
fn not_utf8() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "stream did not contain valid UTF-8",
    )
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
        tail_of_lines(file)
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
        tail_of_lines(std::io::Cursor::new(self.bytes()))
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

    use std::io::{BufRead, Cursor};

    use crate::signing::SigningKey;

    /// The pre-AILAB-852 locator, kept verbatim as the oracle the backward scan
    /// is measured against.
    ///
    /// **Production must not call this.** It is here to show that the new
    /// locator reports the rows the forward walk reported, not to give the
    /// crate a second opinion about what a tail is — and it lives beside the
    /// function it replaced rather than in a harness crate so the two cannot
    /// drift apart unnoticed.
    fn tail_of_lines_forward(bytes: &[u8]) -> Result<Option<PrevHash>, AuditError> {
        let mut last: Option<(usize, String)> = None;
        for (index, line) in bytes.lines().enumerate() {
            let line = line?;
            if !line.trim().is_empty() {
                last = Some((index + 1, line));
            }
        }
        let Some((number, line)) = last else {
            return Ok(None);
        };
        let value: serde_json::Value =
            serde_json::from_str(&line).map_err(|_| AuditError::TornTail { line: number })?;
        let canonical =
            to_canonical_json(&value).map_err(|_| AuditError::TornTail { line: number })?;
        Ok(Some(PrevHash::of_line(canonical.as_bytes())))
    }

    /// A locator's answer, reduced to something comparable: `AuditError` wraps
    /// an `io::Error` and so is not `PartialEq`.
    #[derive(Debug, PartialEq, Eq)]
    enum Tail {
        Empty,
        Hash(PrevHash),
        Torn(usize),
        NotUtf8,
    }

    fn seen(result: Result<Option<PrevHash>, AuditError>) -> Tail {
        match result {
            Ok(None) => Tail::Empty,
            Ok(Some(hash)) => Tail::Hash(hash),
            Err(AuditError::TornTail { line }) => Tail::Torn(line),
            Err(AuditError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData => {
                Tail::NotUtf8
            }
            Err(other) => panic!("unexpected locator error: {other:?}"),
        }
    }

    /// The hash a row's canonical form gets — what both locators must agree on.
    fn hash_of(row: &str) -> Tail {
        let value: serde_json::Value = serde_json::from_str(row).expect("a valid row");
        let canonical = to_canonical_json(&value).expect("canonical");
        Tail::Hash(PrevHash::of_line(canonical.as_bytes()))
    }

    /// A `Cursor` that counts the bytes handed out through `Read`, and nothing
    /// else: seeking is free, which is exactly the difference between locating
    /// a tail and walking to it.
    struct CountingReader<'a> {
        inner: Cursor<&'a [u8]>,
        read: usize,
    }

    impl Read for CountingReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let count = self.inner.read(buf)?;
            self.read += count;
            Ok(count)
        }
    }

    impl Seek for CountingReader<'_> {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

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

    #[test]
    fn tail_locator_matches_forward_walk_on_edge_cases() {
        let cases: Vec<(&str, &[u8], Tail)> = vec![
            ("empty store", b"", Tail::Empty),
            (
                "one row, trailing newline",
                b"{\"a\":1}\n",
                hash_of("{\"a\":1}"),
            ),
            (
                "one row, no trailing newline",
                b"{\"a\":1}",
                hash_of("{\"a\":1}"),
            ),
            (
                "trailing blank rows",
                b"{\"a\":1}\n\n\n",
                hash_of("{\"a\":1}"),
            ),
            (
                "whitespace-only last row",
                b"{\"a\":1}\n   \n",
                hash_of("{\"a\":1}"),
            ),
            (
                "torn last row, with newline",
                b"{\"a\":1}\n{\"b\":\n",
                Tail::Torn(2),
            ),
            ("torn last row, no newline", b"{\"a\":1}\n{", Tail::Torn(2)),
            (
                "blank row before a torn one",
                b"{\"a\":1}\n\n{",
                Tail::Torn(3),
            ),
            (
                "invalid UTF-8 in the last row",
                b"{\"a\":1}\n\xff\xfe",
                Tail::NotUtf8,
            ),
        ];

        for (name, bytes, want) in cases {
            assert_eq!(
                seen(tail_of_lines(Cursor::new(bytes))),
                want,
                "the backward scan reads `{name}` differently"
            );
            assert_eq!(
                seen(tail_of_lines_forward(bytes)),
                want,
                "the forward oracle reads `{name}` differently"
            );
        }

        // Two File answers the shared locator never produces: an empty file is
        // a fresh Chain, and a path that vanished is `FileChainSink`'s own
        // `NotFound` branch, which returns before the locator runs.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("chain.jsonl");
        let sink = FileChainSink::open(&path).expect("open");
        assert_eq!(sink.existing_tail().expect("an empty file"), None);
        std::fs::remove_file(&path).expect("remove");
        assert_eq!(sink.existing_tail().expect("a missing file"), None);
    }

    #[test]
    fn tail_scan_does_not_read_the_prefix() {
        // AILAB-852 AC 1, and the only test that can see it: the tail hash is
        // the same whichever way it is located, so an assertion on the hash
        // alone stays green over a forward walk of the whole store.
        let mut payload = Vec::new();
        let mut row = 0u64;
        while payload.len() < 1024 * 1024 {
            payload.extend_from_slice(format!("{{\"n\":{row}}}\n").as_bytes());
            row += 1;
        }
        let prefix = payload.len();
        assert!(prefix >= 1024 * 1024, "prefix is only {prefix} bytes");
        payload.extend_from_slice(b"{\"tail\":true}\n");

        let mut counting = CountingReader {
            inner: Cursor::new(payload.as_slice()),
            read: 0,
        };
        let found = tail_of_lines(&mut counting).expect("tail");

        assert_eq!(
            found.map(Tail::Hash).unwrap_or(Tail::Empty),
            hash_of("{\"tail\":true}"),
            "the located row must be the last one"
        );
        assert_eq!(
            found,
            tail_of_lines_forward(&payload).expect("oracle"),
            "the backward scan must report the row the forward walk reports"
        );
        assert!(
            counting.read < 64 * 1024,
            "locating the tail read {} bytes over a {prefix}-byte prefix; \
             a forward walk reads all of it",
            counting.read
        );
    }

    #[test]
    fn opening_a_session_on_thousands_of_lines_recovers_the_forward_walk_tail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("long.jsonl");

        // One write, not ten thousand appends: `FileChainSink::append` fsyncs
        // every line, and this fixture is about the read.
        let mut payload = String::new();
        for row in 0..10_000u64 {
            payload.push_str(&format!("{{\"n\":{row}}}\n"));
        }
        std::fs::write(&path, &payload).expect("write");

        let want = tail_of_lines_forward(payload.as_bytes())
            .expect("oracle")
            .expect("a tail");
        let sink = FileChainSink::open(&path).expect("open");
        assert_eq!(
            sink.existing_tail().expect("tail"),
            Some(want),
            "the adapter must locate the 10_000th row the forward walk located"
        );

        // And the Session that opens on it back-references the same hash. A
        // Durable sink, so a provisioned key — never the dev seed (ADR-0012).
        let _writer = crate::AuditWriter::open(&path, SigningKey::from_seed([0x2a; 32]))
            .expect("open a Session on the existing Chain");
        let text = std::fs::read_to_string(&path).expect("read back");
        let opened: serde_json::Value =
            serde_json::from_str(text.lines().nth(10_000).expect("the new Open line"))
                .expect("the Open line parses");
        assert_eq!(opened["line_type"], serde_json::Value::from("open"));
        assert_eq!(
            opened["prev_session_tail"],
            serde_json::Value::from(want.to_hex()),
            "the Open line must back-reference the last row already in the file"
        );
    }
}
