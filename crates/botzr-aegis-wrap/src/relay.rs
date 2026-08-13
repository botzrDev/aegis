//! The pump: client ↔ wrap ↔ child, newline-framed, byte-oriented.
//!
//! # Framing
//!
//! A **frame** is the bytes up to and **not including** the `\n` that delimited
//! it. Frames are `Vec<u8>`, never `String`:
//!
//! - Bytes inside a frame are relayed verbatim. A trailing `\r` (CRLF framing)
//!   is **preserved**, not stripped, and invalid UTF-8 is relayed unchanged —
//!   it merely means "not a `tools/call`" to the recorder.
//! - Request and response digests cover **exactly** the frame bytes: the `\r`
//!   is in, the `\n` delimiter is out.
//! - The only normalization is at the framing layer itself: the `\n` delimiter
//!   is re-emitted (so a final frame that arrived without one gains one), and a
//!   frame that is empty or all ASCII whitespace is dropped rather than
//!   forwarded, because it carries no JSON-RPC message.
//!
//! Reading with `BufRead::read_until(b'\n')` rather than `BufRead::lines()` is
//! load-bearing, not a style choice: `lines()` yields `Err(InvalidData)` on any
//! non-UTF-8 byte, and a reader loop that treats a read error as end-of-stream
//! would turn one stray byte from a third-party server into a silent EOF —
//! truncating the session, and swallowing every stderr byte that followed.
//!
//! # Threading
//!
//! Three plain `std::thread::spawn` helpers feed one main event loop:
//!
//! ```text
//! thread A  client_in     ──ClientFrame / ClientEof──┐
//! thread B  child stdout  ──ChildFrame  / ChildEof───┤ mpsc ─→ main loop
//! thread C  child stderr  ──writes child_err directly, no channel
//! ```
//!
//! **All audit work happens on the main thread.** The `AuditWriter` and every
//! in-flight `CallSession` live in the loop, so there is no `Mutex<CallSession>`
//! and no lifetime to thread through a worker.
//!
//! The readers are `'static` and detached, not scoped. A `std::thread::scope`
//! would have to join thread A on the way out, and thread A can be blocked
//! forever on a live TTY — so the scope would hang on exactly the path this
//! module has to survive, the child dying while the client is still typing. The
//! child is reaped before returning, so a detached reader leaves no zombie; the
//! process exits and takes the thread with it.
//!
//! # Ordering (both directions are load-bearing)
//!
//! - Client → child: **record first, relay second.** The intent line must be
//!   durable before the request can reach the tool.
//! - Child → client: **relay first, record second.** The client never waits on
//!   an fsync that can just as correctly happen after its response is on the
//!   wire.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use botzr_aegis_audit::{load_signing_key, AuditWriter};

use crate::config::{WrapConfig, WrapStreams};
use crate::error::WrapError;
use crate::record::{self, Observed, PendingCall, Unanswered};

/// How often a bounded poll re-asks its question.
const POLL: Duration = Duration::from_millis(20);
/// How long the child gets, after its stdin closes, to produce *anything*
/// before wrap stops waiting for it. Re-armed by every byte the child sends.
const REAP_GRACE: Duration = Duration::from_secs(5);
/// How long the stderr tee gets to drain after the child is reaped.
const STDERR_DRAIN: Duration = Duration::from_secs(2);
/// How long a diagnostic waits for the stderr sink before giving up on it.
///
/// The sink is shared with the tee thread, which can be parked mid-write on a
/// pipe nobody is reading. Blocking here would make one unread pipe an
/// unbounded wait on wrap's exit path, so the diagnostic is dropped instead.
const SINK_LOCK_GRACE: Duration = Duration::from_secs(2);

/// Said once per session, the first time a JSON-RPC batch array goes past.
///
/// Named on the child-stderr sink rather than hidden: a batched `tools/call` is
/// relayed with **no** audit record, and an audit tool that bypasses itself in
/// silence is worse than one that says so. See the crate README.
const BATCH_BYPASS_DIAGNOSTIC: &str = "aegis wrap: relayed a JSON-RPC batch array \
     — any tools/call inside a batch is NOT recorded (known gap, see the botzr-aegis-wrap README)";

/// Said once, when the child quits under a client that is still open.
const CHILD_DIED_EARLY_DIAGNOSTIC: &str =
    "aegis wrap: child process exited before the client closed stdin";

/// The child's stderr sink, shared because two writers need it: the tee thread
/// and the main thread's lifecycle diagnostics.
type SharedErr = Arc<Mutex<Box<dyn Write + Send>>>;

/// What the reader threads tell the main loop.
enum Event {
    ClientFrame(Vec<u8>),
    ClientEof,
    ChildFrame(Vec<u8>),
    ChildEof,
}

/// Run a wrap session on this process's own stdio.
///
/// Returns the exit code the caller should hand back to the shell.
pub fn run_wrap(config: &WrapConfig) -> Result<u8, WrapError> {
    run_wrap_with_streams(
        config,
        WrapStreams {
            client_in: Box::new(io::stdin()),
            client_out: Box::new(io::stdout()),
            child_err: Box::new(io::stderr()),
        },
    )
}

/// [`run_wrap`], with the client-facing streams supplied by the caller.
///
/// See [`WrapStreams`] for why this seam exists.
pub fn run_wrap_with_streams(config: &WrapConfig, streams: WrapStreams) -> Result<u8, WrapError> {
    let (program, args) = config
        .child_argv
        .split_first()
        .ok_or(WrapError::EmptyArgv)?;

    // Key and sink before the child: a wrap session that cannot record must not
    // have already started a tool server.
    let signing_key = load_signing_key(&config.signing_key_path)?;
    let writer = AuditWriter::open(&config.audit_path, signing_key)?;

    let mut child = spawn_child(program, args, config)?;

    // `Stdio::piped()` on all three was just requested, so these are present.
    let child_stdin = child.stdin.take().expect("child stdin was piped");
    let child_stdout = child.stdout.take().expect("child stdout was piped");
    let child_stderr = child.stderr.take().expect("child stderr was piped");

    let shared_err: SharedErr = Arc::new(Mutex::new(streams.child_err));
    let mut client_out = streams.client_out;

    let (tx, rx) = mpsc::channel();
    spawn_client_reader(streams.client_in, tx.clone());
    spawn_child_reader(child_stdout, tx.clone());
    let stderr_tee = spawn_stderr_tee(child_stderr, Arc::clone(&shared_err));
    // The loop ends on `ChildEof`; dropping the spare sender means it also ends
    // if both readers vanish without one.
    drop(tx);

    let pumped = pump(&writer, &rx, child_stdin, &mut client_out, &shared_err);
    // Reap unconditionally. A pump that failed must not leave a zombie behind,
    // and the child holds the audit-relevant exit status either way.
    let reaped = reap(&mut child);
    // The tee is drained *after* the child is gone, so the child's last stderr
    // bytes cannot be lost to the return. Bounded, because a grandchild holding
    // the pipe open must not be able to hang wrap.
    drain(stderr_tee, STDERR_DRAIN);

    let child_died_early = pumped?;
    let status = reaped?;

    if child_died_early {
        diagnose(&shared_err, CHILD_DIED_EARLY_DIAGNOSTIC);
    }

    let code = exit_code_of(&status);
    // A child that quits under a live client is a failure of the session even
    // when the child itself thought it exited cleanly.
    Ok(if child_died_early && code == 0 {
        1
    } else {
        code
    })
}

/// The main event loop. Returns whether the child died while the client was
/// still open.
fn pump(
    writer: &AuditWriter,
    rx: &Receiver<Event>,
    child_stdin: ChildStdin,
    client_out: &mut Box<dyn Write + Send>,
    child_err: &SharedErr,
) -> Result<bool, WrapError> {
    // `Option` because client EOF closes the pipe by dropping the handle.
    let mut child_stdin = Some(child_stdin);
    let mut client_open = true;
    let mut child_died_early = false;
    let mut batch_named = false;
    // Set once the client is gone. Until then the loop blocks indefinitely,
    // which is correct: a live client may say nothing for hours.
    let mut shutdown_deadline: Option<Instant> = None;
    // Why any calls left in flight went unanswered. Only the two exits below
    // change it, and they are different facts — see [`Unanswered`].
    let mut unanswered = Unanswered::ChildExited;
    let mut pending: HashMap<String, PendingCall<'_>> = HashMap::new();

    loop {
        // LOAD-BEARING: after client EOF the wait is bounded. A child that
        // ignores stdin EOF and goes silent would otherwise park this loop on
        // `recv()` forever and `reap`'s bounded poll would never be reached —
        // the shell would never get its prompt back. Expiry falls through to
        // `reap`, which kills it.
        //
        // Equally load-bearing: the deadline is re-armed by every child frame
        // below, so this bounds *silence*, not work. A child still answering
        // after client EOF is not truncated, and no record ever says a live
        // process exited.
        let event = match shutdown_deadline {
            None => match rx.recv() {
                Ok(event) => event,
                Err(_) => break,
            },
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    unanswered = Unanswered::ShutdownGraceExpired;
                    break;
                }
                match rx.recv_timeout(remaining) {
                    Ok(event) => event,
                    Err(RecvTimeoutError::Timeout) => {
                        unanswered = Unanswered::ShutdownGraceExpired;
                        break;
                    }
                    // Both readers are gone, which means the child's stdout is
                    // closed: the child is not coming back.
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        };
        match event {
            Event::ClientFrame(frame) => {
                if is_blank(&frame) {
                    continue;
                }
                // Record first: the intent line has to be durable before the
                // request can reach the tool.
                match record::observe_client_line(writer, &frame)? {
                    // A repeated id replaces the older call, whose `Drop` emits
                    // the fail-closed outcome — one id, one answerable call.
                    Observed::Pending(id_key, call) => {
                        pending.insert(id_key, *call);
                    }
                    Observed::Batch => {
                        if !batch_named {
                            batch_named = true;
                            diagnose(child_err, BATCH_BYPASS_DIAGNOSTIC);
                        }
                    }
                    Observed::Ignored => {}
                }
                if let Some(stdin) = child_stdin.as_mut() {
                    if write_frame(stdin, &frame).is_err() {
                        // The child's stdin is gone. Stop feeding it and let the
                        // `ChildEof` that must follow end the loop, rather than
                        // failing the whole session on a broken pipe.
                        child_stdin = None;
                    }
                }
            }
            Event::ClientEof => {
                client_open = false;
                // Dropping the handle closes the pipe, which is the child's
                // shutdown signal.
                child_stdin = None;
                shutdown_deadline = Some(Instant::now() + REAP_GRACE);
            }
            Event::ChildFrame(frame) => {
                // Any output at all proves the child is alive and working, so a
                // shutdown in progress restarts its grace from now. Without
                // this, a child still answering at the 5 s mark would be cut
                // off mid-session and its in-flight calls recorded against a
                // process that had not exited.
                if let Some(deadline) = shutdown_deadline.as_mut() {
                    *deadline = Instant::now() + REAP_GRACE;
                }
                if is_blank(&frame) {
                    continue;
                }
                // Relay first: the client does not wait on our fsync.
                write_frame(client_out, &frame)?;
                if let Some(call) =
                    record::response_id_key(&frame).and_then(|id_key| pending.remove(&id_key))
                {
                    record::complete_relayed(call, &frame)?;
                }
            }
            Event::ChildEof => {
                child_died_early = client_open;
                break;
            }
        }
    }

    // Every call still in flight is a call the child never answered — said with
    // the reason that is actually true of this exit.
    for (_, call) in pending.drain() {
        record::complete_unanswered(call, unanswered)?;
    }
    Ok(child_died_early)
}

/// Write one frame verbatim, then the `\n` that delimits it, then flush.
///
/// The delimiter is re-emitted rather than carried through the relay, which is
/// what gives a final frame that arrived without a newline exactly one.
fn write_frame(sink: &mut impl Write, frame: &[u8]) -> io::Result<()> {
    sink.write_all(frame)?;
    sink.write_all(b"\n")?;
    sink.flush()
}

/// A frame with no message in it. Dropped rather than forwarded — see the
/// module's framing note.
fn is_blank(frame: &[u8]) -> bool {
    frame.iter().all(u8::is_ascii_whitespace)
}

/// Spawn the child, re-execing through `aegis __confine-exec` when a
/// confinement profile is set. The profile travels in the environment, never
/// argv (`/proc/<pid>/cmdline` is world-readable). Enforcement facts come back
/// on `AEGIS_CONFINE_REPORT`, a file next to the audit path — not stdin/stdout
/// (MCP) and not stderr (the tee).
fn spawn_child(program: &str, args: &[String], config: &WrapConfig) -> Result<Child, WrapError> {
    let mut cmd = if let Some(profile) = &config.confinement {
        let exe = std::env::current_exe().map_err(|source| WrapError::Spawn {
            program: program.to_string(),
            source,
        })?;
        let mut report = config.audit_path.as_os_str().to_os_string();
        report.push(".enforced.json");
        let json = serde_json::to_string(profile).map_err(|e| WrapError::Spawn {
            program: program.to_string(),
            source: io::Error::new(io::ErrorKind::InvalidData, e),
        })?;
        let mut cmd = Command::new(exe);
        cmd.arg("__confine-exec")
            .arg("--")
            .arg(program)
            .args(args)
            .env(botzr_aegis_confine::PROFILE_ENV, json)
            .env(botzr_aegis_confine::REPORT_ENV, report);
        cmd
    } else {
        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd
    };
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| WrapError::Spawn {
            program: program.to_string(),
            source,
        })
}

fn spawn_client_reader(client_in: Box<dyn Read + Send>, tx: Sender<Event>) {
    spawn_reader(client_in, tx, Event::ClientFrame, Event::ClientEof);
}

fn spawn_child_reader(child_stdout: ChildStdout, tx: Sender<Event>) {
    spawn_reader(child_stdout, tx, Event::ChildFrame, Event::ChildEof);
}

/// Newline-framed reader thread: one event per frame, then exactly one EOF
/// event.
///
/// `read_until` rather than `lines()`: see the module's framing note. Bytes are
/// carried as bytes, so no input can be *invalid* here — only short.
///
/// A read *error* is reported as EOF. From the relay's point of view the two are
/// the same fact — no more frames are coming from this side — and inventing a
/// third state would give the loop a case with no correct action. What matters
/// is that a non-UTF-8 byte is no longer one of those errors.
fn spawn_reader<R: Read + Send + 'static>(
    reader: R,
    tx: Sender<Event>,
    frame_event: fn(Vec<u8>) -> Event,
    eof_event: Event,
) {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        loop {
            let mut frame = Vec::new();
            match reader.read_until(b'\n', &mut frame) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            // The delimiter is framing, not content: it leaves here and is
            // re-emitted by `write_frame`. A trailing `\r` is content and stays.
            if frame.last() == Some(&b'\n') {
                frame.pop();
            }
            if tx.send(frame_event(frame)).is_err() {
                // The main loop is gone; nothing left to relay to.
                return;
            }
        }
        let _ = tx.send(eof_event);
    });
}

/// Tee the child's stderr to the caller's sink, **byte for byte**.
///
/// **Never swallowed and never merged into `client_out`**: a wrapped server's
/// diagnostics are most of what makes a wrap session debuggable, and stdout
/// carries JSON-RPC only.
///
/// Deliberately not line-oriented and deliberately not UTF-8. Third-party
/// servers launched through `npx` or `python` emit progress bars, ANSI escapes
/// and occasionally raw binary; a `lines()` tee would stop at the first
/// non-UTF-8 byte and silently swallow everything after it, which is the
/// opposite of this crate's one promise about stderr. Raw chunks also mean a
/// partial line with no trailing newline reaches the operator immediately
/// instead of being held back.
fn spawn_stderr_tee(child_stderr: ChildStderr, sink: SharedErr) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut reader = child_stderr;
        let mut buf = [0u8; 8192];
        loop {
            let read = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            let mut guard = lock(&sink);
            if guard.write_all(&buf[..read]).is_err() {
                break;
            }
            let _ = guard.flush();
        }
    })
}

/// Wait, bounded, for a detached thread to finish.
///
/// `JoinHandle::join` would be unbounded, and this is called on the exit path.
fn drain(handle: JoinHandle<()>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(POLL);
    }
    let _ = handle.join();
}

/// Reap the child: poll for a clean exit, then kill it.
///
/// Bounded on purpose. `Child::wait` would block forever on a server that
/// ignores stdin EOF, and wrap must not be the reason a shell never gets its
/// prompt back.
fn reap(child: &mut Child) -> Result<ExitStatus, WrapError> {
    let deadline = Instant::now() + REAP_GRACE;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(POLL);
    }
    // Best-effort: the child may have exited between the last poll and here.
    let _ = child.kill();
    Ok(child.wait()?)
}

/// Map the child's exit status onto a process exit code.
///
/// A signalled child reports no code at all; `1` is the honest "it did not exit
/// cleanly". A non-zero code whose low byte is zero maps to `1` for the same
/// reason — reporting success for a failure would be worse than losing the
/// exact number.
fn exit_code_of(status: &ExitStatus) -> u8 {
    match status.code() {
        Some(0) => 0,
        None => 1,
        Some(code) => match (code as u32 & 0xff) as u8 {
            0 => 1,
            truncated => truncated,
        },
    }
}

/// Put one wrap-authored line on the child-stderr sink, best effort.
///
/// Best effort in two ways, both deliberate: the write itself is unchecked
/// (there is nowhere left to report a failure to report), and the lock is
/// **bounded** — if the tee thread is parked writing to a pipe nobody reads,
/// the diagnostic is dropped rather than turned into an unbounded wait.
fn diagnose(sink: &SharedErr, message: &str) {
    let Some(mut guard) = lock_bounded(sink, SINK_LOCK_GRACE) else {
        return;
    };
    let _ = writeln!(guard, "{message}");
    let _ = guard.flush();
}

/// `lock`, but it gives up instead of waiting forever.
fn lock_bounded(
    sink: &SharedErr,
    timeout: Duration,
) -> Option<MutexGuard<'_, Box<dyn Write + Send>>> {
    let deadline = Instant::now() + timeout;
    loop {
        match sink.try_lock() {
            Ok(guard) => return Some(guard),
            // Same reasoning as `lock`: a poisoned sink is still a usable one.
            Err(TryLockError::Poisoned(poisoned)) => return Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(POLL);
            }
        }
    }
}

/// A poisoned sink means a previous write panicked. Recovering the guard keeps
/// the child's diagnostics flowing; refusing to would turn one bad write into
/// permanent silence.
///
/// Only the tee thread blocks on this. The tee has nothing else to do and no
/// exit path depends on it finishing — `drain` is bounded — so a slow consumer
/// parks one detached thread rather than the process.
fn lock(sink: &SharedErr) -> MutexGuard<'_, Box<dyn Write + Send>> {
    sink.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
