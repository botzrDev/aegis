//! End-to-end wrap relay overhead: a real child process, a real signed audit
//! sink, real fsyncs.
//!
//! Per iteration one whole [`run_wrap_with_streams`] session runs — signing key
//! loaded, `AuditWriter` opened, mirror child spawned, `CALLS_PER_ITER` scripted
//! JSON-RPC lines relayed and answered, child reaped, `close` line written.
//! `Throughput::Elements(CALLS_PER_ITER)` makes Criterion's `thrpt` row the
//! per-call figure; the `time` row is the whole session.
//!
//! Every iteration **verifies the session it just timed** — exit code and
//! `outcome`-row count — because a truncated session is a fast one, and a bench
//! that ignores what the run produced will happily publish the median of work
//! that did not happen. See [`wrap_session`].
//!
//! # What this number does not license
//!
//! - **It is not a sandbox overhead figure.** Wrap records; it does not confine
//!   (AILAB-626/628). Nothing here is the cost of isolating anything.
//! - **It is not portable.** A recorded call is two JSONL lines and therefore
//!   **two `sync_all` calls** (`crates/botzr-aegis-audit/src/writer.rs:218`), the
//!   shipped G3 durability default. On this box the audit crate's own two-line
//!   `begin_complete` cycle already publishes ~4.7 ms
//!   (`benches/results/cell_and_audit.md`), essentially all of it fsync on a
//!   WSL2 filesystem. Expect these medians to move by an order of magnitude
//!   elsewhere, and do not quote them as an Aegis-side compute cost.
//! - **Child spawn is amortised, not excluded.** One `fork`/`exec` of the mirror
//!   child is inside every iteration and is divided by `CALLS_PER_ITER` in the
//!   per-call figure. A one-call-per-process reading of it would be wrong.
//! - **The child is a fixture, not a tool.** The mirror child answers from a
//!   `match`; a real MCP server's own work is not in here.
//!
//! # Why the second group exists
//!
//! Isolating the recording work alone (parse → digest → `CallSession`
//! begin/complete) would mean reaching `record::observe_client_line`, which is
//! `pub(crate)`. Adding public API to make a bench possible is barred (PRD §10),
//! so the split is obtained by **differencing** instead: `ping_relayed_only`
//! drives the identical session shape over lines that are relayed with zero
//! interception, leaving spawn + key + `open`/`close` + byte relay in both
//! groups and only the per-call recording in one.

use std::hint::black_box;
use std::io::{self, Cursor};
use std::path::{Path, PathBuf};

use botzr_aegis_wrap::{run_wrap_with_streams, WrapConfig, WrapStreams};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use tempfile::TempDir;

/// JSON-RPC lines per iteration. Large enough that one child spawn is a small
/// share of the session, small enough that a sample stays under a second.
const CALLS_PER_ITER: u64 = 50;

/// One scripted client session: `CALLS_PER_ITER` lines of `method`, each with a
/// distinct id so every response matches exactly one request.
fn script(method: &str, params: &str) -> Vec<u8> {
    let mut out = String::new();
    for id in 1..=CALLS_PER_ITER {
        out.push_str(&format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}"{params}}}"#
        ));
        out.push('\n');
    }
    out.into_bytes()
}

/// One whole wrap session, start to finish — **checked**, then returned.
///
/// `client_out` and `child_err` are `io::sink()` so the measurement is wrap's
/// own cost rather than a terminal's. The audit path is caller-supplied and
/// **fresh per iteration**: reusing one file would make `AuditWriter::open`
/// rescan an ever-growing chain tail, which is a cost that climbs with the
/// sample number instead of a stationary one.
///
/// # Why the session is verified inside the timed region
///
/// A truncated session is *fast*. If wrap stops relaying early — a shutdown
/// grace that expires, a reader that mistakes a byte for EOF — it still returns
/// `Ok`, and a bench that only `expect`ed the `Result` would publish a median
/// for a session that carried fewer calls than it claims. So each iteration
/// asserts the exit code **and** counts the `outcome` rows the run actually
/// produced. The cost is one small file read per iteration against a
/// millisecond-scale, fsync-dominated session; measuring a number that might be
/// silently wrong is the worse trade.
fn wrap_session(
    child: &str,
    key_path: &Path,
    audit_path: PathBuf,
    script: &[u8],
    expected_outcomes: usize,
) -> u8 {
    let config = WrapConfig {
        child_argv: vec![child.to_owned()],
        audit_path: audit_path.clone(),
        signing_key_path: key_path.to_path_buf(),
        confinement: None,
    };
    let streams = WrapStreams {
        // Owned because `Box<dyn Read + Send>` is `'static`; a few KB of memcpy
        // against a millisecond-scale session.
        client_in: Box::new(Cursor::new(script.to_vec())),
        client_out: Box::new(io::sink()),
        child_err: Box::new(io::sink()),
    };
    let code =
        run_wrap_with_streams(&config, streams).expect("the mirror child relay must succeed");
    assert_eq!(
        code, 0,
        "a session that did not shut down cleanly is not the session this bench claims to measure"
    );

    let recorded = std::fs::read_to_string(&audit_path)
        .expect("the audit sink must exist")
        .lines()
        .filter(|line| line.contains("\"line_type\":\"outcome\""))
        .count();
    assert_eq!(
        recorded, expected_outcomes,
        "a truncated session is faster and would publish a median for work that never happened"
    );
    code
}

fn overhead(c: &mut Criterion) {
    let dir = TempDir::new().expect("temp dir for audit sinks");
    let key_path = dir.path().join("signing.key");
    // A persistent sink has no dev-key fallback (AILAB-620): mint a real key,
    // once, outside every measured region.
    botzr_aegis_audit::generate_signing_key(&key_path, false).expect("signing key");

    let child = env!("CARGO_BIN_EXE_aegis-wrap-mirror-child");
    let recorded = script(
        "tools/call",
        r#","params":{"name":"echo","arguments":{"text":"hello"}}"#,
    );
    let relayed = script("ping", "");

    let mut group = c.benchmark_group("wrap_relay");
    group.throughput(Throughput::Elements(CALLS_PER_ITER));

    // The shipped path: every line is a `tools/call`, so every line is an
    // intent line before the child sees it and an outcome line after the client
    // has its response.
    let mut recorded_session = 0u64;
    group.bench_function("tools_call_recorded", |b| {
        b.iter(|| {
            recorded_session += 1;
            let audit_path = dir
                .path()
                .join(format!("recorded-{recorded_session}.jsonl"));
            black_box(wrap_session(
                black_box(child),
                &key_path,
                audit_path,
                black_box(&recorded),
                CALLS_PER_ITER as usize,
            ))
        });
    });

    // Attribution baseline, informational: `ping` is relayed with zero
    // interception (`crates/botzr-aegis-wrap/src/record.rs:116-131`), so this
    // is the same session minus the per-call recording.
    let mut relayed_session = 0u64;
    group.bench_function("ping_relayed_only", |b| {
        b.iter(|| {
            relayed_session += 1;
            let audit_path = dir.path().join(format!("relayed-{relayed_session}.jsonl"));
            // Zero outcome rows is the *point* of this group: `ping` is relayed
            // with no recording at all, so any row here would mean the two
            // groups no longer differ only by the recording.
            black_box(wrap_session(
                black_box(child),
                &key_path,
                audit_path,
                black_box(&relayed),
                0,
            ))
        });
    });

    group.finish();
}

criterion_group!(benches, overhead);
criterion_main!(benches);
