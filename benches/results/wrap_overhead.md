# `aegis wrap` relay overhead Criterion results (AILAB-625)

One number, measured end to end: what it costs to put `aegis wrap` between an
MCP client and a stdio child server. Per iteration a whole
`run_wrap_with_streams` session runs — signing key loaded, `AuditWriter` opened,
child spawned, 50 scripted JSON-RPC lines relayed and answered, child reaped,
`close` line written.

**What it deliberately does not cover.** This is not a confinement cost: this
run sets `confinement: None`, so wrap records without confining and the
capability/sandbox stations never run here. It is not a policy or wasmtime
number either — those live in
[`hot_path.md`](https://github.com/botzrDev/aegis/blob/main/benches/results/hot_path.md)
and
[`cell_and_audit.md`](https://github.com/botzrDev/aegis/blob/main/benches/results/cell_and_audit.md).
It is
not a portable figure: a recorded call is two JSONL lines and therefore two
`sync_all` calls, so the median is dominated by this filesystem. And it is not a
measure of any real MCP server's work — the child is the in-repo mirror fixture,
which answers from a `match`.

## Hardware / OS

```
uname -a
Linux botzrDev 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux

lscpu (selected):
Architecture:                         x86_64
Model name:                           AMD Ryzen AI 5 340 w/ Radeon 840M
CPU(s):                               4
Thread(s) per core:                   2
Core(s) per socket:                   2
Hypervisor vendor:                    Microsoft
Virtualization type:                  full

rustc -Vv:
rustc 1.86.0 (05f9846f8 2025-03-31)
host: x86_64-unknown-linux-gnu
LLVM version: 19.1.7
```

**Environment notes:** WSL2 / Linux; Criterion 0.5.1 (`Cargo.lock`); Gnuplot not
installed (plotters backend); `bench` profile (optimized); repo-pinned toolchain
1.86 (`rust-toolchain.toml`). Date: 2026-08-12.

**Same box and same toolchain as `cell_and_audit.md`**, so the audit crate's
`audit_emission/begin_complete` (**4.7185 ms**, 2026-08-10) is directly
comparable and is used below as the reference for the fsync cost sitting inside
every recorded call.

## Command

```bash
cargo bench -p botzr-aegis-wrap
```

## Summary vs targets

Criterion reports `[lower median upper]` per **iteration** (50 calls);
`Throughput::Elements(50)` turns the `thrpt` row into the per-call figure.
Per-call medians below are the published iteration median ÷ 50, which agrees
with the reciprocal of the `thrpt` median to four significant figures.

| Group | Median / session (50 calls) | Median / call | Target | Status |
|---|---|---|---|---|
| `wrap_relay/tools_call_recorded` | **218.54 ms** | **4.371 ms** | 0.5–2 ms (informational) | **miss** (~2.19× over the 2 ms ceiling) |
| `wrap_relay/ping_relayed_only` | **6.8027 ms** | **136.05 µs** | informational (attribution baseline) | n/a |

**Derived attribution — recording, per recorded call: 4.235 ms.**
`(218.54 ms − 6.8027 ms) ÷ 50`. Everything the two groups share — key load,
`AuditWriter::open`, child spawn, 50 relayed lines and 50 responses, reap,
`close` — cancels in the subtraction, leaving the per-call `intent` + `outcome`
pair. That 4.235 ms lands within 11% of the audit crate's own two-line
`begin_complete` cycle (4.7185 ms), which is the expected result if wrap's
recording is exactly two durable lines and nothing else.

**The miss is the honest outcome, not a regression.** The 0.5–2 ms target
(spec §1.9 / §3.4) is informational and predates the measurement. Two `sync_all`
calls on this filesystem cost ~4.2 ms on their own, so no arrangement of wrap
code reaches 2 ms per recorded call while durability stays at the shipped G3
default. Reaching it needs a different mechanism (batched or deferred fsync),
which is a durability decision, not a tuning exercise. Nothing was narrowed,
stripped, or made private-API-shaped to improve the number (PRD §10).

## Criterion text tables

Raw output of the published run, verbatim:

```
Gnuplot not found, using plotters backend
Benchmarking wrap_relay/tools_call_recorded
Benchmarking wrap_relay/tools_call_recorded: Warming up for 3.0000 s

Warning: Unable to complete 100 samples in 5.0s. You may wish to increase target time to 19.8s, or reduce sample count to 20.
Benchmarking wrap_relay/tools_call_recorded: Collecting 100 samples in estimated 19.757 s (100 iterations)
Benchmarking wrap_relay/tools_call_recorded: Analyzing
wrap_relay/tools_call_recorded
                        time:   [210.32 ms 218.54 ms 227.62 ms]
                        thrpt:  [219.66  elem/s 228.80  elem/s 237.74  elem/s]
Found 11 outliers among 100 measurements (11.00%)
  6 (6.00%) high mild
  5 (5.00%) high severe
Benchmarking wrap_relay/ping_relayed_only
Benchmarking wrap_relay/ping_relayed_only: Warming up for 3.0000 s
Benchmarking wrap_relay/ping_relayed_only: Collecting 100 samples in estimated 5.0924 s (400 iterations)
Benchmarking wrap_relay/ping_relayed_only: Analyzing
wrap_relay/ping_relayed_only
                        time:   [6.3020 ms 6.8027 ms 7.3371 ms]
                        thrpt:  [6.8147 Kelem/s 7.3500 Kelem/s 7.9339 Kelem/s]
Found 18 outliers among 100 measurements (18.00%)
  11 (11.00%) high mild
  7 (7.00%) high severe
```

The Criterion warning is left in: the recorded group needs ~20 s for 100
samples, and the run was not shortened by cutting the sample count.

## Stability across runs

Two consecutive runs of the same command on the same box. Run 1 is published
above; run 2 is the immediate repeat, so Criterion also printed its
`change:` comparison against run 1.

| Run | `tools_call_recorded` / call | `ping_relayed_only` / call | derived recording / call | outliers (rec / ping) |
|---|---|---|---|---|
| 1 *(published)* | 4.371 ms | 136.05 µs | 4.235 ms | 11% / 18% |
| 2 | 4.176 ms | 136.70 µs | 4.040 ms | 3% / 6% |

Criterion's own verdict on run 2 was **`No change in performance detected`** for
both groups (`p = 0.06` and `p = 0.92`). The published run is the noisier of the
two and its median is the slower of the two; the verdict is a miss in both.

## What each group actually measures

**`wrap_relay/tools_call_recorded` — the shipped recording path, whole session.**
Every one of the 50 client lines is a `tools/call` with a distinct id, so every
line takes the full recording route in
`crates/botzr-aegis-wrap/src/record.rs:59-119`: `serde_json::from_str` on the raw
line, `RequestDigest::of_request_bytes` over the verbatim bytes
(`record.rs:78`), `PolicySetHash::of_canonical_bytes` over the pass-through
constant (`record.rs:79`), `CallSession::begin` (`record.rs:110`) — one `intent`
line, fsynced **before** the request is relayed
(`crates/botzr-aegis-wrap/src/relay.rs:199-203`) — and then, on the child's
matching response, `complete_relayed` (`record.rs:129-161`) with the `deny_all`
grant, the response digest, the metrics and `complete()` — the second line, and
the second fsync (`crates/botzr-aegis-audit/src/writer.rs:218`). Also inside the
iteration and **not** amortised away: `load_signing_key` and `AuditWriter::open`
(`relay.rs:90-91`), the child `spawn` (`relay.rs:93-102`), the bounded reap
(`relay.rs:319-333`), the stderr-tee drain (`relay.rs:127`), and the `close`
line the `AuditWriter` writes on drop.

**`wrap_relay/ping_relayed_only` — the same session with the recording removed.**
`ping` is not `tools/call`, so `observe_client_line` returns `None` at
`record.rs:66` before any digest, session or audit line exists; the line is
relayed with zero interception and the mirror child answers
`{"result":{"mirrored":"ping"}}`. The group therefore carries the identical
fixed cost — key, writer `open`/`close`, spawn, reap, drain — plus 50 round
trips of pure byte relay.

**Its per-call figure is an upper bound on byte relay, not a measurement of it.**
136.05 µs/call is 6.8027 ms of session cost divided by 50, and most of that
session cost is the fixed part (one process spawn, one key load, two fsynced
Session lines). This bench does not separate spawn from per-line relay, and no
third group was added to try: the only figure it is used for is the
subtraction above, where the fixed part cancels.

**What is outside the measured region:** the `TempDir`, the signing **key
generation** (`generate_signing_key`, once, hoisted), and both scripted request
bodies — all built before the first iteration. Inside the region but negligible
against milliseconds: a `Vec<String>` argv clone, a `PathBuf` join, and a few KB
of `script.to_vec()` memcpy per session.

**Why the audit file is fresh per iteration.** Each session writes to
`recorded-<n>.jsonl` / `relayed-<n>.jsonl` in one hoisted `TempDir`. Reusing a
single path would make `AuditWriter::open` recover the previous Session's tail
from an ever-growing file, so the per-iteration cost would climb with the sample
number — a non-stationary measurement. File creation is consequently inside the
timed region, which is the honest trade and is far below the fsync cost that
dominates it.

## Notes

- **No public API was added to any crate to make this bench possible (PRD §10).**
  A group isolating the recording work alone — parse + digest + `CallSession`
  begin/complete, with no child and no byte relay — was considered and
  **skipped**: `record::observe_client_line` and `complete_relayed` are
  `pub(crate)` and a bench is an external crate, so the only way to reach them
  would have been to widen `botzr-aegis-wrap`'s public surface for a
  measurement. The attribution is obtained by differencing two shipped-path
  groups instead, and `benches/results/cell_and_audit.md`'s
  `audit_emission/begin_complete` already isolates the durable cycle from the
  other side.
- **Child-process spawn is amortised across the 50 calls in every group.** A
  per-call figure derived from a one-call-per-process session would be much
  larger and would not describe how wrap is used — a wrap process lives for a
  whole client session.
- The outlier rates (up to 18% in run 1) are consistent with the 20 ms poll
  granularity of `reap` (`relay.rs:47`, `relay.rs:319-333`) and of `drain`
  (`relay.rs:303-312`) occasionally landing inside an iteration when the child
  has not yet been reaped by the time the pump breaks. That mechanism is a
  hypothesis from reading the code, **not** something this bench measured;
  per-sample data would be needed to confirm it.
- Wrap does not meter the child, so nothing in these numbers is the child's own
  resource use. `CallMetrics::peak_memory_bytes` is recorded as `0` = "not
  measured" (`record.rs:152-155`).
- HTML reports live under `target/criterion/` and are **not** committed.
