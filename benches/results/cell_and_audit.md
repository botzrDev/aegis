# Cell instantiation + audit emission Criterion results (AEG-005 / AILAB-683)

Covers the two AEG-005 rows `hot_path.md` deliberately does not: wasmtime
instantiation (warm and cold) and audit record emission. Policy and capability
numbers stay in
[`hot_path.md`](https://github.com/botzrDev/aegis/blob/main/benches/results/hot_path.md).

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
```

**Environment notes:** WSL2 / Linux; Criterion 0.5.1; Gnuplot not installed
(plotters backend); `wasmtime` 36.0.13 and `wasmtime-wasi` 36.0.12
(`Cargo.lock`); `bench` profile (optimized). Date: 2026-08-10.

**Toolchain differs from `hot_path.md`.** That file cites rustc 1.96.0; this run
used the repo-pinned 1.86 (`rust-toolchain.toml`). Numbers across the two files
are not strictly comparable.

## Command

```bash
cargo bench -p botzr-aegis-sandbox -p botzr-aegis-audit
```

## Summary vs targets

| Group | Median | Target | Status |
|---|---|---|---|
| `instantiation/warm` | **49.339 µs** | < 0.5 ms | **pass** (~10× under) |
| `instantiation/cold` | **39.490 ms** | < 5 ms | **fail** (~7.9× over) |
| `instantiation/cold_engine_only` | **456.08 µs** | informational | n/a |
| `instantiation/cold_compile_only` | **29.351 ms** | informational | n/a |
| `audit_emission/begin_complete` | **4.7185 ms** | none, deliberately — see below | n/a |
| `audit_emission/serialize_only` | **468.46 ns** | informational | n/a |

Criterion reports `[lower median upper]` as time/op; medians above are the
middle sample. All six come from a single process run.

## Criterion text tables

```
instantiation/warm      time:   [48.175 µs 49.339 µs 50.624 µs]
instantiation/cold      time:   [36.838 ms 39.490 ms 42.364 ms]
instantiation/cold_engine_only
                        time:   [438.01 µs 456.08 µs 478.53 µs]
instantiation/cold_compile_only
                        time:   [28.335 ms 29.351 ms 30.455 ms]

audit_emission/begin_complete
                        time:   [4.6635 ms 4.7185 ms 4.7730 ms]
audit_emission/serialize_only
                        time:   [462.98 ns 468.46 ns 474.43 ns]
```

## Stability across runs

This box is noisy for the compile-bound groups, so the verdicts below rest on
four consecutive runs rather than the single published one. Blank cells are
groups that did not exist yet in that run.

| Run | `warm` | `cold` | `cold_engine_only` | `cold_compile_only` | `begin_complete` |
|---|---|---|---|---|---|
| 1 | 54.519 µs | 27.799 ms | — | — | 4.6620 ms |
| 2 | 57.894 µs | 37.237 ms | 412.58 µs | 29.806 ms | — |
| 3 | 54.493 µs | 29.700 ms | 441.35 µs | 29.601 ms | 5.0875 ms |
| 4 *(published)* | 49.339 µs | 39.490 ms | 456.08 µs | 29.351 ms | 4.7185 ms |

`cold` swings 27.8–39.5 ms (~±20% around its mean) while its two components are
comparatively stable — engine construction 412–456 µs, compile/link
29.4–29.8 ms. In run 4 the components sum to ~29.8 ms against a 39.5 ms `cold`
median, i.e. **the splits do not reconcile with `cold` run-for-run**; only the
per-component medians are stable enough to attribute with. Both verdicts hold in
every run regardless: warm clears 0.5 ms by 8.6–10.1×, cold misses 5 ms by
5.6–7.9×.

## What each group actually measures

**`instantiation/warm` — includes a WIT `run` and a tokio runtime, not
instantiation alone.** `PreparedTool.tool_pre` is private and there is
deliberately no public instantiate-only API (adding one to make a bench possible
is forbidden by PRD §10), so the warm iteration goes through
`SandboxEngine::execute`. That is, per iteration:

1. `block_on` runs the guest future on the engine's tokio runtime
   (`crates/botzr-aegis-sandbox/src/engine.rs`). **These numbers were measured
   before AILAB-809**, when a fresh current-thread runtime was built per call
   and was therefore inside the median; the engine now builds one runtime in
   `SandboxEngine::new` and reuses it, so this step is amortized and the figure
   below is an upper bound on today's cost (re-measuring is AILAB-796's);
2. `build_store` — WASI ctx from the grant, memory limiter, epoch deadline;
3. `tool_pre.instantiate_async` — the actual warm instantiation;
4. the WIT `run` export.

The fixture is `tests/fixtures/echo-tool/echo.wasm`, whose `run` is an identity
copy of a 4-byte input, so guest-side work is negligible — but the
canonical-ABI lower/lift of `list<u8>` is inside the median. **49.339 µs is an
upper bound on warm re-instantiation, not an isolated instantiate cost**, and
the four components above were not separated because doing so would require new
public API.

The warm cache being measured is `PreparedTool { tool_pre }`
(`crates/botzr-aegis-sandbox/src/engine.rs:160-161`), populated by
`linker.instantiate_pre` at `engine.rs:81` and re-instantiated at
`engine.rs:286-289`. The `InstancePre` in `PreparedFixture` is a different,
`#[cfg(feature = "test-utils")]` object and is **not** what these numbers cover.

**`instantiation/cold` — fresh `Engine` + compile/link, no execute.**
`SandboxEngine::new()` + `prepare(ECHO)` per iteration. It deliberately does not
call `execute`, so cold-compile cost is never conflated with warm
instantiation-from-cache.

**Why cold misses 5 ms: it is `prepare`, not engine setup.** Engine construction
— config, linker, WASI link, epoch ticker spawn, plus the ticker join that
`Drop` pays — is **456.08 µs**, roughly 1–2% of every cold median observed.
`prepare` on an already-built engine is **29.351 ms**: that is `Component::new`
(Cranelift compilation of the 62 KB wit-bindgen component) plus
`linker.instantiate_pre` link resolution plus `ToolPre::new`, dominated by the
Cranelift compile but not exclusively it. There is no epoch-ticker thread storm.
The 5 ms target does not survive contact with an AOT compile of a component of
this size on 4 vCPUs; reaching it needs a different mechanism, not tuning.
Execution Report §7 was amended accordingly rather than the measurement being
reshaped to fit.

**`audit_emission/begin_complete` — the full two-line durable cycle.**
`CallSession::begin` (emits the `intent` line) → set policy allowed / capability
granted / execution success / metrics → `complete` (emits the `outcome` line).
Two JSONL lines means **two `sync_all` calls**
(`crates/botzr-aegis-audit/src/writer.rs:74`); the fsync-per-line is the shipped
G3 durability default and was not stripped for the bench. One writer is reused
across iterations so `TempDir` creation is not timed.

**The cycle is fsync-bound, and that is measured rather than assumed.**
`serialize_only` runs the same two records through the already-public
`to_json_line` with no file write and no fsync: **468.46 ns**, or **~0.01% of
the 4.7185 ms cycle**. Serialization is not a meaningful cost here; essentially
the entire median is write + fsync latency on WSL2's filesystem. Expect it to
move by an order of magnitude on a different filesystem, and **do not cite it as
an Aegis-side overhead figure**.

**There is no target on that row, and the blank is a decision rather than an
omission (AILAB-851).** `serialize_only` settles what the median is made of:
468.46 ns of Aegis-side work inside a 4.7185 ms cycle, so ~99.99% of it is
`write` + `fsync` latency on WSL2's filesystem. A number in that column would
therefore be a durability target for *someone else's storage stack* — it would
pass on an NVMe host and fail on a network mount without a line of this
repository changing, which is a claim about the hardware wearing a claim about
Aegis. The sentence above already forbids citing this figure as Aegis-side
overhead; a target would quietly license exactly that. What the row is for is
attribution, and it does that job with `serialize_only` beside it. If a
durability target is ever wanted it belongs on a named storage profile, not on
this row.

## Isolated ed25519 signing (AILAB-620)

Added because the previous section makes the emission cycle unusable as a
crypto number: at 4.7185 ms it is a measurement of `fsync`, and quoting a 50 µs
signing target against it would be a claim about the filesystem. This group
measures one thing — `SigningKey::sign` over bytes already in hand.

**Hardware / OS / toolchain: identical to the run above** (AMD Ryzen AI 5 340,
4 vCPUs, WSL2 Linux 6.6.87.2, rustc 1.86.0, Criterion 0.5.1, `bench` profile,
plotters backend). Date: 2026-08-11.

```bash
cargo bench -p botzr-aegis-audit --bench sign
```

| Group | Median | Target | Status |
|---|---|---|---|
| `audit_signing/sign_outcome_line` | **13.765 µs** | < 50 µs (AILAB-620) | **pass** (~3.6× under) |

```
audit_signing/sign_outcome_line
                        time:   [13.641 µs 13.765 µs 13.907 µs]
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild
```

Per iteration: one ed25519 signature over the canonical signing input of a
representative `outcome` line — the JCS form with `signature` absent and
`key_id` present (ADR-0003), built **once outside the loop**. No `AuditWriter`,
no file, no fsync, no canonicalization inside the measured region, so the median
is the signature and nothing else. The key comes from `insecure_dev_key`:
signing cost is a property of ed25519, not of which 32 bytes the seed holds, and
a fixed seed keeps the bench deterministic. Nothing here reads a key file.

**What this does and does not license.** 13.765 µs is the cost of *signing a
line*. It is not the cost of emitting one — that is `begin_complete` above, and
it is ~340× larger because of two `sync_all` calls. Adding signing to the shipped
emit path is therefore invisible against fsync; that is a statement about how
expensive durability is, not about how cheap ed25519 is. Cite the two numbers
together or neither.

## An audited call, end to end (AILAB-851)

Added because nothing here or in
[`hot_path.md`](https://github.com/botzrDev/aegis/blob/main/benches/results/hot_path.md)
measured a **call**. `hot_path/multi_rule` is stations 1–2 at 2.71 µs;
`audit_emission/begin_complete` is the two-line durable cycle on its own. Neither
is what one `Runtime::execute_host_call` costs, and the two do not add up to it
either. This group drives the whole pipeline — POLICY → CAPABILITY → SANDBOX →
AUDIT — with a host handler as the executable, so wasmtime compilation stays in
`instantiation/cold` where it belongs.

**It lives in this file rather than a fourth one** because
[`benches/README.md`](https://github.com/botzrDev/aegis/blob/main/benches/README.md)
declares exactly three scopes and all three are included verbatim into the book's
Benchmarks chapter. This file already owns audit record emission; an audited call
is that scope one level up.

**Two arms, one variable.** Both runtimes are built identically and differ only in
the sink: `durable_sink` is a `FileChainSink` with a provisioned key — the
configuration that retains evidence, and the one a Durable sink requires a real
key for (ADR-0012) — and `volatile_sink` is the shipped default, an in-memory
Chain that emits, signs and chains every record and then keeps none of it past
the process.

### EVERY NUMBER BELOW IS PROVISIONAL

This box swings ±20% on identical binaries — the `instantiation/cold` table above
is the evidence — and these were taken while it was doing other work. For this
group there is now direct evidence rather than an inherited caution: re-running it
in a second independent session on the same box did not reproduce the first
session's `durable_sink` figures at all. The two sessions' ranges do not overlap,
a 6.1× spread across six runs, and the table below records every one of them.
**AILAB-796 is the ticket that re-measures on a quiet machine**, and until it
lands nothing here should be quoted as a median. What is worth reading is the
*shape*: two to three orders of magnitude between the two sinks.

**Hardware / OS / toolchain: identical to the first run in this file** (AMD Ryzen
AI 5 340, 4 vCPUs, WSL2 Linux 6.6.87.2, rustc 1.86.0, Criterion 0.5.1, `bench`
profile, plotters backend). Date: 2026-09-01.

```bash
cargo bench -p botzr-aegis-runtime --bench audited_call
```

| Group | Range across six runs *(provisional)* | Target | Status |
|---|---|---|---|
| `audited_call/durable_sink` | **2.86 – 17.5 ms** — spans 6.1× across six runs in two sessions; not reproducible | none — see `begin_complete` above | n/a |
| `audited_call/volatile_sink` | **32.9 – 37.4 µs** — reproduces within 1.14× | none set | n/a |

```
audited_call/durable_sink
                        time:   [3.0238 ms 3.2586 ms 3.5437 ms]
Found 2 outliers among 20 measurements (10.00%)
audited_call/volatile_sink
                        time:   [34.153 µs 34.432 µs 34.799 µs]
Found 2 outliers among 20 measurements (10.00%)
```

### Stability across six runs in two independent sessions

Two independent sessions on the same box, three runs each. Nothing about the
binary, the hardware or the bench parameters differs between them.

| Run | Session | `durable_sink` | `volatile_sink` | ratio |
|---|---|---|---|---|
| 1 | 2026-09-01 | 3.2586 ms | 34.432 µs | 94.6× |
| 2 | 2026-09-01 | 2.8585 ms | 34.791 µs | 82.2× |
| 3 | 2026-09-01 | 3.7153 ms | 32.889 µs | 113.0× |
| 4 | 2026-09-07 | 17.505 ms | 34.889 µs | 501.7× |
| 5 | 2026-09-07 | 9.832 ms | 37.370 µs | 263.1× |
| 6 | 2026-09-07 | 13.895 ms | 33.566 µs | 414.0× |

**The volatile arm is the only reproducible number here, and the ratio is the
least stable thing in the group.** `volatile_sink` holds inside 1.14× across all
six runs and both sessions. `durable_sink` spans 6.12×, and the two sessions do
not merely differ — their ranges do not overlap at all, the second session's
fastest run being 2.6× the first session's slowest. Because the durable term
dominates the quotient, the ratio inherits every bit of that variance and spans
82×–502×. So the honest claim is *two to three orders of magnitude*, not a
figure, and no median for the durable arm belongs in this file at all. Anything
tighter needs AILAB-796.

### What the pair shows

**The configuration that is fast is the configuration that retains nothing.**
Both arms emit two signed, chained records per call; the only difference is
whether those records survive the process. That difference spans 82×–502× across
the six runs above — and it is almost entirely `fsync`, for the reason
`serialize_only` established above: serialization is 468 ns against a
millisecond-scale cycle. Evidence that outlives
the process costs two `sync_all` calls, and no amount of Aegis-side tuning
touches that number.

It also puts `hot_path/multi_rule` in proportion. Stations 1–2 are 2.71 µs;
the same call reaching AUDIT against the *unretained* default is 34.4 µs, about
13× more; against a retaining sink it is 2.86–17.5 ms, another 82×–502× beyond
that. The published 2.71 µs covers well under a percent of a durable call and
must not be quoted as its cost.

### The cross-check that would not reconcile, and its resolution

An end-to-end audited call appeared to measure **less** than
`audit_emission/begin_complete` (3.2586 ms against 4.7185 ms) while doing
strictly more work: the pipeline emits the same two lines through
`CallSession::begin` and `complete`
([`crates/botzr-aegis-runtime/src/pipeline.rs`](https://github.com/botzrDev/aegis/blob/main/crates/botzr-aegis-runtime/src/pipeline.rs)),
and adds policy, capability, the request digest and handler dispatch on top.
That is not possible if both figures measure the same fsync work under the same
conditions, so at least one of them had to be non-comparable.

**The six-run table above resolves it, and the split falls exactly on the
session boundary.** All three runs from 2026-09-01 land below `begin_complete`'s
4.7185 ms (3.2586, 2.8585, 3.7153 ms); all three from 2026-09-07 land above it
(17.505, 9.832, 13.895 ms). Neither figure was wrong when it was taken — the
first session simply caught a quiet `fsync` window. The two numbers are **not
separable at this measurement precision**: the fsync term dominates both, and it
varies by more than the gap between them. The earlier explanation that
`emission.rs` writes a larger fixture record than this group's grant remains
true, but it is not needed to account for the discrepancy and cannot be measured
apart from the noise.

That this was answerable one session later is entirely because the failure was
published instead of omitted — a number that does not reconcile is evidence about
the measurement, and hiding it would have left the next reader to rediscover it.
AILAB-796 should still re-measure both in one process run.

### Why the sample budget is capped

`MemoryChainSink` holds an `Arc<Mutex<Vec<u8>>>` and never truncates, so the
volatile arm retains every byte it emits for the life of the bench process. At
Criterion's default budget it would append hundreds of megabytes and start
measuring the allocator. The group therefore sets a 500 ms warm-up, a 2 s
measurement window and 20 samples; peak RSS for the run above was 124 MB. Both
arms get the same budget, so the comparison is unaffected — but the sample count
is lower than the rest of this file, which is a second reason to treat these as
provisional.

## Notes

- The sandbox crate's benches are compiled with the `test-utils` feature on,
  because a pre-existing self dev-dependency
  (`crates/botzr-aegis-sandbox/Cargo.toml:43`) enables it for all dev targets so
  `tests/sandbox.rs` can reach the fixture API. The bench uses **no**
  `test-utils` item: the feature gates only additive `prepare_fixture` /
  `execute_fixture` / `PreparedFixture`, none of which is on the measured
  `prepare` / `execute` path.
- No public API was added to either crate to make these benches possible.
  `serialize_only` uses `to_json_line`, which was already exported.
- HTML reports live under `target/criterion/` and are **not** committed.
