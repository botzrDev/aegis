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
| `audit_emission/begin_complete` | **4.7185 ms** | no target set | n/a |
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

1. `block_on_async` builds a **fresh current-thread tokio runtime**
   (`crates/botzr-aegis-sandbox/src/engine.rs:366-372`) — one per call, not
   amortized;
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
