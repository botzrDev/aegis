# Coverage ratchet

> **Status:** current (AILAB-636, re-based under AILAB-712) · **Last updated:** 2026-08-25
> **Related:** [README § Quickstart](../README.md#quickstart) · [`coverage/baseline.json`](../coverage/baseline.json) · [`scripts/coverage.sh`](../scripts/coverage.sh) · [Release checklist](release-checklist.md)

Total workspace line coverage may not go down. CI enforces that on every pull
request and every push to `main`; the release checklist enforces it again at tag
time. This page is the contributor-facing half — what the gate measures, and
what to do when it fails for a legitimate reason.

## What is measured

`cargo llvm-cov --workspace` over one instrumented test run, reduced to a single
number: **total lines covered / total lines**. Not per-crate, not per-file, not
branch or region coverage. The current high-water mark lives in
[`coverage/baseline.json`](../coverage/baseline.json).

Scope follows the Cargo workspace. `fuzz/` is an excluded sibling project with
its own nightly toolchain, and `governance/` is a separate Python service — the
ratchet covers neither.

One file inside the workspace is excluded too, via `--ignore-filename-regex` in
the script: `crates/botzr-aegis-confine/src/bin/probe.rs`, which is a **test
fixture** and says so in its own module doc. Counting a fixture as product
coverage is a category error. `crates/botzr-aegis-cli/src/confine_exec.rs` has
the same measurement problem (below) and is deliberately **kept**: it is real
enforcement code, and dropping the confinement mechanism out of the report is
how a coverage number stops being worth reading.

## Two things this number does not mean

Both were measured on this repo under AILAB-712, not inferred.

**`exec()` and signal deaths erase coverage.** LLVM writes profile data from an
`atexit` handler. `CommandExt::exec` replaces the process image and a SIGSYS
kill never unwinds, so neither runs one — a process that takes either path
writes **no profile data at all**, including for the lines it executed on the
way there. `confine_exec.rs` therefore reports well under 100% while its whole
success path is exercised end to end by a passing test that asserts a real
Landlock ABI and a seccomp filter that denies something. The control that shows
this is not a general subprocess problem: `crates/botzr-aegis-cli/src/main.rs`
measures 100%, and it only ever runs inside a spawned binary. To measure code
behind an exec, write a test where the **exec fails** and the function returns.

**In-crate `#[cfg(test)]` modules count in the denominator; `tests/` integration
tests do not.** Measured in sequence on one tree: eight tests added under
`tests/` moved the numerator by 48 and left the denominator identical; four
added inside a `src/` file added 63 lines to the denominator and covered about
50 of them, which is below the workspace average and so *lowered* the reported
percentage while strictly improving the testing. A small drop is therefore not
by itself a regression — check whether the denominator moved. It also means the
metric is sensitive to where a test file lives, which is worth knowing before
anyone optimises against it.

## The three subcommands

| Command | Writes baseline? | Use when |
|---|---|---|
| `./scripts/coverage.sh report` | no | You want the numbers, including the per-file table, with no pass/fail verdict. |
| `./scripts/coverage.sh check` | no | Reproducing what CI runs. Exits non-zero if coverage dropped. |
| `./scripts/coverage.sh bump` | **raises only** | You improved coverage and want the new floor committed. |

All three run the full instrumented suite (~10 min cold) and need
`cargo install cargo-llvm-cov --locked` — CI pins 0.6.21.

`check` compares against the baseline with a **0.05 percentage-point** tolerance,
so run-to-run noise does not fail the build. A real regression is orders of
magnitude larger than that.

The tolerance was 0.01 until 2026-08-25, sized for float rounding. The
measurement is not merely rounded, though — it is nondeterministic. Timing
branches in `crates/botzr-aegis-wrap/src/relay.rs` (the post-EOF shutdown grace,
the reap poll) land differently between runs: two runs over an identical tree
measured 37 and then 40 missed lines there, 0.028 percentage points, which a
0.01 gate would have failed on unchanged code. 0.05 covers roughly five lines in
ten thousand. If that jitter is ever removed at the source, this can go back
down.

## When the gate fails

CI failing means the change removed more covered lines than it added, relative to
the total. Two legitimate responses:

**1. Add tests.** The default. Cover the new code, re-run `check`, done.

**2. Hand-edit the baseline.** For a genuine, reviewed drop — you deleted or
refactored heavily tested code, and the remaining code is not less tested than it
was. Edit `coverage/baseline.json` **in the same PR as the change that caused the
drop**, update `recorded_at` / `recorded_commit` to match, and put a one-line
rationale in the commit message. A baseline edit that arrives in its own PR is
indistinguishable from switching the gate off.

`bump` cannot be used for this: it refuses to write a number lower than the
committed one. That refusal is the ratchet — lowering is always a deliberate,
reviewed, hand-written act, never a command someone ran.

Removing the gate — deleting the `coverage` job, or dropping `check` from the
release checklist — is out of scope for any change that is failing it.

## Provenance fields

Beyond the measurement, the baseline records where the number came from:

| Field | Meaning |
|---|---|
| `recorded_at` / `recorded_commit` | When and on what tree this number was **measured**. |
| `sanity_checked_at` / `sanity_checked_commit` | When it was last **re-measured and confirmed still accurate**, without changing it. |

`bump` stamps both pairs with today's date and `HEAD`, suffixing the sha with
`-dirty` if the tree had uncommitted changes — a number measured on a dirty tree
is not reproducible from that commit. A hand-edit must update these fields by
hand: a baseline whose provenance is stale cannot be told apart from one that was
typed rather than measured.

The gate itself reads only `percent`, `lines_covered`, and `lines_total`.
Provenance is informational, unknown keys are ignored, and a baseline missing
these fields still passes `check`.

## Where it runs

- **CI:** job `coverage` in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml),
  triggered on `pull_request` and `push` to `main`.
- **Release:** step 2 of the [release checklist](release-checklist.md) — coverage
  is release-blocking.
