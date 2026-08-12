# Coverage ratchet

> **Status:** current (AILAB-636) · **Last updated:** 2026-08-12
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

## The three subcommands

| Command | Writes baseline? | Use when |
|---|---|---|
| `./scripts/coverage.sh report` | no | You want the numbers, including the per-file table, with no pass/fail verdict. |
| `./scripts/coverage.sh check` | no | Reproducing what CI runs. Exits non-zero if coverage dropped. |
| `./scripts/coverage.sh bump` | **raises only** | You improved coverage and want the new floor committed. |

All three run the full instrumented suite (~10 min cold) and need
`cargo install cargo-llvm-cov --locked` — CI pins 0.6.21.

`check` compares against the baseline with a **0.01 percentage-point** tolerance,
so float noise between runs does not fail the build. A real regression is orders
of magnitude larger than that.

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
