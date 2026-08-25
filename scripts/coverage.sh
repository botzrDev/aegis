#!/usr/bin/env bash
# Workspace line-coverage gate.
#
#   scripts/coverage.sh report   measure and print totals (no gate)
#   scripts/coverage.sh check    fail if line coverage drops below the
#                                committed baseline (coverage/baseline.json)
#   scripts/coverage.sh bump     raise the baseline to the current measurement
#                                (refuses to lower it)
#
# The baseline is a ratchet: `check` never writes it, `bump` only raises it.
# Lowering it requires hand-editing the JSON in a reviewed commit — see
# docs/coverage-ratchet.md.
#
# The gate reads only `percent`, `lines_covered`, and `lines_total` from the
# baseline. Every other key (provenance, `note`, anything added later) is
# informational: unknown keys are ignored, and a baseline missing them still
# passes `check`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASELINE="coverage/baseline.json"
MODE="${1:-report}"

# Files excluded from the measurement, as one regex.
#
# `probe.rs` is a **test fixture** — its own module doc says "Test fixture for
# `botzr-aegis-confine`. Not operator surface." Counting a fixture as product
# coverage is a category error, and it is one that actively misleads here:
# the fixture's `restrict-exec` verb ends in `exec()` and its `connect` verb is
# *expected* to die by SIGSYS, and neither a replaced process image nor a
# signal death runs LLVM's `atexit` handler, so the strongest confinement tests
# in the repo write no profile data at all. The fixture therefore reports ~41%
# while being exercised by every escape test we have (AILAB-712, 2026-08-25).
#
# `crates/botzr-aegis-cli/src/confine_exec.rs` has the same exec ceiling and is
# deliberately **not** excluded: it is real enforcement code, its refusal paths
# do measure, and dropping the confinement mechanism out of the report is how a
# coverage number stops being worth reading. Its own doc comment names the
# ceiling instead.
IGNORE_REGEX='botzr-aegis-confine/src/bin/probe\.rs$'

# Stamped into the baseline by `bump` so a committed number can be traced back
# to the tree it was measured on. Unavailable git/date is not fatal — the gate
# does not depend on provenance.
HEAD_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
# A number measured on a dirty tree is not reproducible from that commit, so say
# so rather than recording a sha that does not describe what was measured.
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  HEAD_SHA="$HEAD_SHA-dirty"
fi
TODAY="$(date -u +%F 2>/dev/null || echo unknown)"

case "$MODE" in
report | check | bump) ;;
*)
  echo "usage: $0 [report|check|bump]" >&2
  exit 2
  ;;
esac

if ! cargo llvm-cov --version >/dev/null 2>&1; then
  echo "error: cargo-llvm-cov is not installed." >&2
  echo "  cargo install cargo-llvm-cov --locked" >&2
  exit 1
fi
rustup component add llvm-tools-preview >/dev/null 2>&1 || true

SUMMARY_JSON="$(mktemp /tmp/aegis-coverage-XXXXXX.json)"
trap 'rm -f "$SUMMARY_JSON"' EXIT

# One instrumented test run; reports are derived from the collected profdata.
cargo llvm-cov --workspace --locked --no-report
# `--ignore-filename-regex` belongs on the *report* commands, not on collection:
# the profile data is gathered for everything and filtered when it is reduced.
# Both reports must carry it or the table and the gated number disagree.
cargo llvm-cov report --ignore-filename-regex "$IGNORE_REGEX" # human-readable per-file table (informational)
cargo llvm-cov report --ignore-filename-regex "$IGNORE_REGEX" \
  --json --summary-only --output-path "$SUMMARY_JSON"

python3 - "$MODE" "$SUMMARY_JSON" "$BASELINE" "$HEAD_SHA" "$TODAY" <<'PY'
import json, sys

mode, summary_path, baseline_path, head_sha, today = sys.argv[1:6]

# Percentage-point tolerance for measurement noise; real regressions are larger.
#
# 0.05, not 0.01. The original value was sized for float rounding, but the
# measurement is not merely rounded — it is nondeterministic. Timing-dependent
# branches in `crates/botzr-aegis-wrap/src/relay.rs` (the post-EOF shutdown
# grace, the reap poll) land differently between runs: two runs over an
# identical tree measured 37 and then 40 missed lines there, which is 0.028
# percentage points and would have failed a 0.01 gate on unchanged code.
#
# 0.05 covers roughly five lines out of ten thousand. A real regression is
# orders of magnitude larger, so the gate keeps its teeth (AILAB-712).
EPSILON = 0.05

with open(summary_path) as f:
    totals = json.load(f)["data"][0]["totals"]["lines"]
covered, count, percent = totals["covered"], totals["count"], totals["percent"]

print(f"\ntotal line coverage: {percent:.2f}% ({covered}/{count} lines)")

try:
    with open(baseline_path) as f:
        baseline = json.load(f)
except FileNotFoundError:
    baseline = None

def provenance(when_key, commit_key):
    """Format one provenance pair, or None if the baseline records neither."""
    when, commit = baseline.get(when_key), baseline.get(commit_key)
    if not when and not commit:
        return None
    return f"{when or '?'} @ {commit or '?'}"


if baseline is not None:
    print(
        f"committed baseline:  {baseline['percent']:.2f}% "
        f"({baseline['lines_covered']}/{baseline['lines_total']} lines)"
    )
    # Informational only — a baseline without provenance still gates normally.
    recorded = provenance("recorded_at", "recorded_commit")
    checked = provenance("sanity_checked_at", "sanity_checked_commit")
    if recorded:
        print(f"  recorded:       {recorded}")
    if checked:
        print(f"  sanity-checked: {checked}")

if mode == "report":
    sys.exit(0)

if mode == "check":
    if baseline is None:
        print(f"error: {baseline_path} missing; run scripts/coverage.sh bump", file=sys.stderr)
        sys.exit(1)
    if percent + EPSILON < baseline["percent"]:
        print(
            f"FAIL: line coverage {percent:.2f}% is below the committed "
            f"baseline {baseline['percent']:.2f}%.\n"
            f"Add tests for the new code, or (if the drop is deliberate) "
            f"hand-edit {baseline_path} in a reviewed commit.",
            file=sys.stderr,
        )
        sys.exit(1)
    print("OK: coverage is at or above the committed baseline")
    sys.exit(0)

# mode == "bump"
if baseline is not None and percent < baseline["percent"]:
    print(
        f"refusing to bump: current {percent:.2f}% is below baseline "
        f"{baseline['percent']:.2f}% (the ratchet only goes up)",
        file=sys.stderr,
    )
    sys.exit(1)

new_baseline = {
    "schema_version": 1,
    "metric": "lines",
    "scope": "cargo workspace (--workspace)",
    "lines_covered": covered,
    "lines_total": count,
    "percent": round(percent, 4),
    # A bump *is* a fresh measurement, so both pairs point at this tree.
    # Written unconditionally: a bump that carried forward the previous
    # provenance would attribute new numbers to the commit that produced the
    # old ones. A hand-edited baseline must update these by hand for the same
    # reason — stale provenance is indistinguishable from a typed number.
    "recorded_at": today,
    "recorded_commit": head_sha,
    "sanity_checked_at": today,
    "sanity_checked_commit": head_sha,
    "note": "High-water mark for scripts/coverage.sh check. Raise via `scripts/coverage.sh bump`; lowering requires a hand-edited, reviewed commit. See docs/coverage-ratchet.md.",
}
import os
os.makedirs(os.path.dirname(baseline_path), exist_ok=True)
with open(baseline_path, "w") as f:
    json.dump(new_baseline, f, indent=2)
    f.write("\n")
print(f"baseline written to {baseline_path}")
PY
