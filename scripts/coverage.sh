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
# Lowering it requires hand-editing the JSON in a reviewed commit.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASELINE="coverage/baseline.json"
MODE="${1:-report}"

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
cargo llvm-cov report # human-readable per-file table (informational)
cargo llvm-cov report --json --summary-only --output-path "$SUMMARY_JSON"

python3 - "$MODE" "$SUMMARY_JSON" "$BASELINE" <<'PY'
import json, sys

mode, summary_path, baseline_path = sys.argv[1], sys.argv[2], sys.argv[3]

# Percentage-point tolerance for float noise; real regressions are larger.
EPSILON = 0.01

with open(summary_path) as f:
    totals = json.load(f)["data"][0]["totals"]["lines"]
covered, count, percent = totals["covered"], totals["count"], totals["percent"]

print(f"\ntotal line coverage: {percent:.2f}% ({covered}/{count} lines)")

try:
    with open(baseline_path) as f:
        baseline = json.load(f)
except FileNotFoundError:
    baseline = None

if baseline is not None:
    print(
        f"committed baseline:  {baseline['percent']:.2f}% "
        f"({baseline['lines_covered']}/{baseline['lines_total']} lines)"
    )

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
    "note": "High-water mark for scripts/coverage.sh check. Raise via `scripts/coverage.sh bump`; lowering requires a hand-edited, reviewed commit.",
}
import os
os.makedirs(os.path.dirname(baseline_path), exist_ok=True)
with open(baseline_path, "w") as f:
    json.dump(new_baseline, f, indent=2)
    f.write("\n")
print(f"baseline written to {baseline_path}")
PY
