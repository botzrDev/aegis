#!/usr/bin/env bash
# Evidence bundle (AILAB-606): run the bounded evidence subset, write a stamped dir.
#
# Usage (from workspace root):
#   ./scripts/evidence-bundle.sh                    # deny-suite + adversarial-demo + stress
#   AEGIS_EVIDENCE_FUZZ=1 ./scripts/evidence-bundle.sh  # + 30s policy_yaml fuzz smoke (needs nightly + cargo-fuzz)
#
# Writes evidence/YYYYMMDD-HHMMSS/ with MANIFEST.txt, per-suite logs, pointers.txt.
# Bounded: unit/integration tests only — no cargo bench, no long fuzz campaigns.
# Exit 0 only when all required test suites pass. Requires cargo.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="evidence/$(date +%Y%m%d-%H%M%S)"
mkdir -p evidence
mkdir "$OUT"

echo "==> evidence bundle: $OUT" >&2

{
  echo "commit: $(git rev-parse HEAD)"
  echo "describe: $(git describe --always --dirty)"
  # sed consumes all input — head would SIGPIPE rustc under pipefail
  rustc -Vv | sed -n '1,5p'
  uname -a
  echo "date: $(date)"
} >"$OUT/MANIFEST.txt"

run_suite() {
  local package="$1"
  local log="$2"
  echo "==> cargo test -p $package" >&2
  if ! cargo test -p "$package" 2>&1 | tee "$OUT/$log"; then
    echo "FAIL: cargo test -p $package (see $OUT/$log)" >&2
    exit 1
  fi
}

run_suite aegis-deny-suite deny-suite.log
run_suite aegis-adversarial-demo adversarial-demo.log
run_suite aegis-stress-suite stress.log

cat >"$OUT/pointers.txt" <<'POINTERS'
docs/findings.md             — findings synthesis: measured guarantees, gaps, case studies
docs/threat-model.md         — scope, trust boundaries, named non-goals, residual risks
fuzz/README.md               — policy_yaml fuzz harness + campaign log (cited, not re-run here)
benches/results/hot_path.md  — Criterion hot-path results on cited hardware (cited, not re-run here)
POINTERS

if [[ "${AEGIS_EVIDENCE_FUZZ:-0}" == "1" ]]; then
  if rustup run nightly cargo fuzz --help >/dev/null 2>&1; then
    echo "==> fuzz smoke: policy_yaml (30s, bounded)" >&2
    if ! cargo +nightly fuzz run policy_yaml -- -max_total_time=30 2>&1 | tee "$OUT/fuzz-smoke.log"; then
      echo "FAIL: fuzz smoke (see $OUT/fuzz-smoke.log)" >&2
      exit 1
    fi
  else
    echo "fuzz smoke skipped: nightly toolchain and/or cargo-fuzz not available" \
      | tee "$OUT/fuzz-smoke.log" >&2
  fi
fi

echo "==> bundle complete: $OUT" >&2
ls -la "$OUT"
