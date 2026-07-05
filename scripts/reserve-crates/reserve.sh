#!/usr/bin/env bash
# Reserve botzr-aegis-* crate names on crates.io (AEG-7).
# Usage: reserve.sh [--check | --dry-run | --publish] [--delay SECS]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STUBS="$ROOT/stubs"
PUBLISH_DELAY="${PUBLISH_DELAY:-120}"

CRATES=(
  botzr-aegis-core
  botzr-aegis-policy
  botzr-aegis-capability
  botzr-aegis-sandbox
  botzr-aegis-audit
  botzr-aegis-runtime
  botzr-aegis-cli
  botzr-aegis-sidecar
)

usage() {
  cat <<EOF
Usage: reserve.sh [--check | --dry-run | --publish] [--delay SECS]

  --check       Verify stubs build/package; report publish state (default)
  --dry-run     cargo publish --dry-run for each unpublished stub
  --publish     Upload 0.0.0 placeholders (skips already-published; requires cargo login)
  --delay SECS  Seconds between publishes (default: ${PUBLISH_DELAY}; env PUBLISH_DELAY)

crates.io rate-limits new-crate publishes. If you hit 429, wait for the time in the
error message, then re-run --publish — already-published crates are skipped.
EOF
}

require_cargo_login() {
  if [[ ! -f "${HOME}/.cargo/credentials.toml" ]]; then
    echo "error: ~/.cargo/credentials.toml missing — run: cargo login" >&2
    exit 1
  fi
}

is_published() {
  local name="$1"
  local out
  out="$(cargo search "$name" --limit 1 2>&1 || true)"
  [[ "$out" == *"${name} ="* ]]
}

check_name_status() {
  local name="$1"
  if is_published "$name"; then
    echo "ok  $name (already published)"
    return 0
  fi
  echo "ok  $name (available)"
}

check_name_free() {
  local name="$1"
  if is_published "$name"; then
    echo "skip $name (already published)"
    return 0
  fi
  local out
  out="$(cargo search "$name" --limit 1 2>&1 || true)"
  if [[ -n "$out" && "$out" != *"no crates found"* && "$out" != *"Updating crates.io index"* ]]; then
    if [[ "$out" == *"$name"* && "$out" != *"${name} ="* ]]; then
      echo "error: $name appears taken by another owner on crates.io:" >&2
      echo "  $out" >&2
      return 1
    fi
  fi
  echo "ok  $name (available)"
}

mode="${1:---check}"
shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --delay)
      PUBLISH_DELAY="${2:?--delay requires seconds}"
      shift 2
      ;;
    -h | --help) usage; exit 0 ;;
    *) echo "error: unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

case "$mode" in
  --check | --dry-run | --publish) ;;
  -h | --help) usage; exit 0 ;;
  *) echo "error: unknown option: $mode" >&2; usage; exit 1 ;;
esac

echo "==> botzr-aegis-* reservation ($mode)"
echo "    stubs: $STUBS"
echo

for crate in "${CRATES[@]}"; do
  if [[ ! -d "$STUBS/$crate" ]]; then
    echo "error: missing stub directory: $STUBS/$crate" >&2
    exit 1
  fi
done

echo "==> publish state (cargo search)"
for crate in "${CRATES[@]}"; do
  check_name_status "$crate"
done
echo

echo "==> package check (cargo package --allow-dirty)"
for crate in "${CRATES[@]}"; do
  echo "-- $crate"
  (cd "$STUBS/$crate" && cargo package --allow-dirty --quiet)
  echo "   packaged ok"
done
echo

if [[ "$mode" == "--check" ]]; then
  echo "All checks passed. Run with --dry-run or --publish when ready."
  exit 0
fi

require_cargo_login

if [[ "$mode" == "--dry-run" ]]; then
  echo "==> dry-run publish"
  for crate in "${CRATES[@]}"; do
    if is_published "$crate"; then
      echo "-- $crate (skip — already published)"
      continue
    fi
    echo "-- $crate"
    (cd "$STUBS/$crate" && cargo publish --dry-run --allow-dirty)
  done
  echo
  echo "Dry-run complete. Run with --publish to claim remaining names."
  exit 0
fi

pending=()
for crate in "${CRATES[@]}"; do
  if is_published "$crate"; then
    echo "skip $crate (already published)"
  else
    pending+=("$crate")
  fi
done

if [[ ${#pending[@]} -eq 0 ]]; then
  echo
  echo "All eight crates already published. Mark AEG-7 Done."
  exit 0
fi

echo
echo "==> publishing ${#pending[@]} remaining placeholder(s) (${PUBLISH_DELAY}s delay between uploads)"
echo "    Ctrl-C within 5s to abort."
sleep 5

for i in "${!pending[@]}"; do
  crate="${pending[$i]}"
  echo "-- publishing $crate"
  if ! (cd "$STUBS/$crate" && cargo publish --allow-dirty); then
    echo
    echo "Publish failed (often 429 rate limit). Wait for the time in the error, then re-run:" >&2
    echo "  $0 --publish" >&2
    exit 1
  fi
  echo "   published $crate"
  if [[ "$i" -lt $((${#pending[@]} - 1)) ]]; then
    echo "   waiting ${PUBLISH_DELAY}s (crates.io new-crate rate limit)..."
    sleep "$PUBLISH_DELAY"
  fi
done

echo
echo "Done. Verify: cargo search botzr-aegis-core --limit 1"
echo "Then mark AEG-7 Done in Linear."
