#!/usr/bin/env bash
# MCP stdio host smoke (AEG-29): spawn botzr-aegis-mcp → initialize → tools/call → audit.
#
# Usage (from workspace root):
#   ./scripts/mcp-stdio-smoke.sh
#   ./scripts/mcp-stdio-smoke.sh --keep-audit   # leave AUDIT_PATH for inspection
#
# Exit 0 only when tools/call echoes successfully and audit JSONL has a schema v1
# success outcome. Requires `cargo` (builds the mcp binary).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

KEEP_AUDIT=0
for arg in "$@"; do
  case "$arg" in
    --keep-audit) KEEP_AUDIT=1 ;;
    -h|--help)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown arg: $arg" >&2
      exit 2
      ;;
  esac
done

AUDIT_PATH="${TMPDIR:-/tmp}/aegis-mcp-smoke-$$.jsonl"
cleanup() {
  if [[ "$KEEP_AUDIT" -eq 0 ]]; then
    rm -f "$AUDIT_PATH"
  else
    echo "audit kept at: $AUDIT_PATH" >&2
  fi
}
trap cleanup EXIT

echo "==> building botzr-aegis-mcp" >&2
cargo build -p botzr-aegis-mcp --quiet

TARGET_DIR="$(cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
BIN="${TARGET_DIR}/debug/botzr-aegis-mcp"
if [[ ! -x "$BIN" ]]; then
  echo "error: binary not found at $BIN" >&2
  exit 1
fi

: >"$AUDIT_PATH"

echo "==> spawn: $BIN --audit $AUDIT_PATH" >&2

# stdout = JSON-RPC; binary readiness logs go to this script's stderr.
RESPONSES="$(
  {
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"aegis-mcp-stdio-smoke","version":"0"}}}'
    # Notification — server returns silence (no id).
    printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"mcp-stdio-smoke"}}}'
  } | "$BIN" --audit "$AUDIT_PATH"
)"

line_count="$(printf '%s\n' "$RESPONSES" | grep -c . || true)"
if [[ "$line_count" -lt 2 ]]; then
  echo "error: expected ≥2 JSON-RPC responses (initialize + tools/call), got:" >&2
  printf '%s\n' "$RESPONSES" >&2
  exit 1
fi

INIT_LINE="$(printf '%s\n' "$RESPONSES" | sed -n '1p')"
CALL_LINE="$(printf '%s\n' "$RESPONSES" | sed -n '2p')"

if ! printf '%s' "$INIT_LINE" | grep -q 'botzr-aegis-mcp'; then
  echo "error: initialize response missing serverInfo name:" >&2
  echo "$INIT_LINE" >&2
  exit 1
fi

if ! printf '%s' "$CALL_LINE" | grep -q 'mcp-stdio-smoke'; then
  echo "error: tools/call did not echo payload:" >&2
  echo "$CALL_LINE" >&2
  exit 1
fi

if printf '%s' "$CALL_LINE" | grep -q '"isError":true'; then
  echo "error: tools/call returned isError=true:" >&2
  echo "$CALL_LINE" >&2
  exit 1
fi

if [[ ! -s "$AUDIT_PATH" ]]; then
  echo "error: audit file empty or missing: $AUDIT_PATH" >&2
  exit 1
fi

if ! grep -q '"phase":"intent"' "$AUDIT_PATH"; then
  echo "error: audit missing intent line:" >&2
  cat "$AUDIT_PATH" >&2
  exit 1
fi

OUTCOME="$(grep '"phase":"outcome"' "$AUDIT_PATH" || true)"
if [[ -z "$OUTCOME" ]]; then
  echo "error: audit missing outcome line:" >&2
  cat "$AUDIT_PATH" >&2
  exit 1
fi

if ! printf '%s' "$OUTCOME" | grep -q '"schema_version":1'; then
  echo "error: outcome missing schema_version 1:" >&2
  echo "$OUTCOME" >&2
  exit 1
fi

if ! printf '%s' "$OUTCOME" | grep -q '"status":"success"'; then
  echo "error: outcome not success:" >&2
  echo "$OUTCOME" >&2
  exit 1
fi

echo "ok: MCP stdio smoke — initialize + tools/call + audit schema v1 success" >&2
exit 0
