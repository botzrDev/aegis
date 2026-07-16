#!/usr/bin/env bash
# MCP stdio host smoke (AEG-29 / AEG-28): spawn botzr-aegis-mcp → protocol → audit.
#
# Usage (from workspace root):
#   ./scripts/mcp-stdio-smoke.sh              # initialize + tools/list + echo allow
#   ./scripts/mcp-stdio-smoke.sh --deny       # also tools/call exfil → policy deny audit
#   ./scripts/mcp-stdio-smoke.sh --keep-audit # leave AUDIT_PATH for inspection
#
# Exit 0 only when required audit outcomes are present (schema v1). Requires cargo.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

KEEP_AUDIT=0
RUN_DENY=0
for arg in "$@"; do
  case "$arg" in
    --keep-audit) KEEP_AUDIT=1 ;;
    --deny) RUN_DENY=1 ;;
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

REQS=$(mktemp)
{
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"aegis-mcp-stdio-smoke","version":"0"}}}'
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"mcp-stdio-smoke"}}}'
  if [[ "$RUN_DENY" -eq 1 ]]; then
    printf '%s\n' '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exfil","arguments":{"text":"should-be-denied"}}}'
  fi
} >"$REQS"

RESPONSES="$("$BIN" --audit "$AUDIT_PATH" <"$REQS")"
rm -f "$REQS"

expect_lines=3
[[ "$RUN_DENY" -eq 1 ]] && expect_lines=4

line_count="$(printf '%s\n' "$RESPONSES" | grep -c . || true)"
if [[ "$line_count" -lt "$expect_lines" ]]; then
  echo "error: expected ≥${expect_lines} JSON-RPC responses, got ${line_count}:" >&2
  printf '%s\n' "$RESPONSES" >&2
  exit 1
fi

INIT_LINE="$(printf '%s\n' "$RESPONSES" | sed -n '1p')"
LIST_LINE="$(printf '%s\n' "$RESPONSES" | sed -n '2p')"
CALL_LINE="$(printf '%s\n' "$RESPONSES" | sed -n '3p')"

if ! printf '%s' "$INIT_LINE" | grep -q 'botzr-aegis-mcp'; then
  echo "error: initialize response missing serverInfo name:" >&2
  echo "$INIT_LINE" >&2
  exit 1
fi

if ! printf '%s' "$LIST_LINE" | grep -q '"echo"'; then
  echo "error: tools/list missing echo:" >&2
  echo "$LIST_LINE" >&2
  exit 1
fi
if ! printf '%s' "$LIST_LINE" | grep -q '"exfil"'; then
  echo "error: tools/list missing exfil (multi-tool catalog):" >&2
  echo "$LIST_LINE" >&2
  exit 1
fi

if ! printf '%s' "$CALL_LINE" | grep -q 'mcp-stdio-smoke'; then
  echo "error: tools/call echo did not echo payload:" >&2
  echo "$CALL_LINE" >&2
  exit 1
fi
if printf '%s' "$CALL_LINE" | grep -q '"isError":true'; then
  echo "error: tools/call echo returned isError=true:" >&2
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

SUCCESS_OUTCOME="$(grep '"phase":"outcome"' "$AUDIT_PATH" | grep '"tool_id":"echo"' || true)"
if [[ -z "$SUCCESS_OUTCOME" ]]; then
  SUCCESS_OUTCOME="$(grep '"phase":"outcome"' "$AUDIT_PATH" | grep '"status":"success"' || true)"
fi
if [[ -z "$SUCCESS_OUTCOME" ]]; then
  echo "error: missing success outcome for echo:" >&2
  cat "$AUDIT_PATH" >&2
  exit 1
fi
if ! printf '%s' "$SUCCESS_OUTCOME" | grep -q '"schema_version":1'; then
  echo "error: echo outcome missing schema_version 1:" >&2
  echo "$SUCCESS_OUTCOME" >&2
  exit 1
fi

if [[ "$RUN_DENY" -eq 1 ]]; then
  DENY_LINE="$(printf '%s\n' "$RESPONSES" | sed -n '4p')"
  if ! printf '%s' "$DENY_LINE" | grep -q '"isError":true'; then
    echo "error: tools/call exfil expected isError=true:" >&2
    echo "$DENY_LINE" >&2
    exit 1
  fi

  DENY_OUTCOME="$(grep '"phase":"outcome"' "$AUDIT_PATH" | grep '"tool_id":"exfil"' || true)"
  if [[ -z "$DENY_OUTCOME" ]]; then
    echo "error: missing audit outcome for exfil:" >&2
    cat "$AUDIT_PATH" >&2
    exit 1
  fi
  if ! printf '%s' "$DENY_OUTCOME" | grep -q '"schema_version":1'; then
    echo "error: exfil outcome missing schema_version 1:" >&2
    echo "$DENY_OUTCOME" >&2
    exit 1
  fi
  if ! printf '%s' "$DENY_OUTCOME" | grep -Eq '"status":"denied"|MCP deny-smoke: exfil blocked'; then
    echo "error: exfil outcome not a policy deny:" >&2
    echo "$DENY_OUTCOME" >&2
    exit 1
  fi
  echo "ok: MCP stdio smoke — catalog + echo allow + exfil deny audited" >&2
else
  echo "ok: MCP stdio smoke — catalog + echo allow + audit schema v1 success" >&2
fi
exit 0
