#!/usr/bin/env bash
# MCP live-deny demo (AILAB-611) — the script behind docs/demos/mcp-live-deny.cast.
#
# One pass over the shipped path: run the stdio-gateway smoke, then drive one
# gateway session of our own and show, from that single session, the JSON-RPC
# error an MCP client receives for a denied call, the schema v2 audit record
# that same denial wrote, and a signature check pinning that record file.
#
# Usage (from workspace root):
#   scripts/mcp-live-deny-demo.sh                # run the demo
#   DEMO_PAUSE=0 scripts/mcp-live-deny-demo.sh   # drop the reading pauses (CI)
#
# Recording the cast — asciinema is maintainer tooling, not a workspace
# dependency, and this script runs fine without it:
#   cargo build -p botzr-aegis-mcp -p botzr-aegis-cli   # pre-warm; keeps the cast short
#   asciinema rec -c 'scripts/mcp-live-deny-demo.sh' docs/demos/mcp-live-deny.cast
#
# The assertions live in scripts/mcp-stdio-smoke.sh, which this script runs
# first. The demo adds presentation only: it exits 0 only when that smoke does.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PAUSE="${DEMO_PAUSE:-2.5}"

if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
else
  BOLD=''; DIM=''; CYAN=''; RESET=''
fi

beat() { [[ "$PAUSE" == "0" ]] || sleep "$PAUSE"; }

stage() {
  echo
  echo "${BOLD}${CYAN}── $1 ${RESET}"
  echo
}

# Created before anything that can fail, so the trap also cleans up the paths
# below when a stage aborts under `set -e`. The signing key and the signed
# record file both live in here; neither is a souvenir worth leaving in TMPDIR.
DEMO_DIR="$(mktemp -d)"
cleanup() { rm -rf "$DEMO_DIR"; }
trap cleanup EXIT

echo "${BOLD}Aegis — MCP live deny${RESET}"
echo "${DIM}An MCP client asks for two tools. One is policy-allowed, one is not.${RESET}"
echo "${DIM}Pipeline: policy → capability → sandbox → audit${RESET}"
beat

stage "1/4  Gateway over stdio: echo allowed, exfil denied"
echo "${DIM}\$ scripts/mcp-stdio-smoke.sh --deny${RESET}"
./scripts/mcp-stdio-smoke.sh --deny
beat

# Beats 2-4 are one gateway session, so the JSON-RPC refusal on screen and the
# record on screen are the same denied call rather than two lookalike runs.
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
BIN="${TARGET_DIR}/debug/botzr-aegis-mcp"
AEGIS="${TARGET_DIR}/debug/aegis"
KEY_PATH="${DEMO_DIR}/demo.key"
AUDIT_PATH="${DEMO_DIR}/audit.jsonl"

# A persistent --audit sink has no dev-key fallback (AILAB-620), so mint one.
PUBLIC_KEY="$("$AEGIS" keygen --out "$KEY_PATH" 2>/dev/null | sed -n 's/^public_key //p')"
if [[ -z "$PUBLIC_KEY" ]]; then
  echo "error: keygen did not print a public_key" >&2
  exit 1
fi
: >"$AUDIT_PATH"

RESPONSES="$(
  {
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"aegis-live-deny-demo","version":"0"}}}'
    printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exfil","arguments":{"text":"steal-the-secrets"}}}'
  } | "$BIN" --audit "$AUDIT_PATH" --signing-key "$KEY_PATH" 2>/dev/null
)"

stage "2/4  What the MCP client receives for the denied call"
echo "${DIM}\$ printf '<initialize> <initialized> <tools/call exfil>' | botzr-aegis-mcp --audit …${RESET}"
printf '%s\n' "$RESPONSES" | sed -n '2p' | python3 -m json.tool
echo "${DIM}A typed refusal the caller can branch on — not a hang, not a silent empty result.${RESET}"
beat

stage "3/4  What that same call wrote to the audit record"
grep '"line_type":"outcome"' "$AUDIT_PATH" \
  | grep '"tool_id":"exfil"' \
  | tail -1 \
  | python3 -m json.tool
echo "${DIM}schema_version 2. Denials are first-class records: policy denied, capability never${RESET}"
echo "${DIM}reached, execution never happened — each axis stated, and the whole line signed.${RESET}"
beat

stage "4/4  The record file pins to the key this session published"
echo "${DIM}\$ aegis verify --key ${PUBLIC_KEY} <audit.jsonl>${RESET}"
"$AEGIS" verify --key "$PUBLIC_KEY" "$AUDIT_PATH"
echo "${DIM}The key_id above is the fingerprint of that public key, not a second key.${RESET}"
beat

echo
echo "${BOLD}Denied at station 1, audited anyway, and the record verifies.${RESET}"
echo "${DIM}Reproduce: scripts/mcp-live-deny-demo.sh · assertions: scripts/mcp-stdio-smoke.sh --deny${RESET}"
