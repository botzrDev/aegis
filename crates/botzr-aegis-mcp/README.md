# botzr-aegis-mcp

Phase 2 **MCP stdio gateway** for Aegis. External MCP clients (Claude Desktop, Cursor, etc.) call tools over stdio; each `tools/call` runs through:

```
POLICY → CAPABILITY → SANDBOX → AUDIT
```

via `Runtime::execute_tool_call`. This is a research scaffold — not a production MCP firewall.

**Decision lock:** see [`DECISIONS.md`](./DECISIONS.md) (D17 / OQ-13). Former crate name was `botzr-aegis-sidecar` (UDS gRPC story retired).

## In-process vs out-of-process

| Pattern | Where | Use when |
|---|---|---|
| **In-process library** | `examples/dreamd-poc` | Linking Aegis into the same process (dreamd Stage 1) |
| **Out-of-process MCP** | this binary | Hosts that speak MCP stdio and should not link the crate graph |

Do not re-wire dreamd through this binary.

## Run (stdio)

```bash
# From workspace root — write audit JSONL to a known path for inspection:
cargo run -p botzr-aegis-mcp -- --audit /tmp/aegis-mcp-audit.jsonl

# Optional policy YAML (replaces the built-in default):
cargo run -p botzr-aegis-mcp -- --policy path/to/policy.yaml --audit /tmp/aegis-mcp-audit.jsonl
```

**Default policy** (when `--policy` is omitted): allow everything **except** `exfil`
(station-1 deny-smoke for AEG-28).

### Host smoke (spawn → tools/call → audit)

Reproducible end-to-end path without a full agent host (AEG-29 / AEG-28):

```bash
./scripts/mcp-stdio-smoke.sh              # initialize + tools/list + echo allow
./scripts/mcp-stdio-smoke.sh --deny       # also call exfil; require policy-deny audit
./scripts/mcp-stdio-smoke.sh --keep-audit # leave the audit JSONL for inspection
```

The script builds `botzr-aegis-mcp`, spawns it with `--audit`, speaks MCP over stdio,
and exits non-zero unless the expected audit outcome(s) land with `schema_version: 1`.

### Cursor / Claude MCP client config

Point a Cursor/Claude-style MCP host at the built binary (stdio). Logs go to
**stderr**; stdout is reserved for MCP JSON-RPC (one message per line).

```json
{
  "mcpServers": {
    "aegis": {
      "command": "/absolute/path/to/target/debug/botzr-aegis-mcp",
      "args": ["--audit", "/tmp/aegis-mcp-audit.jsonl"]
    }
  }
}
```

Build first with `cargo build -p botzr-aegis-mcp`, then set `command` to that binary
path (or wrap with `cargo run -p botzr-aegis-mcp --` if your host allows multi-arg
commands). Optional: add `"--policy", "/path/to/policy.yaml"` to `args`.

## Tool catalog

Both tools use the same Model A WASM fixture (`tests/fixtures/echo-tool/`). Arguments:
`{ "text": "..." }`. No ambient `net` grants.

| Tool | Default policy | Purpose |
|------|----------------|---------|
| `echo` | **allow** | Happy-path `tools/call` through the full pipeline |
| `exfil` | **deny** (station 1) | Deny-smoke: refused before capability/sandbox; still audited |

## Trust model

Smoke path is **Model A** (WASM isolation). **Model B** host functions are a weaker boundary — see [`docs/threat-model.md`](../../docs/threat-model.md).

## Protocol surface

Minimal in-repo MCP JSON-RPC subset (see DECISIONS.md): `initialize`, `tools/list`, `tools/call`, `ping`. Not a full MCP SDK — chosen for MSRV 1.86 compatibility and inspectability.
