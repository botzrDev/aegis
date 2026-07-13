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

# Optional policy YAML (default: allow-all):
cargo run -p botzr-aegis-mcp -- --policy path/to/policy.yaml --audit /tmp/aegis-mcp-audit.jsonl
```

Point a Cursor/Claude-style MCP host at the binary (stdio). Example host config shape:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "/path/to/botzr-aegis-mcp",
      "args": ["--audit", "/tmp/aegis-mcp-audit.jsonl"]
    }
  }
}
```

Logs go to **stderr**; stdout is reserved for MCP JSON-RPC (one message per line).

## Smoke tool

`echo` — Model A WASM fixture under `tests/fixtures/echo-tool/`. Arguments: `{ "text": "..." }`. No ambient `net` grants.

## Trust model

Smoke path is **Model A** (WASM isolation). **Model B** host functions are a weaker boundary — see [`docs/threat-model.md`](../../docs/threat-model.md).

## Protocol surface

Minimal in-repo MCP JSON-RPC subset (see DECISIONS.md): `initialize`, `tools/list`, `tools/call`, `ping`. Not a full MCP SDK — chosen for MSRV 1.86 compatibility and inspectability.
