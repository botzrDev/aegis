# MCP gateway

`botzr-aegis-mcp` is a Phase 2 **stdio server** that exposes Aegis's own
tool catalog. External MCP clients call tools over stdio; each
`tools/call` runs through [the pipeline](pipeline.md) via
`Runtime::execute_tool_call`.

This is a research scaffold — not a production MCP firewall.

**It is not an interposer.** There is no child process and no
pass-through. For wrapping someone else's server, see
[`aegis wrap`](wrap.md).

## Catalog

Both tools use the same Model A WASM fixture. Arguments: `{ "text": "..." }`.

| Tool | Default policy | Purpose |
|---|---|---|
| `echo` | **allow** | Happy-path `tools/call` through the full pipeline |
| `exfil` | **deny** (station 1) | Deny-smoke: refused before capability/sandbox; still audited |

## Run

```bash
cargo run -p botzr-aegis-cli -- keygen --out /tmp/aegis-signing.key
cargo run -p botzr-aegis-mcp -- \
  --audit /tmp/aegis-mcp-audit.jsonl --signing-key /tmp/aegis-signing.key
```

`--audit` requires `--signing-key`. Omit both and the sink is a temp file
signed by the compiled-in dev key.

Watchable reproduction: [Demos](demos/) (`mcp-live-deny.cast`).

Full protocol notes:
[`crates/botzr-aegis-mcp/README.md`](https://github.com/botzrDev/aegis/blob/main/crates/botzr-aegis-mcp/README.md).
