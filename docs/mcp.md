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

This book documents `main`. The published `0.3.0` gateway differs — see
[below](#what-030-does-instead).

```bash
cargo run -p botzr-aegis-cli -- keygen --out /tmp/aegis-signing.key
cargo run -p botzr-aegis-mcp -- \
  --audit /tmp/aegis-mcp-audit.jsonl --signing-key /tmp/aegis-signing.key
```

`--audit` requires `--signing-key`. Omit both and the sink is a temp file
signed by the compiled-in dev key.

### What `0.3.0` does instead

If you installed from crates.io, the commands above fail. At the `v0.3.0`
tag the gateway parses `--policy` and `--audit` only — there is no
`--signing-key` — and `aegis keygen` does not exist, so there is no key to
pass. Records at that version are `schema_version: 1`: unsigned, with no
`seq` or `prev_hash` chain, so `aegis verify` has nothing to walk.

```bash
# crates.io 0.3.0
botzr-aegis-mcp --audit /tmp/aegis-mcp-audit.jsonl
```

Signing, chaining, and schema v2 arrive with the next registry cut. Until
then, build from [`main`](https://github.com/botzrDev/aegis) for them.

Watchable reproduction: [Demos](demos/) (`mcp-live-deny.cast`).

Full protocol notes:
[`crates/botzr-aegis-mcp/README.md`](https://github.com/botzrDev/aegis/blob/main/crates/botzr-aegis-mcp/README.md).
