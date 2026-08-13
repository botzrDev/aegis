# Crate map

Nine crates in the workspace. **Eight** are on crates.io at `0.3.0`.
`botzr-aegis-wrap` is in-tree and first appears on the registry with the
next cut.

| Crate | Responsibility | `0.3.0` |
|---|---|---|
| `botzr-aegis-core` | Pure types and traits; zero I/O | published |
| `botzr-aegis-policy` | YAML → `Arc<PolicySet>`; sync eval | published |
| `botzr-aegis-capability` | Default-deny resolver and grant minting | published |
| `botzr-aegis-sandbox` | wasmtime host; cap-std preopens; resource limits | published |
| `botzr-aegis-audit` | Schema-versioned records, always emitted | published |
| `botzr-aegis-runtime` | Orchestrator — `Runtime::execute_tool_call` | published |
| `botzr-aegis-mcp` | MCP stdio gateway for Aegis's own catalog | published |
| `botzr-aegis-cli` | Binary `aegis` | published |
| `botzr-aegis-wrap` | Stdio MCP interposer — records, does not confine | in-tree only |

`governance/` is a separate Python (Layer 2) service — not a workspace
member, never writes into the Rust runtime.

`botzr-aegis-sidecar` is yanked. The Phase 2 gateway is
`botzr-aegis-mcp`. Do not confuse that gateway with `aegis wrap`.

Crate READMEs on crates.io are the API notes. This book is the
stranger-facing hub.
