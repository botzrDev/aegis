# AEG-20 — dreamd Stage 1 PoC

Proves dreamd MCP tools (`append_node`, `search_nodes`) route through Aegis
library-mode runtime with **POLICY → CAPABILITY → AUDIT** on every Model B call.

## Layout

| Path | Role |
|------|------|
| `fixtures/dreamd-policy.yaml` | PRD §8 policy manifest (fs scope, net deny, rate-limit, role gate, dream approval) |
| `src/lib.rs` | Thin dreamd adapter + grant-enforced fs effects |
| `tests/dreamd_poc.rs` | Allow + deny demonstrations with JSONL audit |
| `benches/search_overhead.rs` | D5 — wrapped vs bare `search_nodes` latency |
| `DECISIONS.md` | D17/OQ-13 and OQ-4 outputs |

## Run

```bash
cargo test -p dreamd-poc
cargo bench -p dreamd-poc --bench search_overhead
```

## Integration boundary

**In-process library adapter** (recommended for Stage 1):

```
MCP harness → dreamd MemoryMcpServer (optional)
           → Aegis Runtime::execute_host_call (policy + capability + audit)
           → host effect (grant check → .agent/ I/O)
```

dreamd remains the memory store (D2). Aegis is not an audit store for dreamd —
it emits its own JSONL per tool call.

Out-of-process MCP gateway (`botzr-aegis-mcp`) is Phase 2 for external hosts; this PoC stays in-process and does not require it.

## Model B caveat

Host effects run in-process. The sandbox station is skipped; isolation is
grant-check + audit only. See `docs/threat-model.md` §3.
