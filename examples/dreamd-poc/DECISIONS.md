# AEG-20 decision outputs

## D17 / OQ-13 — `botzr-aegis-mcp` crate

**Decision (lock):** Defer a standalone `botzr-aegis-mcp` generic MCP proxy binary to **Phase 2**.

**Rationale from PoC:**
- Stage 1 integration is an **in-process library adapter** (`Runtime::execute_host_call` + thin dreamd effect handlers). This satisfies the research goal: prove policy/capability/audit wrap every MCP-equivalent call.
- A generic MCP stdio proxy would duplicate dreamd's existing `dreamd mcp` transport and add a second JSON-RPC parsing layer without new security guarantees.
- Phase 2 `botzr-aegis-mcp` remains valuable for **non-dreamd MCP servers** once a second consumer exists; dreamd-specific wiring stays in a consumer crate or dreamd fork PR.

**Amendment:** None — aligns with AEG-12 D17 draft.

## D5 — `search_nodes` wrap vs mutating-only gate

**Benchmark:** `cargo bench -p dreamd-poc --bench search_overhead` (see `benches/results/` after run).

**Gate rule (lock for Stage 1):**

| Measurement | Result |
|-------------|--------|
| Bare `search_nodes` stub | ~5.5 µs median |
| Aegis-wrapped (policy + capability + audit JSONL) | ~22 ms median |

Wrapped read path exceeds the **~1 ms** D5 threshold — dominated by per-call audit I/O, not policy eval. **Lock: mutating-only full wrap** (`append_node`, `dream`); reads (`search_nodes`) get policy allow + capability read grant + audit strategy TBD (sampled/async sink) before `v0.1.0`.

Re-benchmark against real dreamd Tantivy + production audit sink before tag.

## OQ-4 — dreamd release target

**Status (2026-07-10):** dreamd is **cloneable and buildable** at `0.1.0-rc.2` on `main` (`https://github.com/botzrDev/dreamd`).

| Signal | Value |
|--------|-------|
| Crate version | `0.1.0-rc.2` |
| MCP tools | `search_nodes`, `append_node` — shipped in `dreamd-core/src/mcp/mod.rs` |
| npm shim | `dreamd-mcp@0.1.0-rc.2` (release tarballs on GitHub; npm publish may lag RC) |
| GA target | RC drops `-rc.N` per DR-009 → **v0.1.0** or **v0.1.1** for Aegis `v0.1.0` tag pairing |

**Recommendation:** Target **dreamd v0.1.0 GA** (or `0.1.1` if RC blockers remain) as the Aegis `v0.1.0` integration pin. Stage 1 PoC intentionally avoids a path dependency on `dreamd-core` to keep the Aegis workspace lean; Stage 2 wires real `MemoryMcpServer` behind a feature flag.

## D16–D19 ratification

Not ratified in this session — `aegis-context/AEG-12-decision-log.md` was not present in this worktree. Austin: confirm ratification locally.
