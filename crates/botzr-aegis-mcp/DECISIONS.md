# botzr-aegis-mcp — decision log

## D17 / OQ-13 — Phase 2 gateway surface is MCP (locked)

**Decision:** The Phase 2 out-of-process gateway is **MCP over stdio**, not UDS gRPC/HTTP.

**Crate evolution:** `botzr-aegis-sidecar` was renamed in-place to `botzr-aegis-mcp` (one crate, one binary). Keeping a second stub would leave a contradictory gRPC story in the research tree.

**Transport:** stdio JSON-RPC (MCP), newline-delimited. Chosen for reproducibility: deterministic spawn, no port races, every request/response pair capturable for demos and papers. HTTP/SSE deferred.

**Relation to dreamd (AEG-20):** dreamd Stage 1 stays an **in-process library adapter** (`Runtime::execute_host_call`). This crate is the **out-of-process** gateway for external MCP clients (Claude/Cursor-style hosts) that should not link the Aegis crate graph. Do not re-wire dreamd through this binary.

**Authority:** AEG-12 D17; `examples/dreamd-poc/DECISIONS.md` (OQ-13 lock); AEG-25.

## Model A vs Model B honesty

This scaffold’s smoke path is **Model A** (registered WASM `echo` fixture → `Runtime::execute_tool_call`). Isolation is wasmtime + grant-configured WASI.

**Model B** (host functions) is a different trust boundary: the effect runs in host Rust; capability check + audit only — sandbox does not contain the effect. See [`docs/threat-model.md`](../../docs/threat-model.md) §3. Do not market Model B as full sandbox isolation.

## Protocol adapter (no external MCP SDK in this slice)

Workspace **MSRV is 1.86**. Current `rmcp` 2.x pulls `darling` requiring rustc 1.88+, so this slice ships a **minimal in-repo MCP JSON-RPC subset** (`initialize`, `tools/list`, `tools/call`, `ping`) in `src/mcp.rs`.

Rationale for research: every gateway byte is reviewable; the security claim remains `tools/call` → `Runtime::execute_tool_call` → audit JSONL. Revisit pinning `rmcp` when MSRV allows, or if a host requires a fuller protocol surface.

## Non-goals (this crate, this slice)

- Full MCP auth / session binding
- Governance write-back into Rust policy files
- Duplicating dreamd’s `dreamd mcp` transport for dreamd tools
- crates.io publish of the rename (unless Austin asks)
- Full MCP SDK feature parity (resources, prompts, SSE, OAuth)
