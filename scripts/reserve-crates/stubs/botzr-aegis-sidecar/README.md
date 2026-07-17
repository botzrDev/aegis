# RETIRED — use `botzr-aegis-mcp` instead

The name `botzr-aegis-sidecar` is **retired**. It is not maintained, and no functional implementation will ship under it.

**Replacement:**

- crates.io: <https://crates.io/crates/botzr-aegis-mcp>
- GitHub: <https://github.com/botzrDev/aegis>

## Why

This crate never shipped a UDS gRPC/HTTP sidecar — that design is retired and no longer planned. The Phase 2 gateway for [Aegis](https://github.com/botzrDev/aegis) is **MCP over stdio** (`botzr-aegis-mcp`), instead of the sidecar transport this name originally implied.

## What this release is

`0.0.1` exists only as a signpost pointing at `botzr-aegis-mcp`. It contains no functionality — no gateway, no transport, no runtime. Do not depend on it.

License: MIT
