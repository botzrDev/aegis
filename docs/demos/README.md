# Demo recordings

Terminal casts of Aegis behaving as documented. Each one is a recording of the
script named beside it, run unedited — the cast is a convenience for readers who
want to watch before running anything, not a substitute for running it.

## `mcp-live-deny.cast` — MCP live deny

Recorded from [`scripts/mcp-live-deny-demo.sh`](https://github.com/botzrDev/aegis/blob/main/scripts/mcp-live-deny-demo.sh).
Four beats:

1. [`scripts/mcp-stdio-smoke.sh --deny`](https://github.com/botzrDev/aegis/blob/main/scripts/mcp-stdio-smoke.sh) — the
   assertion gate. It spawns the MCP stdio gateway over the real pipeline,
   allows an `echo` call, refuses an `exfil` call, and checks the resulting
   records. The demo exits 0 only when this exits 0.

Beats 2–4 are then one gateway session the demo drives itself, under a freshly
minted signing key and its own audit sink — so the refusal on screen and the
record on screen are the same call, not two lookalike runs:

2. The JSON-RPC response the MCP client receives for the refused call —
   `"code": "POLICY_DENIED"`, `"isError": true`. A typed refusal the caller can
   branch on, not a hang and not a silent empty result.
3. The `schema_version: 2` audit outcome that same call wrote: `policy.status`
   `denied`, `capability.status` `denied` ("policy blocked before capability"),
   `execution.status` `host_denied` ("not executed") — each station stated
   separately, the whole line signed.
4. `aegis verify --key <public_key>` pinning that record file to the key the
   session published.

CI does not run this script. The equivalent assertions run there as
`botzr-aegis-mcp` unit and stdio tests under `cargo test --workspace`.

Replay:

```bash
asciinema play docs/demos/mcp-live-deny.cast
```

Run it live instead — no asciinema required:

```bash
scripts/mcp-live-deny-demo.sh
```

Re-record (maintainers; `asciinema` is maintainer tooling, not a workspace
dependency):

```bash
cargo build -p botzr-aegis-mcp -p botzr-aegis-cli   # pre-warm, so the cast stays short
asciinema rec -c 'scripts/mcp-live-deny-demo.sh' docs/demos/mcp-live-deny.cast
```

`DEMO_PAUSE=0` drops the script's reading pauses, which is what you want in CI
and not what you want in a recording.

## Scope

This is a research artifact, not a certification. The cast shows the default
catalog's `exfil` tool refused at the policy station under the shipped default
policy — one path, on one machine. What that does and does not establish is set
out in the [threat model](../threat-model.md) and the
[findings report](../findings.md).
