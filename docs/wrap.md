# Wrapping an MCP server

`aegis wrap` sits in the middle of an existing MCP session and writes a
schema-v2 chained, signed audit record for every `tools/call` it carries.

```
client ──stdin──▶ aegis wrap ──stdin──▶ child MCP server
client ◀─stdout── aegis wrap ◀─stdout── child MCP server
                       │
                       └── audit JSONL (intent + outcome per tools/call)
```

```bash
aegis keygen --out /tmp/aegis-signing.key
aegis wrap \
  --audit /tmp/wrap-audit.jsonl \
  --signing-key /tmp/aegis-signing.key \
  -- npx -y some-mcp-server
```

Then pin the record. `aegis verify` distinguishes **pinned** from
**unpinned** ([ADR-0004](adr/0004-embedded-key-with-labelled-trust.md)):

```bash
aegis verify --key <public_key printed by keygen> /tmp/wrap-audit.jsonl
```

`--audit` and `--signing-key` are both required. Wrap has no temp-sink
mode: the only thing an interposer produces is its record.

The literal `--` ends wrap's own flags. Everything after it is the child
argv, including the child's `--help`.

`wrap` is on `main`. It is **not** in the `0.3.0` crates.io tarball, and
neither is the `keygen` you need to mint its signing key.

## What this is not

**Wrap records; it does not confine.** Read this list before describing
wrap as a sandbox, a firewall, or a guard:

- **No policy evaluation.** No `PolicyEngine`, no rules, no allow/deny
  decision. Every `tools/call` is relayed. Nothing is ever blocked at
  this layer.
- **No argument matching.** Wrap does not look at `params.arguments` at
  all.
- **No filesystem or network restriction on the child.** The child is an
  ordinary OS process running under the operator's own account, with the
  operator's own authority. There is no Landlock, no seccomp, no cap-std
  preopen.
- **Not Model A isolation.** Nothing runs inside wasmtime here. This is
  closer to Model B than to Model A, and weaker than either: wrap does
  not even enforce a grant before an effect, because the effect happens
  inside a process it does not control. See
  [trust models](trust-models.md) and
  [threat model §3](threat-model.md#3-trust-boundaries-model-a-vs-model-b).

What wrap does buy is **evidence**: a hash-chained, signed record of
which tools were called, with digests of the exact request and response
bytes, that survives the session and can be verified with `aegis verify`.

OS confinement (Landlock / seccomp on Linux, Seatbelt on macOS) is
Backlog, not shipped. Do not lead with a capability the reader may not
have.

The library crate is
[`botzr-aegis-wrap`](https://github.com/botzrDev/aegis/blob/main/crates/botzr-aegis-wrap/README.md).
