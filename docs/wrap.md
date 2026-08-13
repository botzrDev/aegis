# Wrapping an MCP server

`aegis wrap` sits in the middle of an existing MCP session and writes a
schema-v2 chained, signed audit record for every **single** `tools/call`
it carries. Calls sent inside a JSON-RPC batch array are relayed but
**not** recorded — see [the recording gap](#the-batch-recording-gap).

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

## The batch recording gap

A `tools/call` sent inside a **JSON-RPC batch array** is relayed to the
child and executed, but no audit record is written for it. The chain
stays internally valid and `aegis verify` still passes — it simply has no
line for that call, and nothing in the record says one is missing.

Wrap says so out loud rather than hiding it: the first batch of a session
prints a diagnostic on the child's stderr sink naming the gap. Treat a
wrap chain as complete evidence **only** for clients that send one
request per message.

OS confinement (Landlock / seccomp on Linux, Seatbelt on macOS) is
Backlog, not shipped. Do not lead with a capability the reader may not
have.

## What recording costs

Interposing is not free, and the number **misses its target**:
`wrap_relay/tools_call_recorded` measures **4.371 ms per recorded
`tools/call`** against an informational 0.5–2 ms budget — ~2.19× over. A
relayed message that is *not* recorded costs 136.05 µs, so essentially the
whole difference is the recording itself: an `intent` and an `outcome` line,
each flushed and `sync_all`'d under the shipped G3 durability default. Two
fsyncs cost ~4.2 ms on the reference filesystem on their own, which is why no
arrangement of wrap code reaches 2 ms while durability stays where it is.

Expect a different figure on a different filesystem, and see
[Benchmarks](benchmarks.md) for the hardware and the full attribution.

The library crate is
[`botzr-aegis-wrap`](https://github.com/botzrDev/aegis/blob/main/crates/botzr-aegis-wrap/README.md).
