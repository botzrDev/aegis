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

# Opt-in OS confinement (Linux). Without --confine, wrap only records.
aegis wrap \
  --audit /tmp/wrap-audit.jsonl \
  --signing-key /tmp/aegis-signing.key \
  --confine --allow-exec-support \
  --allow-read /var/data --allow-net example.com:443 \
  -- npx -y some-mcp-server
```

`--allow-exec-support` is not decoration. Landlock is deny-by-default, so a
profile of `--allow-read /var/data` alone means the dynamic loader cannot map
libc and the child fails with `Permission denied` **before its own `main`
runs**. The flag grants read on `/usr /lib /lib64 /bin /sbin /etc /dev /proc`
— enough to start a dynamically linked program, and a **named hole**: a child
holding it can still read `/etc/passwd` and walk `/proc`. It is deliberately
not implied by `--confine`, because a widening that large should be something
an operator typed. A statically linked server does not need it.

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

**Wrap confines only when `--confine` is given, on Linux, and records
what was enforced.** Without `--confine` the child is an ordinary OS
process with the authority of the account that started it. Read this
list before describing wrap as a sandbox, a firewall, or a guard:

- **No policy evaluation.** No `PolicyEngine`, no rules, no allow/deny
  decision. Every `tools/call` is relayed. Nothing is ever blocked at
  this layer.
- **No argument matching.** Wrap does not look at `params.arguments` at
  all.
- **No filesystem or network restriction unless `--confine`.** Default
  wrap is an ordinary OS process under the operator's account. `--confine`
  applies Landlock and seccomp derived from `--allow-read` /
  `--allow-write` / `--allow-net` (Linux). `--confine` with no
  `--allow-*` is deny-everything. `--best-effort` is an explicit opt-in
  to partial enforcement; without it, a kernel that cannot honour the
  full profile refuses to exec.
- **The seccomp filter is a network deny-list, not a syscall sandbox.**
  Its default action is *allow*. With no `--allow-net` it kills the
  socket/connect/bind family on `SIGSYS`; everything it does not name —
  `ptrace`, `unshare`, `mount` — is permitted. With `--allow-net` the
  filter is installed and denies nothing, which is why the enforcement
  record carries `seccomp_network_denied` alongside `seccomp_applied`.
  Read the pair, never `seccomp_applied` alone.
- **Not Model A isolation.** Nothing runs inside wasmtime here. This is
  closer to Model B than to Model A, and weaker than either unless
  `--confine` is also given. See
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

macOS Seatbelt confinement is a later ticket (AILAB-630), not this one.
`--confine` is Linux-only.

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
