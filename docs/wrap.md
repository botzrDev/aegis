# Wrapping an MCP server

`aegis wrap` sits in the middle of an existing MCP session and writes a
schema-v2 chained, signed audit record for every `tools/call` it carries —
including one sent inside a JSON-RPC batch array, see
[batched calls](#batched-calls).

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

# Opt-in policy enforcement. Without --policy, nothing is ever blocked.
aegis wrap \
  --audit /tmp/wrap-audit.jsonl \
  --signing-key /tmp/aegis-signing.key \
  --policy ./policy.yaml \
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
what was enforced. It evaluates policy only when `--policy` is given.**
Without them the child is an ordinary OS process with the authority of
the account that started it. Read this list before describing wrap as a
sandbox, a firewall, or a guard:

- **No policy evaluation unless `--policy`.** Default wrap runs no rules
  and makes no allow/deny decision: every `tools/call` is relayed and
  nothing is blocked at this layer. `--policy <YAML>` (AILAB-793) is the
  opt-in — see [Enforcing a policy](#enforcing-a-policy) — and a denied
  `tools/call` is then refused with a JSON-RPC `-32042` error
  ([ADR-0015](adr/0015-wrap-may-synthesize-a-refusal.md)). No
  `PolicyEngine` lives in the wrap crate either way: it asks a
  `CallGate` and the CLI implements one.
- **No argument matching.** Wrap does not look at `params.arguments` at
  all — a policy rule here matches on tool identity, nothing else.
- **No capability minting, ever.** Not even under `--policy`: a gate
  decides *whether* a call may go and resolves no grant, so every
  record still carries the `deny_all` pass-through grant.
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
- **With no `--allow-net`, io_uring is unavailable to the child — all of
  it, not just its network operations.** The ring dispatches socket and
  connect from memory shared with the kernel, so those operations never
  cross a syscall seccomp can inspect; until 2026-08-25 a confined process
  could reach the network that way while the record said
  `seccomp_network_denied: true` (AILAB-807). seccomp cannot read
  submission-queue entries, so no filter can permit io_uring file I/O
  while denying io_uring network I/O. **The price, stated in the same
  breath: a child that uses io_uring for ordinary file I/O — some
  databases, some async runtimes — dies on `SIGSYS` under a
  network-denying profile.** Give it `--allow-net` or do not confine it.
- **The network claim rests on enumeration, and enumeration has a tail.**
  The filter denies the interfaces it names. Any kernel interface that
  carries a packet without crossing one of them is an open path that has
  to be *discovered* rather than prevented — io_uring was exactly that.
  Landlock covers the filesystem side at the LSM layer, where io_uring is
  caught like any other caller; moving the network side there too is
  AILAB-810 and is **not shipped**.
- **Not Model A isolation.** Nothing runs inside wasmtime here. This is
  closer to Model B than to Model A, and weaker than either unless
  `--confine` is also given. See
  [trust models](trust-models.md) and
  [threat model §3](threat-model.md#3-trust-boundaries-model-a-vs-model-b).

What wrap does buy is **evidence**: a hash-chained, signed record of
which tools were called, with digests of the exact request and response
bytes, that survives the session and can be verified with `aegis verify`.

## Batched calls

A `tools/call` sent inside a **JSON-RPC batch array** is recorded exactly
as one sent in a frame of its own: an `intent` before the array reaches
the child, an `outcome` when the child's answer comes back. The array is
relayed whole and unsplit in both directions — wrap does not rewrite a
batch into per-call frames.

Under `--policy` it can refuse one, and only whole: a batch cannot be
filtered without re-serializing it onto the child's stdin, which wrap
never does, so one refused `tools/call` drops the entire frame. See
[Enforcing a policy](#enforcing-a-policy).

The calls in a batch **share the frame's digests**: N intents carry the
same `request_digest` and their N outcomes the same `response_digest`,
because on each wire there was exactly one frame. A batched element never
was a frame of its own, so digesting a re-serialized element would commit
a signed record to bytes that crossed no wire.

macOS Seatbelt confinement is a later ticket (AILAB-630), not this one.
`--confine` is Linux-only.

## Enforcing a policy

**Off unless `--policy <YAML>` is passed.** That flag is the whole
opt-in; there is no separate `--enforce`, and a wrap process without it
is byte-for-byte identical on the client stream to one built before this
existed.

With it, every well-formed `tools/call` is evaluated before the frame may
reach the child. An **allowed** call is relayed verbatim and answered
verbatim. A **refused** one — denied, rate-limited, or pending approval —
never reaches the child, and the client is told so rather than left
blocked on an id that would never be answered:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32042,
 "message":"aegis wrap refused this tools/call",
 "data":{"aegis":{"layer":"wrap","code":"POLICY_DENIED"}}}}
```

That frame is the **only** JSON-RPC wrap ever authors
([ADR-0015](adr/0015-wrap-may-synthesize-a-refusal.md)). `-32042`,
`data.aegis.layer` and the `error`-rather-than-`result` envelope do not
vary; `data.aegis.code` does, across `POLICY_DENIED`, `RATE_LIMITED`,
`PENDING_APPROVAL` and `HOST_DENIED`.

The record is the evidence, and it is what distinguishes a wrap refusal
from a child's own error: `policy: denied`, `capability: denied` with
reason `policy blocked before capability`, `execution: host_denied` with
reason `not executed`, and the **real** Policy Set content hash rather
than the pass-through stand-in a relayed call carries.

A **batch** is refused whole. Every `tools/call` in a dropped array is
answered and recorded — the refused ones name their own cause, and an
allowed sibling gets `HOST_DENIED` with reason `not executed: sibling
call in this batch was refused` while its record still says its policy
verdict was `allowed`.

**What `--policy` does not change.** `initialize`, `tools/list`, `ping`,
notifications and unknown methods all still reach the child, and
`-32601` is still never synthesized: "this call is refused" is a claim
wrap can make, "no such method" is not. No capability is minted, so the
record still carries the `deny_all` grant. `--confine` remains a
separate flag answering a different question. A `PendingApproval`
verdict is a refusal here, not a park — parking is AILAB-629 and is not
built.

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
