# botzr-aegis-wrap

Transparent **stdio MCP interposer** for Aegis. Wrap sits in the middle of an
existing MCP session — client ↔ `aegis wrap` ↔ child server — relays it in both
directions, and writes a schema-v2 chained, signed audit record for every
`tools/call` it carries.

*Every* means every: a `tools/call` sent inside a JSON-RPC **batch array** is
recorded the same way one sent in a frame of its own is, and the array still
reaches the child whole — see [Batched calls](#batched-calls).

```
client ──stdin──▶ aegis wrap ──stdin──▶ child MCP server
client ◀─stdout── aegis wrap ◀─stdout── child MCP server
                       │
                       └── audit JSONL (intent + outcome per tools/call)
```

## What this is not

**Wrap confines only when `--confine` is given, on Linux, and evaluates policy
only when `--policy` is given.** Without them the child is an ordinary OS
process with the authority of the account that started it. Read this list
before describing wrap as a sandbox by default:

- **No policy evaluation unless `--policy`.** Default wrap runs no rules and
  makes no allow/deny decision: every `tools/call` is relayed and nothing is
  ever blocked at this layer. `--policy <YAML>` (AILAB-793) turns that on —
  see [Enforcing a policy](#enforcing-a-policy). Even then no `PolicyEngine`
  lives in this crate; wrap asks a `CallGate` and the CLI supplies one.
- **No argument matching.** Wrap does not look at `params.arguments` at all, and
  will not: argument matching was canceled in AILAB-626. A policy rule here
  matches on tool identity, nothing else.
- **No filesystem or network restriction unless `--confine`.** Default wrap is
  the operator's own account. `--confine` (AILAB-628) applies Landlock and
  seccomp from `--allow-read` / `--allow-write` / `--allow-net`.
- **No capability minting, ever.** Not even under `--policy`: a gate decides
  *whether* a call may go, it resolves no grant, so every record still carries
  the `deny_all` pass-through grant.
- **No approval parking, no schema pinning** (AILAB-629 / AILAB-627). A
  `PendingApproval` verdict under `--policy` is a **refusal**, not a park.
- **No refusal of a batch by default.** A JSON-RPC **batch** — a top-level
  array — is recorded call by call (see [Batched calls](#batched-calls)) and
  still relayed, like everything else. Under `--policy` a batch cannot be
  filtered, so one refused `tools/call` in it refuses the whole frame; the
  array is never re-encoded or split.
- **Not Model A isolation.** Nothing runs inside wasmtime here. This is closer
  to Model B than to Model A, and weaker than either: wrap does not even enforce
  a grant before an effect, because the effect happens inside a process it does
  not control. See [`docs/threat-model.md`](../../docs/threat-model.md) §3.

What wrap does buy is **evidence**: a hash-chained, signed record of which tools
were called, with digests of the exact request and response bytes, that survives
the session and can be verified with `aegis verify`.

## Framing: what is preserved, what is normalized

A **frame** is the bytes up to and **not including** the `\n` that delimited it.
The relay is byte-oriented — `BufRead::read_until(b'\n')`, `Vec<u8>`,
`serde_json::from_slice` — never `String`.

| | |
|---|---|
| **Preserved** | Every byte *inside* a frame, relayed verbatim in both directions. A trailing `\r` (CRLF framing) is **content and is kept**. Invalid UTF-8 is kept — it only means "not a `tools/call`" to the recorder, never end-of-stream. |
| **Digested** | Exactly the frame bytes: the `\r` is in, the `\n` delimiter is out. |
| **Normalized** | The `\n` delimiter is re-emitted, so a final frame that arrived without one gains one. A frame that is empty or all ASCII whitespace is dropped rather than forwarded — it carries no JSON-RPC message. |

Nothing else is rewritten: wrap never re-encodes a parsed value back onto the
wire, so a child's key order, spacing and number formatting reach the client
untouched.

The child's **stderr** is a plain byte tee with no framing and no encoding
requirement at all — progress bars, ANSI escapes and stray binary all pass
through, and one bad byte cannot swallow what follows it.

## What gets recorded

Every `tools/call` — sent as its own frame, or carried inside a batch array.
`initialize`, `tools/list`, `ping`, notifications, and every method this build
has never heard of are relayed with **zero** interception — no session, no audit
line, and never a locally synthesized `-32601`. That last one holds under
`--policy` exactly as without it: "this call is refused" is a claim wrap is in a
position to make, and "no such method" is not. Wrap is an interposer, not a
second server. The one frame an enforcing session may author — the answer to a
`tools/call` it *refused*, and only that — is
[ADR-0015](../../docs/adr/0015-wrap-may-synthesize-a-refusal.md); see
[Enforcing a policy](#enforcing-a-policy).

### Batched calls

A top-level array is walked element by element, and each well-formed
`tools/call` inside it opens the same `intent` before the frame reaches the
child and the same `outcome` when the answer comes back. An element that is not
a `tools/call` is skipped exactly as a whole `initialize` frame is; one that
cannot name a tool takes the same immediate three-axis deny a malformed object
frame takes.

**N calls in one batch share one `request_digest`, and their N outcomes share
one `response_digest`.** A batched element never was a frame, so the digests
cover the array the client actually wrote and the array the child actually
answered with. Re-serializing an element to give it a digest of its own would
commit a signed record to bytes that crossed no wire.

The frame itself is relayed **whole and unsplit** in both directions. Splitting
a batch into N object frames would be a rewrite rather than a relay, and wrap
never puts bytes on either wire that it did not receive.

### Which child frames can close a call

A child frame completes a pending `tools/call` only when it is **response-shaped**:
`result` or `error` present, `method` absent (JSON-RPC 2.0 §5). Matching on `id`
alone would be a bug, not a shortcut — **MCP is bidirectional.** A server issues
its own requests to the client (`sampling/createMessage`, `elicitation/create`,
`roots/list`) numbered from the *server's* id space, which shares no namespace
with the client's and collides with it routinely. Keying on `id` alone lets one
of those close a pending call: wrap would sign an `Allowed` / `Granted` /
`Success` outcome whose `response_digest` covers **a request the tool never
answered**, and the real response would arrive to match nothing. A false signed
record is strictly worse than a missing one. Server-initiated requests are
relayed, exactly like everything else, with no recording effect.

A recorded call is two lines, in this order:

| line | when | why that order |
|---|---|---|
| `intent` | before the request reaches the child | a wrap process that dies mid-call still says a call was in flight |
| `outcome` | after the response is already on its way to the client | the client never waits on an fsync that can happen after |

Fields worth knowing:

- **`policy_set_hash`** is `SHA-256("aegis-wrap-passthrough-v0")`. It is a
  documented stand-in, **not** a real Policy Set — wrap evaluated none, and
  naming a set it did not run would be the more dishonest option.
- **`capability`** is `granted` with `CapabilityGrant::deny_all(...)`: zero fs,
  zero net, zero resource ceiling. That is the truthful description of a
  pass-through — wrap minted no authority, so the record must not claim any.
- **`decision_axes`** stays `{}`: no policy and no capability station ran, so
  there are no verdict inputs to record.
- **`peak_memory_bytes`** is `0`, meaning *not measured*. Wrap does not meter the
  child process. `wall_ms` is the round trip through wrap, not the child's own
  accounting.

### A child JSON-RPC `error` is recorded as `execution: success`

If the child answers with a JSON-RPC `error` object, the outcome line still says
`"execution":{"status":"success"}`.

That is deliberate. **The call ran; the tool erred.** `HostDenied` is reserved
for the call never being answered at all, and it comes in two distinct flavours
with two distinct reason strings (below). Collapsing any of these would make
"the tool returned an error" indistinguishable from "the runtime refused to run
it", which is exactly the distinction an audit trail exists to keep. Every
mapping is covered by tests in `tests/relay.rs`.

### The two ways a call goes unanswered

| `execution.reason` | what actually happened |
|---|---|
| `child exited before responding` | the child's stdout reached EOF — the **process is gone** |
| `client closed stdin; child did not answer within the shutdown grace` | the client closed stdin, the child stayed **alive** and produced nothing for 5 s, and wrap is about to reap and kill it |

They are never interchanged. A record is a signed statement, and saying a
process exited when it is still running is a false one — while "the child is
slow" and "the child is gone" are exactly the two states an operator opens this
file to tell apart.

### A malformed `tools/call`

A `tools/call` whose `params.name` is missing or not a string is recorded as
`tool_id: "<unknown>"` with a denied policy, a denied capability, and
`host_denied` execution — and **is still relayed**. Wrap does not block; the
child answers with its own `-32602`.

## Enforcing a policy

**Off unless `--policy <YAML>` is passed.** Presence of that flag is the whole
opt-in; there is no second `--enforce`, and a default `aegis wrap` process is
byte-for-byte identical on the client stream to one built without this feature.

```bash
aegis wrap --audit /tmp/wrap-audit.aarl --signing-key ~/.aegis/signing.key \
           --policy ./policy.yaml -- npx -y some-mcp-server
```

With it, every well-formed `tools/call` is evaluated before the frame may reach
the child:

- **Allowed** — the frame is relayed verbatim and the response comes back
  verbatim, exactly as without the flag. The record carries the real Policy Set
  hash and the rule that decided it, and still the `deny_all` grant: wrap minted
  no capability.
- **Refused** (denied, rate-limited, or pending approval) — the frame **never
  reaches the child**, and the client gets a JSON-RPC error rather than silence:

  ```json
  {"jsonrpc":"2.0","id":1,"error":{"code":-32042,
   "message":"aegis wrap refused this tools/call",
   "data":{"aegis":{"layer":"wrap","code":"POLICY_DENIED"}}}}
  ```

  The record says `policy: denied`, `capability: denied` with reason
  `policy blocked before capability`, and `execution: host_denied` with reason
  `not executed`. `-32042`, `data.aegis.layer` and the `error`-rather-than
  -`result` envelope never vary; only `data.aegis.code` does
  (`POLICY_DENIED` / `RATE_LIMITED` / `PENDING_APPROVAL` / `HOST_DENIED`).

**A batch is refused whole.** Wrap never re-serializes a parsed value onto the
child's stdin, so an array carrying one refused `tools/call` cannot be filtered
down to its allowed elements — the frame is dropped instead. Every `tools/call`
in it is answered and recorded: the refused ones name their own cause, and an
allowed sibling gets `HOST_DENIED` with reason `not executed: sibling call in
this batch was refused` and a record that still says its policy verdict was
`allowed`. A batch whose calls are all allowed relays whole and unsplit, as
always.

**What enforcement does not change.** `initialize`, `tools/list`, `ping`,
notifications and unknown methods all still reach the child; `-32601` is still
never synthesized; `--confine` is still a separate, orthogonal flag; and no
`PolicyEngine` enters this crate's dependency graph. Wrap asks a `CallGate`
trait and the CLI implements it over `botzr-aegis-policy`. A `PendingApproval`
verdict is a refusal here, not a park — parking is AILAB-629 and is not built.

## Lifecycle

- Client stdin EOF closes the child's stdin, which is the child's shutdown
  signal. Wrap then gives the child a **5 s shutdown grace** — and the grace
  bounds *silence, not work*: **every frame the child sends re-arms it**. A
  child still answering queued calls a minute after the client hung up is
  carried to completion; a child that says nothing at all for 5 s is given up
  on. `reap` then polls `try_wait` every 20 ms for a further 5 s before `kill`.
- Exit code is `0` only when the child shut down cleanly with code 0; otherwise
  the child's own code, or `1` if it was signalled or killed.
- A child that exits while the client is still open prints
  `aegis wrap: child process exited before the client closed stdin` to stderr
  and returns non-zero. Every call still in flight is closed `host_denied`.
- The child's **stderr is teed, never swallowed** (byte for byte, no encoding
  assumed), and never merged into stdout — stdout carries JSON-RPC only.
- **No unbounded wait on the shutdown path.** Not the event loop after client
  EOF, not the reap, not the stderr drain, and not the lock on the shared
  stderr sink — a diagnostic that cannot take that lock within 2 s is dropped
  rather than blocking wrap behind a pipe nobody is reading. (The one place
  wrap can still block indefinitely is a *write* to a client or child that has
  stopped reading its own pipe. That is the transport's backpressure, not a
  wait wrap invents, and it cannot be bounded without dropping protocol bytes.)
- **No SIGINT/SIGTERM handler is installed.** See
  [`DECISIONS.md`](./DECISIONS.md).

## Verifying the record

The audit file is an ordinary Aegis Chain file:

```bash
aegis keygen --out /tmp/aegis-signing.key
# … run a wrap session writing /tmp/wrap-audit.jsonl …
aegis verify /tmp/wrap-audit.jsonl --key <public_key printed by keygen>
```

`Verified` requires the Session's signed `close` line, which is written when the
`AuditWriter` drops — so a wrap process killed with SIGKILL leaves an
`Indeterminate` tail, by design.

## Library use

```rust,ignore
use botzr_aegis_wrap::{run_wrap, WrapConfig, WrapMode};

let config = WrapConfig {
    child_argv: vec!["npx".into(), "-y".into(), "some-mcp-server".into()],
    audit_path: "/tmp/wrap-audit.aarl".into(),
    signing_key_path: "/tmp/aegis-signing.key".into(),
    mode: WrapMode::Record,
};
let code = run_wrap(&config)?;
```

`WrapMode::Record` is the transparent relay. `WrapMode::Confine(profile)` adds
OS confinement of the child, and `WrapMode::Enforce { gate, confinement }` puts
every `tools/call` to a `CallGate` first — see [Enforcing a policy](#enforcing-a-policy).

Both paths are required: a persistent record file has no dev-key fallback
(AILAB-620). Mint the key with `aegis keygen --out <PATH>`.

`run_wrap_with_streams` is the same relay with caller-supplied client streams. It
exists so the integration tests and the overhead bench can drive a **real** child
process end to end without an in-process pipe (`std::io::pipe` is Rust 1.87; the
workspace MSRV is 1.86). It is a testability seam, not a narrowing of the product
surface.
