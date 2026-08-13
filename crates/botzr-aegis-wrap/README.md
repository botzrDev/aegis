# botzr-aegis-wrap

Transparent **stdio MCP interposer** for Aegis. Wrap sits in the middle of an
existing MCP session — client ↔ `aegis wrap` ↔ child server — relays it in both
directions, and writes a schema-v2 chained, signed audit record for each single
`tools/call` it carries.

*Each single* rather than *every*: a `tools/call` sent inside a JSON-RPC **batch
array** is relayed and **not** recorded. That gap is real, named on stderr when
it happens, and described under [What this is not](#what-this-is-not).

```
client ──stdin──▶ aegis wrap ──stdin──▶ child MCP server
client ◀─stdout── aegis wrap ◀─stdout── child MCP server
                       │
                       └── audit JSONL (intent + outcome per tools/call)
```

## What this is not

**Wrap confines only when `--confine` is given, on Linux.** Without it the
child is an ordinary OS process with the authority of the account that
started it. Read this list before describing wrap as a sandbox by default:

- **No policy evaluation.** No `PolicyEngine`, no rules, no allow/deny decision.
  Every `tools/call` is relayed. Nothing is ever blocked at this layer.
- **No argument matching.** Wrap does not look at `params.arguments` at all
  (AILAB-626).
- **No filesystem or network restriction unless `--confine`.** Default wrap is
  the operator's own account. `--confine` (AILAB-628) applies Landlock and
  seccomp from `--allow-read` / `--allow-write` / `--allow-net`.
- **No approval parking, no schema pinning** (AILAB-629 / AILAB-627).
- **No record for a batched `tools/call`.** A JSON-RPC **batch** — a top-level
  array — is relayed like anything else, and *nothing inside it is recorded*.
  Recording one would mean a session per element, a response matched element by
  element, and a request digest over bytes that never were a frame; none of that
  is built. A client that batches its calls therefore gets an audit file with
  **no** rows for them. Wrap prints
  `aegis wrap: relayed a JSON-RPC batch array — any tools/call inside a batch is
  NOT recorded (known gap, …)` to the child-stderr sink the first time it sees
  one, because an audit tool that bypasses itself in silence is worse than one
  that says so. (In practice MCP clients send one request per frame; this is a
  protocol-legal path, not the common one.)
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

Only a `tools/call` sent as its own frame. `initialize`, `tools/list`, `ping`,
notifications, batch arrays, and every method this build has never heard of are
relayed with **zero** interception — no session, no audit line, and never a
locally synthesized `-32601`. Wrap is an interposer, not a second server.

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
use botzr_aegis_wrap::{run_wrap, WrapConfig};

let config = WrapConfig {
    child_argv: vec!["npx".into(), "-y".into(), "some-mcp-server".into()],
    audit_path: "/tmp/wrap-audit.jsonl".into(),
    signing_key_path: "/tmp/aegis-signing.key".into(),
};
let code = run_wrap(&config)?;
```

Both paths are required: a persistent record file has no dev-key fallback
(AILAB-620). Mint the key with `aegis keygen --out <PATH>`.

`run_wrap_with_streams` is the same relay with caller-supplied client streams. It
exists so the integration tests and the overhead bench can drive a **real** child
process end to end without an in-process pipe (`std::io::pipe` is Rust 1.87; the
workspace MSRV is 1.86). It is a testability seam, not a narrowing of the product
surface.
