# botzr-aegis-wrap — decision log

Decisions taken while building AILAB-625 (D3 · transparent stdio MCP
interposer). Anything not recorded here is not a decision, it is an accident.

## No `rmcp`; hand-rolled JSON-RPC framing (MSRV 1.86)

The workspace pins `rust-version = "1.86"` and CI runs `cargo +1.86 check
--workspace --locked`. `rmcp` 2.x pulls `darling`, which needs rustc 1.88+; the
crates.io tip is 3.x. Same finding as
[`botzr-aegis-mcp/DECISIONS.md`](../botzr-aegis-mcp/DECISIONS.md) — an MCP SDK
does not fit under this MSRV.

So wrap ships a hand-rolled bidirectional relay: newline-delimited frames,
`BufRead::read_until(b'\n')` in, `write_all` + `flush` out, `serde_json` used
**only** to answer three questions per frame — "is this a `tools/call`?", "what
is its `id`?", "is this child frame a response at all?". The relayed bytes are
never re-encoded from the parsed value.

Revisit when MSRV moves. This is a deferral, not a rejection of the protocol.

## The relay is byte-oriented, not `String`-oriented

`BufRead::lines()` was the first implementation and it was wrong twice over.

It yields `Err(InvalidData)` on any non-UTF-8 byte, and the reader loop reports a
read error as EOF — so **one stray byte from a third-party server silently ended
the session**, and, on the stderr tee, swallowed every byte that followed it.
That directly contradicted this crate's one unconditional promise about stderr.
A server launched through `npx` or `python` emitting a progress bar or an ANSI
escape is not an exotic case.

It also **stripped a trailing `\r`**, so a CRLF-framed client's request digest
covered bytes the child never received — a quiet break in the one thing a digest
is for.

So: frames are `Vec<u8>`, parsed with `from_slice`, digested verbatim, and
written back followed by a re-emitted `\n`. The exact contract — `\r` preserved,
delimiter excluded from the digest, blank frames dropped, a missing final
newline supplied — is in the README's *Framing* table, and it is a contract
rather than an implementation note because the digests commit to it.

The stderr tee went further and dropped framing altogether: it copies raw
chunks, so a partial line reaches the operator immediately and nothing can make
it stop early.

## No `tokio`; three threads and an mpsc

Sync `std::io` + `std::thread` only. Three detached reader threads (client stdin,
child stdout, child stderr) feed one main event loop over an `mpsc` channel, and
**all audit work happens on the main thread** — so there is no
`Mutex<CallSession>` and no lifetime to thread through a worker.

The readers are `std::thread::spawn`, deliberately **not** `std::thread::scope`.
A scope must join every thread on the way out, and the client-stdin reader can be
blocked forever on a live TTY — so a scope would hang on exactly the path this
crate has to survive, the child dying while the client is still typing. The child
is reaped before returning, so a detached reader leaves no zombie; the process
exits and takes the thread with it.

## The post-EOF wait is bounded in the loop, not only in `reap`

The design brief's §3 loop says "keep looping until `ChildEof`" and its §5 says
"wait for the child with a bounded poll". Those only agree if the wait after
client EOF is itself bounded: a child that ignores stdin EOF and writes nothing
further would park `rx.recv()` forever and `reap`'s bounded poll would never be
reached.

So client EOF arms a 5 s deadline on the event loop. Expiry falls through to
`reap`, which polls `try_wait` every 20 ms for a further 5 s and then `kill`s.

## …but the grace bounds *silence*, not work — and expiry is not a death

The first version armed that deadline once and never moved it. That turns a
timeout meant to catch a **hung** child into a truncation of a **working** one:
a client that queues thirty calls and hangs up gets its session cut off at 5 s
mid-answer, and — far worse — every call still in flight was recorded
`host_denied` with the hardcoded reason `"child exited before responding"`
about a process that was alive and answering. An audit record is a signed
statement; that one was false.

Two changes, both load-bearing:

1. **Every child frame re-arms the deadline.** The original hang is still
   caught, because a child that ignores stdin EOF and goes silent produces no
   frames — silence is exactly what the grace now measures.
2. **Deadline expiry has its own reason string.**
   `child exited before responding` is reserved for a real `ChildEof`;
   grace expiry records
   `client closed stdin; child did not answer within the shutdown grace`.
   Wrap never attributes an exit to a process that did not exit. The two are
   different facts and the `Unanswered` enum in `record.rs` makes them
   impossible to spell with one string.

Both are covered by deliberately slow tests (~8 s each) in `tests/relay.rs`:
observing a 5 s grace from outside the process takes longer than 5 s, and there
is no honest shortcut.

## Nothing on the shutdown path waits without a bound

Stated as a claim, so here is the audit of it. After the pump returns: `reap`
polls `try_wait` (bounded, 5 s, then `kill`); `drain` polls `is_finished`
(bounded, 2 s, then abandons the thread); and the lock on the shared stderr sink
is a `try_lock` retry (bounded, 2 s, then the diagnostic is dropped).

That last one was a real bug, not a hypothetical: the exit path took a blocking
`Mutex::lock` on a sink the tee thread could be parked inside — mid-write to a
pipe nobody was reading. One unread stderr pipe would have hung wrap forever
while this file claimed it could not.

The tee thread itself still blocks on the sink, deliberately: it has nothing
else to do, and no exit path waits on it (`drain` is bounded).

What is *not* bounded, and cannot be: a **write** to a client or child that has
stopped reading its own pipe. That is the transport's backpressure. Bounding it
would mean dropping protocol bytes, which is worse than blocking.

## A `tools/call` inside a JSON-RPC batch is recorded like a single (AILAB-788)

*Supersedes the earlier decision to relay a batch without recording it, and the
one-time stderr diagnostic that named that hole. Both are gone from the code.*

A top-level array is a legal JSON-RPC batch, and a call inside one runs exactly
as a call in its own frame does. So it is recorded exactly the same way: an
`intent` before the frame reaches the child, an `outcome` when the answer comes
back. The array is walked element by element; a non-`tools/call` element is
skipped as a whole `initialize` frame is, and one that cannot name a tool takes
the same three-axis deny the malformed object path takes.

Two alternatives were on the table and both were worse. **Dropping the frame** so
it never reaches the child would need wrap to answer the client with a JSON-RPC
error the child never produced — the one thing this crate refuses to do
(AILAB-789). **Relaying while recording `Denied` / `not executed`** would sign a
refusal of a call the child really ran, which is precisely the defect `e92450a`
exists for.

**The N calls in a batch share one `request_digest`, and their N outcomes share
one `response_digest`.** A batched element never was a frame; the digests cover
the arrays the client and child actually wrote. Giving an element a digest of
its own would mean re-serializing it and committing a signed record to bytes
that crossed no wire — the `digest.rs` verbatim rule, which outranks the
convenience of a per-call digest.

The frame is still relayed **whole and unsplit** in both directions. Splitting a
batch into N object frames would be a rewrite rather than a relay.

## The pass-through grant is `deny_all`, not `denied`

On a relayed call the outcome records `capability: granted` with
`CapabilityGrant::deny_all(tool_id, grant_id)` — zero fs, zero net, zero
ceilings.

This reads oddly at first ("granted nothing?") and it is still the honest
record. The two alternatives are worse:

- Recording `capability: denied` would say the call was **refused**. It was not:
  it ran, and the tool answered. A recheck reading that file would reconstruct a
  denial that never happened.
- Recording a grant with actual fs/net authority would invent ambient authority
  wrap never minted and cannot enforce.

`deny_all` says precisely what happened: *this call was relayed under zero
capability authority from Aegis.* Spec §3.1 and pre-flight fact 7 mandate it.
Nothing replaces it with a resolved grant. Argument matchers were canceled in
AILAB-626, and `--confine` (AILAB-628) shipped but applies OS confinement without
minting a capability grant — `record.rs` does not branch on it, so a confined run
records `deny_all` too.

## Only a response-shaped frame can close a call — because MCP is bidirectional

Matching a child frame to a pending call on its `id` alone is wrong, and it is
wrong for a protocol reason rather than a defensive one. **An MCP server sends
its own requests to the client** — `sampling/createMessage`,
`elicitation/create`, `roots/list` — numbered from the server's own id space.
That space shares nothing with the client's, so a collision is ordinary: both
sides usually start at 1.

Under `id`-only matching, a server request carrying id 1 closes the client's
pending call 1. Wrap signs `Allowed` / `Granted` / `Success` with a
`response_digest` over **a request the tool never answered**, and the real
response, arriving a moment later, matches nothing and is recorded nowhere. A
false signed record is strictly worse than a missing one.

So a frame completes a call only if it is response-shaped: `result` or `error`
present and `method` absent (JSON-RPC 2.0 §5). Everything else is relayed with
no recording effect — including a batch-array response, which is the same gap
seen from the other side. The mirror child's `test/server-request` hook exists
solely to reproduce the collision, and the test recomputes the recorded digest
over the exact bytes of each frame so the assertion cannot be satisfied by the
wrong one.

## A child JSON-RPC `error` maps to `ExecutionOutcome::Success`

The call ran; the tool erred. `HostDenied` is reserved for the child **process**
failing to answer — it exited, or was killed. Collapsing the two would make "the
tool returned an error" indistinguishable from "the runtime refused to run it",
which is the distinction an audit trail exists to keep. Documented in the README
and covered by two tests.

## `policy_set_hash` is a documented stand-in

`SHA-256("aegis-wrap-passthrough-v0")`. Wrap runs **no** policy engine, so there
is no Policy Set to hash. The schema requires the field — a verdict whose ruleset
is unknown cannot be rechecked — so it carries a stable, named constant that says
"relayed under the wrap pass-through regime, version 0" rather than a hash of a
set that was never evaluated. Nothing is scheduled to replace it: argument
matchers were canceled in AILAB-626, so the stand-in is shipped behaviour rather
than a placeholder awaiting work.

## The CLI verb is `wrap`, not `run`

`aegis run` is WASM-only: `RunArgs` requires `--component`, and the pipeline it
drives is `POLICY → CAPABILITY → SANDBOX → AUDIT` over a wasmtime guest. Wrap
drives none of that — its only station is AUDIT. Overloading one verb across two
trust models is how "Aegis ran it" comes to mean two incompatible things. The
Execution Report's `aegis run --` prose for D3 is superseded (standing
report-reconciliation rule).

## No signal handler — a named limitation, not an omission

**Wrap installs no SIGINT/SIGTERM handler.** A signal handler needs either a new
dependency (`signal-hook`) or `unsafe`, and both are barred: no new workspace
dependency, and `unsafe_code = "forbid"` is workspace-wide.

What happens instead: when wrap dies, its file descriptors close, so the child
sees stdin EOF — the same shutdown signal the clean path sends. A terminal Ctrl-C
signals the whole process group anyway, so the child gets the signal directly.

What is genuinely lost: on SIGKILL, `AuditWriter::drop` does not run, so the
Session has no signed `close` line and a verifier reports `Indeterminate` rather
than `Verified`. That is the documented, intended reading of an unanchored tail
(ADR-0002) — but it is a real gap, and it is recorded here rather than glossed.

## The mirror child is a `[[bin]]`, and `autobins = false`

`src/bin/mirror_child.rs` is a test fixture, not a product surface. It is a
declared `[[bin]]` because `CARGO_BIN_EXE_*` only resolves declared bin targets,
and the relay has to be exercised against a **real** child process — an
in-process fake would test the parser and not the pipes.

`autobins = false` because the explicit target is named
`aegis-wrap-mirror-child` while the file is `mirror_child.rs`; leaving
autodiscovery on risks a second inferred target from the same file.

It is deliberately **not** an Aegis catalog server. Answering any unknown method
with `{"result":{"mirrored":"<method>","frame_len":<n>}}` is the ironclad relay
probe: a client that receives `mirrored` proves wrap relayed, because a local
`-32601` short-circuit could not have produced it — and `frame_len`, the byte
length of the frame *as the child received it*, is how a test proves the framing
survived (a CRLF-framed request arrives exactly one byte longer).

Its hooks are all named `test/…` and each exists for one assertion:
`test/exit` (child death), `test/error` (tool error), `test/stderr` and
`test/stderr-binary` (the tee, including a non-UTF-8 byte), `test/slow` (work
after client EOF), `test/hang` (silence after client EOF), and
`test/server-request` (a server→client request colliding with the client's id).
The fixture is byte-oriented for the same reason the relay is: a `lines()`
fixture would give up on the invalid-UTF-8 frame itself, and then the test could
not tell a fixture that quit from a relay that truncated.

## Non-goals (this crate, this slice)

- Argument matchers — canceled in AILAB-626, so permanently out of scope rather
  than deferred — approval parking (AILAB-629), schema-hash pinning (AILAB-627)
- Landlock/seccomp was a non-goal for this slice and has since shipped as
  `--confine` (AILAB-628)
- Changing `botzr-aegis-mcp`'s catalog behaviour — from wrap's point of view it
  is just another unmodified stdio MCP server
- Driving the enforcement pipeline: no `RuntimeBuilder`, no `PolicyEngine`, no
  `execute_tool_call`, no capability resolution
- Resource metering of the child process
- HTTP/SSE transport, or Content-Length framing
- **Refusing** a batch, or splitting one into per-element frames on either wire
  — batched calls are recorded and the array is relayed whole; see the batch
  section above
