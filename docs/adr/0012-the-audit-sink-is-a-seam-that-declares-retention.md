# The audit sink is a public seam that declares its own retention

**Status:** accepted (2026-08-14)

`AuditWriter` keeps owning the chain rule — stamp `seq` and `prev_hash` under the lock, sign,
hash the signed form, append — and `ChainState`'s single-lock design is unchanged. The seam is
only *where the bytes land*: a public `ChainSink` trait, with the fsync a property of the file
adapter rather than an option on the writer.

The trait carries a **retention** declaration — `Durable` or `Volatile` — and the constructor
refuses a `Durable` sink signed by `insecure_dev_key`. The default sink is `Volatile` and
in-memory: `Runtime::default()` builds a `MemoryChainSink`, so a run given no `--audit` retains
nothing after the process exits and the banner says so.

Shipped in two slices — the seam, `Retention`, `MemoryChainSink` and `FileChainSink` in
AILAB-701; the in-memory default, the removal of both temp-file constructors, and `tempfile`'s
exit from the production dependency graph in AILAB-702.

## Why

G3 durability is load-bearing, and `writer.rs`'s module doc stated it as a property of the
module. Once the sink is an argument, that sentence describes an adapter the writer does not
own: a chain appended to a third-party sink and a chain fsynced to disk are byte-identical and
indistinguishable to a verifier. ADR-0007's rule — *the record states what was enforced, not
what was asked for* — is the same rule one layer up, and `e92450a` is what it costs to
discover that late.

A `durable: bool` option on the writer was rejected outright: it would make the durability
guarantee configurable in production, which is precisely what must not happen. Declaring
retention on the adapter says which guarantee applies without offering to weaken it.

Retention also turns out to be the honest spelling of an invariant already in the tree.
`RuntimeBuilder::audit_file(path, key)` takes the key as a required parameter, and
`check_audit_key_pair` (`cli/src/lib.rs`, with the same rule inlined in `mcp/src/bridge.rs`)
uses "was a path supplied?" as a proxy for "will this be retained?". Retention is the thing
that proxy was reaching for, so the pairing rule generalises: **Durable sinks require a
provisioned key; only Volatile sinks may carry `insecure_dev_key`.**

## Considered options

A `test-utils`-gated, crate-private seam was the cheaper option and was rejected. It fixes
the test ergonomics and nothing else, and the trait's value is as an extension point for
embedders who need a sink Aegis does not ship.

A trait *hierarchy* — `DurableChainSink: ChainSink` adding `existing_tail`, making retention
a bound rather than a declared value — was also considered and rejected for surface
simplicity. The cost is accepted and named below.

## Consequences

- **The default sink does not touch the filesystem.** `Runtime::default()` used a temp-file
  sink whose `TempDir` was dropped with the writer — so `aegis` and
  `aegis run` printed `Audit: /tmp/…/audit.jsonl` for a directory deleted at process exit
  (verified 2026-08-14 against the shipped `0.3.0` binary). The default is now a
  `MemoryChainSink`: it names no path, and the banner reads
  `Audit: (volatile sink — records are not retained)`. A retained record needs
  `--audit <PATH>` together with `--signing-key <PATH>`. `tempfile` left the production
  dependency graph as a result, not as a goal — it remains a `[dev-dependency]` of
  `botzr-aegis-audit` for benches and tests.
- **`audit/benches/emission.rs` is pinned to an explicit file sink.** It called
  `AuditWriter::open_temp` directly — never the runtime default — so what forced the rewrite
  was deleting that constructor, not flipping `Runtime::default()`. It measures the
  fsync-per-line path, and pointing it at the new in-memory default would have published a
  number for work the shipped file sink does not do. It now opens a `FileChainSink` over a
  `TempDir` the bench owns, with a provisioned key, and still fsyncs on the hot path.
- **`AuditWriter::path()` returns `Option<&Path>`**, and the production callers that print it
  take the `None` arm for the default sink. It is cached at construction, outside the chain
  lock, because a printer must not queue behind an in-flight fsync to learn a value that never
  changes. `AuditWriter::retention()` reports the sink's declaration and is cached beside it
  for consistency — it has **no production caller**: both banners switch on `path()`, and
  retention is there for embedders and tests.
- **The default Chain grows in RSS without a bound.** `MemoryChainSink` appends to a `Vec<u8>`
  that is never drained or capped, and `Runtime::default()` keeps no clone, so nothing can
  read or reclaim it. A long-lived process on the default configuration — the MCP stdio
  gateway with no `--audit` is the one that ships — holds every line of the Session in memory
  for its lifetime, where the temp-file default let the OS page and reclaim. Accepted for now
  because the alternative is a retention policy on the sink, which is a second knob on the
  thing ADR-0012 exists to keep declarative; a cap or ring buffer needs its own ticket.
- **A sink can lie.** With one trait and a runtime check, a sink may declare `Durable` and
  return `Ok(None)` from `existing_tail()` over a non-empty store. That is undetectable and
  is documented rather than engineered around. A sink that declares `Durable` and *errors*
  on `existing_tail()` fails closed at construction, matching `with_sink`'s refusal to append
  onto a torn tail (`writer.rs`).
- **The sink has a read side.** `prev_session_tail` requires the previous tail, so a sink
  that cannot answer `existing_tail()` produces Sessions that are permanently unanchored
  under ADR-0002 — see the **Sink** entry in `CONTEXT.md`.
