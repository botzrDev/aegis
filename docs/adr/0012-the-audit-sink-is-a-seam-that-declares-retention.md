# The audit sink is a public seam that declares its own retention

**Status:** accepted (2026-08-14)

> **Implemented 2026-08-16.** Both slices have landed: the `ChainSink` seam,
> `Retention`, `MemoryChainSink` and `FileChainSink` in AILAB-701; the in-memory
> default, the removal of both temp-file constructors, and `tempfile`'s exit from
> the production dependency graph in AILAB-702. The text below is the decision as
> taken on 2026-08-14 and is left unedited — read its "becomes" as the plan of
> record on that date, not as a description of the tree. For what shipped, see
> `CHANGELOG.md` and `docs/cli.md`.

`AuditWriter` keeps owning the chain rule — stamp `seq` and `prev_hash` under the lock, sign,
hash the signed form, append — and `ChainState`'s single-lock design is unchanged. What
becomes a seam is only *where the bytes land*: a public `ChainSink` trait, with the fsync a
property of the file adapter rather than an option on the writer.

The trait carries a **retention** declaration — `Durable` or `Volatile` — and the constructor
refuses a `Durable` sink signed by `insecure_dev_key`. The default sink becomes
`Volatile` and in-memory.

## Why

G3 durability is load-bearing, and `writer.rs:1` states it as a property of the module. Once
the sink is an argument, that sentence describes an adapter the writer does not own: a chain
appended to a third-party sink and a chain fsynced to disk are byte-identical and
indistinguishable to a verifier. ADR-0007's rule — *the record states what was enforced, not
what was asked for* — is the same rule one layer up, and `e92450a` is what it costs to
discover that late.

A `durable: bool` option on the writer was rejected outright: it would make the durability
guarantee configurable in production, which is precisely what must not happen. Declaring
retention on the adapter says which guarantee applies without offering to weaken it.

Retention also turns out to be the honest spelling of an invariant already in the tree.
`RuntimeBuilder::audit_file(path, key)` takes the key as a required parameter, and
`check_audit_key_pair` (`cli/src/lib.rs:232`, duplicated at `mcp/src/bridge.rs:65`) uses
"was a path supplied?" as a proxy for "will this be retained?". Retention is the thing that
proxy was reaching for, so the pairing rule generalises: **Durable sinks require a
provisioned key; only Volatile sinks may carry `insecure_dev_key`.**

## Considered options

A `test-utils`-gated, crate-private seam was the cheaper option and was rejected. It fixes
the test ergonomics and nothing else, and the trait's value is as an extension point for
embedders who need a sink Aegis does not ship.

A trait *hierarchy* — `DurableChainSink: ChainSink` adding `existing_tail`, making retention
a bound rather than a declared value — was also considered and rejected for surface
simplicity. The cost is accepted and named below.

## Consequences

- **The default sink stops touching the filesystem.** `Runtime::default()` used
  `AuditWriter::open_temp`, whose `TempDir` is dropped with the writer — so `aegis` and
  `aegis run` printed `Audit: /tmp/…/audit.jsonl` for a directory deleted at process exit
  (verified 2026-08-14 against the shipped `0.3.0` binary). A Volatile sink names no path and
  says so. `tempfile` leaves the production dependency graph as a result, not as a goal.
- **`audit/benches/emission.rs` must be pinned to an explicit file sink.** It uses
  `open_temp` today and is measuring the fsync path; switching the default silently changes
  what it reports.
- **`AuditWriter::path()` becomes `Option<&Path>`**, with three production callers printing
  it.
- **A sink can lie.** With one trait and a runtime check, a sink may declare `Durable` and
  return `Ok(None)` from `existing_tail()` over a non-empty store. That is undetectable and
  is documented rather than engineered around. A sink that declares `Durable` and *errors*
  on `existing_tail()` fails closed at construction, matching `recover_tail`'s existing
  refusal to append onto a torn tail (`writer.rs:247-252`).
- **The sink has a read side.** `prev_session_tail` requires the previous tail, so a sink
  that cannot answer `existing_tail()` produces Sessions that are permanently unanchored
  under ADR-0002 — see the **Sink** entry in `CONTEXT.md`.
