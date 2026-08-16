# CLI

Installed binary name: `aegis`. This page documents `main`.

```
aegis <version> — research runtime for secure agent tool execution

Usage:
  aegis [--policy <PATH>] [--audit <PATH> --signing-key <PATH>]
  aegis run --component <WASM> --id <TOOL_ID> [OPTIONS]
  aegis wrap --audit <PATH> --signing-key <PATH> -- <CMD> [ARGS…]
  aegis verify [--key <HEX>]... [--trust-store <PATH>] <PATH>
  aegis recheck --policy <YAML> <PATH>
  aegis keygen --out <PATH> [--force]
```

**Only `run` is in the published `0.3.0` binary.** `keygen`, `verify`,
`recheck`, and `wrap` landed after that tag and reach the registry with
the next cut — until then, [build from source](install.md#from-source).

Full flag tables: [`crates/botzr-aegis-cli/README.md`](https://github.com/botzrDev/aegis/blob/main/crates/botzr-aegis-cli/README.md).

## `aegis keygen`

Writes a fresh ed25519 seed to `--out` as 64 lowercase hex characters.
Prints `public_key` and `key_id`. Generation is never implicit — a key
minted on the emit path would silently invalidate every pin held against
the old one.

On Unix the file is created `0600`, and `aegis` refuses to *load* a key
readable by group or others. Elsewhere the mode is neither set nor
checked: there is no portable equivalent, and claiming one would be a
guarantee the code cannot keep.

## `aegis run`

Registers a `wasm32-wasip2` component and executes one call through
[the pipeline](pipeline.md). `--audit` and `--signing-key` travel
together, or neither is given.

**Without `--audit`, nothing is kept.** Bare `aegis` and `aegis run` with
no `--audit` write to a **Volatile**, in-memory sink and print

```
Audit: (volatile sink — records are not retained)
```

instead of a path. The bytes die with the process: there is no file to
open afterwards, nothing for `aegis verify` or `aegis recheck` to read,
and the Session is signed by the dev key compiled into
`botzr-aegis-audit` — so it is not evidence, and never was. Naming a path
there would be the overclaim
([ADR-0012](adr/0012-the-audit-sink-is-a-seam-that-declares-retention.md)).

To get a retained record, pass `--audit <PATH>` **and**
`--signing-key <PATH>`. That is a Durable sink, and a Durable sink refuses
the dev key — which is why the two flags travel together rather than one
of them defaulting.

> **The published `0.3.0` binary differs here.** At tag `v0.3.0` there is
> no `--signing-key` at all: `--audit <PATH>` is accepted alone, and the
> records it writes are **unsigned** — no signing code shipped at that tag,
> so a `0.3.0` audit file carries no signature to attribute and `aegis
> verify` has nothing to check. It also defaults to a temp *file* sink and
> prints that `/tmp/…/audit.jsonl` path for a directory it deletes at exit
> (verified 2026-08-14 against the shipped binary). Signing, the in-memory
> default, and therefore the requirement that the two flags travel
> together, are `main` changes that reach the registry with the next cut.
> Flags on this page are `main`'s; do not read them against an installed
> `0.3.0`.

## `aegis wrap`

Interpose on a child stdio MCP server and **record** every `tools/call`.
Confines only when `--confine` is given, on Linux. Does not evaluate
policy or inspect arguments. See [Wrapping an MCP server](wrap.md).

## `aegis verify`

Reads one Chain file and reports a verdict. Exit codes are API
([ADR-0002](adr/0002-verify-reports-coverage-not-pass-fail.md)):

| Exit | Meaning |
|---|---|
| `0` | `Verified` |
| `1` | `Tampered` — or a usage error |
| `2` | Could not read the record or the trust store |
| `3` | `Indeterminate` |

Two trust states ([ADR-0004](adr/0004-embedded-key-with-labelled-trust.md)):

- **`Verified (unpinned)`** — every signature checks out against the key
  the file itself published. Internal consistency only. An attacker who
  rewrites a whole Session signs it with their own key and the walk comes
  out clean.
- **`Verified (pinned to <fp>)`** — same walk, plus every `open` key was
  one you supplied out of band. That is the provenance claim.

A pinned file that legally rotates across several anchored keys has no
single fingerprint to name, so it prints bare **`Verified (pinned)`** —
still the provenance claim, just over more than one key ([SPEC.md
§8.4](spec.md)).

A quickstart that prints bare `Verified` without saying which is an
overclaim.

## `aegis recheck`

Re-evaluates every recorded outcome against a *new* Policy Set and prints
a would-block diff. **Nothing is executed.** The command is `recheck`,
never `replay` ([ADR-0008](adr/0008-d2-re-evaluation-is-recheck-not-replay.md)).

`--policy` is required. An implicit allow-all set would answer a question
nobody asked.

| Exit | Meaning |
|---|---|
| `0` | Every call unchanged |
| `1` | A call is newly blocked, allowed, or parked — or a usage error |
| `2` | Could not read the policy or the record |
| `3` | Indeterminate — at least one call could not be answered for |

`3` outranks `1`. Recheck does not verify signatures; asking what today's
rules would have done to a file `verify` would call `Tampered` is a
legitimate forensic question.
