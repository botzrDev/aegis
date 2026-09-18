# Install

## From crates.io (`0.3.0`)

```sh
cargo install botzr-aegis-cli
```

**The published `0.3.0` binary has one subcommand: `run`** (plus the
bare-invocation ready banner). `keygen`, `verify`, `recheck`, and `wrap`
all landed after the tag was cut and are only on `main`. If you want the
evidence verbs, [build from source](#from-source).

`0.3.0` also predates the current record format. It writes
`schema_version: 1`: unsigned lines with no `seq` / `prev_hash` chain. The
hash-chained, ed25519-signed schema v2 this book describes — and the
`aegis verify` that walks it — are `main` only, and arrive together in the
next cut.

Library consumers:

```toml
[dependencies]
botzr-aegis-runtime = "0.3.0"
```

Standalone sandbox (no orchestrator):

```toml
[dependencies]
botzr-aegis-sandbox = "0.3.0"
botzr-aegis-core = "0.3.0"
```

See [`INTEGRATION.md`](https://github.com/botzrDev/aegis/blob/main/crates/botzr-aegis-sandbox/INTEGRATION.md).

The `0.3.0` tarballs on crates.io are **MIT as published**. The repository
and every release cut after `0.3.0` are dual `Apache-2.0 OR MIT`
([ADR-0011](adr/0011-dual-apache-2.0-or-mit-supersedes-oq1.md)).

## From source

```bash
git clone https://github.com/botzrDev/aegis
cd aegis
cargo build -p botzr-aegis-cli
```

`main` is where `keygen`, `verify`, `recheck`, and `wrap` live. MSRV is 1.86.

**This is the only way to reach `aegis wrap --policy`** — the opt-in under which
wrap refuses a denied `tools/call` instead of relaying it
([ADR-0015](adr/0015-wrap-may-synthesize-a-refusal.md)). `cargo install
botzr-aegis-cli` gets you the `0.3.0` `run`-only binary above and is not a
substitute; the wrap walk is in the [quickstart](quickstart.md#wrap-a-child-and-refuse-one-call).
Two in-tree crates back it — `botzr-aegis-wrap` and `botzr-aegis-confine` — and
neither is on the registry at `0.3.0`; both first appear on the next cut, which
publishes ten crates.

The binary itself needs no WASM target — it depends on no fixture crate. Add
one before running the test suite or the [quickstart](quickstart.md), which do
build `wasm32-wasip2` guests:

```bash
rustup target add wasm32-wasip2
```

## What ships, per platform

Everything below is on `main`. **Native OS confinement is Linux-only**
([ADR-0010](adr/0010-macos-confinement-fast-follows-m4.md)), which is why that
qualifier travels beside any containment claim rather than sitting in a footnote.

| Layer | Linux | macOS |
|---|---|---|
| Policy evaluation — tool id, role and capability axes | yes | yes |
| Capability grants — default-deny, minted per call | yes | yes |
| Model A cell — a per-call wasmtime `Store` built from the grant | yes | yes |
| Signed, hash-chained record (`schema_version: 2`) on every exit path | yes | yes |
| [`aegis verify`](cli.md#aegis-verify) — pinned or unpinned | yes | yes |
| [`aegis recheck`](cli.md#aegis-recheck) — executes nothing | yes | yes |
| [`aegis wrap --policy`](wrap.md#enforcing-a-policy) — refuses a `tools/call` | yes | yes |
| [`aegis wrap --confine`](wrap.md) — Landlock fs + a seccomp network deny-list | yes | **no** |

Not shipped on either platform, and deliberately absent from that table: matching
a call's `arguments` (AILAB-626, canceled — a rule matches tool identity and
nothing else), parking a call for human approval (AILAB-629), pinning a tool
schema by hash (AILAB-627), and Landlock `AccessNet` (AILAB-810). macOS Seatbelt
confinement is AILAB-630.

## MCP gateway

```sh
cargo install botzr-aegis-mcp
```

This binary serves **Aegis's own catalog** (`echo` / `exfil`) over stdio.
It is not an interposer in front of someone else's server. For that, see
[`aegis wrap`](wrap.md) (from source, until the next crates.io cut) — the
[quickstart](quickstart.md#wrap-a-child-and-refuse-one-call) wraps this gateway as
a stand-in for any stdio MCP server, with a separate record file for each end.

The published `0.3.0` gateway takes `--policy` and `--audit` only. It has
no `--signing-key`, so the signed-record workflow in the
[MCP gateway chapter](mcp.md#run) needs a source build — that chapter's
[What `0.3.0` does instead](mcp.md#what-030-does-instead) spells out the
difference.
