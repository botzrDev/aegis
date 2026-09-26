# Introduction

Aegis is a **research instrument** for secure agent tool execution, built in
Rust on [wasmtime](https://wasmtime.dev/). It sits *underneath* agent
frameworks — it is not an orchestrator, not a dashboard, not an LLM layer.

> A reproducible runtime for testing what agent tool isolation actually
> guarantees.

The goal is not to assert that agent tools are safe. It is to make the
isolation claims **falsifiable**: a pipeline you can run, a malicious guest
you can point at it, benchmarks you can reproduce, and a threat model that
names its own gaps.

## Hypothesis

> A **default-deny**, capability-grant-driven, **per-call** WASM sandbox with
> mandatory audit can contain an adversarial or prompt-injected tool call such
> that **no single mistake** — a forgotten host check, a malformed policy, a
> panicking host function — escalates into ambient host authority.

That is a design goal to be measured and attacked, not a guarantee. See the
[threat model](threat-model.md) for what is in scope, what is explicitly
not, and where the honesty boundaries are.

## What this book covers

- How to [install](install.md) and [run](quickstart.md) one Model A call
- The load-bearing [pipeline](pipeline.md) and the two [trust models](trust-models.md)
- The CLI, including [`aegis wrap`](wrap.md) — records every `tools/call`; evaluates policy only with `--policy`; confines the child only with `--confine` (Linux)
- [Policy YAML](policy.md) as it ships today (`tool` / `capability` / `role` matchers only)
- Evidence: [threat model](threat-model.md), [findings](findings.md), [record format](spec.md)

The [quickstart](quickstart.md) shows one policy refusal, from a clone of
`main`, against Aegis's own gateway standing in for any stdio server. The
published `0.3.0` binary cannot wrap. Default wrap is still evidence, not
a firewall: without `--policy` it blocks nothing, and a refusal under
`--policy` is tool identity, not a sandbox. `--confine` (Linux) is a
separate opt-in.

## Current release

Published crates on crates.io are **`0.3.0`** (eight crates). Two things are
newer than that tag and only exist on
[`main`](https://github.com/botzrDev/aegis):

- `botzr-aegis-wrap`, a ninth in-tree crate
- every `aegis` subcommand except `run` — `keygen`, `verify`, `recheck`, and
  `wrap` all landed after `0.3.0` was cut

Build from source for those. See [Install](install.md).

## Building this book

From the repository root:

```bash
cd docs && mdbook serve    # http://localhost:3000
cd docs && mdbook build
```

Both write to `target/book/`. That is `build-dir` in `book.toml`, not a
default: the book's `src` is `docs/` itself, so an output directory inside
`docs/` would be copied back into the next build as a nested duplicate.

mdBook 0.5.4 is what CI pins, and the same pinned build publishes this book
to <https://botzrdev.github.io/aegis/> on every push to `main`.
