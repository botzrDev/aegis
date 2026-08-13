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

- How to [install](guide/install.md) and [run](guide/quickstart.md) one Model A call
- The load-bearing [pipeline](guide/pipeline.md) and the two [trust models](guide/trust-models.md)
- The CLI, including [`aegis wrap`](guide/wrap.md) — which **records and does not confine**
- [Policy YAML](guide/policy.md) as it ships today (`tool` / `capability` / `role` matchers only)
- Evidence: [threat model](threat-model.md), [findings](findings.md), [record format](guide/spec.md)

It does **not** document a 15-minute path from wrapping a third-party MCP
server to a policy-blocked call. That is the D4 launch README, and it waits
until wrap actually evaluates policy. Today wrap is evidence, not a firewall.

## Current release

Published crates on crates.io are **`0.3.0`** (eight crates). Two things are
newer than that tag and only exist on
[`main`](https://github.com/botzrDev/aegis):

- `botzr-aegis-wrap`, a ninth in-tree crate
- every `aegis` subcommand except `run` — `keygen`, `verify`, `recheck`, and
  `wrap` all landed after `0.3.0` was cut

Build from source for those. See [Install](guide/install.md).

## Building this book

From the repository root:

```bash
cd docs && mdbook serve    # http://localhost:3000
cd docs && mdbook build --dest-dir ../target/book
```

mdBook 0.5.4 is what CI pins. GitHub Pages deploy is a maintainer step;
until it is live, this tree is the hub.
