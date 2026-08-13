# Aegis documentation

This folder is the source of the Aegis documentation book. Navigation lives in
[`SUMMARY.md`](SUMMARY.md); the files themselves are flat, so a page's location
tells you nothing and the table of contents tells you everything.

```bash
cd docs && mdbook serve    # http://localhost:3000
```

Start at [Introduction](intro.md).

## Getting started

| Page | What it is |
|---|---|
| [Install](install.md) | crates.io and from-source, and which subcommands each actually has |
| [Quickstart](quickstart.md) | One Model A call through the pipeline, then verify the record |

## Concepts

| Page | What it is |
|---|---|
| [The pipeline](pipeline.md) | `POLICY → CAPABILITY → SANDBOX → AUDIT`, and what each station does not do |
| [Trust models](trust-models.md) | Model A (WASM, strong isolation) vs Model B (host function, none) |
| [Terminology](terminology.md) | Words the project uses on purpose, and the ones it avoids |

## Guides

| Page | What it is |
|---|---|
| [CLI](cli.md) | Every subcommand, flag, and exit code |
| [Wrapping an MCP server](wrap.md) | `aegis wrap` — records; **does not confine** |
| [Policy YAML](policy.md) | The language as it ships: `tool` / `capability` / `role` matchers only |
| [Library mode](library.md) | `RuntimeBuilder` for embedding the pipeline |
| [MCP gateway](mcp.md) | Aegis's own tool catalog over stdio — not an interposer |

## Evidence

| Page | What it is |
|---|---|
| [Threat model](threat-model.md) | Scope, trust boundaries, named non-goals, residual risks |
| [Findings](findings.md) | What isolation is measured to guarantee — and not |
| [Record format](spec.md) | The Agent Action Record wire contract (includes `spec/SPEC.md`) |
| [Benchmarks](benchmarks.md) | Published numbers on cited hardware |
| [Demos](demos/) | Watchable reproductions |

## Reference

| Page | What it is |
|---|---|
| [Crate map](crates.md) | The nine crates and what is published |
| [Architecture decisions](adr.md) | Index of the eleven ADRs in [`adr/`](adr/) |
| [Audit schema v1](audit-schema.md) | Superseded by schema v2 — kept as the record |
| [Security](security.md) | Disclosure policy (includes the root `SECURITY.md`) |

## Not in the book

Maintainer procedures, deliberately left out of the reader-facing table of
contents:

- [`release-checklist.md`](release-checklist.md) — publish order and gates
- [`coverage-ratchet.md`](coverage-ratchet.md) — how the coverage floor moves
