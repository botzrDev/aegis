# Install

## From crates.io (`0.3.0`)

```sh
cargo install botzr-aegis-cli
```

**The published `0.3.0` binary has one subcommand: `run`** (plus the
bare-invocation ready banner). `keygen`, `verify`, `recheck`, and `wrap`
all landed after the tag was cut and are only on `main`. If you want the
evidence verbs, [build from source](#from-source).

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
([ADR-0011](../adr/0011-dual-apache-2.0-or-mit-supersedes-oq1.md)).

## From source

```bash
git clone https://github.com/botzrDev/aegis
cd aegis
rustup target add wasm32-wasip2
cargo build -p botzr-aegis-cli
```

`main` is where `keygen`, `verify`, `recheck`, and `wrap` live. MSRV is 1.86.

## MCP gateway

```sh
cargo install botzr-aegis-mcp
```

This binary serves **Aegis's own catalog** (`echo` / `exfil`) over stdio.
It is not an interposer in front of someone else's server. For that, see
[`aegis wrap`](wrap.md) (from source, until the next crates.io cut).
