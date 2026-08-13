# Quickstart

Requires Rust (MSRV 1.86) with the `wasm32-wasip2` target and
[`cargo-component`](https://github.com/bytecodealliance/cargo-component) for
the in-repo WASM fixtures.

```bash
rustup target add wasm32-wasip2
cargo install cargo-component
```

From a clone of [`botzrDev/aegis`](https://github.com/botzrDev/aegis):

```bash
cargo test --workspace
```

## One Model A call

A persistent record file is signed by a key you provision — once, per host.

```bash
cargo run -p botzr-aegis-cli -- keygen --out /tmp/aegis-signing.key
# stdout: public_key <hex> / key_id <hex>

cargo run -p botzr-aegis-cli -- \
  run \
  --component tests/fixtures/echo-tool/echo.wasm \
  --id echo \
  --input 'hello' \
  --audit /tmp/aegis-audit.jsonl \
  --signing-key /tmp/aegis-signing.key
# stdout: hello
```

Then pin the record. `aegis verify` distinguishes **pinned** from
**unpinned** — a bare “Verified” without saying which is an overclaim
([ADR-0004](../adr/0004-embedded-key-with-labelled-trust.md)):

```bash
cargo run -p botzr-aegis-cli -- \
  verify --key <public_key printed by keygen> /tmp/aegis-audit.jsonl
# Verified (pinned to <key_id>)
```

Without `--key` / `--trust-store` the same file reports
`Verified (unpinned)`: internal consistency only, not provenance.

## Adversarial demo

```bash
./scripts/build-fixtures.sh
cargo test -p aegis-adversarial-demo
```

A deliberately malicious `wasip2` guest — write-under-readonly, `..`
traversal, symlink escape, HTTP exfil — all refused through
`Runtime::execute_tool_call`.

## What this is not

This quickstart needs the repository (fixtures, scripts). It does not wrap a
third-party MCP server, and it does not show a policy block of a child
process. [`aegis wrap`](wrap.md) records a child; it does not refuse its
calls.
