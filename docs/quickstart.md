# Quickstart

Requires Rust (MSRV 1.86) with the `wasm32-wasip2` target:

```bash
rustup target add wasm32-wasip2
```

The WASM fixtures used below are committed, so you do not need
[`cargo-component`](https://github.com/bytecodealliance/cargo-component) to
run the pipeline. You need it only to *rebuild* fixtures, which the
[adversarial demo](#adversarial-demo) does:

```bash
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
([ADR-0004](adr/0004-embedded-key-with-labelled-trust.md)):

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

## Wrap a child, and refuse one call

`aegis wrap` interposes on an existing stdio MCP session. By default it relays
everything and records every `tools/call`; **`--policy <YAML>` is the opt-in
under which a denied call is refused before it reaches the child**
([ADR-0015](adr/0015-wrap-may-synthesize-a-refusal.md)).

The child below is Aegis's own [MCP gateway](mcp.md) standing in for any stdio
MCP server — substitute yours after the `--`. Both halves need a clone of
`main`: the published `0.3.0` binary has neither `wrap` nor `keygen`
([Install](install.md)).

```bash
cargo build -p botzr-aegis-cli -p botzr-aegis-mcp --release

cat > /tmp/deny-echo.yaml <<'EOF'
version: 1
default: allow
rules:
  - id: deny-echo
    action: deny
    tool: echo
    reason: "quickstart"
EOF

./target/release/aegis keygen --out /tmp/aegis-signing.key
# stdout: public_key <hex> / key_id <hex>

printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}' \
  | ./target/release/aegis wrap \
      --audit /tmp/wrap-audit.aarl \
      --signing-key /tmp/aegis-signing.key \
      --policy /tmp/deny-echo.yaml \
      -- ./target/release/botzr-aegis-mcp \
           --audit /tmp/gateway-audit.aarl \
           --signing-key /tmp/aegis-signing.key
# client stdout is the refusal, not the echo body:
# {"error":{"code":-32042,"data":{"aegis":{"code":"POLICY_DENIED","layer":"wrap"}},
#  "message":"aegis wrap refused this tools/call"},"id":1,"jsonrpc":"2.0"}

./target/release/aegis verify --key <public_key printed by keygen> /tmp/wrap-audit.aarl
# Verified (pinned to <key_id>)
```

Run it again without `--policy` and the same pipe prints the `echo` result:
**default wrap blocks nothing**, and that is the only difference between the two
invocations on the client stream.

**Two record files, on purpose.** Wrap records the call it *carried*, the gateway
the call it *executed*; one path for both would interleave two Chains and neither
would verify. After the run above, `/tmp/gateway-audit.aarl` holds no call at all
— the refused frame never reached the child — while `/tmp/wrap-audit.aarl` holds
an intent and an outcome naming `deny-echo` as the matched rule, with the **real**
Policy Set hash rather than the pass-through stand-in a relayed call carries.
Records carry the `.aarl` extension
([ADR-0014](adr/0014-the-record-file-extension-is-aarl.md)).

Drop `--key` here and the same walk reports `Verified (unpinned)` — the same
distinction as in the Model A beat above, and for the same reason.

## What this is not

This quickstart needs the repository (fixtures, scripts, and — for the wrap beat
— a source build, because `wrap` and `keygen` are not in the published `0.3.0`
binary). What it shows is a refusal by **tool identity**: `--policy` never looks at
`params.arguments`, mints no capability, and puts nothing inside wasmtime, so a
wrapped child is closer to Model B than Model A and weaker than either unless
`--confine` (Linux) is also given. A chain that abuses a *legitimate* tool on the
same server is not blocked here. [`aegis wrap`](wrap.md) lists the rest before you
describe it as a sandbox, a firewall, or a guard.
