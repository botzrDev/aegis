# DamageBot demo (AEG-22)

Reproducible credibility artifact: a sacrificial adversarial wasip2 guest driven
through the full Aegis enforcement pipeline.

## Prerequisites

- Rust 1.80+ with `wasm32-wasip2` target
- [`cargo-component`](https://github.com/bytecodealliance/cargo-component)

```bash
rustup target add wasm32-wasip2
cargo install cargo-component
```

## 1. Build the adversarial guest

```bash
./scripts/build-fixtures.sh
```

This compiles `tests/fixtures/damage-bot` and copies `damage-bot.wasm` beside
the source.

## 2. Run the adversarial acceptance tests

```bash
cargo test -p aegis-adversarial-demo
```

Each test calls `Runtime::execute_tool_call` with a JSON attack selector and
asserts:

| Test | Attack | Expected refusal |
|------|--------|------------------|
| `guest_write_under_readonly_grant_is_refused` | `write_readonly` | WASI write denied on `/ro0` |
| `guest_dotdot_escape_is_refused` | `dotdot_escape` | cap-std blocks `..` traversal |
| `guest_symlink_escape_is_refused` | `symlink_escape` | cap-std blocks symlink escape |
| `guest_http_without_net_grant_is_refused` | `http_exfil` | Model B host: no net grant |
| `guest_http_to_disallowed_host_is_refused` | `http_exfil` | Model B host: host not in grant |
| `guest_http_to_allowed_host_passes_grant_then_stubs` | `http_allowed` | Grant passes; v1 stub denies effect |

## 3. Full workspace gate

```bash
cargo test --workspace
```

## Responsible disclosure framing

DamageBot is a **deliberately malicious** guest used only to prove containment.
Do not point it at production data or live networks. Payloads are in-repo and
documented; findings are tracked in the [threat model](../../docs/threat-model.md)
(AEG-17).
