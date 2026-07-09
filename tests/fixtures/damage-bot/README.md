# damage-bot — adversarial wasip2 guest (AEG-22)

Sacrificial guest for the Aegis credibility demo. Each `run` input selects one
attack mode; the enforcement pipeline must refuse it and emit a two-phase audit
record.

## Build

Requires `cargo-component` and the `wasm32-wasip2` target:

```bash
rustup target add wasm32-wasip2
cargo install cargo-component   # if not already installed

cd tests/fixtures/damage-bot
cargo component build --release --target wasm32-wasip2
cp ../../../target/wasm32-wasip2/release/damage_bot.wasm ./damage-bot.wasm
```

Or from the repo root:

```bash
./scripts/build-fixtures.sh
```

## Attack modes

| `attack` value      | What it tries                                      |
|---------------------|----------------------------------------------------|
| `write_readonly`    | Create `/ro0/pwned.txt` under a read-only grant    |
| `dotdot_escape`     | Read `/ro0/../../../etc/passwd`                      |
| `symlink_escape`    | Read `/ro0/escape` (symlink to outside preopen)    |
| `http_exfil`        | `http.get` to a host outside the net grant         |
| `http_allowed`      | `http.get` to an allow-listed host (v1 stub)       |

Input shape: `{"attack":"<mode>"}`.
