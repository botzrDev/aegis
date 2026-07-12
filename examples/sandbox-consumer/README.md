# sandbox-consumer (AEG-18 · Stage 3)

Proof that **`botzr-aegis-sandbox` is a standalone dependency**. This crate wires
the wasmtime sandbox using *only* `botzr-aegis-sandbox` + `botzr-aegis-core` —
nothing from the Aegis orchestrator (runtime / policy / capability / audit). It
is the shape an external host takes when it wants sandboxed WASM execution but
already owns its own policy/trust model and mints capability grants itself.

```bash
# Happy path: scan the fixture tree and print findings + metrics.
cargo run -p sandbox-consumer

# Consumer proof: standalone happy path + read-only deny smoke.
cargo test -p sandbox-consumer

# Confirm the orchestrator stack is absent from the dependency tree.
cargo tree -p sandbox-consumer
```

What it demonstrates (`src/lib.rs`):

1. `SandboxEngine::new` — build the engine once.
2. Hand-build a `CapabilityGrant` from core types (no `CapabilityResolver`).
3. `prepare` the embedded wasip2 path-detector guest, then `execute` it in a
   fresh, grant-scoped `Store`.
4. A read-only grant denies a guest write attempt cleanly (never a silent
   success).

See [`../../crates/botzr-aegis-sandbox/INTEGRATION.md`](../../crates/botzr-aegis-sandbox/INTEGRATION.md)
for the full wiring guide and the Model A vs Model B trust boundary, and
[`DECISIONS.md`](DECISIONS.md) for the D20 extract-shape lock.
