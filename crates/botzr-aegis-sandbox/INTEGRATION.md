# Integrating `botzr-aegis-sandbox`

This crate is a **standalone dependency**. An external host can take it (plus
`botzr-aegis-core` for the grant types) to get sandboxed WASM execution
*without* pulling the Aegis orchestrator — no `botzr-aegis-runtime`, `-policy`,
`-capability`, or `-audit`. If you already own a policy/trust model and can mint
your own capability grants, this is the whole surface you need.

A runnable proof lives at [`examples/sandbox-consumer/`](../../examples/sandbox-consumer)
— it depends on exactly `botzr-aegis-sandbox` + `botzr-aegis-core` and nothing
else (`cargo tree -p sandbox-consumer` confirms).

## 1. Add the dependency

`botzr-aegis-sandbox` re-exports the sandbox API; `botzr-aegis-core` provides the
grant types (`CapabilityGrant`, `FsGrant`, `NetGrant`, `ToolId`). Take both.

**crates.io** (published under the `botzr-aegis-*` namespace):

```toml
[dependencies]
botzr-aegis-sandbox = "0.3.0"
botzr-aegis-core = "0.3.0"
```

**git** (track `main` before/without a crates.io release):

```toml
[dependencies]
botzr-aegis-sandbox = { git = "https://github.com/botzrDev/aegis" }
botzr-aegis-core = { git = "https://github.com/botzrDev/aegis" }
```

**path** (vendored / in-workspace):

```toml
botzr-aegis-sandbox = { path = "…/aegis/crates/botzr-aegis-sandbox" }
botzr-aegis-core = { path = "…/aegis/crates/botzr-aegis-core" }
```

> The workspace pins wasmtime in `[workspace.dependencies]`; the whole crate
> moves as one wasmtime major (currently **36.x**, `WASMTIME_PIN_MAJOR`). A guest
> must be a `wasip2` component.

## 2. Minimal call sequence

```rust
use botzr_aegis_core::{CapabilityGrant, FsGrant, ToolId, DEFAULT_MAX_OUTPUT_BYTES};
use botzr_aegis_sandbox::SandboxEngine;

// 1. Build the engine once (it compiles components; reuse it across calls).
let engine = SandboxEngine::new()?;

// 2. Compile + link the component once.
let prepared = engine.prepare(component_bytes)?;

// 3. Mint a grant yourself — no CapabilityResolver required. The store is
//    configured *from this grant*: read preopens mount at /ro0, /ro1, …;
//    write preopens at /rw0, …; net is default-deny; memory + wall are capped.
let grant = CapabilityGrant {
    grant_id: "my-grant".to_string(),
    tool_id: ToolId::new("path-detector"),
    fs: Some(FsGrant {
        read_paths: vec!["/abs/path/to/scan/root".to_string()],
        write_paths: vec![],            // empty ⇒ writes denied, not silent
    }),
    net: None,                          // None ⇒ no network
    max_memory_bytes: 16 * 1024 * 1024,
    max_wall_ms: 1_000,
    max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES, // per-call return cap; default 1 MiB
};

// 4. Execute in a fresh, grant-scoped Store. Never share a Store across calls.
let run = engine.execute(&prepared, &grant, br#"{"scan_root":"fixtures"}"#);
match run.output {
    Ok(bytes) => { /* guest returned bytes */ }
    Err(err)  => { /* classified trap / resource-exceeded — audit-ready */ }
}
// run.metrics carries observed wall_ms + peak_memory_bytes.
```

> **`max_output_bytes` is host-side.** A hand-building consumer **must** set it
> (default 1 MiB). Unlike memory + wall, the sandbox does **not** enforce this
> cap — guest output is host-side bytes, so `engine.execute` returns them
> unchecked. The Aegis runtime enforces it after a successful run
> (`ResourceExceeded { kind: "output" }`); a standalone consumer that bypasses
> the runtime must apply the same ceiling to `run.output` itself.

- `SandboxEngine::new` / `prepare` / `execute` — the WIT `tool` world path
  (Model A guests that export `run`).
- `prepare_fixture` / `execute_fixture` — raw component fixtures with no WIT
  exports (used by the deny-suite / resource-metering tests). Behind the
  **`test-utils`** feature, off by default: a production consumer has no business
  instantiating a component that never declared the WIT `tool` world.
- Failing exit paths classify into
  [`SandboxError`](https://docs.rs/botzr-aegis-sandbox): `Trap`,
  `ResourceExceeded { kind }`, `ComponentLoad`, `StoreConfig`, … — each already
  maps to a schema-versioned audit outcome via `to_execution_outcome()`, so a
  host that keeps an audit log can record every exit (including deny/trap).

## 3. Model A vs Model B — read this before trusting isolation

- **Model A (WASM guest logic)** runs *inside* wasmtime and gets true isolation:
  cap-std preopens can't be escaped by `..`, symlinks, or TOCTOU; network is
  off unless registered; memory and wall-clock are capped per call.
- **Model B (host functions, `aegis:host/*`)** runs its effect in **host Rust**.
  The sandbox gives Model B **zero** isolation — each host function must enforce
  the grant *before* the effect. If your consumer adds host functions, you are
  responsible for the capability check on the host side.

See the [threat model](../../docs/threat-model.md) for the full Model A vs
Model B trust boundary. Docs and marketing must be blunt that Model B is not
full sandbox isolation.

## 4. Dependency direction (locked — OQ-3 / D12)

**Consumers depend on Aegis; Aegis never depends on a consumer.** The edge is
one-way: `uveddi → botzr-aegis-sandbox`. Do not add a path/git dependency from
any Aegis crate back to a consumer, and never copy consumer source into this
repo. (uveddi is CC-BY-NC-SA; Aegis is MIT — the MIT crate must stay free of the
NC-SA code.)

## 5. Validation evidence

- **Stage 2 detector scorecard** — [`tests/stage2-demo/`](../../tests/stage2-demo)
  drives the real wasip2 path-detector guest through the full
  `POLICY → CAPABILITY → SANDBOX → AUDIT` pipeline and asserts native ↔ wasm
  equivalence (design doc D10), plus guest-level deny and wall-clock cap. That is
  the gate this integration story is contingent on; it is green on `main`.
- **Stage 3 consumer proof** — [`examples/sandbox-consumer/`](../../examples/sandbox-consumer)
  runs the same guest through `SandboxEngine` alone, proving the sandbox is
  consumable without the orchestrator.
