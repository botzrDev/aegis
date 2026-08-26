# botzr-aegis-runtime

Aegis runtime orchestrator — wires the full enforcement pipeline in load-bearing order:

```
POLICY → CAPABILITY → SANDBOX → AUDIT
```

This is the library-mode entry point for the Aegis research runtime. It owns one
instance of each pipeline station, one registry of tools, and two execution
entry points: `execute_tool_call` (Model A, WASM) and `execute_host_call`
(Model B, host effect).

## Construction

`RuntimeBuilder` is the shared construction facade — the CLI and the MCP gateway
both go through it, so policy/audit wiring lives in exactly one place. Every
option is optional; unset means the `Runtime::default()` behaviour (`allow_all`
policy, in-memory Volatile audit sink that retains nothing).

```rust
use std::path::Path;
use botzr_aegis_runtime::RuntimeBuilder;

let mut rt = RuntimeBuilder::new()
    .policy_file(Path::new("policy.yaml"))?   // or .policy_yaml(yaml_str)?
    .audit_file(Path::new("/tmp/audit.jsonl"), Path::new("/tmp/aegis-signing.key"))?
    .build()?;                                 // -> Result<Runtime, BuildError>
```

Policy YAML is parsed once, up front: a bad document fails at the builder call
that supplied it, not on the first tool call.

`audit_file` takes the signing key's path and it is **not** optional: a
persistent record file is one somebody will later pin a `Verified (pinned)` label
to, so it is never signed with the dev seed compiled into `botzr-aegis-audit`.
Generate the key once with `aegis keygen --out /tmp/aegis-signing.key`. A key
that is missing, malformed, or readable beyond its owner fails the build
(`BuildError::LoadSigningKey`) rather than falling back to anything. Leaving
`audit_file` unset keeps the default in-memory Volatile sink, which *is*
dev-key-signed, retains nothing past the process, and is not a production
record.

## Registration

`register_tool` is **the** registration path: it associates a tool's manifest
(authority) with its executable artifact **atomically**.

```rust
pub fn register_tool(&mut self, manifest: ToolManifest, executable: ToolExecutable)
    -> Result<(), RegisterError>;

pub enum ToolExecutable {
    WasmComponent(Vec<u8>),                                // Model A, WIT `run` export
    #[cfg(feature = "test-utils")]                         // raw WASM, no WIT world
    WasmFixture { bytes: Vec<u8>, entry_export: String },
    HostHandler(HostHandler),                              // Model B host effect
}

pub type HostHandler =
    Box<dyn Fn(&HostEffectContext<'_>, &[u8]) -> Result<Vec<u8>, HostEffectError> + Send + Sync>;
```

Every check runs **before** any mutation — duplicate tool id, manifest
`ToolKind` vs. `ToolExecutable` variant, SHA-256 pin (G10), sandbox prepare — so
a failed registration leaves the runtime exactly as it was. There is no way
through the public API to grant a manifest without an executable, or to install
an executable without authority.

Kind and executable must agree: `ToolKind::Wasm` accepts `WasmComponent` (or,
under the `test-utils` feature, `WasmFixture`); `ToolKind::Host` accepts
`HostHandler`. Anything else is `RegisterError::KindMismatch`. A tool id
registers exactly once — re-registration is `RegisterError::DuplicateTool`, not
a silent replace.

Three thin wrappers cover the common cases:

| Wrapper | Executable it builds |
|---|---|
| `register(manifest, component_bytes)` | `WasmComponent` |
| `register_fixture(manifest, component_bytes, entry_export)` *(`test-utils` only)* | `WasmFixture` |
| `register_from_manifest(manifest)` | `WasmComponent`, bytes read from `base_dir.join(component_path)` |

### The `test-utils` feature

`WasmFixture` / `register_fixture` are raw-component fixture APIs for the
deny-suite and resource-cap tests: they instantiate a component that never
declared the WIT `tool` world. They are **off by default** and only exist when
the `test-utils` feature is enabled (which also turns on
`botzr-aegis-sandbox/test-utils`). A default-features build has no fixture
registration path at all.

```rust
use botzr_aegis_capability::{ToolInfo, ToolKind, ToolManifest};
use botzr_aegis_core::ToolId;
use botzr_aegis_runtime::sha256_hex;

let wasm_bytes = std::fs::read("tests/fixtures/echo-tool/echo.wasm")?;
let manifest = ToolManifest::new(
    ToolInfo {
        id: ToolId::new("echo"),
        version: "0.1.0".into(),
        kind: ToolKind::Wasm,
    },
    "tests/fixtures/echo-tool",
)
.with_sha256(sha256_hex(&wasm_bytes));

rt.register(manifest, wasm_bytes)?;
```

`capabilities()` returns a **read-only** `&CapabilityResolver` for exactly that
reason: writing a manifest into the resolver without its executable is the
split-authority state `register_tool` exists to prevent. Introspection only —
mutation is deliberately not exposed.

## Execution — Model A (WASM)

```rust
pub fn execute_tool_call(&self, req: ToolCallRequest<'_>) -> Result<Vec<u8>, AegisError>;
pub async fn execute_tool_call_async(&self, req: ToolCallRequest<'_>) -> Result<Vec<u8>, AegisError>;
```

```rust
let tool = ToolId::new("echo");
let output = rt.execute_tool_call(ToolCallRequest::new(
    tool.clone(),
    b"hello-aegis",
    PolicyRequest::for_tool(&tool),
))?;
```

One request struct, mirroring `HostCallRequest`. The caller names the Decision
Axes it asserts, so a rule gated on `role` or `capability` reaches a WASM call
exactly as it reaches a host one; `PolicyRequest::for_tool` asserts tool
identity and nothing else. **The caller does not supply a digest.** The pipeline computes
`RequestDigest::of_request_bytes(input)` internally from the exact — raw,
unreformatted — bytes the execution step will see, and that is what lands in the
audit record. No public API accepts a caller-supplied `request_digest`, so audit
cannot be made to record a digest that does not match the payload.

A Model B host tool reaching this entry point fails closed — use
`execute_host_call`.

**Pick the entry that matches your context.** The sync entry blocks on the
sandbox engine's tokio runtime, and tokio forbids blocking from inside another
runtime. Called from an async context it returns
`AegisError::NestedRuntime { entry }` rather than panicking, and it does so
*before* the pipeline opens a Call Session — a nested runtime is an embedder
integration bug, not a call that reached a station, so **no audit record is
written for it**. Inside a runtime, use `execute_tool_call_async`: same
stations, same short-circuits, same record.

Two things that entry is not:

- **Not non-blocking.** A guest gets an epoch *trap* deadline, not an
  async-yield one, so it runs to completion or to `max_wall_ms` inside a single
  poll; audit's append+fsync is synchronous on the same thread. On a
  current-thread runtime that stalls the whole reactor for the call's duration.
- **Not the only thing the guard catches.** The refusal tests
  `Handle::try_current()`, which is broader than tokio's own rule: a
  `spawn_blocking` thread carries a runtime handle but is not entered as a
  driver, so `block_on` would succeed there and the sync entry still refuses.
  From a blocking thread use
  `Handle::current().block_on(rt.execute_tool_call_async(req))`.

## Execution — Model B (host effect)

```rust
pub fn execute_host_call(&self, req: HostCallRequest<'_>) -> Result<Vec<u8>, AegisError>;
pub async fn execute_host_call_async(&self, req: HostCallRequest<'_>) -> Result<Vec<u8>, AegisError>;

pub struct HostCallRequest<'a> {
    pub tool_id: ToolId,
    pub input: &'a [u8],
    pub policy: PolicyRequest<'a>,
}
```

```rust
use botzr_aegis_capability::{ToolInfo, ToolKind, ToolManifest};
use botzr_aegis_core::ToolId;
use botzr_aegis_policy::PolicyRequest;
use botzr_aegis_runtime::{HostCallRequest, LogLevel, ToolExecutable};

let tool = ToolId::new("append_node");
let manifest = ToolManifest::new(
    ToolInfo {
        id: tool.clone(),
        version: "0.1.0".into(),
        kind: ToolKind::Host,
    },
    std::env::temp_dir(),
);

rt.register_tool(
    manifest,
    ToolExecutable::HostHandler(Box::new(|ctx, input| {
        // The context checks the grant before the effect; the handler cannot skip it.
        ctx.log_emit(LogLevel::Info, "appending")?;
        Ok(input.to_vec())
    })),
)?;

let output = rt.execute_host_call(HostCallRequest::new(
    tool.clone(),
    b"{}",
    PolicyRequest::for_tool(&tool),
))?;
```

The handler is the one stored at registration time; it receives a
`HostEffectContext` built from the minted grant, never a raw grant. Sandbox is
not invoked (`botzr_aegis_core::HOST_PIPELINE_STAGES` is
`policy → capability → audit`). A WASM
tool reaching this entry point fails closed, as does an unregistered tool.
`HostCallRequest` has no `request_digest` field for the same reason as Model A.
The sync/async split is the same as Model A's, and for the same reason: Model B
runs no sandbox station, but it shares the one pipeline driver, which is async
because Model A's execution step is.

## Model B host effects

Host tools (Model B) run their effect in host Rust, so the sandbox protects
nothing. Use `HostEffectContext` — it checks the grant before every effect it
owns (`http_get`, `open_read`, `open_write_append`, `log_emit`) and reaches the
filesystem only through cap-std `Dir` handles opened from the grant.

`Runtime::execute_host_call_with` takes a caller-supplied raw closure instead of
the registered handler and is a **research escape hatch**: the runtime hands the
closure a `&CapabilityGrant`, checks nothing before it runs, and applies only the
output cap after it returns — so the closure author owns enforcement. It is not
a supported way to ship an effect. It has no async twin — like the other sync
entries it returns `AegisError::NestedRuntime` from inside a runtime, and an
async research caller should register the handler and use
`execute_host_call_async`. Neither path is sandbox isolation — see
[`docs/threat-model.md`](../../docs/threat-model.md) §3.

## Guarantees

- **Short-circuit:** a policy denial never reaches capability or sandbox
- **Ceiling folding:** policy limits are folded into grants but can never raise them
- **Audit on every exit:** success, denial, trap, and panic all produce records — a `NestedRuntime` refusal is the one non-exit, and produces none because no call ran
- **Runtime-derived digest:** the audited `request_digest` is computed from the call's own raw input bytes; callers cannot supply one
- **Atomic registration:** manifest and executable are written together, after all checks — a failed `register_tool` mutates nothing
- **SHA-256 pinning:** registration rejects component bytes that don't match the manifest digest (G10)

## Dependencies

All five runtime crates: `core`, `policy`, `capability`, `sandbox`, `audit`.
