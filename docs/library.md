# Library mode

`botzr-aegis-runtime` is the library-mode entry point. The CLI and the MCP
gateway both go through `RuntimeBuilder`, so policy and audit wiring lives
in one place.

```rust
use std::path::Path;
use botzr_aegis_runtime::{BuildError, RuntimeBuilder};

fn main() -> Result<(), BuildError> {
    let mut rt = RuntimeBuilder::new()
        .policy_file(Path::new("policy.yaml"))?
        .audit_file(Path::new("/tmp/audit.jsonl"), Path::new("/tmp/aegis-signing.key"))?
        .build()?;
    Ok(())
}
```

Each builder step returns `Result`, so the chain needs a `Result`-returning
scope — the `?`s above do not work at the top level of a snippet.

`audit_file` takes the signing key's path and it is **not** optional. A
persistent record file is one somebody will later pin a
`Verified (pinned)` label to, so it is never signed with the dev seed
compiled into `botzr-aegis-audit`. Leaving `audit_file` unset keeps the
temp sink, which *is* dev-key-signed and is not a production record.

## Registration

`register_tool` associates a tool's manifest with its executable
**atomically**. Kind and executable must agree: `ToolKind::Wasm` with a
WASM component, `ToolKind::Host` with a `HostHandler`. Duplicate ids are
an error, not a silent replace.

## Execution

- **Model A:** `execute_tool_call(tool_id, input)` — the caller does not
  supply a digest. The pipeline hashes the raw input bytes itself.
- **Model B:** `execute_host_call(HostCallRequest { … })` — the handler
  receives a `HostEffectContext` built from the minted grant. The sandbox
  is not invoked.

`execute_host_call_with` is a research escape hatch: the runtime hands
the closure a `&CapabilityGrant` and checks nothing before it runs. It is
not a supported way to ship an effect.

Full API notes:
[`crates/botzr-aegis-runtime/README.md`](https://github.com/botzrDev/aegis/blob/main/crates/botzr-aegis-runtime/README.md).

## Standalone sandbox

`botzr-aegis-sandbox` + `botzr-aegis-core` can be taken without the
orchestrator. Wiring guide:
[`INTEGRATION.md`](https://github.com/botzrDev/aegis/blob/main/crates/botzr-aegis-sandbox/INTEGRATION.md).
Runnable proof: `examples/sandbox-consumer/`.
