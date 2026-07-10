# botzr-aegis-runtime

Aegis runtime orchestrator — wires the full enforcement pipeline in load-bearing order:

```
POLICY → CAPABILITY → SANDBOX → AUDIT
```

This is the library-mode entry point for the Aegis research runtime. It owns one instance of each pipeline station and exposes a single `execute_tool_call(tool_id, input_digest, input)` method.

## Usage

```rust
use botzr_aegis_runtime::Runtime;

let rt = Runtime::new();
// Policy and audit are configurable:
let rt = Runtime::new()
    .with_policy(PolicyEngine::from_yaml(yaml)?)
    .with_audit(AuditWriter::open("/tmp/audit.jsonl")?::w);

// Register a tool:
rt.register(manifest, wasm_bytes)?;

// Execute a call:
let output = rt.execute_tool_call(tool_id, sha256_hex(input), input)?;
```

## Guarantees

- **Short-circuit:** a policy denial never reaches capability or sandbox
- **Ceiling folding:** policy limits are folded into grants but can never raise them
- **Audit on every exit:** success, denial, trap, and panic all produce records
- **SHA-256 pinning:** registration rejects component bytes that don't match the manifest digest (G10)

## Dependencies

All five runtime crates: `core`, `policy`, `capability`, `sandbox`, `audit`.
