# botzr-aegis-audit

Structured audit records for Aegis — wraps the entire enforcement pipeline (POLICY → CAPABILITY → SANDBOX → **AUDIT**).

Always emitted on every exit path: success, policy deny, capability deny, resource-exceeded, trap, and panic.

## Schema

Each tool call produces a two-phase audit trail:

1. **Intent** — recorded before execution begins (`call_id`, `tool_id`, `input_digest`)
2. **Outcome** — recorded when the call completes (`status`, `policy_outcome`, `capability_outcome`, `execution_outcome`, `metrics`)

If the runtime panics during execution, the `CallSession`'s `Drop` guard emits a trap record automatically (fail-closed: every call is accounted for).

## Writer

`AuditWriter` appends JSONL to a file with per-line `fsync` for durability (G3). Schema version is validated before every write.

```rust
let writer = AuditWriter::open("path/to/audit.jsonl")?;
// or for ephemeral testing:
let writer = AuditWriter::open_temp()?;
```

## Dependencies

- `botzr-aegis-core` for shared types (`AuditIntent`, `AuditRecord`, `CallMetrics`)
- `serde` / `serde_json` for JSON serialization
