# botzr-aegis-audit

Structured audit records for Aegis — wraps the entire enforcement pipeline (POLICY → CAPABILITY → SANDBOX → **AUDIT**).

Always emitted on every exit path: success, policy deny, capability deny, resource-exceeded, trap, panic, and abandon.

## Schema

Wire format is frozen at `schema_version: 1` — see [`docs/audit-schema.md`](../../docs/audit-schema.md).

Each tool call produces a two-phase audit trail:

1. **Intent** — recorded before execution begins (`call_id`, `tool_id`, `input_digest`)
2. **Outcome** — recorded when the call completes (`policy`, `capability`, `execution`; optional `wall_ms` / `peak_memory_bytes`)

A begun `CallSession` is fail-closed by construction. Its seeds serialize as default-deny (never `allowed` / `granted` / `success`), and an incomplete session always emits exactly one outcome when dropped — a trap on panic, a host-denied `session abandoned` on any other abandon / early return / error. A forgotten `complete()` can never leave an orphan intent (fail-closed: every call is accounted for).

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
