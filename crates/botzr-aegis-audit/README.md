# botzr-aegis-audit

Structured audit records for Aegis — wraps the entire enforcement pipeline (POLICY → CAPABILITY → SANDBOX → **AUDIT**).

Always emitted on every exit path: success, policy deny, capability deny, resource-exceeded, trap, panic, and abandon.

## Schema

Wire format is `schema_version: 2` (AILAB-619) — every appended line is a link in a hash chain.

Each tool call produces a two-line audit trail:

1. **Intent** — recorded and fsynced before execution begins (`call_id`, `tool_id`, `request_digest`)
2. **Outcome** — recorded when the call completes (`policy`, `capability`, `execution`, `decision_axes`, `policy_set_hash`; optional `wall_ms` / `peak_memory_bytes` / `grant_id` / `response_digest`)

A begun `CallSession` is fail-closed by construction. Its seeds serialize as default-deny (never `allowed` / `granted` / `success`), and an incomplete session always emits exactly one outcome when dropped — a trap on panic, a host-denied `session abandoned` on any other abandon / early return / error. A forgotten `complete()` can never leave an orphan intent (fail-closed: every call is accounted for).

## Writer

One `AuditWriter` is one **Session**: it appends the `Open` line on construction and the `Close` line on `Drop`, and owns the chain state (`seq`, tail hash) behind the same lock as the file handle. Rows are canonical (RFC 8785 JCS) JSON with per-line `fsync` for durability (G3), so the bytes a verifier reads are the bytes that were hashed. Schema version is validated before every write.

`Open`, `Outcome`, `Decision` and `Close` are ed25519-signed; `Intent` is hashed into the chain but never signed, because it is fsynced ahead of execution and signing must stay off the pre-execution critical path.

```rust
let writer = AuditWriter::open("path/to/audit.jsonl", signing_key)?;
// or for ephemeral testing, signed by the loudly-named dev key:
let writer = AuditWriter::open_temp()?;
```

**`Drop` does not run on SIGKILL.** Close-on-drop covers clean exit and unwind only; a Session with no `Close` is what a verifier reports as `Indeterminate`.

Key *lifecycle* — where a private key lives, its permissions, first-run generation — is AILAB-620. Until then `open_temp` and the runtime default sink use `insecure_dev_key()`, whose seed is compiled into this crate and is not a secret.

## Dependencies

- `botzr-aegis-core` for shared types (`AuditIntent`, `AuditRecord`, `CallMetrics`, the digest newtypes, JCS)
- `ed25519-dalek` for signing and verification — the private key lives here, never in core
- `serde` / `serde_json` for JSON serialization
