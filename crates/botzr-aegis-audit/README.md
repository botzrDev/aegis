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

## The signing key

The key is a **seed file**: one line of 64 lowercase hex characters — the 32-byte ed25519 seed — with an optional trailing newline. Same hex dialect as `PublicKey`. No PEM, no PKCS#8, no JSON, no comments.

```bash
aegis keygen --out /path/to/aegis-signing.key   # prints public_key <hex> and key_id <hex>
aegis run … --audit /path/to/session.jsonl --signing-key /path/to/aegis-signing.key
aegis verify --key <public_key hex> /path/to/session.jsonl
```

In-process the same two calls are `generate_signing_key(path, force)` and `load_signing_key(path)`.

**Permissions.** Generation creates the file `0600` and fsyncs it. On Unix, loading **refuses** any key readable by group or others (`mode & 0o077 != 0`) — a private key anyone on the host can read is not a private key. On non-Unix platforms the mode check is skipped rather than approximated; there is no portable equivalent and an invented ACL check would be a claim this code cannot keep.

**Generation is never implicit.** Nothing on the emit path mints a key. `load_signing_key` fails closed on every failure — missing, unreadable, loose permissions, bad hex, wrong length — and never falls back to `insecure_dev_key()` or to emitting unsigned records. `RuntimeBuilder::audit_file` takes the key path as a *required* argument for the same reason: a persistent sink is a file somebody will later pin a `Verified (pinned to <fp>)` label to, and a key minted silently on first run would publish a brand-new public key in the `Open` Line and quietly break every pin the operator held.

`insecure_dev_key()` survives only where it cannot be mistaken for provisioned authority: `AuditWriter::open_temp`, the runtime's throwaway default sink, and tests. Its seed is compiled into this crate, ships in every published artifact, and is not a secret — a Line it signs can only ever be reported `Verified (unpinned)`.

**Rotation** is normative in [`spec/SPEC.md`](../../spec/SPEC.md) §8.4 and is not restated here. In terms of this file: rotating means `aegis keygen` into a *new* seed file and starting a *new* process. One `AuditWriter` is one Session and holds one key for its lifetime, so a key change mid-Session is not something an emitter can produce — and a verifier reads it as `Tampered`.

The seed is not zeroized after use: `ed25519-dalek` is pinned `default-features = false, features = ["fast"]` and pulling in `zeroize` is out of scope. The seed lives as long as the `SigningKey` does.

## Dependencies

- `botzr-aegis-core` for shared types (`AuditIntent`, `AuditRecord`, `CallMetrics`, the digest newtypes, JCS)
- `ed25519-dalek` for signing and verification — the private key lives here, never in core
- `getrandom` for the 32 seed bytes `generate_signing_key` needs, and nothing else — filling the seed directly keeps `ed25519-dalek` on its `default-features = false, features = ["fast"]` pin instead of dragging in `rand`
- `serde` / `serde_json` for JSON serialization
