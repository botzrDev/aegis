# botzr-aegis-core

Pure types and traits for the Aegis enforcement pipeline. Zero I/O, no async
runtime, no wasmtime — every other runtime crate depends inward on this one.

This crate holds the values that appear in an enforcement decision or an audit
line: `ToolId`, `CapabilityGrant`, `PolicyAction`, the digest newtypes
(`RequestDigest`, `PolicySetHash`, `PrevHash`, …), the schema-v2 record types,
and RFC 8785 JCS canonicalization. It does **not** parse policy, mint grants,
run WASM, or write files.

## Pipeline constants

Load-bearing order — do not reorder:

```rust
pub const PIPELINE_STAGES: &[&str] = &["policy", "capability", "sandbox", "audit"];
pub const HOST_PIPELINE_STAGES: &[&str] = &["policy", "capability", "audit"];
```

`HOST_PIPELINE_STAGES` is Model B: the effect runs in host Rust, so there is no
sandbox station. Isolation is the grant check plus the audit record. See the
[threat model](../../docs/threat-model.md) §3.

## What lives here

| Surface | Role |
|---|---|
| `CapabilityGrant`, `FsGrant`, `NetGrant`, `HttpGrant` | Minted authority a call executes under |
| `ToolId`, `ToolKind` | Identity; `Wasm` vs `Host` |
| `AuditIntent`, `AuditRecord`, `AuditOpen`, `AuditClose`, `AuditDecision` | Schema-v2 line types (`AUDIT_SCHEMA_VERSION = 2`) |
| `DecisionAxes` | Inputs a policy verdict is a function of — never the raw argument tree |
| `jcs` | Canonical JSON (RFC 8785) used as the hash input for every signed line |

The canonical tool WIT world is `wit/aegis/tool/`, not this crate.

## Dependencies

`serde`, `serde_json`, `sha2`. No `ed25519-dalek` — core holds signature *bytes*,
never keys. Signing lives in `botzr-aegis-audit`.
