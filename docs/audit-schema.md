# Aegis audit schema (v1 freeze)

> **⚠️ SUPERSEDED for schema version 2.** AILAB-619 bumped
> `AUDIT_SCHEMA_VERSION` to `2`: `phase` became `line_type` with six values,
> `input_digest` became `request_digest`, and every line gained chain
> (`seq`, `prev_hash`) and signature (`signature`, `key_id`) fields.
> **The current wire contract is [`spec/SPEC.md`](spec.md).** This page
> is kept as the v1 record; do not implement against it.

> **Status:** Frozen at `schema_version: 1` for v0.1 (OQ-15 T7 / AEG-34)  
> **Authority:** types in [`crates/botzr-aegis-core/src/audit.rs`](https://github.com/botzrDev/aegis/blob/main/crates/botzr-aegis-core/src/audit.rs) · writers in [`botzr-aegis-audit`](https://github.com/botzrDev/aegis/tree/main/crates/botzr-aegis-audit/)  
> **Constant:** `AUDIT_SCHEMA_VERSION = 1` (`u32`)

This document is the Layer 2 / governance **input contract** for JSONL audit lines.
CI golden snapshots freeze the wire shape; this page documents that shape for humans.

**Additive-only evolution:** new fields may be introduced via `serde(default)` and/or
`Option` + `skip_serializing_if`. Consumers must ignore unknown fields. A
breaking change requires bumping `AUDIT_SCHEMA_VERSION` (out of scope for this
freeze).

---

## Record kinds (two-phase durability)

Each tool call produces **two JSONL lines** (G3):

1. **Intent** — appended **before** sandbox / host work begins (`phase: "intent"`).
2. **Outcome** — appended on **every exit path** (`phase: "outcome"`), including
   policy deny, capability deny, success, trap, resource exceeded, and host deny.
   The `CallSession` `Drop` guard makes this structural: an incomplete session
   always emits exactly one fail-closed outcome — a `trap` (`"host panic during
   tool call"`) if the runtime panics mid-call, otherwise a `host_denied`
   (`"session abandoned"`) for any other abandon / early return / error — so a
   forgotten `complete()` can never leave an orphan intent.

| Rust type | `phase` value | Role |
|---|---|---|
| `AuditIntent` | `"intent"` | Pre-work line |
| `AuditRecord` | `"outcome"` | Post-work / exit-path line |

`AuditPhase` serializes with serde `rename_all = "snake_case"`.

---

## Intent fields (`AuditIntent`)

| JSON field | Type | Notes |
|---|---|---|
| `schema_version` | `u32` | Always `1` today (`AUDIT_SCHEMA_VERSION`) |
| `phase` | string | Always `"intent"` |
| `call_id` | string | Stable id for pairing intent ↔ outcome |
| `tool_id` | string | `ToolId` (serde transparent newtype) |
| `input_digest` | string | Digest of call input — **not** raw input |

---

## Outcome fields (`AuditRecord`)

| JSON field | Type | Notes |
|---|---|---|
| `schema_version` | `u32` | Always `1` today |
| `phase` | string | Always `"outcome"` |
| `call_id` | string | Matches the prior intent line |
| `tool_id` | string | `ToolId` |
| `input_digest` | string | Same digest policy as intent |
| `policy` | object | Tagged `PolicyOutcome` (see below) |
| `capability` | object | Tagged `CapabilityOutcome` |
| `execution` | object | Tagged `ExecutionOutcome` |
| `wall_ms` | `u64`, optional | Present only when sandbox ran; omitted otherwise (`skip_serializing_if` none) |
| `peak_memory_bytes` | `u64`, optional | Peak guest linear memory when sandbox ran; omitted otherwise |

Optional helpers on the Rust side: `CallMetrics { wall_ms, peak_memory_bytes }` via
`AuditRecord::with_metrics`. Those two numeric fields are flattened onto the
outcome record — there is no nested `metrics` object on the wire.

---

## Tagged outcomes

All three enums use `#[serde(tag = "status", rename_all = "snake_case")]`.
The `status` field selects the variant; payload fields sit beside it.

### `PolicyOutcome` (`policy`)

| `status` | Extra fields |
|---|---|
| `"allowed"` | *(none)* |
| `"denied"` | `reason` (string) |
| `"rate_limited"` | `reason` (string) |
| `"pending_approval"` | `approval_id` (string) |

### `CapabilityOutcome` (`capability`)

| `status` | Extra fields |
|---|---|
| `"granted"` | `grant` (`CapabilityGrant` object) |
| `"denied"` | `reason` (string); `denied_capability` (`string \| null`) — optional machine-readable axis (e.g. `fs`, `net.http`, `tool.registry`) |

`CapabilityGrant` (when granted) includes: `grant_id`, `tool_id`, `fs` / `net`
(optional), `max_memory_bytes`, `max_wall_ms`, `max_output_bytes`. See
`crates/botzr-aegis-core/src/grant.rs`.

### `ExecutionOutcome` (`execution`)

| `status` | Extra fields |
|---|---|
| `"success"` | *(none)* |
| `"trap"` | `message` (string) |
| `"resource_exceeded"` | `kind` (string) |
| `"host_denied"` | `reason` (string) |

---

## Digests and secrets

**Shipped today**

- `input_digest` on both Intent and Outcome. It is **runtime-derived**:
  the pipeline computes `sha256_hex(input)` from the exact bytes the execution
  step will see. No public runtime API (`execute_tool_call`,
  `execute_host_call`) accepts a caller-supplied digest, so the field cannot be
  made to disagree with the payload.
- No raw tool input, env, or tokens in the audit line.

**Absent / deferred (not in schema v1 wire format)**

- `output_digest` — **not a field** on `AuditIntent` or `AuditRecord`. Do not
  expect or emit it. Threat-model wording matches this (AEG-35).

---

## Metrics

| Field | When present | When omitted |
|---|---|---|
| `wall_ms` | Sandbox execution completed (or was measured) | Policy/capability short-circuit; sandbox never ran |
| `peak_memory_bytes` | Same as `wall_ms` | Same |

Both use `#[serde(default, skip_serializing_if = "Option::is_none")]`.

---

## Sinks

| Sink | Status |
|---|---|
| JSONL via `AuditWriter` | **Shipped** — append one JSON object per line; per-line `flush` + `fsync` (`sync_all`) for durability |
| OpenTelemetry / OTLP export | **Deferred** — not in v0.1; no OTel crate or export path |

Schema version is validated by the writer before each emit (`AUDIT_SCHEMA_VERSION`).

---

## Golden snapshots (CI freeze)

Schema drift fails CI. Cite these fixtures:

**Unit / crate goldens —** `crates/botzr-aegis-audit/tests/golden/`

- `policy_deny.json`
- `capability_denied.json`
- `rate_limit.json`
- `pending_approval.json`
- `trap.json`
- `resource_exceeded.json`
- `panic.json` — `Drop` panic-guard outcome (default-deny seeds + host-panic trap)
- `abandoned_session.json` — begun-but-never-completed outcome (default-deny seeds + `host_denied` `session abandoned`)

**Deny-suite goldens —** `tests/deny-suite/tests/golden/`

- `policy_deny.json`
- `capability_net_denied.json`
- `capability_unregistered.json`
- `resource_memory.json`

**Orchestrator golden —**

- `crates/botzr-aegis-runtime/tests/golden/resource_exceeded_orchestrator.json`

---

## Authority

| Concern | Location |
|---|---|
| Record types, enums, `AUDIT_SCHEMA_VERSION` | `botzr-aegis-core` (`src/audit.rs`) |
| JSONL writer, `CallSession` / Drop-trap | `botzr-aegis-audit` |
| This freeze document | `docs/audit-schema.md` |
