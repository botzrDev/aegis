# botzr-aegis-policy

YAML policy engine for Aegis — Station 1 of the enforcement pipeline (**POLICY** → CAPABILITY → SANDBOX → AUDIT).

Policies are parsed once at startup into an `Arc<PolicySet>`. Evaluation is synchronous with a target of <100 µs. Conflict resolution follows a G5 model: deny-overrides, most-specific-wins, and explicit priority tie-breaking.

## Features

- **Default-deny or default-allow** per-policy-set
- **Rate limiting** with fixed-window counters and injectable `Clock`
- **Pending approval** flow with minted approval IDs
- **Hot reload** via `ArcSwap` — swap the active set without restarting
- **Sha-256 digest** (FNV-1a) for policy set identity in audit records

## Policy format

See `tests/fixtures/policies/` for example YAML. Every rule specifies a `tool` matcher, an `action` (allow/deny/rate_limit/pending_approval), and optional `limits` (max memory, max wall time).

## Dependencies

- `botzr-aegis-core` for shared types (`PolicyAction`, `ToolId`)
- `serde` / `serde_norway` for YAML deserialization
- `arc-swap` for lock-free hot reload
