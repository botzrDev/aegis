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

On-disk shape is YAML `version: 1`. Every rule has an `id`, an `action`
(`allow` / `deny` / `rate_limit` / `pending_approval`), and optional matchers.
Matchers today are `tool`, `capability`, and `role` only — **policy does not
inspect call arguments.** Argument-level matching is not shipped.

Worked examples:

- [`examples/dreamd-poc/fixtures/dreamd-policy.yaml`](../../examples/dreamd-poc/fixtures/dreamd-policy.yaml)
- [`fuzz/corpus/policy_yaml/`](../../fuzz/corpus/policy_yaml/) (parse-surface seeds)

`pending_approval` is reject-with-resume-token: the call is not executed and no
grant is minted. It is not a parked in-flight call.

The full language is documented in the [policy YAML chapter](../../docs/guide/policy.md)
of the docs book.

## Dependencies

- `botzr-aegis-core` for shared types (`PolicyAction`, `ToolId`)
- `serde` / `serde_norway` for YAML deserialization
- `arc-swap` for lock-free hot reload
