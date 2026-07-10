# botzr-aegis-capability

Default-deny capability resolver and grant minting for Aegis — Station 2 of the enforcement pipeline (POLICY → **CAPABILITY** → SANDBOX → AUDIT).

## Core IP: grant minting

The resolver owns a registry of `ToolManifest` entries (declarative needs for fs, net, http, and limits). When a tool call arrives, `resolve_with_ceiling()` folds any policy-derived `PolicyCeiling` into the manifest's declared needs and mints a `CapabilityGrant` — the narrowest set of privileges that satisfies both the manifest and the policy ceiling.

Key invariant: the ceiling can only **lower** limits, never raise them (enforced by `narrow_grant()`).

## Grant narrowing

`narrow_grant()` takes a requested `CapabilityGrant` and a ceiling `PolicyCeiling`, returning a grant that is a subset of both. This is property-tested via proptest:
- `narrowed_grant_never_broader_than_parent`

Path canonicalization prevents symlink-escape in filesystem grants. HTTP validation rejects wildcard hosts.

## Dependencies

- `botzr-aegis-core` for shared types (`CapabilityGrant`, `ToolId`)
- `proptest` (dev) for property-based narrowing tests
