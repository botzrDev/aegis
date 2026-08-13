# botzr-aegis-capability

Default-deny capability resolver and grant minting for Aegis — Station 2 of the enforcement pipeline (POLICY → **CAPABILITY** → SANDBOX → AUDIT).

## Core IP: grant minting

The resolver owns a registry of `ToolManifest` entries (declarative needs for fs, net, http, and limits). When a tool call arrives, `resolve_with_ceiling()` folds any policy-derived `ResourceCeiling` into the manifest's declared needs and mints a `CapabilityGrant` — the narrowest set of privileges that satisfies both the manifest and the policy ceiling.

Key invariant: the ceiling can only **lower** limits, never raise them.
`resolve_with_ceiling()` applies it by combining the resolver's own ceiling with
the per-call one before resolving.

## Grant narrowing

`narrow_grant()` mints a **sub-tool** grant from a parent grant, checking that
the sub-tool cannot widen what the parent already holds:

```rust
pub fn narrow_grant(
    parent_grant: &CapabilityGrant,
    parent_manifest: &ToolManifest,
    sub_manifest: &ToolManifest,
    grant_id: impl Into<String>,
    ceiling: ResourceCeiling,
) -> Result<CapabilityGrant, CapabilityError>
```

It validates fs and net narrowing against the two manifests, mints the grant,
and then re-checks the result with `ensure_grant_narrowed`, so a minting bug
cannot silently produce a broader grant than the parent. `grant_is_subset()`
is the public subset oracle. Property-tested via proptest:
`narrowed_grant_never_broader_than_parent`.

Path canonicalization prevents symlink-escape in filesystem grants. HTTP validation rejects wildcard hosts.

## Dependencies

- `botzr-aegis-core` for shared types (`CapabilityGrant`, `ToolId`)
- `proptest` (dev) for property-based narrowing tests
