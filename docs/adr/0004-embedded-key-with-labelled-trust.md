# The signing key is embedded, and `aegis verify` labels its trust level

**Status:** accepted (2026-08-10) · lands in AILAB-620, surfaced by AILAB-621

A per-host ed25519 keypair signs outcome lines. The Session-`Open` line carries the public key, every signed line carries `key_id` (its fingerprint), and `aegis verify` **always prints the fingerprint** and distinguishes two success states: `Verified (pinned to <fp>)` when a key is supplied via `--key` or a trust store, and `Verified (unpinned)` when not — the latter stated as *internal consistency only*, explicitly not a claim about provenance. A `key_id` that fails to match a supplied trust store is `Tampered`.

The problem this addresses: with a self-embedded key and no anchor, an attacker who rewrites an entire session signs it with their own key, embeds that key, and verification passes clean. Reporting a bare "verified" there would reproduce the report §1 critique — *logs you must trust the vendor about are not evidence* — inside our own verifier.

## Considered options

**Require an external trust anchor** — refuse `Verified` unless `key_id` resolves. Cryptographically the most honest and it can never overclaim. Rejected on the D4 exit criterion: the stranger with a README and fifteen minutes has no trust store, so the headline demo would either ship a key out-of-band or end on exit 3.

**Sigstore-style keyless** (OIDC identity + transparency log) genuinely solves anchoring by putting a third party in the loop. Rejected for v0: network dependency and a heavy toolchain, against a local-first stdio wrapper running on a laptop. Report §4 defers hosted infrastructure until pull exists. Not foreclosed — `key_id` is the extension point.

**Hash chain only, defer signing to v0.2.** Against a full-rewrite attacker a self-embedded signature adds little over a bare hash chain, so this is a defensible honest v0.1 and it would shrink AILAB-619 considerably. Rejected because adding `signature` and `key_id` later is a format break, and format stability is the thesis (§2, §10.4). Ship the fields now, strengthen what they prove later.

## Consequences

- **`key_id` joins the record.** Without it a verifier cannot select a key and rotation is inexpressible. It is the field that lets this decision be upgraded — to TOFU, to a trust store, to sigstore — without a format break.
- **The labelled verdict is the point, not a caveat.** `Verified (unpinned)` is what makes an unanchored chain honest. Same discipline as [ADR-0002](./0002-verify-reports-coverage-not-pass-fail.md): the tool never claims more than the evidence supports, and the honest answer always has somewhere to go.
- **TOFU first-seen pinning belongs at the D3 layer**, reusing the §6.1 schema-hash first-seen registry rather than inventing a second registry with different semantics. Not v0.1 scope.
- **Key rotation is expressible but unspecified.** `key_id` per signed line means a file *can* contain lines under two keys. SPEC.md must say whether a verifier accepts that and under what conditions, or the first rotation produces an argument.
- **Private key handling is out of the format.** Where the key lives, its file permissions, and whether it is generated on first run are AILAB-620 implementation concerns, not spec surface.
