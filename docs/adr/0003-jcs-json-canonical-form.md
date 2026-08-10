# JCS JSON is the canonical form, over a constrained value space

**Status:** accepted (2026-08-09) · lands in AILAB-619

Records hash under [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785), and stay JSONL on disk. SPEC.md additionally constrains the value space so that JCS's hard cases are unreachable: no floating-point values anywhere, digests as fixed-length lowercase hex, integers as `u64` below 2^53, and absent fields **omitted rather than null**.

The decision turns on one property of [ADR-0001](./0001-aar-chain-and-envelope.md): because `request_digest` is SHA-256 over **raw request bytes** and payloads live in the Envelope, arbitrary user data never enters the canonical form. The canonicalizer only ever sees Aegis's own field set. JCS's genuinely difficult parts — ES6 number formatting, float edge cases, unnormalized Unicode in attacker-chosen keys — all live in user data, and there is none.

## Considered options

**Deterministic CBOR (RFC 8949 §4.2)** is the stronger canonical form in the abstract — fewer footguns, native byte strings, no hex-encoding decision to get wrong. It was rejected on the D4 exit criterion: *"a stranger with the README, a laptop, and fifteen minutes can... verify the audit chain themselves."* A binary evidence artifact cannot be `cat`'d, `grep`'d, or eyeballed, and the surrounding ecosystem — the shipped JSONL audit file, MCP's JSON-RPC — is JSON throughout. Adoption cost matters more than encoding elegance when the format is the durable asset.

**An explicit length-prefixed field transcript** (the Certificate Transparency approach) is arguably the easiest to reimplement correctly — no library in any language, zero number ambiguity. Rejected as bespoke: an RFC is easier to hand a vendor than a hand-rolled encoding, and every added field would need a spec revision naming its byte position.

## Consequences

- **The value-space constraints are normative, not stylistic.** They are what make JCS safe here, so SPEC.md states them as requirements and the record types enforce them by construction — which the digest newtypes from ADR-0001 already do for the hash fields.
- **Omit, never null.** Already how `wall_ms` and `peak_memory_bytes` serialize (`core/src/audit.rs:73,77`). A canonical form cannot leave absent-vs-null to the emitter.
- **The `u64 < 2^53` bound is for cross-language verifiers**, not for Rust. A JavaScript verifier reading `seq` as a `Number` is the realistic third-party implementation, and silently losing precision above 2^53 would break verification in a way nobody would attribute to the format.
- **Storage shape is unchanged.** JSONL with one record per line, as shipped. JCS defines the hash input, not the file.
- **Test vectors must include the canonicalization step**, not just the final hash — otherwise an implementer who canonicalizes wrong sees only "hash mismatch" with no way to locate the error.
