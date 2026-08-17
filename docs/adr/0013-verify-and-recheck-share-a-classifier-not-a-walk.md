# Verify and Recheck share a line classifier, not a walk

**Status:** accepted (2026-08-14)

> **Implemented 2026-08-17** (AILAB-703). `line_type_field`,
> `line_type_from_value` and `SessionCounter` are public in
> `botzr-aegis-core/src/audit.rs`, beside `AuditLineType::from_wire`. Both walks
> number Sessions with the shared counter, and the v1 `phase` fallback has left
> the CLI binary. Neither verb's behaviour changed: `aegis verify` calls the
> field-only reader and still refuses a line with no `line_type`, `aegis recheck`
> calls the fallback-aware one and still reports v1 records, and Session
> boundaries come from `line_type` alone in both. Address extraction landed as
> the shared Session ordinal only — `Position` and the two verdict types stayed
> with their consumers, and `seq` was deliberately not unified, because verify
> reads a missing `seq` as `Tampered` where recheck prints 0. The text below is
> the decision as taken on 2026-08-14 and is left unedited. For what shipped,
> see `CHANGELOG.md`.

The duplication between `aegis verify`'s walk (`audit/src/verdict.rs`) and `aegis recheck`'s
(`cli/src/recheck.rs`) is resolved by extracting only what they genuinely share: line-type
routing including the schema-v1 `phase` fallback, Session numbering, and address extraction.
That lands as a small public surface in `botzr-aegis-core`, beside `AuditLineType::from_wire`.

The two walks are **not** merged. Each keeps its own iteration, strictness, and error policy.

## Why

The obvious refactor — one Chain reader both walks consume — cannot be built without one of
them changing what it means. Verify canonicalizes, hashes, checks signatures, enforces `seq`
ordering and Session structure, and stops at the first tamper. Recheck deliberately does none
of that, and `recheck.rs:119-122` argues why:

> an unparseable line is stepped over rather than reported: a torn tail is a statement about
> the file's integrity, and answering it here would be a second, weaker verifier living next
> to the real one.

Recheck also understands v1's `phase` spelling, which verify deliberately does not. So the
disagreements between the two walks on malformed input are designed, not drift.

A reader with a `Strict`/`Lenient` parameter was rejected for the same reason ADR-0012
rejects a `durable: bool`: it makes a verification guarantee configurable at the call site.

`core` rather than `audit` because the two facts being extracted are wire-vocabulary facts,
and `AuditLineType::from_wire` — the function that already turns a wire token into meaning —
lives in `core/src/audit.rs`. Splitting "what `line_type` means" from "what `phase` meant"
across two crates re-creates the problem. Anyone reading a Chain already depends on both
crates, since `audit` does not re-export core's types.

## Consequences

- **The comments stop being the mechanism.** `recheck.rs:145-149` and the LOAD-BEARING
  paragraph at `:231-239` exist to keep two independent implementations of Session numbering
  in agreement — the same expression written at `verdict.rs:575` and `recheck.rs:189`. After
  this they cite a shared function instead of describing one.
- **Schema-v1 knowledge leaves the binary.** `is_outcome_shaped` (`cli/src/recheck.rs:244`)
  is currently the only Rust in the workspace that knows `phase` was v1's spelling of
  `line_type`; the only other record is `docs/audit-schema.md`, marked SUPERSEDED.
- **AILAB-688 stays open.** Unifying the two walks' strictness is the recheck-vs-verify
  boundary question, and this decision deliberately does not answer it.
- **The remaining duplication is accepted.** Hashing, signature checking, ordering, and
  torn-tail policy stay per-consumer. That is the point, not a shortfall.
- **`cli/src/recheck.rs:265` is not duplication.** Its schema-version gate runs on raw JSON
  before deserialization; `policy/src/recheck.rs:261` runs on a typed `AuditRecord` after.
  They are layered on purpose and both stay.
