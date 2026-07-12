# AEG-18 decision outputs

## D20 — `botzr-aegis-sandbox` extract shape (Stage 3)

**Authority:** MASTER PRD §8 Stage 3; design doc build order §310 + D11/D12/OQ-3.
**Prerequisite:** Stage 2 detector scorecard green on `main` (`tests/stage2-demo/`,
AEG-15) — proves the sandbox path (D10) this consumer story is contingent on.

**Decision (lock):**

| Item | Lock |
|---|---|
| Extract meaning | `botzr-aegis-sandbox` is **already** a standalone workspace crate. Stage 3 = **prove + document** consumability, not carve a crate out of a monolith. Proof: [`examples/sandbox-consumer/`](.) compiles and runs a real wasip2 guest with only sandbox + core. |
| Min consumer deps | `botzr-aegis-sandbox` + `botzr-aegis-core`. **Never** `-runtime`, `-policy`, `-capability`, `-audit`. Consumers mint their own `CapabilityGrant` (hand-built from core) or later pull `botzr-aegis-capability`; the orchestrator is not required. |
| Dependency direction | One-way, locked (OQ-3 / D12): `uveddi → botzr-aegis-sandbox`. Aegis never depends on a consumer; no consumer source is copied into this MIT repo. |
| uveddi wiring | **Out of this PR.** The one-way dependency direction (OQ-3) puts the wiring in the `botzrDev/uveddi` repo, not here; follow-up there in a separate session after Austin's OK. Deferred per the AEG-18 product decision (2026-07-12). |
| crates.io | **Publish `0.1.0` — authorized this ticket** (2026-07-12). Publishing `botzr-aegis-sandbox` requires its only Aegis dependency, `botzr-aegis-core`, to be published first, so the release is the ordered pair **core `0.1.0` → sandbox `0.1.0`**. `INTEGRATION.md` documents the crates.io dep as primary with git-on-`main` as the fallback. Execution steps + dry-run are tracked with the ticket; the actual `cargo publish` is an irreversible, token-gated step run with Austin's final go-ahead. |

**Rationale.** Anti-pattern §14 forbids a premature shared-crate story until both
Stage 1/2 PoCs exist. dreamd (AEG-20) and path-detector (AEG-15) are both on
`main`, so the extract is unblocked. Stage 3 deliberately proves the sandbox is
consumable *alone* — an external host that already owns policy/trust takes the
narrowest possible slice.

**Out of scope (unchanged from spec):** a `botzrDev/uveddi` PR — never opened
here; the one-way direction keeps that wiring in the consumer repo — plus
reimplementing its plugin lifecycle, re-proving D10 equivalence (cited from
Stage 2), Stage 4 governance (AEG-19), G8 `max_output_bytes`, and publishing the
full `botzr-aegis-*` suite (core + sandbox only this ticket).
