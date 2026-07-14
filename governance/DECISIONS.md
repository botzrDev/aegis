# Governance decisions

## D21 — Slice 1 storage and apply model

**Decision:** Layer 2 slice 1 is a FastAPI service with **in-process state** for the
ingest buffer. No Postgres, SQLite, pgvector, LiteLLM, or Celery in this slice.

**Proposals never auto-apply** into the Rust runtime. Rule-based narrowing emits
`status: pending_human` only. Floor violations surface as HTTP 409 (human-gated);
widening ambient authority is never an auto-apply path.

**Deferred to AEG-19b+ / later slices:** Postgres/pgvector learning fabric,
LiteLLM guardian beyond stub, Celery workers, evolving policy-pack versioning UI.

**Rationale:** Tracer-bullet first slice of MASTER PRD §7 — prove the four
defenses with tests before adding durable store or LLM guardians.

## D22 — Slice 2 immune/drift detectors (AEG-24)

**Decision:** Rule-based drift detectors (`capability_creep`, `rate_spike`,
`anomalous_allow_deny`) scan the in-process ingest buffer and emit
`pending_human` findings. Findings live on `GovernanceState` (no durable store).
HTTP: `POST /v1/detect`, `GET /v1/findings`.

**NullGuardian** is a passthrough stub for a later LLM guardian — no
LiteLLM/OpenAI imports or API keys. Detectors never emit widening policy and
never auto-apply into the Rust runtime. Policy floor on `/v1/propose` unchanged.

**Out:** Postgres/pgvector, Celery, CLI-only packaging, live LLM review,
auto-apply.

**Rationale:** MASTER PRD §7 SHOULD (2) as a tracer bullet on the frozen audit
schema, without reopening D21’s storage/LLM deferrals.

## D23 — Slice 3 evolving policy packs (AEG-26)

**Decision:** Versioned **policy packs** live **in-process** on `GovernanceState`
(`PackRegistry`) — no Postgres/SQLite/pgvector/LiteLLM/Celery. A pack is a
floor-checked policy YAML snapshot with `pack_id`, monotonic `version`, lineage
(`parent_version`), `rationale`, and `source_call_ids` from audit outcomes.

**Floor before mint.** `create_from_proposal` runs `check_floor(current,
proposed)` first; a widen raises `PackFloorError` → HTTP `409` and is **not
stored** (same human-gated family as `/v1/propose`). New packs always start
`pending_human` even after a floor ACCEPT.

**Ratify is governance-only.** A human accepts/rejects a pack in-process
(`accepted`/`rejected`); ratify **never** writes into the Rust runtime
(`botzr-aegis-*`) — no auto-apply, no blind-load. Double-ratify is `409`.

HTTP: `POST /v1/packs`, `GET /v1/packs`, `GET /v1/packs/{id}`,
`GET /v1/packs/{id}/versions/{version}`,
`POST /v1/packs/{id}/versions/{version}/ratify`. `/v1/propose` does not
auto-create packs.

**Out (still deferred):** pgvector learning fabric / SHOULD (3), live LLM
guardian, Celery, pack-authoring UI, durable pack store, crates.io.

**Rationale:** MASTER PRD §7 SHOULD (1) evolving policy packs as a tracer bullet
— identity + lineage + human ratification on the in-process state, without
reopening D21’s storage/LLM deferrals or the never-auto-apply invariant.
