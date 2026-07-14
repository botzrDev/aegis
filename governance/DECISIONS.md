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
