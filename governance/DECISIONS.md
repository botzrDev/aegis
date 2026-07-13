# Governance decisions

## D21 — Slice 1 storage and apply model

**Decision:** Layer 2 slice 1 is a FastAPI service with **in-process state** for the
ingest buffer. No Postgres, SQLite, pgvector, LiteLLM, or Celery in this slice.

**Proposals never auto-apply** into the Rust runtime. Rule-based narrowing emits
`status: pending_human` only. Floor violations surface as HTTP 409 (human-gated);
widening ambient authority is never an auto-apply path.

**Deferred to AEG-19b+:** Postgres/pgvector learning fabric, LiteLLM guardian,
Celery workers, evolving policy-pack versioning UI, immune/drift detectors beyond
stub interfaces.

**Rationale:** Tracer-bullet first slice of MASTER PRD §7 — prove the four
defenses with tests before adding durable store or LLM guardians.
