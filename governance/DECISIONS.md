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

## D24 — Slice 4 pgvector learning fabric (AEG-32 / AILAB-122)

**Decision:** **Learning patterns are the only durable governance state.** They
live in PostgreSQL 16 + pgvector (`learning_patterns`, `vector(16)`, HNSW
`vector_cosine_ops`). The ingest buffer, drift findings, and the policy-pack
registry remain **in-process** on `GovernanceState` — D21–D23 are not reopened.

**Deterministic schema-v1 vectors.** `FEATURE_SCHEMA_VERSION = 1` encodes only
fields audit schema v1 actually ships (policy/capability/execution status,
grant shape, `wall_ms`, `peak_memory_bytes`, `max_output_bytes`) into a fixed
16-dim layout with documented bounds clamped to `[0, 1]`. No embedding
provider, no API key, no network call — vectors are reproducible from the same
JSONL, which is what published findings require. `tool_id` stays a column and
an exact-match filter; it is never hashed into the vector. Stored `content` is
a canonical summary: identifiers, status strings, grant shape, resource
metrics. Free-text reasons/messages are excluded, and the fields schema v1
never carried (raw prompt/input/output, agent, project) cannot appear.

**Nearest neighbors are evidence, never policy authority.** `/v1/propose`
returns `learning_evidence` **after** the rule-based proposal and **after** the
floor check. Neighbors never alter `status`, `policy_yaml`, or the floor
decision; a widen is still `409` before any neighbor is looked up. Rows and
vectors are untrusted input to evidence *presentation* only.

**Ingest order is load-bearing:** validate → persist patterns in one
transaction → only then extend the in-memory buffer. A store failure is `503`
with neither side partially updated. Re-ingesting the same JSONL is idempotent
by `call_id`.

**Schema is explicit:** `python -m aegis_governance.learning_postgres migrate`,
configured by `AEGIS_GOVERNANCE_DATABASE_URL`. The web app never mutates schema
at import time, and no production URL or password is committed.

**Evidence is capped and disclosed:** at most 3 neighbors per source call, 5
total. Neighbor lookup for a proposal is one batched query — a per-source query
would open a connection per call, and the ingest buffer feeding
`source_call_ids` is unbounded. Searches are pinned to the current
`FEATURE_SCHEMA_VERSION`, since two layouts would otherwise share one
`vector(16)` column and produce meaningless cross-version distances.
Connections carry `connect_timeout` and `statement_timeout` defaults: a
blackholed database must raise into the 503 path rather than park a threadpool
worker indefinitely, which is the one failure mode "DB exceptions never produce
policy output" does not by itself cover.

**Known limit, recorded deliberately:** the fixed layout collides by
construction. Outcomes with equal status triple and grant shape and no recorded
metrics encode identically, so on a homogeneous buffer every distance is `0.0`
and ordering falls to the `call_id` tie-break. Replay stays deterministic —
which is what published findings require — but the evidence signal is weak
until dims 13–15 vary. Sharpening it means a feature schema v2, not an edit to
v1.

HTTP: `POST /v1/patterns/search` (`404` unknown source, `422` limit outside
`[1, 50]`); `learning_evidence` added to `POST /v1/propose`; `/health` reports
the active store mode (never the URL).

**Out (still deferred):** LiteLLM/OpenAI/Anthropic guardians (AEG-33 /
AILAB-124), Celery/Redis, durable packs/findings/buffer, generating policy YAML
from neighbors, auto-apply.

**Rationale:** MASTER PRD §7 SHOULD (3) as a narrow tracer bullet — prove
durable, reproducible similarity search on the frozen audit schema without
reopening the never-auto-apply invariant or adding an LLM dependency.
