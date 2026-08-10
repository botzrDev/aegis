# Aegis governance (Layer 2) — slices 1–4

> # ⛔ BREAK: INGEST IS BROKEN AGAINST THE CURRENT RUNTIME
>
> **The Rust runtime now emits audit schema version 2 (AILAB-619). This service
> hard-rejects `schema_version != 1`, so every line the runtime writes today is
> refused by `/v1/ingest`. Nothing in `governance/` has been migrated.**
>
> **Migration owner: AILAB-624.** Do not patch around this here — the models,
> the validation and the feature extractor all move together in that ticket.
>
> What changed in schema 2, all of it breaking for this service:
>
> | v1 | v2 |
> |---|---|
> | `phase` (`intent` \| `outcome`) | `line_type` — **six** types: `open`, `intent`, `outcome`, `decision`, `close`, `checkpoint` (reserved) |
> | `input_digest` | `request_digest` |
> | — | `seq`, `prev_hash` — every line is a link in a hash chain |
> | — | `signature`, `key_id` — ed25519 over the line's canonical form |
> | — | `policy_set_hash`, `grant_id`, `response_digest` |
> | — | `decision_axes` — always present, possibly `{}`; carries `capability`, `role`, `session`, `matched_rule`, `approval_ref`, derived `fs` / `net` |
> | — | lines hash under RFC 8785 (JCS); rows on disk are in canonical form |
>
> Two consequences this service's *design* has to answer, not just its parsers:
> `AuditPhase` no longer describes the wire (six line types, not two phases), and
> `FEATURE_SCHEMA_VERSION`'s "schema-v1 outcome" input is now a v2 outcome — a
> vector layout pinned to one audit schema cannot silently accept the other.
>
> Format reference: [`spec/SPEC.md`](../spec/SPEC.md).

Python FastAPI service for audit ingest, policy-floor checks, **narrow-only**
policy proposals, **rule-based drift findings**, **versioned policy packs**, and
a **pgvector learning fabric**. Not a Cargo workspace member; does not write
into the Rust runtime.

## Defenses (load-bearing)

1. **Policy floor never relaxable** — `check_floor` rejects widen past `floor.default.yaml`.
2. **Never blind-load policy** — current/proposed YAML are validated before compare.
3. **Auto-apply only narrows** — widen → `pending_human` / HTTP 409; proposals never auto-apply to Rust.
4. **Audit ingest is untrusted** — reject `schema_version != 1`; fail closed on missing required outcome fields. **This is the break above: the runtime now emits `2`. Owner AILAB-624.**

Detectors (slice 2) emit `pending_human` findings only — never policy YAML, never auto-widen.

Policy packs (slice 3) are versioned, floor-checked policy snapshots minted
`pending_human`. They live **in-process** on `GovernanceState` (no DB). A human
**ratifies** (accept/reject) inside governance only — ratify **never** writes
into `botzr-aegis-*`. Pack create runs `check_floor` first; a widen is `409` and
is not stored.

The learning fabric (slice 4) adds nearest-pattern **evidence**. It does not
add a fifth defense and it does not weaken the four above: neighbors never
alter `status`, `policy_yaml`, or a floor decision, and a widen is still `409`
*before* any neighbor is looked up.

## Learning fabric (slice 4, D24)

**Patterns are the only durable state.** The ingest buffer, findings, and packs
stay in-process. One table, `learning_patterns`, stores a deterministic
`vector(16)` per validated schema-v1 outcome.

**Deterministic feature schema v1** — no embedding provider, no API key, no
network call, so stored vectors are reproducible from the same JSONL:

| Dims | Meaning |
|---|---|
| 0–3 | policy one-hot: `allowed` / `denied` / `rate_limited` / `pending_approval` |
| 4–5 | capability one-hot: `granted` / `denied` |
| 6–9 | execution one-hot: `success` / `trap` / `resource_exceeded` / `host_denied` |
| 10 | granted filesystem read paths present |
| 11 | granted filesystem write paths present |
| 12 | granted HTTP entries present |
| 13 | bounded `log1p(wall_ms)` (bound 60 000 ms) |
| 14 | bounded `log1p(peak_memory_bytes)` (bound 1 GiB) |
| 15 | bounded `log1p(grant.max_output_bytes)` (bound 1 GiB) |

Every axis clamps to `[0, 1]`; missing metrics/grants encode as zero. `tool_id`
is **not** hashed into the vector — it stays a column and an exact-match filter,
so similarity never blurs tool identity. Bounds are frozen with
`FEATURE_SCHEMA_VERSION`: changing one requires a new version, not an edit.

Stored `content` is a canonical summary — identifiers, status strings, grant
*shape* (counts and limits), resource metrics. Audit schema v1 carries no raw
prompt/input/output, agent, or project, and the store adds none; free-text
runtime reasons and messages are dropped too.

**Ingest order is load-bearing:** validate → persist patterns in one
transaction → *only then* extend the in-memory buffer. A configured store that
fails returns `503` with neither side partially updated. Re-ingesting the same
JSONL is idempotent by `call_id`.

### Evidence semantics and known limits

`/v1/propose` attaches at most **3 neighbors per source call**, deduplicated by
`pattern_id` and capped at **5 items total**
(`EVIDENCE_PER_SOURCE_CALL` / `EVIDENCE_TOTAL` in `app.py`). A 40-source
proposal returning 4 evidence items is the cap, not a bug. Neighbor lookup for
all source calls is one batched query, so evidence cost does not grow with the
unbounded ingest buffer.

**The layout collides by construction, and that limits what evidence means.**
With no resource metrics recorded, any two outcomes sharing policy, capability,
and execution status *and* grant shape encode identically — distance `0.0`.
On a homogeneous buffer, ordering therefore falls entirely to the `call_id`
tie-break, which is "lexicographically first", not "most similar". Replay stays
deterministic (what published findings need), but treat the evidence signal as
weak until outcomes vary along dims 13–15. Only `wall_ms`,
`peak_memory_bytes`, and `max_output_bytes` are continuous.

**Reading rows is not trusting them.** Neighbors are presented to a human;
they never alter `status`, `policy_yaml`, or a floor decision.

**Operational defaults.** Connections carry `connect_timeout=5` and
`statement_timeout=15000` unless the URL sets its own — a blackholed database
must raise (and become a `503`) rather than park a threadpool worker forever.
Searches are pinned to the current `FEATURE_SCHEMA_VERSION`: two layouts share
one `vector(16)` column, so a stale-version row is neither a valid probe nor a
valid neighbor.

## Run

```bash
cd governance
uv venv .venv && uv pip install -e ".[dev]"
# or: python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

.venv/bin/uvicorn aegis_governance.app:app --reload
```

Without `AEGIS_GOVERNANCE_DATABASE_URL` the service runs with an in-process
learning store; `/health` reports which one is active (mode only, never the
URL).

### Postgres + pgvector setup

```bash
docker run -d --name aegis-pgvector -p 5432:5432 \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=aegis_governance pgvector/pgvector:pg16

export AEGIS_GOVERNANCE_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/aegis_governance
.venv/bin/python -m aegis_governance.learning_postgres migrate
.venv/bin/python -m aegis_governance.learning_postgres status
```

Migrations live in `governance/migrations/` and are applied **explicitly** —
the app never mutates schema at import time. Never commit a password or a
production URL.

## Test

```bash
cd governance
.venv/bin/python -m pytest -q

# include the real pgvector integration tests (they skip without this):
AEGIS_GOVERNANCE_TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/aegis_governance_test \
  .venv/bin/python -m pytest -q
```

The pgvector tests run against `pgvector/pgvector:pg16` — the real `vector(16)`
column and `<=>` cosine operator, not SQLite or a mocked operator. They use a
**separate** `AEGIS_GOVERNANCE_TEST_DATABASE_URL` on purpose: `tests/conftest.py`
clears `AEGIS_GOVERNANCE_DATABASE_URL` for every test, so running the suite in a
shell where you exported it for `migrate` neither fails the non-DB tests nor
writes rows into your live database.

## HTTP surface

| Method | Path | Behavior |
|--------|------|----------|
| `GET` | `/health` | liveness + active learning-store mode |
| `POST` | `/v1/ingest` | body = JSONL text (schema v1); persists patterns, then buffers; `503` if the store is down |
| `POST` | `/v1/propose` | narrow-only proposal over ingest buffer; 409 on floor violation; adds `learning_evidence` |
| `POST` | `/v1/patterns/search` | `{call_id, tool_id?, limit?}` → nearest patterns by cosine distance, source excluded; `404` unknown source, `422` limit outside `[1, 50]` |
| `GET` | `/v1/floor` | active floor document |
| `POST` | `/v1/detect` | run rule-based drift detectors (+ NullGuardian); append findings |
| `GET` | `/v1/findings` | list in-process `pending_human` findings |
| `POST` | `/v1/packs` | floor-check `{current_policy_yaml, policy_yaml, rationale, source_call_ids, pack_id?}` → mint pack `pending_human`; `409` on widen (not stored) |
| `GET` | `/v1/packs` | list all packs, all versions, newest first |
| `GET` | `/v1/packs/{pack_id}` | latest version for id (`404` if missing) |
| `GET` | `/v1/packs/{pack_id}/versions/{version}` | exact version (`404` if missing) |
| `POST` | `/v1/packs/{pack_id}/versions/{version}/ratify` | body `{accept}` → status flip (`accepted`/`rejected`); `404` if missing, `409` if already terminal |

Ratify is governance-only bookkeeping: it flips in-process status and never
applies the pack into the Rust runtime. Packs are created from a proposal
payload via `/v1/packs`; `/v1/propose` does **not** auto-create packs.

`learning_evidence` on `/v1/propose` is a list of
`{pattern_id, call_id, tool_id, distance}` — pointers into the audit trail for
a human reviewer. It carries no policy fragment, and the proposal is
byte-identical with an empty store.

## Out of scope

LiteLLM/OpenAI/Anthropic keys, Celery/Redis, pack-authoring UI, durable
pack/finding/buffer state, policy YAML generated from neighbors, auto-apply /
blind-load into `botzr-aegis-*` crates. See `DECISIONS.md` (D21–D24).
