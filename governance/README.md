# Aegis governance (Layer 2) — slices 1–4

Python FastAPI service for audit ingest, policy-floor checks, **narrow-only**
policy proposals, **rule-based drift findings**, **versioned policy packs**, and
a **pgvector learning fabric**. Not a Cargo workspace member; does not write
into the Rust runtime.

## Defenses (load-bearing)

1. **Policy floor never relaxable** — `check_floor` rejects widen past `floor.default.yaml`.
2. **Never blind-load policy** — current/proposed YAML are validated before compare.
3. **Auto-apply only narrows** — widen → `pending_human` / HTTP 409; proposals never auto-apply to Rust.
4. **Audit ingest is untrusted** — reject `schema_version != 2`; fail closed on missing required outcome fields.

Detectors (slice 2) emit `pending_human` findings only — never policy YAML, never auto-widen.

## Audit schema v2 (AILAB-624)

Ingest speaks **audit schema version 2** — the Agent Action Record format in
[`spec/SPEC.md`](../spec/SPEC.md), as emitted by the runtime since AILAB-619.

**Schema v1 is refused.** SPEC §12 states v1 is not compatible, and a v1 line
carries no `seq`, no `prev_hash` and no signature — admitting one would put a
record with no integrity evidence into the store. The error names the version
and the reason rather than failing as generic corruption. See `DECISIONS.md` D25.

What the migration changed here:

| v1 | v2 |
|---|---|
| `phase` (`intent` \| `outcome`) | `line_type` — **six** types: `open`, `intent`, `outcome`, `decision`, `close`, `checkpoint` (reserved) |
| `input_digest` | `request_digest` |
| — | `seq`, `prev_hash` — every line is a link in a hash chain |
| — | `signature`, `key_id` — ed25519 over the line's canonical form |
| — | `policy_set_hash`, `grant_id`, `response_digest` |
| — | `decision_axes` — always present, possibly `{}`; carries `capability`, `role`, `session`, `matched_rule`, `approval_ref`, derived `fs` / `net` |

### Three rejection classes, deliberately distinct

| Input | Result |
|---|---|
| `schema_version != 2` | `IngestError` → HTTP 400. The batch aborts. |
| Missing/mistyped `line_type`, `seq` or `prev_hash` | `IngestError` → HTTP 400. Not a chain line; a format violation, not an unknown extension (SPEC §5). |
| A `line_type` this service does not consume | **Skipped and counted.** Never an abort. |

That third row is the format's whole extensibility story (SPEC §5.2). An emitter
may add line types within version 2, so treating an unfamiliar one as corruption
would make every future addition a breaking change. `open`, `close`, `decision`,
`checkpoint` and anything newer are skipped; `/v1/ingest` reports `skipped` and
`skipped_by_type`, keyed by the emitter's **verbatim** token — collapsing
unknowns into one "other" bucket can tell an operator that something was
unreadable but not *what*.

Downstream stays **outcome-centric**: detectors, proposals and the learning
fabric read `batch.outcomes`. Skipped lines are reported, not analysed.

### Parsing is not verifying

`signature` and `key_id` are validated as *present* on lines the spec signs,
because ingest fails closed on missing required fields. Nothing here checks an
ed25519 signature, walks `prev_hash`, or recomputes a `line_hash` — a line with
a present-but-forged signature parses cleanly. Verification is `aegis verify`
(AILAB-621); until it lands, nothing downstream of ingest may be called
verified.

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
`vector(16)` per validated outcome line.

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
*shape* (counts and limits), resource metrics. The audit schema carries no raw
prompt/input/output, agent, or project, and the store adds none; free-text
runtime reasons and messages are dropped too.

**`FEATURE_SCHEMA_VERSION` stayed at 1 across the audit v1 → v2 migration.**
Every axis above reads a field schema 2 kept under the same name with the same
meaning, so the same call encodes to a byte-identical vector under either wire
version — the golden vectors in `tests/test_learning.py` are unchanged while
the fixtures beneath them were rewritten to v2, which is the evidence. Bumping
would have been a version with no layout behind it *and* would have hidden every
already-stored row, since searches pin to the current feature version. What v2
added — `decision_axes`, `policy_set_hash`, `grant_id`, `response_digest` — is
parsed but deliberately **not** encoded: putting any of it into the embedding
changes stored vector meaning, which is a version bump and its own decision.

Only `content` moved with the wire: the digest key is now `request_digest`. A
migrated database holds no `input_digest` rows — `002` will not complete while
any `audit_schema_version = 1` row remains, and the CHECK then forbids writing
another — so this is a clean cut, not a mixed-key store.

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

`002_audit_schema_v2.sql` moves the `audit_schema_version` CHECK from 1 to 2 on
a database `001` already created (`CREATE TABLE IF NOT EXISTS` is a no-op
against an existing one). If any row still holds version 1 it **refuses and
tells you the count** rather than deleting evidence to make its own constraint
pass — those rows are yours, and no re-ingest can reproduce them now that v1 is
refused. Review them, remove them, re-run.

It is deliberately a single `DO` block so that refusal cannot half-apply. If you
run migrations with `psql` rather than the command above, pass
`-v ON_ERROR_STOP=1`: psql otherwise continues past an error and **exits 0**, so
a refused migration looks like a successful one in a script's exit status.

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
| `POST` | `/v1/ingest` | body = JSONL text (audit schema v2); persists patterns, then buffers; reports `skipped` / `skipped_by_type`; `400` on wrong version or a broken chain field; `503` if the store is down |
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
