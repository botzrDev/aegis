# Aegis governance (Layer 2) — slices 1–3

Python FastAPI service for audit ingest, policy-floor checks, **narrow-only**
policy proposals, **rule-based drift findings**, and **versioned policy packs**.
Not a Cargo workspace member; does not write into the Rust runtime.

## Defenses (load-bearing)

1. **Policy floor never relaxable** — `check_floor` rejects widen past `floor.default.yaml`.
2. **Never blind-load policy** — current/proposed YAML are validated before compare.
3. **Auto-apply only narrows** — widen → `pending_human` / HTTP 409; proposals never auto-apply to Rust.
4. **Audit ingest is untrusted** — reject `schema_version != 1`; fail closed on missing required outcome fields.

Detectors (slice 2) emit `pending_human` findings only — never policy YAML, never auto-widen.

Policy packs (slice 3) are versioned, floor-checked policy snapshots minted
`pending_human`. They live **in-process** on `GovernanceState` (no DB). A human
**ratifies** (accept/reject) inside governance only — ratify **never** writes
into `botzr-aegis-*`. Pack create runs `check_floor` first; a widen is `409` and
is not stored.

## Run

```bash
cd governance
uv venv .venv && uv pip install -e ".[dev]"
# or: python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

.venv/bin/uvicorn aegis_governance.app:app --reload
```

## Test

```bash
cd governance
.venv/bin/python -m pytest -q
```

## HTTP surface

| Method | Path | Behavior |
|--------|------|----------|
| `GET` | `/health` | liveness |
| `POST` | `/v1/ingest` | body = JSONL text (schema v1) |
| `POST` | `/v1/propose` | narrow-only proposal over ingest buffer; 409 on floor violation |
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

## Out of scope

Postgres/pgvector, LiteLLM/OpenAI keys, Celery, pack-authoring UI,
durable pack/detector state, auto-apply / blind-load into `botzr-aegis-*`
crates. See `DECISIONS.md` (D21, D22, D23).
