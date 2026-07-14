# Aegis governance (Layer 2) — slices 1–2

Python FastAPI service for audit ingest, policy-floor checks, **narrow-only**
policy proposals, and **rule-based drift findings**. Not a Cargo workspace
member; does not write into the Rust runtime.

## Defenses (load-bearing)

1. **Policy floor never relaxable** — `check_floor` rejects widen past `floor.default.yaml`.
2. **Never blind-load policy** — current/proposed YAML are validated before compare.
3. **Auto-apply only narrows** — widen → `pending_human` / HTTP 409; proposals never auto-apply to Rust.
4. **Audit ingest is untrusted** — reject `schema_version != 1`; fail closed on missing required outcome fields.

Detectors (slice 2) emit `pending_human` findings only — never policy YAML, never auto-widen.

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

## Out of scope

Postgres/pgvector, LiteLLM/OpenAI keys, Celery, evolving policy-pack UI,
durable detector state, auto-apply into `botzr-aegis-*` crates. See
`DECISIONS.md` (D21, D22).
