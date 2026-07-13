# Aegis governance (Layer 2) — slice 1

Python FastAPI service for audit ingest, policy-floor checks, and **narrow-only**
policy proposals. Not a Cargo workspace member; does not write into the Rust
runtime.

## Defenses (load-bearing)

1. **Policy floor never relaxable** — `check_floor` rejects widen past `floor.default.yaml`.
2. **Never blind-load policy** — current/proposed YAML are validated before compare.
3. **Auto-apply only narrows** — widen → `pending_human` / HTTP 409; proposals never auto-apply to Rust.
4. **Audit ingest is untrusted** — reject `schema_version != 1`; fail closed on missing required outcome fields.

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

## Out of scope (slice 1)

Postgres/pgvector, LiteLLM, Celery, evolving policy-pack UI, immune/drift beyond
stubs, auto-apply into `botzr-aegis-*` crates. See `DECISIONS.md` (D21).
