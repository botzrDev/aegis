"""PostgreSQL 16 + pgvector implementation of `LearningStore` (AEG-32, D24).

Patterns are the **only** durable governance state. The ingest buffer, drift
findings, and policy packs stay in-process on `GovernanceState` (D21–D23).

Schema changes are explicit: run

    python -m aegis_governance.learning_postgres migrate

The web app never mutates schema at import time.

Methods here are synchronous psycopg calls. Async routes must dispatch them via
`run_in_threadpool`; sync (`def`) routes already run in FastAPI's threadpool.
Every call opens its own short-lived connection, so no wasmtime-style shared
mutable state leaks across requests and a dead connection cannot poison later
ones.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Optional, Sequence

import psycopg
from pgvector import Vector
from pgvector.psycopg import register_vector
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.types.json import Jsonb

from aegis_governance.learning import (
    DEFAULT_SEARCH_LIMIT,
    FEATURE_SCHEMA_VERSION,
    LearningStoreError,
    PatternNeighbor,
    SourcePatternNotFoundError,
    clamp_search_limit,
    pattern_from_record,
)
from aegis_governance.models import AuditRecord

DATABASE_URL_ENV = "AEGIS_GOVERNANCE_DATABASE_URL"
MIGRATIONS_DIR_ENV = "AEGIS_GOVERNANCE_MIGRATIONS_DIR"

# A partitioned database must *raise* rather than park a threadpool worker
# forever: a blackholed host never returns TCP RST, so without an explicit
# timeout the store call blocks indefinitely, never becomes a
# LearningStoreError, and never reaches the 503 path. Enough of those and every
# sync route starves, including /health.
CONNECT_TIMEOUT_SECONDS = 5
STATEMENT_TIMEOUT_MS = 15_000


def build_conninfo(database_url: str) -> str:
    """Add timeout defaults without overriding what the operator set."""
    params = conninfo_to_dict(database_url)
    params.setdefault("connect_timeout", str(CONNECT_TIMEOUT_SECONDS))
    options = str(params.get("options") or "")
    if "statement_timeout" not in options:
        params["options"] = (
            f"{options} -c statement_timeout={STATEMENT_TIMEOUT_MS}"
        ).strip()
    return make_conninfo("", **params)

_UPSERT_SQL = """
INSERT INTO learning_patterns (
    pattern_id, call_id, tool_id,
    audit_schema_version, feature_schema_version,
    embedding, content
)
VALUES (%s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (call_id) DO UPDATE SET
    tool_id = EXCLUDED.tool_id,
    audit_schema_version = EXCLUDED.audit_schema_version,
    feature_schema_version = EXCLUDED.feature_schema_version,
    embedding = EXCLUDED.embedding,
    content = EXCLUDED.content
"""

# The feature-schema pin is load-bearing: two layouts share one vector(16)
# column, so comparing across versions would silently produce meaningless
# distances. A stale-version row is not a valid probe and not a valid neighbor.
_SOURCE_SQL = """
SELECT embedding FROM learning_patterns
WHERE call_id = %s AND feature_schema_version = %s
"""

# `<=>` is pgvector's cosine distance, matching learning.cosine_distance.
#
# call_id is the tie-break so equal-distance neighbors order deterministically:
# a published finding has to replay identically. That secondary sort key means
# the planner sorts exactly rather than walking the HNSW index approximately —
# the deliberate trade at research-instrument data sizes. The index stays for
# when the corpus outgrows an exact scan; benchmarks must not claim otherwise.
_NEIGHBORS_SQL = """
SELECT pattern_id, call_id, tool_id, feature_schema_version, content,
       embedding <=> %(probe)s AS distance
FROM learning_patterns
WHERE call_id <> %(call_id)s
  AND feature_schema_version = %(feature_schema_version)s
  AND (%(tool_id)s::text IS NULL OR tool_id = %(tool_id)s)
ORDER BY distance ASC, call_id ASC
LIMIT %(limit)s
"""

# One round trip for every source call in a proposal. Looping the single-source
# query instead would open one connection per source, and the ingest buffer it
# comes from is unbounded — that exhausts Postgres' connection slots.
_BATCH_NEIGHBORS_SQL = """
SELECT s.call_id AS source_call_id,
       n.pattern_id, n.call_id, n.tool_id, n.feature_schema_version,
       n.content, n.distance
FROM (
    SELECT call_id, embedding
    FROM learning_patterns
    WHERE call_id = ANY(%(call_ids)s)
      AND feature_schema_version = %(feature_schema_version)s
) s
CROSS JOIN LATERAL (
    SELECT p.pattern_id, p.call_id, p.tool_id, p.feature_schema_version,
           p.content, p.embedding <=> s.embedding AS distance
    FROM learning_patterns p
    WHERE p.call_id <> s.call_id
      AND p.feature_schema_version = %(feature_schema_version)s
      AND (%(tool_id)s::text IS NULL OR p.tool_id = %(tool_id)s)
    ORDER BY distance ASC, p.call_id ASC
    LIMIT %(limit)s
) n
"""


def _neighbor(row: Sequence[Any]) -> PatternNeighbor:
    """(pattern_id, call_id, tool_id, feature_schema_version, content, distance)."""
    return PatternNeighbor(
        pattern_id=str(row[0]),
        call_id=row[1],
        tool_id=row[2],
        distance=float(row[5]),
        feature_schema_version=row[3],
        content=row[4],
    )


def default_migrations_dir() -> Path:
    """`governance/migrations`, or `AEGIS_GOVERNANCE_MIGRATIONS_DIR` if set."""
    override = os.environ.get(MIGRATIONS_DIR_ENV)
    if override:
        return Path(override)
    # src/aegis_governance/learning_postgres.py → governance/
    return Path(__file__).resolve().parents[2] / "migrations"


def apply_migrations(
    database_url: str,
    migrations_dir: Optional[Path] = None,
) -> list[str]:
    """Apply every `*.sql` in name order. Each file is idempotent by design.

    Returns the applied filenames. Explicit, operator-run, never on import.
    """
    directory = migrations_dir or default_migrations_dir()
    if not directory.is_dir():
        raise LearningStoreError(f"migrations directory not found: {directory}")
    files = sorted(directory.glob("*.sql"))
    if not files:
        raise LearningStoreError(f"no .sql migrations in {directory}")

    applied: list[str] = []
    try:
        with psycopg.connect(build_conninfo(database_url)) as conn:
            with conn.cursor() as cur:
                for path in files:
                    cur.execute(path.read_text())
                    applied.append(path.name)
    except psycopg.Error as e:
        raise LearningStoreError(f"migration failed: {e}") from e
    return applied


class PostgresLearningStore:
    """`LearningStore` backed by Postgres 16 + pgvector.

    Rows and vectors are untrusted inputs to *evidence presentation* only. They
    never become policy authority: no method here emits policy YAML, relaxes
    the floor, or auto-applies anything.
    """

    mode = "postgres"

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    @classmethod
    def from_env(cls) -> Optional["PostgresLearningStore"]:
        """Build from `AEGIS_GOVERNANCE_DATABASE_URL`, or None when unset."""
        url = os.environ.get(DATABASE_URL_ENV)
        if not url:
            return None
        return cls(url)

    def _connect(self) -> psycopg.Connection:
        conn = psycopg.connect(build_conninfo(self.database_url))
        try:
            # Requires `CREATE EXTENSION vector` — i.e. the migration was run.
            register_vector(conn)
        except Exception:
            conn.close()
            raise
        return conn

    def upsert_patterns(self, records: Sequence[AuditRecord]) -> int:
        """Idempotent batch upsert by `call_id`, in exactly one transaction.

        Duplicate `call_id`s inside a batch are collapsed first: Postgres
        refuses to let `ON CONFLICT DO UPDATE` touch the same row twice.
        """
        if not records:
            return 0
        staged = {rec.call_id: pattern_from_record(rec) for rec in records}
        rows = [
            (
                p.pattern_id,
                p.call_id,
                p.tool_id,
                p.audit_schema_version,
                p.feature_schema_version,
                Vector(list(p.embedding)),
                Jsonb(p.content),
            )
            for p in staged.values()
        ]
        try:
            # `with conn` commits on clean exit and rolls the whole batch back
            # on any error — no partially persisted batch.
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.executemany(_UPSERT_SQL, rows)
        except psycopg.Error as e:
            raise LearningStoreError(f"pattern upsert failed: {e}") from e
        return len(rows)

    def search_neighbors(
        self,
        call_id: str,
        *,
        tool_id: Optional[str] = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
    ) -> list[PatternNeighbor]:
        """Nearest stored patterns by cosine distance, source row excluded."""
        capped = clamp_search_limit(limit)
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(_SOURCE_SQL, (call_id, FEATURE_SCHEMA_VERSION))
                    source = cur.fetchone()
                    if source is None:
                        # No probe vector is invented for an unknown source.
                        raise SourcePatternNotFoundError(
                            f"no stored pattern for call {call_id!r}"
                        )
                    cur.execute(
                        _NEIGHBORS_SQL,
                        {
                            "probe": source[0],
                            "call_id": call_id,
                            "feature_schema_version": FEATURE_SCHEMA_VERSION,
                            "tool_id": tool_id,
                            "limit": capped,
                        },
                    )
                    fetched = cur.fetchall()
        except psycopg.Error as e:
            raise LearningStoreError(f"pattern search failed: {e}") from e

        return [_neighbor(row) for row in fetched]

    def search_neighbors_batch(
        self,
        call_ids: Sequence[str],
        *,
        tool_id: Optional[str] = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
    ) -> dict[str, list[PatternNeighbor]]:
        """Neighbors for many sources in one query, one connection.

        Sources with no stored pattern are simply absent from the result — the
        caller decides what an unknown source means. Use `search_neighbors` when
        an unknown source must be an explicit not-found.
        """
        unique = list(dict.fromkeys(call_ids))
        if not unique:
            return {}
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        _BATCH_NEIGHBORS_SQL,
                        {
                            "call_ids": unique,
                            "feature_schema_version": FEATURE_SCHEMA_VERSION,
                            "tool_id": tool_id,
                            "limit": clamp_search_limit(limit),
                        },
                    )
                    fetched = cur.fetchall()
        except psycopg.Error as e:
            raise LearningStoreError(f"pattern search failed: {e}") from e

        grouped: dict[str, list[PatternNeighbor]] = {}
        for row in fetched:
            grouped.setdefault(row[0], []).append(_neighbor(row[1:]))
        return grouped

    def count(self) -> int:
        """Row count — test/diagnostic helper."""
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT count(*) FROM learning_patterns")
                    row = cur.fetchone()
        except psycopg.Error as e:
            raise LearningStoreError(f"pattern count failed: {e}") from e
        return int(row[0]) if row else 0


def _require_url() -> str:
    url = os.environ.get(DATABASE_URL_ENV)
    if not url:
        raise SystemExit(
            f"{DATABASE_URL_ENV} is not set. Example (local test container):\n"
            f"  export {DATABASE_URL_ENV}="
            "postgresql://postgres:postgres@localhost:5432/aegis_governance"
        )
    return url


def main(argv: Optional[Sequence[str]] = None) -> int:
    """`python -m aegis_governance.learning_postgres migrate`."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in {"migrate", "status"}:
        print(
            "usage: python -m aegis_governance.learning_postgres {migrate|status}",
            file=sys.stderr,
        )
        return 2

    url = _require_url()
    if args[0] == "migrate":
        applied = apply_migrations(url)
        for name in applied:
            print(f"applied {name}")
        print(f"migrations complete ({len(applied)} file(s))")
        return 0

    store = PostgresLearningStore(url)
    print(f"learning_patterns rows: {store.count()}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
