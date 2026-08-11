"""Real PostgreSQL 16 + pgvector integration (AEG-32 slice 4).

These tests require an actual `pgvector/pgvector:pg16` service — there is no
SQLite or mocked-operator substitute, because the point is to exercise the real
`vector(16)` column, the real `<=>` cosine operator, and real transaction
rollback. They skip when `AEGIS_GOVERNANCE_TEST_DATABASE_URL` is unset so the
rest of the suite still runs without Docker.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from aegis_governance.learning import (
    VECTOR_DIMENSIONS,
    InMemoryLearningStore,
    LearningStoreError,
    SourcePatternNotFoundError,
    encode_pattern,
    pattern_id_for,
)
from aegis_governance.learning_postgres import (
    PostgresLearningStore,
    apply_migrations,
)
from aegis_governance.models import AuditRecord
from test_learning import make_record

FIXTURES = Path(__file__).parent / "fixtures"
TEST_URL_ENV = "AEGIS_GOVERNANCE_TEST_DATABASE_URL"

pytestmark = pytest.mark.skipif(
    not os.environ.get(TEST_URL_ENV),
    reason=f"{TEST_URL_ENV} not set (needs pgvector/pgvector:pg16)",
)


@pytest.fixture()
def database_url() -> str:
    return os.environ[TEST_URL_ENV]


@pytest.fixture()
def store(database_url: str) -> PostgresLearningStore:
    import psycopg

    apply_migrations(database_url)
    with psycopg.connect(database_url) as conn:
        conn.execute("TRUNCATE learning_patterns")
    return PostgresLearningStore(database_url)


PRE_MIGRATION_TABLE = """
CREATE TABLE learning_patterns (
    pattern_id UUID PRIMARY KEY,
    call_id TEXT NOT NULL UNIQUE,
    tool_id TEXT NOT NULL,
    audit_schema_version INTEGER NOT NULL
        CONSTRAINT learning_patterns_audit_schema_version_check
        CHECK (audit_schema_version = 1),
    feature_schema_version INTEGER NOT NULL,
    embedding vector(16) NOT NULL,
    content JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

VERSION_CHECK_SQL = (
    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
    "WHERE conname = 'learning_patterns_audit_schema_version_check'"
)


def _version_check(conn) -> str:  # type: ignore[no-untyped-def]
    row = conn.execute(VERSION_CHECK_SQL).fetchone()
    assert row is not None, "the audit-version CHECK must never be absent"
    return row[0]


def _top_level_statements(sql: str) -> list[str]:
    """Split SQL into top-level statements the way psql does.

    Dollar-quoted bodies (`$$ ... $$`) are opaque, so a `;` inside a `DO` block
    does not end a statement. Comments are stripped first.
    """
    without_comments = "\n".join(
        line.split("--", 1)[0] for line in sql.splitlines()
    )
    statements: list[str] = []
    current: list[str] = []
    in_dollar = False
    index = 0
    while index < len(without_comments):
        if without_comments.startswith("$$", index):
            in_dollar = not in_dollar
            current.append("$$")
            index += 2
            continue
        char = without_comments[index]
        if char == ";" and not in_dollar:
            statements.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        index += 1
    if "".join(current).strip():
        statements.append("".join(current).strip())
    return [s for s in statements if s]


def test_upgrading_a_v1_database_never_leaves_it_unconstrained(
    database_url: str,
) -> None:
    """002 must refuse a database holding v1 rows *without* weakening it.

    The failure this guards is specific and was real: with the guard and the
    constraint swap as separate top-level statements, a raise aborts only
    itself, `DROP CONSTRAINT` then succeeds, `ADD CONSTRAINT` fails against the
    very rows the guard objected to, and the table is left with **no** version
    constraint at all. Asserting "migration raised" is not enough — assert what
    the table looks like afterwards.
    """
    import psycopg

    try:
        with psycopg.connect(database_url, autocommit=True) as conn:
            conn.execute("DROP TABLE IF EXISTS learning_patterns")
            conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
            conn.execute(PRE_MIGRATION_TABLE)
            conn.execute(
                "INSERT INTO learning_patterns (pattern_id, call_id, tool_id, "
                "audit_schema_version, feature_schema_version, embedding, content) "
                "VALUES (%s, 'legacy-v1', 'reader', 1, 1, %s, '{}'::jsonb)",
                (str(pattern_id_for("legacy-v1")), "[" + ",".join(["0"] * 16) + "]"),
            )
            assert "audit_schema_version = 1" in _version_check(conn)

        # Run it the way psql does — statement by statement, autocommit, no
        # ON_ERROR_STOP — NOT via apply_migrations(). apply_migrations wraps
        # every file in one psycopg transaction, so it rolls the damage back
        # and is safe *by accident*; testing only that path would have let the
        # non-atomic version through green. The README hands operators psql
        # snippets, so psql semantics are a real operator path.
        migration = (
            Path(__file__).resolve().parents[1]
            / "migrations"
            / "002_audit_schema_v2.sql"
        ).read_text()
        raised = False
        with psycopg.connect(database_url, autocommit=True) as conn:
            for statement in _top_level_statements(migration):
                try:
                    conn.execute(statement)
                except psycopg.Error:
                    raised = True  # psql would print ERROR and carry on
        assert raised, "the guard must refuse a database holding v1 rows"

        with psycopg.connect(database_url, autocommit=True) as conn:
            # The pre-existing constraint must survive the refusal intact.
            assert "audit_schema_version = 1" in _version_check(conn)
            # And it must still be enforced, not merely present.
            with pytest.raises(psycopg.errors.CheckViolation):
                conn.execute(
                    "INSERT INTO learning_patterns (pattern_id, call_id, tool_id, "
                    "audit_schema_version, feature_schema_version, embedding, "
                    "content) VALUES (%s, 'bogus', 't', 999, 1, %s, '{}'::jsonb)",
                    (str(pattern_id_for("bogus")), "[" + ",".join(["0"] * 16) + "]"),
                )
            # Refusal, not deletion: the operator's row is still there.
            count = conn.execute("SELECT count(*) FROM learning_patterns").fetchone()
            assert count is not None and count[0] == 1

            # Remediate the way the error message and README instruct.
            conn.execute("DELETE FROM learning_patterns WHERE audit_schema_version <> 2")

        apply_migrations(database_url)
        with psycopg.connect(database_url, autocommit=True) as conn:
            assert "audit_schema_version = 2" in _version_check(conn)
    finally:
        # Leave the shared database in the shape every other test expects.
        with psycopg.connect(database_url, autocommit=True) as conn:
            conn.execute("DROP TABLE IF EXISTS learning_patterns")
        apply_migrations(database_url)


def test_migration_is_idempotent_and_creates_the_vector_schema(
    database_url: str,
) -> None:
    import psycopg

    expected = ["001_learning_patterns.sql", "002_audit_schema_v2.sql"]
    assert apply_migrations(database_url) == expected
    # Explicit, operator-run, and safe to re-apply.
    assert apply_migrations(database_url) == expected

    with psycopg.connect(database_url) as conn:
        ext = conn.execute(
            "SELECT 1 FROM pg_extension WHERE extname = 'vector'"
        ).fetchone()
        assert ext is not None
        dims = conn.execute(
            "SELECT atttypmod FROM pg_attribute "
            "WHERE attrelid = 'learning_patterns'::regclass AND attname = 'embedding'"
        ).fetchone()
        assert dims is not None and dims[0] == VECTOR_DIMENSIONS
        index_names = {
            row[0]
            for row in conn.execute(
                "SELECT indexname FROM pg_indexes WHERE tablename = 'learning_patterns'"
            ).fetchall()
        }
        assert "learning_patterns_embedding_hnsw_idx" in index_names
        # The audit-version pin moved 1 -> 2 with ingest (AILAB-624). 002 is
        # what carries it to a database 001 already created, so assert the
        # constraint the table actually ended up with, not the DDL text.
        check = conn.execute(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conname = 'learning_patterns_audit_schema_version_check'"
        ).fetchone()
        assert check is not None, "audit schema version CHECK must exist"
        assert "audit_schema_version = 2" in check[0]


def test_batch_upsert_is_idempotent_by_call_id(
    store: PostgresLearningStore, database_url: str
) -> None:
    import psycopg

    record = AuditRecord.model_validate(
        json.loads((FIXTURES / "resource_exceeded.json").read_text())
    )
    # Duplicate call_ids inside one batch collapse instead of erroring.
    assert store.upsert_patterns([record, record, record]) == 1
    assert store.count() == 1
    # Re-ingesting the same JSONL is a no-op, not a duplicate row.
    store.upsert_patterns([record])
    assert store.count() == 1

    with psycopg.connect(database_url) as conn:
        row = conn.execute(
            "SELECT pattern_id, tool_id, audit_schema_version, feature_schema_version, "
            "content FROM learning_patterns WHERE call_id = %s",
            (record.call_id,),
        ).fetchone()
    assert row is not None
    assert str(row[0]) == str(pattern_id_for(record.call_id))
    assert row[1] == record.tool_id
    assert row[2] == 2  # audit schema version, moved by AILAB-624
    assert row[3] == 1  # feature schema version, deliberately unchanged
    assert row[4]["policy_status"] == "allowed"
    # The stored digest key follows the wire rename.
    assert "request_digest" in row[4] and "input_digest" not in row[4]


def test_failed_transaction_persists_nothing(store: PostgresLearningStore) -> None:
    """One bad row rolls the whole batch back — no partially persisted batch."""
    good_a = make_record(call_id="txn-good-a")
    good_b = make_record(call_id="txn-good-b")
    bad = make_record(call_id="txn-bad")
    # Violates the CHECK (audit_schema_version = 2) pin on the table. Schema 1
    # is exactly what the pin exists to keep out: ingest refuses it, so a row
    # holding it is one no re-ingest could reproduce.
    bad.schema_version = 1

    with pytest.raises(LearningStoreError):
        store.upsert_patterns([good_a, bad, good_b])

    assert store.count() == 0


def test_cosine_search_excludes_source_orders_nearest_and_filters_tool_id(
    store: PostgresLearningStore,
) -> None:
    source = make_record(call_id="pg-src", tool_id="reader")
    near = make_record(call_id="pg-near", tool_id="reader", wall_ms=5100)
    far = make_record(
        call_id="pg-far",
        tool_id="reader",
        policy={"status": "denied", "reason": "blocked"},
        capability={"status": "denied", "reason": "policy blocked"},
        execution={"status": "host_denied", "reason": "not executed"},
        wall_ms=None,
        peak_memory_bytes=None,
    )
    other_tool = make_record(call_id="pg-other", tool_id="writer", wall_ms=5100)
    assert store.upsert_patterns([source, near, far, other_tool]) == 4

    neighbors = store.search_neighbors("pg-src")
    assert "pg-src" not in {n.call_id for n in neighbors}
    assert [n.call_id for n in neighbors] == ["pg-near", "pg-other", "pg-far"]
    assert neighbors == sorted(neighbors, key=lambda n: n.distance)
    assert neighbors[0].distance == pytest.approx(0.0, abs=1e-3)
    assert neighbors[0].feature_schema_version == 1
    assert neighbors[0].content["tool_id"] == "reader"

    filtered = store.search_neighbors("pg-src", tool_id="reader")
    assert {n.call_id for n in filtered} == {"pg-near", "pg-far"}

    assert len(store.search_neighbors("pg-src", limit=1)) == 1
    # Store-side clamp, independent of the API's 422.
    assert len(store.search_neighbors("pg-src", limit=999)) == 3


def test_batch_search_matches_single_search_and_omits_unknown_sources(
    store: PostgresLearningStore,
) -> None:
    """One round trip for N sources, with identical results to N queries."""
    records = [
        make_record(call_id="b-src", tool_id="reader"),
        make_record(call_id="b-near", tool_id="reader", wall_ms=5100),
        make_record(call_id="b-trap", tool_id="reader", execution={"status": "trap", "message": "x"}),
        make_record(call_id="b-other", tool_id="writer"),
    ]
    store.upsert_patterns(records)

    batched = store.search_neighbors_batch(
        ["b-src", "b-near", "b-never-ingested"], limit=5
    )
    # Unknown sources are omitted, never given an invented probe vector.
    assert set(batched) == {"b-src", "b-near"}
    for call_id in ("b-src", "b-near"):
        single = store.search_neighbors(call_id, limit=5)
        assert [n.call_id for n in batched[call_id]] == [n.call_id for n in single]
        for a, b in zip(batched[call_id], single):
            assert a.distance == pytest.approx(b.distance, abs=1e-9)
        assert call_id not in {n.call_id for n in batched[call_id]}

    assert store.search_neighbors_batch([]) == {}
    filtered = store.search_neighbors_batch(["b-src"], tool_id="writer")
    assert [n.call_id for n in filtered["b-src"]] == ["b-other"]


def test_stale_feature_schema_rows_are_neither_probe_nor_neighbor(
    store: PostgresLearningStore, database_url: str
) -> None:
    """Two layouts share one vector(16) column; comparing across them is noise."""
    import psycopg

    store.upsert_patterns(
        [make_record(call_id="v-stale"), make_record(call_id="v-a"), make_record(call_id="v-b")]
    )
    with psycopg.connect(database_url) as conn:
        conn.execute(
            "UPDATE learning_patterns SET feature_schema_version = 2 "
            "WHERE call_id = 'v-stale'"
        )

    with pytest.raises(SourcePatternNotFoundError):
        store.search_neighbors("v-stale")
    assert "v-stale" not in {n.call_id for n in store.search_neighbors("v-a")}
    assert "v-stale" not in store.search_neighbors_batch(["v-a", "v-stale"])


def test_unknown_source_call_is_not_found(store: PostgresLearningStore) -> None:
    store.upsert_patterns([make_record(call_id="pg-known")])
    with pytest.raises(SourcePatternNotFoundError):
        store.search_neighbors("pg-never-ingested")


def test_postgres_and_in_memory_agree_on_neighbor_order(
    store: PostgresLearningStore,
) -> None:
    """The in-memory test double must not diverge from the real operator."""
    records = [
        make_record(call_id="parity-src", tool_id="reader"),
        make_record(call_id="parity-near", tool_id="reader", wall_ms=5100),
        make_record(call_id="parity-mid", tool_id="reader", execution={"status": "trap", "message": "x"}),
        make_record(
            call_id="parity-far",
            tool_id="reader",
            policy={"status": "denied", "reason": "blocked"},
            capability={"status": "denied", "reason": "policy blocked"},
            execution={"status": "host_denied", "reason": "not executed"},
            wall_ms=None,
            peak_memory_bytes=None,
        ),
    ]
    store.upsert_patterns(records)
    memory = InMemoryLearningStore()
    memory.upsert_patterns(records)

    pg_order = [n.call_id for n in store.search_neighbors("parity-src")]
    mem_order = [n.call_id for n in memory.search_neighbors("parity-src")]
    assert pg_order == mem_order

    for pg_n, mem_n in zip(store.search_neighbors("parity-src"), memory.search_neighbors("parity-src")):
        # float32 storage vs float64 arithmetic — same distance to ~1e-6.
        assert pg_n.distance == pytest.approx(mem_n.distance, abs=1e-6)


def test_embedding_round_trips_at_the_declared_dimension(
    store: PostgresLearningStore, database_url: str
) -> None:
    import psycopg
    from pgvector.psycopg import register_vector

    record = make_record(call_id="pg-roundtrip")
    store.upsert_patterns([record])
    with psycopg.connect(database_url) as conn:
        register_vector(conn)
        row = conn.execute(
            "SELECT embedding FROM learning_patterns WHERE call_id = %s",
            ("pg-roundtrip",),
        ).fetchone()
    assert row is not None
    stored = row[0].to_list()
    assert len(stored) == VECTOR_DIMENSIONS
    for stored_value, expected in zip(stored, encode_pattern(record)):
        assert stored_value == pytest.approx(expected, abs=1e-6)


def test_database_error_raises_store_error_not_a_policy_decision(
    database_url: str,
) -> None:
    """A broken store surfaces as a store error — never as a policy decision.

    Points at the real host with a database that does not exist, so psycopg
    fails immediately and deterministically instead of hanging on a blackholed
    port.
    """
    base, _, query = database_url.partition("?")
    broken_url = base.rsplit("/", 1)[0] + "/aegis_governance_absent_db"
    if query:
        broken_url = f"{broken_url}?{query}"
    broken = PostgresLearningStore(broken_url)

    with pytest.raises(LearningStoreError):
        broken.upsert_patterns([make_record()])
    with pytest.raises(LearningStoreError):
        broken.search_neighbors("anything")
