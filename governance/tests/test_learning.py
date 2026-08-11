"""Feature schema v1 encoder + in-memory learning store (AEG-32 slice 4)."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from aegis_governance.learning import (
    CAPABILITY_STATUSES,
    EXECUTION_STATUSES,
    FEATURE_SCHEMA_VERSION,
    MAX_OUTPUT_BYTES_BOUND,
    PEAK_MEMORY_BYTES_BOUND,
    POLICY_STATUSES,
    VECTOR_DIMENSIONS,
    WALL_MS_BOUND,
    InMemoryLearningStore,
    SourcePatternNotFoundError,
    canonical_content,
    clamp_search_limit,
    encode_pattern,
    pattern_from_record,
    pattern_id_for,
)
from aegis_governance.models import AuditRecord

FIXTURES = Path(__file__).parent / "fixtures"

POLICY_BASE = 0
CAPABILITY_BASE = len(POLICY_STATUSES)
EXECUTION_BASE = CAPABILITY_BASE + len(CAPABILITY_STATUSES)
FS_READ_IDX = EXECUTION_BASE + len(EXECUTION_STATUSES)
FS_WRITE_IDX = FS_READ_IDX + 1
NET_HTTP_IDX = FS_WRITE_IDX + 1
WALL_IDX = NET_HTTP_IDX + 1
MEMORY_IDX = WALL_IDX + 1
OUTPUT_IDX = MEMORY_IDX + 1


def load_fixture(name: str) -> AuditRecord:
    return AuditRecord.model_validate(json.loads((FIXTURES / name).read_text()))


def make_record(**overrides) -> AuditRecord:
    """A granted/success outcome with resource metrics, for the metric axes."""
    base = {
        "schema_version": 2,
        "line_type": "outcome",
        "seq": 0,
        "prev_hash": "00" * 32,
        "call_id": "call-synth-1",
        "tool_id": "reader",
        "request_digest": "ab" * 32,
        "policy_set_hash": "11" * 32,
        "decision_axes": {},
        "signature": "22" * 64,
        "key_id": "33" * 32,
        "policy": {"status": "allowed"},
        "capability": {
            "status": "granted",
            "grant": {
                "grant_id": "g-1",
                "tool_id": "reader",
                "fs": {"read_paths": ["/fixtures"], "write_paths": []},
                "net": {"http": []},
                "max_memory_bytes": 1048576,
                "max_wall_ms": 5000,
                "max_output_bytes": 1048576,
            },
        },
        "execution": {"status": "success"},
        "wall_ms": 5000,
        "peak_memory_bytes": 1048576,
    }
    base.update(overrides)
    return AuditRecord.model_validate(base)


# --- encoder ----------------------------------------------------------------


def test_encoder_is_deterministic_sized_and_bounded() -> None:
    record = load_fixture("resource_exceeded.json")
    first = encode_pattern(record)
    second = encode_pattern(AuditRecord.model_validate(record.model_dump()))

    assert first == second, "the same outcome must encode identically"
    assert len(first) == VECTOR_DIMENSIONS == 16
    assert all(isinstance(v, float) for v in first)
    assert all(0.0 <= v <= 1.0 for v in first), "every axis is clamped to [0, 1]"
    # Identity is derived from call_id, so re-ingest is stable across processes.
    # Pinned to a literal: a namespace change would silently orphan every
    # already-stored pattern_id.
    assert str(pattern_id_for("call-golden-6")) == "594e971b-73f0-5a72-873a-6a72c4fdbb41"


def test_version_pins_moved_only_where_the_meaning_moved() -> None:
    """Audit v1 → v2 changed the wire, not the vector (AILAB-624).

    Every axis reads a field schema 2 kept under the same name with the same
    meaning, so the layout is untouched and the golden vectors below are
    byte-identical to their pre-migration values. Bumping the feature version
    would have hidden every already-stored row — searches pin to the current
    version — for a layout that did not actually change.
    """
    from aegis_governance.audit_ingest import SUPPORTED_SCHEMA_VERSION
    from aegis_governance.learning import AUDIT_SCHEMA_VERSION

    assert FEATURE_SCHEMA_VERSION == 1
    # A stored row can only hold a wire version ingest accepts.
    assert AUDIT_SCHEMA_VERSION == SUPPORTED_SCHEMA_VERSION == 2


# Golden vectors. These pin index → meaning for feature schema v1, which the
# derived-index tests below cannot: they read the same constants the encoder
# does, so reordering POLICY_STATUSES or EXECUTION_STATUSES would keep them
# green while silently changing what every stored vector means.
#
# Unchanged across the audit v1 → v2 migration, on purpose: the fixtures under
# them were rewritten to the v2 wire, and every expected vector stayed the
# same. That is the evidence for keeping FEATURE_SCHEMA_VERSION at 1.
GOLDEN_MAX_OUTPUT = 0.6666667124988269  # log1p(2^20) / log1p(2^30)
GOLDEN_VECTORS: dict[str, tuple[float, ...]] = {
    # policy allowed | capability granted | execution resource_exceeded | fs+net
    "resource_exceeded.json": (
        1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0,
        1.0, 1.0, 1.0, 0.0, 0.0, GOLDEN_MAX_OUTPUT,
    ),
    # policy denied | capability denied | execution host_denied | no grant
    "policy_deny.json": (
        0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    ),
    # policy rate_limited
    "rate_limit.json": (
        0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    ),
    # policy pending_approval
    "pending_approval.json": (
        0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    ),
    # execution trap
    "trap.json": (
        1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0,
        1.0, 1.0, 1.0, 0.0, 0.0, GOLDEN_MAX_OUTPUT,
    ),
    # capability denied while policy allowed
    "capability_denied.json": (
        1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    ),
}


@pytest.mark.parametrize("fixture,expected", sorted(GOLDEN_VECTORS.items()))
def test_golden_vectors_pin_the_frozen_layout(
    fixture: str, expected: tuple[float, ...]
) -> None:
    """Changing any axis's position must break the build, not the corpus.

    Feature schema v1 is frozen: a reorder needs FEATURE_SCHEMA_VERSION = 2,
    not an edit in place, or already-stored vectors change meaning silently.
    """
    assert encode_pattern(load_fixture(fixture)) == pytest.approx(expected, abs=1e-12)


@pytest.mark.parametrize(
    "fixture,status",
    [
        ("policy_deny.json", "denied"),
        ("rate_limit.json", "rate_limited"),
        ("pending_approval.json", "pending_approval"),
        ("resource_exceeded.json", "allowed"),
    ],
)
def test_policy_axis_one_hot(fixture: str, status: str) -> None:
    vector = encode_pattern(load_fixture(fixture))
    block = vector[POLICY_BASE:CAPABILITY_BASE]
    assert sum(block) == 1.0
    assert block[POLICY_STATUSES.index(status)] == 1.0


@pytest.mark.parametrize(
    "fixture,status",
    [
        ("resource_exceeded.json", "resource_exceeded"),
        ("trap.json", "trap"),
        ("capability_denied.json", "host_denied"),
    ],
)
def test_execution_axis_one_hot(fixture: str, status: str) -> None:
    vector = encode_pattern(load_fixture(fixture))
    block = vector[EXECUTION_BASE:FS_READ_IDX]
    assert sum(block) == 1.0
    assert block[EXECUTION_STATUSES.index(status)] == 1.0


def test_capability_grant_and_metric_axes() -> None:
    granted = encode_pattern(load_fixture("resource_exceeded.json"))
    assert granted[CAPABILITY_BASE] == 1.0  # granted
    assert granted[CAPABILITY_BASE + 1] == 0.0  # denied
    assert granted[FS_READ_IDX] == 1.0
    assert granted[FS_WRITE_IDX] == 1.0
    assert granted[NET_HTTP_IDX] == 1.0
    # No metrics on the fixture; missing encodes as zero, never as noise.
    assert granted[WALL_IDX] == 0.0
    assert granted[MEMORY_IDX] == 0.0
    # log1p(2^20) / log1p(2^30) ≈ 2/3 for max_output_bytes = 1 MiB.
    assert granted[OUTPUT_IDX] == pytest.approx(2 / 3, abs=1e-4)

    denied = encode_pattern(load_fixture("capability_denied.json"))
    assert denied[CAPABILITY_BASE] == 0.0
    assert denied[CAPABILITY_BASE + 1] == 1.0
    # No grant → every grant-shaped axis is zero.
    assert denied[FS_READ_IDX] == denied[FS_WRITE_IDX] == denied[NET_HTTP_IDX] == 0.0
    assert denied[OUTPUT_IDX] == 0.0

    metrics = encode_pattern(make_record())
    assert metrics[WALL_IDX] == pytest.approx(
        math.log1p(5000) / math.log1p(WALL_MS_BOUND), abs=1e-9
    )
    assert metrics[MEMORY_IDX] == pytest.approx(
        math.log1p(1048576) / math.log1p(PEAK_MEMORY_BYTES_BOUND), abs=1e-9
    )
    assert metrics[FS_WRITE_IDX] == 0.0  # empty write_paths is not "present"
    assert metrics[NET_HTTP_IDX] == 0.0


def test_metric_axes_clamp_beyond_documented_bounds() -> None:
    huge = make_record(
        wall_ms=WALL_MS_BOUND * 1000,
        peak_memory_bytes=PEAK_MEMORY_BYTES_BOUND * 1000,
    )
    vector = encode_pattern(huge)
    assert vector[WALL_IDX] == 1.0
    assert vector[MEMORY_IDX] == 1.0
    negative = make_record(wall_ms=-5, peak_memory_bytes=0)
    assert encode_pattern(negative)[WALL_IDX] == 0.0
    assert encode_pattern(negative)[MEMORY_IDX] == 0.0

    # Dim 15 clamps on its own bound too — a huge grant must not exceed 1.0.
    big_grant = make_record()
    big_grant.capability.grant.max_output_bytes = MAX_OUTPUT_BYTES_BOUND * 1000
    assert encode_pattern(big_grant)[OUTPUT_IDX] == 1.0


def test_tool_id_is_not_hashed_into_the_vector() -> None:
    """tool_id stays a column/filter — similarity must not blur tool identity."""
    a = make_record(tool_id="reader")
    b = make_record(tool_id="writer", call_id="call-synth-2")
    assert encode_pattern(a) == encode_pattern(b)
    assert pattern_from_record(a).tool_id == "reader"
    assert pattern_from_record(b).tool_id == "writer"


def test_canonical_content_has_no_raw_prompt_output_or_source_fields() -> None:
    content = canonical_content(load_fixture("resource_exceeded.json"))
    assert set(content) == {
        "call_id",
        "tool_id",
        # Renamed with the wire in schema 2; `input_digest` is gone.
        "request_digest",
        "audit_schema_version",
        "feature_schema_version",
        "policy_status",
        "capability_status",
        "execution_status",
        "grant",
        "wall_ms",
        "peak_memory_bytes",
    }
    forbidden = {
        "raw_input",
        "raw_output",
        "prompt",
        "prompt_text",
        "output",
        "output_digest",
        "agent_id",
        "project_id",
        "source_text",
        "reason",
        "message",
    }
    blob = json.dumps(content)
    # Nested too, not just at the top level — the grant shape is a dict.
    assert not forbidden & set(content)
    assert not forbidden & set(content["grant"])
    # Grant shape only — counts and limits, never the granted path strings.
    assert content["grant"]["fs_read_path_count"] == 1
    assert content["grant"]["net_http_entry_count"] == 1
    assert "/fixtures" not in blob
    assert "api.example.com" not in blob
    assert content["feature_schema_version"] == FEATURE_SCHEMA_VERSION
    assert content["audit_schema_version"] == 2
    # Free-text runtime reasons never reach the durable store.
    assert "guest trapped" not in json.dumps(canonical_content(load_fixture("trap.json")))


# --- in-memory store --------------------------------------------------------


def test_upsert_is_idempotent_by_call_id() -> None:
    store = InMemoryLearningStore()
    record = load_fixture("resource_exceeded.json")
    assert store.upsert_patterns([record, record, record]) == 1
    assert store.count() == 1
    store.upsert_patterns([record])
    assert store.count() == 1
    stored = store.get(record.call_id)
    assert stored is not None
    assert stored.pattern_id == str(pattern_id_for(record.call_id))


def test_search_excludes_source_orders_nearest_first_and_filters_tool_id() -> None:
    store = InMemoryLearningStore()
    source = make_record(call_id="src", tool_id="reader")
    near = make_record(call_id="near", tool_id="reader", wall_ms=5100)
    far = make_record(
        call_id="far",
        tool_id="reader",
        policy={"status": "denied", "reason": "blocked"},
        capability={"status": "denied", "reason": "policy blocked"},
        execution={"status": "host_denied", "reason": "not executed"},
        wall_ms=None,
        peak_memory_bytes=None,
    )
    other_tool = make_record(call_id="other", tool_id="writer", wall_ms=5100)
    store.upsert_patterns([source, near, far, other_tool])

    neighbors = store.search_neighbors("src")
    assert [n.call_id for n in neighbors] == ["near", "other", "far"]
    assert "src" not in {n.call_id for n in neighbors}
    assert neighbors[0].distance <= neighbors[-1].distance

    filtered = store.search_neighbors("src", tool_id="reader")
    assert {n.call_id for n in filtered} == {"near", "far"}

    assert len(store.search_neighbors("src", limit=1)) == 1


def test_unknown_source_call_raises_instead_of_probing_a_zero_vector() -> None:
    store = InMemoryLearningStore()
    store.upsert_patterns([make_record()])
    with pytest.raises(SourcePatternNotFoundError):
        store.search_neighbors("call-that-was-never-ingested")


def test_search_limit_is_clamped() -> None:
    assert clamp_search_limit(0) == 1
    assert clamp_search_limit(-7) == 1
    assert clamp_search_limit(10) == 10
    assert clamp_search_limit(999) == 50


def test_batch_search_omits_unknown_sources_and_matches_single_search() -> None:
    store = InMemoryLearningStore()
    store.upsert_patterns(
        [
            make_record(call_id="s1", tool_id="reader"),
            make_record(call_id="s2", tool_id="reader", wall_ms=5100),
        ]
    )
    batched = store.search_neighbors_batch(["s1", "s2", "never-ingested"])
    assert set(batched) == {"s1", "s2"}
    assert batched["s1"] == store.search_neighbors("s1")
    assert store.search_neighbors_batch([]) == {}


# --- store configuration ----------------------------------------------------


def test_conninfo_adds_timeouts_without_overriding_the_operator() -> None:
    """A blackholed database must raise, not park a threadpool worker forever."""
    from psycopg.conninfo import conninfo_to_dict

    from aegis_governance.learning_postgres import (
        CONNECT_TIMEOUT_SECONDS,
        STATEMENT_TIMEOUT_MS,
        build_conninfo,
    )

    defaults = conninfo_to_dict(
        build_conninfo("postgresql://u:p@example-host:5432/db")
    )
    assert defaults["connect_timeout"] == str(CONNECT_TIMEOUT_SECONDS)
    assert f"statement_timeout={STATEMENT_TIMEOUT_MS}" in defaults["options"]
    assert defaults["dbname"] == "db"  # the rest of the URL survives intact

    explicit = conninfo_to_dict(
        build_conninfo(
            "postgresql://u:p@example-host:5432/db"
            "?connect_timeout=30&options=-c%20statement_timeout%3D1000"
        )
    )
    assert explicit["connect_timeout"] == "30"
    assert "statement_timeout=1000" in explicit["options"]
