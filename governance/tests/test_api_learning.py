"""API wiring for the learning fabric (AEG-32 slice 4).

Uses the in-process `LearningStore` so the whole file runs without Docker; the
real `vector(16)` column and `<=>` operator are covered by
`test_learning_postgres.py` against pgvector/pgvector:pg16.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Sequence

from fastapi.testclient import TestClient

from aegis_governance.app import GovernanceState, create_app
from aegis_governance.audit_ingest import ingest_jsonl
from aegis_governance.learning import (
    InMemoryLearningStore,
    LearningStoreError,
    PatternNeighbor,
)

FIXTURES = Path(__file__).parent / "fixtures"

BASELINE = """\
version: 1
default: deny
rules:
  - id: allow-reader
    action: allow
    tool: reader
    limits: { max_memory_bytes: 1048576, max_wall_ms: 5000, max_output_bytes: 1048576 }
"""


def outcomes_jsonl(fixture: str, call_ids: Sequence[str]) -> str:
    """One fixture outcome replayed under distinct call ids."""
    template = json.loads((FIXTURES / fixture).read_text())
    lines = []
    for call_id in call_ids:
        record = dict(template)
        record["call_id"] = call_id
        lines.append(json.dumps(record))
    return "\n".join(lines) + "\n"


class OrderRecordingStore(InMemoryLearningStore):
    """Records how full the in-memory buffer was when persistence ran."""

    def __init__(self, state: GovernanceState) -> None:
        super().__init__()
        self._state = state
        self.buffer_outcomes_at_persist: Optional[int] = None

    def upsert_patterns(self, records):  # type: ignore[no-untyped-def]
        self.buffer_outcomes_at_persist = len(self._state.buffer.outcomes)
        return super().upsert_patterns(records)


class SearchRecordingStore(InMemoryLearningStore):
    """Records whether the proposal path ever reached a neighbor lookup."""

    def __init__(self) -> None:
        super().__init__()
        self.searched = False

    def search_neighbors(self, call_id, *, tool_id=None, limit=10):  # type: ignore[no-untyped-def]
        self.searched = True
        return super().search_neighbors(call_id, tool_id=tool_id, limit=limit)

    def search_neighbors_batch(self, call_ids, *, tool_id=None, limit=10):  # type: ignore[no-untyped-def]
        self.searched = True
        return super().search_neighbors_batch(call_ids, tool_id=tool_id, limit=limit)


class UnavailableLearningStore:
    """A configured store that is down. Not a stand-in for pgvector semantics."""

    mode = "unavailable"

    def upsert_patterns(self, records) -> int:  # type: ignore[no-untyped-def]
        raise LearningStoreError("store is down")

    def search_neighbors(
        self, call_id: str, *, tool_id: Optional[str] = None, limit: int = 10
    ) -> list[PatternNeighbor]:
        raise LearningStoreError("store is down")

    def search_neighbors_batch(
        self, call_ids, *, tool_id: Optional[str] = None, limit: int = 10
    ) -> dict[str, list[PatternNeighbor]]:
        raise LearningStoreError("store is down")


def test_health_reports_learning_store_mode() -> None:
    client = TestClient(create_app(learning_store=InMemoryLearningStore()))
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["learning_store"] == "memory"  # mode only, never the URL


def test_ingest_persists_patterns_before_extending_the_buffer() -> None:
    state = GovernanceState()
    store = OrderRecordingStore(state)
    client = TestClient(create_app(state=state, learning_store=store))

    jsonl = outcomes_jsonl("resource_exceeded.json", ["c1", "c2", "c3"])
    r = client.post("/v1/ingest", content=jsonl, headers={"content-type": "text/plain"})

    assert r.status_code == 200
    body = r.json()
    assert body["outcomes"] == 3
    assert body["patterns_persisted"] == 3
    assert body["buffer_outcomes"] == 3
    # Persistence ran first: the buffer was still empty at that moment.
    assert store.buffer_outcomes_at_persist == 0
    assert store.count() == 3


def test_store_failure_returns_503_and_leaves_the_buffer_untouched() -> None:
    state = GovernanceState()
    client = TestClient(create_app(state=state, learning_store=UnavailableLearningStore()))

    jsonl = outcomes_jsonl("resource_exceeded.json", ["c1", "c2", "c3"])
    r = client.post("/v1/ingest", content=jsonl, headers={"content-type": "text/plain"})

    assert r.status_code == 503
    assert r.json()["detail"]["error"] == "learning_store_unavailable"
    # No partial update on either side.
    assert state.buffer.outcomes == []
    assert state.buffer.intents == []


def test_patterns_search_returns_neighbors_and_excludes_the_source() -> None:
    client = TestClient(create_app(learning_store=InMemoryLearningStore()))
    client.post(
        "/v1/ingest",
        content=outcomes_jsonl("resource_exceeded.json", ["c1", "c2"])
        + outcomes_jsonl("trap.json", ["c3"]),
        headers={"content-type": "text/plain"},
    )

    r = client.post("/v1/patterns/search", json={"call_id": "c1", "limit": 10})
    assert r.status_code == 200
    body = r.json()
    assert body["call_id"] == "c1"
    call_ids = [n["call_id"] for n in body["neighbors"]]
    assert "c1" not in call_ids
    assert call_ids[0] == "c2"  # identical outcome shape → nearest
    first = body["neighbors"][0]
    assert set(first) == {
        "pattern_id",
        "call_id",
        "tool_id",
        "distance",
        "feature_schema_version",
        "content",
    }
    assert first["feature_schema_version"] == 1
    assert first["distance"] <= body["neighbors"][-1]["distance"]


def test_patterns_search_filters_by_tool_id() -> None:
    client = TestClient(create_app(learning_store=InMemoryLearningStore()))
    client.post(
        "/v1/ingest",
        content=outcomes_jsonl("resource_exceeded.json", ["c1", "c2"])
        + outcomes_jsonl("capability_denied.json", ["c9"]),
        headers={"content-type": "text/plain"},
    )

    r = client.post("/v1/patterns/search", json={"call_id": "c1", "tool_id": "reader"})
    assert r.status_code == 200
    assert [n["call_id"] for n in r.json()["neighbors"]] == ["c2"]

    r = client.post("/v1/patterns/search", json={"call_id": "c1", "tool_id": "missing"})
    assert [n["call_id"] for n in r.json()["neighbors"]] == ["c9"]


def test_patterns_search_unknown_source_is_404_and_bad_limit_is_422() -> None:
    client = TestClient(create_app(learning_store=InMemoryLearningStore()))
    client.post(
        "/v1/ingest",
        content=outcomes_jsonl("resource_exceeded.json", ["c1"]),
        headers={"content-type": "text/plain"},
    )

    assert client.post("/v1/patterns/search", json={"call_id": "nope"}).status_code == 404
    for bad in (0, -1, 51, 1000):
        r = client.post("/v1/patterns/search", json={"call_id": "c1", "limit": bad})
        assert r.status_code == 422, bad


def test_patterns_search_503_when_the_store_is_down() -> None:
    client = TestClient(create_app(learning_store=UnavailableLearningStore()))
    r = client.post("/v1/patterns/search", json={"call_id": "c1"})
    assert r.status_code == 503
    assert r.json()["detail"]["error"] == "learning_store_unavailable"


def test_propose_attaches_learning_evidence() -> None:
    client = TestClient(create_app(learning_store=InMemoryLearningStore()))
    client.post(
        "/v1/ingest",
        content=outcomes_jsonl("resource_exceeded.json", ["c1", "c2", "c3"]),
        headers={"content-type": "text/plain"},
    )

    r = client.post("/v1/propose", json={"current_policy_yaml": BASELINE})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "pending_human"
    assert sorted(body["source_call_ids"]) == ["c1", "c2", "c3"]

    evidence = body["learning_evidence"]
    assert evidence, "nearest stored patterns should be attached as evidence"
    for item in evidence:
        assert set(item) == {"pattern_id", "call_id", "tool_id", "distance"}
        assert item["call_id"] in {"c1", "c2", "c3"}
        # Evidence is a pointer, not a policy fragment.
        assert "policy_yaml" not in item
        assert "action" not in item


def test_neighbors_do_not_change_policy_yaml_status_or_floor() -> None:
    """Same buffer, populated vs empty store → byte-identical proposal."""
    batch = ingest_jsonl(outcomes_jsonl("resource_exceeded.json", ["c1", "c2", "c3"]))

    with_patterns = GovernanceState()
    with_patterns.buffer.extend(batch)
    populated = InMemoryLearningStore()
    populated.upsert_patterns(batch.outcomes)
    rich = TestClient(create_app(state=with_patterns, learning_store=populated))

    without_patterns = GovernanceState()
    without_patterns.buffer.extend(
        ingest_jsonl(outcomes_jsonl("resource_exceeded.json", ["c1", "c2", "c3"]))
    )
    bare = TestClient(
        create_app(state=without_patterns, learning_store=InMemoryLearningStore())
    )

    rich_body = rich.post("/v1/propose", json={"current_policy_yaml": BASELINE}).json()
    bare_body = bare.post("/v1/propose", json={"current_policy_yaml": BASELINE}).json()

    assert rich_body["learning_evidence"] != []
    assert bare_body["learning_evidence"] == []
    # Neighbors are evidence only: nothing else about the proposal moves.
    assert rich_body["policy_yaml"] == bare_body["policy_yaml"]
    assert rich_body["status"] == bare_body["status"] == "pending_human"
    assert rich_body["rationale"] == bare_body["rationale"]
    assert rich_body["source_call_ids"] == bare_body["source_call_ids"]
    # Narrowing only — a neighbor never mints a new allow or relaxes a limit.
    assert rich_body["policy_yaml"].count("action: allow") == 1
    assert "max_wall_ms: 2500" in rich_body["policy_yaml"]  # tightened from 5000
    assert "max_wall_ms: 5000" not in rich_body["policy_yaml"]


def test_floor_violation_still_409_and_evidence_cannot_widen_or_auto_apply(
    monkeypatch,
) -> None:
    from aegis_governance.propose import Proposal, ProposalStatus

    widen = Proposal(
        status=ProposalStatus.PENDING_HUMAN,
        rationale="test widen",
        source_call_ids=["c1", "c2", "c3"],
        policy_yaml=(
            "version: 1\ndefault: deny\nrules:\n"
            "  - id: allow-net\n    action: allow\n"
            "    tool: fetcher\n    capability: net.http\n"
        ),
    )
    monkeypatch.setattr(
        "aegis_governance.app.propose_narrowing", lambda *_a, **_k: widen
    )

    store = SearchRecordingStore()
    client = TestClient(create_app(learning_store=store))
    client.post(
        "/v1/ingest",
        content=outcomes_jsonl("resource_exceeded.json", ["c1", "c2", "c3"]),
        headers={"content-type": "text/plain"},
    )
    assert store.count() == 3  # neighbors exist and are still powerless
    store.searched = False

    r = client.post("/v1/propose", json={"current_policy_yaml": BASELINE})
    assert r.status_code == 409
    body = r.json()
    assert body["detail"]["error"] == "floor_violation"
    assert body["detail"]["status"] == "pending_human"
    # Order proof: the floor rejected before the store was ever consulted, so
    # no neighbor could have softened the rejection.
    assert store.searched is False
    # Nothing resembling an applied policy is anywhere in the 409 body.
    assert "policy_yaml" not in json.dumps(body)
    assert "learning_evidence" not in json.dumps(body)


def test_propose_consults_the_store_only_after_the_floor_accepts() -> None:
    """The mirror of the 409 case: an accepted proposal does reach the store."""
    store = SearchRecordingStore()
    client = TestClient(create_app(learning_store=store))
    client.post(
        "/v1/ingest",
        content=outcomes_jsonl("resource_exceeded.json", ["c1", "c2", "c3"]),
        headers={"content-type": "text/plain"},
    )
    store.searched = False

    r = client.post("/v1/propose", json={"current_policy_yaml": BASELINE})
    assert r.status_code == 200
    assert store.searched is True
    assert r.json()["learning_evidence"]
