"""API smoke — health, ingest, floor, propose."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from aegis_governance.app import create_app

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


def test_health() -> None:
    client = TestClient(create_app())
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_get_floor() -> None:
    client = TestClient(create_app())
    r = client.get("/v1/floor")
    assert r.status_code == 200
    body = r.json()
    assert "never_auto_grant" in body
    assert "net" in body["never_auto_grant"]


def test_ingest_and_propose() -> None:
    client = TestClient(create_app())
    line = (FIXTURES / "resource_exceeded.json").read_text().strip()
    jsonl = "\n".join([line] * 3) + "\n"
    r = client.post("/v1/ingest", content=jsonl, headers={"content-type": "text/plain"})
    assert r.status_code == 200
    assert r.json()["outcomes"] == 3

    r = client.post(
        "/v1/propose",
        json={"current_policy_yaml": BASELINE},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "pending_human"
    assert body["policy_yaml"]
    assert body["rationale"]


def test_ingest_rejects_bad_schema() -> None:
    client = TestClient(create_app())
    bad = '{"schema_version":99,"phase":"intent","call_id":"x","tool_id":"t","input_digest":"d"}\n'
    r = client.post("/v1/ingest", content=bad, headers={"content-type": "text/plain"})
    assert r.status_code == 400


def test_propose_floor_violation_returns_409(monkeypatch) -> None:
    """If a widen reaches propose, floor check returns 409 — never auto-apply."""
    from aegis_governance.propose import Proposal, ProposalStatus

    widen = Proposal(
        status=ProposalStatus.PENDING_HUMAN,
        rationale="test widen",
        source_call_ids=["c1"],
        policy_yaml=(
            "version: 1\ndefault: deny\nrules:\n"
            "  - id: allow-net\n    action: allow\n"
            "    tool: fetcher\n    capability: net.http\n"
        ),
    )
    monkeypatch.setattr(
        "aegis_governance.app.propose_narrowing",
        lambda *_a, **_k: widen,
    )
    client = TestClient(create_app())
    r = client.post("/v1/propose", json={"current_policy_yaml": BASELINE})
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "floor_violation"
    assert r.json()["detail"]["status"] == "pending_human"


def test_detect_and_list_findings() -> None:
    client = TestClient(create_app())
    jsonl = (FIXTURES / "rate_spike.jsonl").read_text()
    r = client.post("/v1/ingest", content=jsonl, headers={"content-type": "text/plain"})
    assert r.status_code == 200

    r = client.post("/v1/detect")
    assert r.status_code == 200
    body = r.json()
    assert body["emitted"] >= 1
    assert all(f["status"] == "pending_human" for f in body["findings"])
    kinds = {f["kind"] for f in body["findings"]}
    assert "rate_spike" in kinds

    r = client.get("/v1/findings")
    assert r.status_code == 200
    listed = r.json()
    assert listed["count"] == body["buffer_findings"]
    assert all(f["status"] == "pending_human" for f in listed["findings"])


def test_detect_capability_creep_via_api() -> None:
    client = TestClient(create_app())
    jsonl = (FIXTURES / "capability_creep.jsonl").read_text()
    assert client.post("/v1/ingest", content=jsonl).status_code == 200
    body = client.post("/v1/detect").json()
    kinds = {f["kind"] for f in body["findings"]}
    assert "capability_creep" in kinds
