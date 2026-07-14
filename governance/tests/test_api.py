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

# Narrow snapshot for packs: keeps the allow, adds an explicit deny. Floor ACCEPTs.
NARROW = """\
version: 1
default: deny
rules:
  - id: allow-reader
    action: allow
    tool: reader
    limits: { max_memory_bytes: 1048576, max_wall_ms: 5000, max_output_bytes: 1048576 }
  - id: deny-fetcher
    action: deny
    tool: fetcher
    reason: repeated capability denials observed in audit ingest
"""

# Widen snapshot: mints a fresh net.http allow — a floor axis. Floor REJECTs → 409.
WIDEN = """\
version: 1
default: deny
rules:
  - id: allow-reader
    action: allow
    tool: reader
    limits: { max_memory_bytes: 1048576, max_wall_ms: 5000, max_output_bytes: 1048576 }
  - id: allow-net
    action: allow
    tool: fetcher
    capability: net.http
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


# --- AEG-26 slice 3: evolving policy packs ----------------------------------


def test_packs_create_list_get_ratify() -> None:
    client = TestClient(create_app())
    r = client.post(
        "/v1/packs",
        json={
            "current_policy_yaml": BASELINE,
            "policy_yaml": NARROW,
            "rationale": "tighten fetcher",
            "source_call_ids": ["c1", "c2"],
            "pack_id": "pack-reader",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "pending_human"  # human still ratifies after floor ACCEPT
    assert body["version"] == 1
    assert body["parent_version"] is None
    assert body["source_call_ids"] == ["c1", "c2"]

    # list — all versions, newest first
    r = client.get("/v1/packs")
    assert r.status_code == 200
    assert r.json()["count"] == 1

    # get latest for id
    r = client.get("/v1/packs/pack-reader")
    assert r.status_code == 200
    assert r.json()["version"] == 1

    # get exact version
    r = client.get("/v1/packs/pack-reader/versions/1")
    assert r.status_code == 200

    # ratify accept — governance-only status flip
    r = client.post("/v1/packs/pack-reader/versions/1/ratify", json={"accept": True})
    assert r.status_code == 200
    assert r.json()["status"] == "accepted"

    # double ratify → 409 (terminal)
    r = client.post("/v1/packs/pack-reader/versions/1/ratify", json={"accept": True})
    assert r.status_code == 409


def test_packs_ratify_reject() -> None:
    client = TestClient(create_app())
    client.post(
        "/v1/packs",
        json={
            "current_policy_yaml": BASELINE,
            "policy_yaml": NARROW,
            "rationale": "tighten",
            "source_call_ids": ["c1"],
            "pack_id": "pack-reader",
        },
    )
    r = client.post("/v1/packs/pack-reader/versions/1/ratify", json={"accept": False})
    assert r.status_code == 200
    assert r.json()["status"] == "rejected"


def test_packs_widen_returns_409_and_is_not_stored() -> None:
    client = TestClient(create_app())
    r = client.post(
        "/v1/packs",
        json={
            "current_policy_yaml": BASELINE,
            "policy_yaml": WIDEN,
            "rationale": "widen attempt",
            "source_call_ids": ["c1"],
        },
    )
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "floor_violation"
    assert r.json()["detail"]["status"] == "pending_human"
    # REJECT never stores.
    assert client.get("/v1/packs").json()["count"] == 0


def test_pack_version_lineage_via_api() -> None:
    client = TestClient(create_app())
    payload = {
        "current_policy_yaml": BASELINE,
        "policy_yaml": NARROW,
        "rationale": "tighten",
        "source_call_ids": ["c1"],
        "pack_id": "pack-x",
    }
    r1 = client.post("/v1/packs", json=payload)
    assert r1.json()["version"] == 1
    r2 = client.post("/v1/packs", json=payload)
    assert r2.json()["version"] == 2
    assert r2.json()["parent_version"] == 1
    # latest for id is v2
    assert client.get("/v1/packs/pack-x").json()["version"] == 2


def test_pack_missing_returns_404() -> None:
    client = TestClient(create_app())
    assert client.get("/v1/packs/nope").status_code == 404
    assert client.get("/v1/packs/nope/versions/1").status_code == 404
    r = client.post("/v1/packs/nope/versions/1/ratify", json={"accept": True})
    assert r.status_code == 404


def test_ingest_propose_then_pack_from_proposal() -> None:
    """ingest + propose → POST /v1/packs with the proposal payload → ratify."""
    client = TestClient(create_app())
    line = (FIXTURES / "resource_exceeded.json").read_text().strip()
    jsonl = "\n".join([line] * 3) + "\n"
    client.post("/v1/ingest", content=jsonl, headers={"content-type": "text/plain"})

    pr = client.post("/v1/propose", json={"current_policy_yaml": BASELINE}).json()
    r = client.post(
        "/v1/packs",
        json={
            "current_policy_yaml": BASELINE,
            "policy_yaml": pr["policy_yaml"],
            "rationale": pr["rationale"],
            "source_call_ids": pr["source_call_ids"],
        },
    )
    assert r.status_code == 200
    pack = r.json()
    assert pack["status"] == "pending_human"

    r = client.post(
        f"/v1/packs/{pack['pack_id']}/versions/{pack['version']}/ratify",
        json={"accept": True},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "accepted"
