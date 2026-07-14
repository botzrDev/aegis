"""Guardian stub — passthrough only; no LLM providers in this slice."""

from __future__ import annotations

from pathlib import Path

from aegis_governance.audit_ingest import ingest_jsonl
from aegis_governance.detect import FindingKind, run_detectors
from aegis_governance.guardian import Guardian, NullGuardian

FIXTURES = Path(__file__).parent / "fixtures"


def test_null_guardian_passthrough() -> None:
    batch = ingest_jsonl((FIXTURES / "rate_spike.jsonl").read_text())
    raw = run_detectors(batch)
    reviewed = NullGuardian().review(raw, batch)
    assert len(reviewed) == len(raw)
    assert reviewed[0].kind == FindingKind.RATE_SPIKE
    assert reviewed is not raw  # new list


def test_guardian_protocol_satisfied() -> None:
    g: Guardian = NullGuardian()
    assert g.review([], ingest_jsonl("")) == []
