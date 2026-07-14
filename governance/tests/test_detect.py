"""Rule-based drift detectors — pending_human findings only; never widen."""

from __future__ import annotations

from pathlib import Path

from aegis_governance.audit_ingest import ingest_jsonl
from aegis_governance.detect import FindingKind, FindingStatus, run_detectors

FIXTURES = Path(__file__).parent / "fixtures"


def test_capability_creep_detects_widened_grant() -> None:
    batch = ingest_jsonl((FIXTURES / "capability_creep.jsonl").read_text())
    findings = run_detectors(batch)
    creep = [f for f in findings if f.kind == FindingKind.CAPABILITY_CREEP]
    assert len(creep) == 1
    assert creep[0].status == FindingStatus.PENDING_HUMAN
    assert creep[0].tool_id == "reader"
    assert "fs.read_paths" in creep[0].evidence["axes"]
    assert "net.http" in creep[0].evidence["axes"]
    assert "max_memory_bytes" in creep[0].evidence["axes"]


def test_rate_spike_at_threshold() -> None:
    batch = ingest_jsonl((FIXTURES / "rate_spike.jsonl").read_text())
    findings = run_detectors(batch)
    spikes = [f for f in findings if f.kind == FindingKind.RATE_SPIKE]
    assert len(spikes) == 1
    assert spikes[0].status == FindingStatus.PENDING_HUMAN
    assert spikes[0].tool_id == "chatty"
    assert spikes[0].evidence["count"] == 3


def test_rate_spike_below_threshold_silent() -> None:
    lines = (FIXTURES / "rate_spike.jsonl").read_text().splitlines()[:2]
    batch = ingest_jsonl("\n".join(lines) + "\n")
    findings = run_detectors(batch)
    assert not [f for f in findings if f.kind == FindingKind.RATE_SPIKE]


def test_anomalous_allow_deny() -> None:
    batch = ingest_jsonl((FIXTURES / "anomalous_allow_deny.jsonl").read_text())
    findings = run_detectors(batch)
    anom = [f for f in findings if f.kind == FindingKind.ANOMALOUS_ALLOW_DENY]
    assert len(anom) == 1
    assert anom[0].status == FindingStatus.PENDING_HUMAN
    assert anom[0].tool_id == "flipper"
    assert anom[0].evidence["allowed_count"] == 3
    assert anom[0].evidence["denied_count"] == 3


def test_empty_buffer_quiet() -> None:
    batch = ingest_jsonl("")
    assert run_detectors(batch) == []


def test_findings_never_include_policy_yaml() -> None:
    batch = ingest_jsonl((FIXTURES / "capability_creep.jsonl").read_text())
    for finding in run_detectors(batch):
        assert finding.status == FindingStatus.PENDING_HUMAN
        assert "policy_yaml" not in finding.evidence
        assert "action" not in finding.evidence
        dumped = finding.to_dict()
        assert dumped["status"] == "pending_human"
        assert dumped["kind"] == "capability_creep"
