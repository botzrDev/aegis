"""Narrow-only proposals — never expand ambient authority; pending_human only."""

from __future__ import annotations

from pathlib import Path

from aegis_governance.audit_ingest import ingest_jsonl
from aegis_governance.policy_floor import FloorDecision, check_floor
from aegis_governance.propose import ProposalStatus, propose_narrowing

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


def test_resource_exceeded_proposes_lower_max_wall_ms() -> None:
    # Repeat the resource_exceeded golden enough times to trip the rule.
    line = (FIXTURES / "resource_exceeded.json").read_text().strip()
    jsonl = "\n".join([line] * 3) + "\n"
    batch = ingest_jsonl(jsonl)
    proposal = propose_narrowing(batch, current_policy_yaml=BASELINE)
    assert proposal is not None
    assert proposal.status == ProposalStatus.PENDING_HUMAN
    assert "call-golden-6" in proposal.source_call_ids
    assert proposal.rationale
    assert "max_wall_ms" in proposal.policy_yaml
    # Must tighten relative to baseline
    assert "1000" in proposal.policy_yaml or "2500" in proposal.policy_yaml
    floor = check_floor(BASELINE, proposal.policy_yaml)
    assert floor.decision == FloorDecision.ACCEPT


def test_capability_denials_propose_deny_rule() -> None:
    line = (FIXTURES / "capability_denied.json").read_text().strip()
    jsonl = "\n".join([line] * 3) + "\n"
    batch = ingest_jsonl(jsonl)
    proposal = propose_narrowing(batch, current_policy_yaml=BASELINE)
    assert proposal is not None
    assert proposal.status == ProposalStatus.PENDING_HUMAN
    assert "action: deny" in proposal.policy_yaml
    assert "missing" in proposal.policy_yaml
    floor = check_floor(BASELINE, proposal.policy_yaml)
    assert floor.decision == FloorDecision.ACCEPT


def test_never_proposes_allow_that_expands_authority() -> None:
    text = (FIXTURES / "sample.jsonl").read_text()
    batch = ingest_jsonl(text)
    proposal = propose_narrowing(batch, current_policy_yaml=BASELINE)
    if proposal is None:
        return
    # No new ambient allow for net/exec; any allow must only tighten limits
    assert "capability: net" not in proposal.policy_yaml
    assert "capability: exec" not in proposal.policy_yaml
    assert proposal.status == ProposalStatus.PENDING_HUMAN


def test_empty_buffer_returns_none() -> None:
    from aegis_governance.audit_ingest import IngestBatch

    assert propose_narrowing(IngestBatch(intents=[], outcomes=[]), BASELINE) is None
