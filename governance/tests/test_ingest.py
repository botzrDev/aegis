"""Audit JSONL ingest — schema v1 only; treat input as untrusted."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis_governance.audit_ingest import IngestError, ingest_jsonl

FIXTURES = Path(__file__).parent / "fixtures"


def test_ingest_sample_jsonl_parses_intent_and_outcomes() -> None:
    text = (FIXTURES / "sample.jsonl").read_text()
    batch = ingest_jsonl(text)
    assert len(batch.intents) == 1
    assert len(batch.outcomes) == 6
    assert batch.intents[0].call_id == "call-golden-intent"
    assert batch.outcomes[0].tool_id == "smoke"
    # Post-AEG-24 grants carry max_output_bytes
    granted = next(
        o for o in batch.outcomes if o.capability.status == "granted"
    )
    assert granted.capability.grant is not None
    assert granted.capability.grant.max_output_bytes == 1_048_576


def test_reject_schema_version_not_one() -> None:
    bad = '{"schema_version":2,"phase":"intent","call_id":"x","tool_id":"t","input_digest":"d"}\n'
    with pytest.raises(IngestError, match="schema_version"):
        ingest_jsonl(bad)


def test_reject_outcome_missing_required_fields() -> None:
    # Missing policy/capability/execution
    bad = (
        '{"schema_version":1,"phase":"outcome","call_id":"x",'
        '"tool_id":"t","input_digest":"d"}\n'
    )
    with pytest.raises(IngestError):
        ingest_jsonl(bad)


def test_ignore_unknown_fields_forward_compat() -> None:
    line = (
        '{"schema_version":1,"phase":"intent","call_id":"c1","tool_id":"t",'
        '"input_digest":"d","future_field":true}\n'
    )
    batch = ingest_jsonl(line)
    assert len(batch.intents) == 1


def test_reject_malformed_json() -> None:
    with pytest.raises(IngestError):
        ingest_jsonl("{not json}\n")
