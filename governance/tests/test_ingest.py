"""Audit JSONL ingest — schema v2 only; treat input as untrusted.

Three rejection classes are load-bearing and tested separately: wrong version
aborts, a missing chain field aborts, an unrecognised line type does **not**.
Collapsing the third into the second would make every future line type a
breaking change (SPEC §5.2).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_governance.audit_ingest import (
    MAX_SAFE_INTEGER,
    SUPPORTED_SCHEMA_VERSION,
    IngestError,
    ingest_jsonl,
)
from aegis_governance.models import AuditIntent


def outcome_with(**overrides) -> str:
    """A real golden outcome, minimally perturbed."""
    line = json.loads((FIXTURES / "trap.json").read_text())
    line.update(overrides)
    return json.dumps(line) + "\n"

FIXTURES = Path(__file__).parent / "fixtures"


def test_supported_version_is_two() -> None:
    """The pin the whole service hangs off. Runtime emits 2 (AILAB-619)."""
    assert SUPPORTED_SCHEMA_VERSION == 2


def test_ingest_sample_jsonl_parses_intent_and_outcomes() -> None:
    text = (FIXTURES / "sample.jsonl").read_text()
    batch = ingest_jsonl(text)
    assert len(batch.intents) == 1
    assert len(batch.outcomes) == 6
    assert batch.intents[0].call_id == "call-golden-0"
    assert batch.outcomes[0].tool_id == "smoke"
    # Post-AEG-24 grants carry max_output_bytes
    granted = next(o for o in batch.outcomes if o.capability.status == "granted")
    assert granted.capability.grant is not None
    assert granted.capability.grant.max_output_bytes == 1_048_576


def test_v2_wire_fields_are_parsed() -> None:
    """The rename and the chain/signature additions, on a real golden line."""
    batch = ingest_jsonl((FIXTURES / "policy_deny.json").read_text())
    outcome = batch.outcomes[0]
    assert outcome.schema_version == 2
    assert outcome.line_type == "outcome"
    assert outcome.request_digest  # was `input_digest` in v1
    assert outcome.seq == 2
    assert outcome.prev_hash and outcome.signature and outcome.key_id
    assert outcome.policy_set_hash
    # decision_axes is always present; this golden recorded real axes.
    assert outcome.decision_axes.capability == "fs.read"
    assert outcome.decision_axes.matched_rule == "block-smoke"
    assert outcome.decision_axes.role == "ops"
    assert outcome.decision_axes.fs is not None
    assert outcome.decision_axes.fs.path_canonical == "/fixtures/notes.md"


def test_empty_decision_axes_is_not_absent_axes() -> None:
    """`{}` says the emitter recorded no axes; it must still parse (SPEC §5.3)."""
    batch = ingest_jsonl((FIXTURES / "resource_exceeded.json").read_text())
    axes = batch.outcomes[0].decision_axes
    assert axes.capability is None
    assert axes.fs is None
    assert axes.model_dump(exclude_none=True) == {}


def test_intent_is_unsigned_by_design() -> None:
    """An intent carries no signature; that is absence, not a missing field.

    Asserted against the model's declared fields, not `hasattr` on an instance:
    the attribute is never declared, so `hasattr` would be false for any input
    and would prove nothing.
    """
    batch = ingest_jsonl((FIXTURES / "intent.json").read_text())
    assert len(batch.intents) == 1
    assert "signature" not in AuditIntent.model_fields
    assert "key_id" not in AuditIntent.model_fields
    # An emitter MUST NOT sign an intent (SPEC §5.1). If one does anyway, the
    # member is ignored like any other unrecognised one rather than adopted —
    # governance must not start reporting a signature it never asked for.
    signed = json.loads((FIXTURES / "intent.json").read_text())
    signed["signature"] = "ab" * 64
    parsed = ingest_jsonl(json.dumps(signed) + "\n").intents[0]
    assert not hasattr(parsed, "signature")


# --- skip, don't abort (SPEC §5.2) ------------------------------------------


def test_multi_type_session_skips_non_outcome_lines() -> None:
    """A whole Session: open → intent → outcomes → decision → close.

    Verbatim from `crates/botzr-aegis-audit/tests/golden/` in seq order, so
    this is what the runtime actually writes, not a shape invented here.
    """
    batch = ingest_jsonl((FIXTURES / "session_v2.jsonl").read_text())
    assert len(batch.intents) == 1
    assert len(batch.outcomes) == 8
    assert batch.skipped_by_type() == {"open": 1, "decision": 1, "close": 1}
    # Position is preserved so an operator can find the line that was skipped.
    assert [s.lineno for s in batch.skipped] == [1, 11, 12]
    assert all(s.is_known_type for s in batch.skipped)


def test_unknown_line_type_is_skipped_and_its_token_preserved() -> None:
    """A newer emitter's line is not corruption, and not an anonymous 'other'.

    Collapsing unknowns to one bucket tells an operator that something was
    unreadable but not *what* — the half of the message they need (SPEC §5.2).
    """
    batch = ingest_jsonl((FIXTURES / "unknown_line_types.jsonl").read_text())
    assert batch.intents == [] and batch.outcomes == []
    assert batch.skipped_by_type() == {"checkpoint": 1, "attestation": 2}
    unknown = [s for s in batch.skipped if not s.is_known_type]
    assert [s.line_type for s in unknown] == ["attestation", "attestation"]


def test_unknown_line_type_does_not_block_later_outcomes() -> None:
    """The lines after an unrecognised one must still be consumed."""
    unknown = json.dumps(
        {
            "schema_version": 2,
            "line_type": "some-future-type",
            "seq": 0,
            "prev_hash": "0" * 64,
        }
    )
    outcome = (FIXTURES / "trap.json").read_text().strip()
    batch = ingest_jsonl(f"{unknown}\n{outcome}\n")
    assert len(batch.outcomes) == 1
    assert batch.skipped_by_type() == {"some-future-type": 1}


def test_extend_merges_records_but_not_per_request_skips() -> None:
    """`lineno` is an offset into one body; accumulating them means nothing."""
    buffer = ingest_jsonl((FIXTURES / "sample.jsonl").read_text())
    buffer.extend(ingest_jsonl((FIXTURES / "session_v2.jsonl").read_text()))
    assert len(buffer.outcomes) == 14
    assert len(buffer.intents) == 2
    assert buffer.skipped == []


# --- rejections -------------------------------------------------------------


def test_reject_schema_version_one() -> None:
    """v1 is not compatible and is not accepted (SPEC §12, DECISIONS D25)."""
    v1 = (
        '{"schema_version":1,"phase":"intent","call_id":"x","tool_id":"t",'
        '"input_digest":"d"}\n'
    )
    with pytest.raises(IngestError, match="schema_version"):
        ingest_jsonl(v1)


def test_reject_schema_version_from_the_future() -> None:
    line = '{"schema_version":3,"line_type":"intent","seq":0,"prev_hash":"ab"}\n'
    with pytest.raises(IngestError, match="schema_version"):
        ingest_jsonl(line)


@pytest.mark.parametrize(
    "line,reason",
    [
        ('{"schema_version":2,"seq":0,"prev_hash":"ab"}', "line_type"),
        ('{"schema_version":2,"line_type":"outcome","prev_hash":"ab"}', "seq"),
        ('{"schema_version":2,"line_type":"outcome","seq":0}', "prev_hash"),
        # Wire types are exact: a string seq is not an integer seq.
        (
            '{"schema_version":2,"line_type":"outcome","seq":"0","prev_hash":"ab"}',
            "seq",
        ),
        (
            '{"schema_version":2,"line_type":"outcome","seq":true,"prev_hash":"ab"}',
            "seq",
        ),
        ('{"schema_version":2,"line_type":"","seq":0,"prev_hash":"ab"}', "line_type"),
    ],
)
def test_missing_chain_field_is_a_format_violation_not_an_extension(
    line: str, reason: str
) -> None:
    """A future line type may add anything; it may not leave the chain (SPEC §5)."""
    with pytest.raises(IngestError, match=reason):
        ingest_jsonl(line + "\n")


def test_reject_outcome_missing_required_fields() -> None:
    # Chain fields present, outcome body absent — fails closed on the body.
    bad = (
        '{"schema_version":2,"line_type":"outcome","seq":0,"prev_hash":"' + "0" * 64 + '",'
        '"call_id":"x","tool_id":"t","request_digest":"' + "0" * 64 + '"}\n'
    )
    with pytest.raises(IngestError, match="invalid audit record"):
        ingest_jsonl(bad)


def test_reject_outcome_missing_decision_axes() -> None:
    """`decision_axes` is always present, even when empty (SPEC §5.3)."""
    outcome = json.loads((FIXTURES / "trap.json").read_text())
    del outcome["decision_axes"]
    with pytest.raises(IngestError, match="decision_axes"):
        ingest_jsonl(json.dumps(outcome) + "\n")


def test_reject_outcome_missing_signature() -> None:
    """An outcome is in the signed set; a missing signature is a missing field.

    Presence only — nothing here verifies it. That is `aegis verify`
    (AILAB-621).
    """
    outcome = json.loads((FIXTURES / "trap.json").read_text())
    del outcome["signature"]
    with pytest.raises(IngestError, match="signature"):
        ingest_jsonl(json.dumps(outcome) + "\n")


# --- the normative value space (SPEC §3.2) and wire forms (SPEC §2) ---------
#
# Accepting a line the format calls invalid is worse than rejecting it: `aegis
# verify` would report the same file `Tampered` while governance reported it
# ingested, and nothing in the system would explain the disagreement.


def test_reject_floats_anywhere_in_a_line() -> None:
    """"An integral float (`1.0`) is a float and is not an escape hatch."""
    # 2.0 == 2 in Python, so a bare `!=` version pin would let this through.
    with pytest.raises(IngestError, match="schema_version"):
        ingest_jsonl(outcome_with(schema_version=2.0))
    with pytest.raises(IngestError, match="floating-point"):
        ingest_jsonl(outcome_with(seq=6.0))
    with pytest.raises(IngestError, match="floating-point"):
        ingest_jsonl(outcome_with(wall_ms=12.5))


def test_reject_integers_at_or_above_2_53() -> None:
    """The bound is for a JavaScript verifier reading `seq` as a `Number`."""
    with pytest.raises(IngestError, match=r"outside \[0, 2\^53\)"):
        ingest_jsonl(outcome_with(seq=MAX_SAFE_INTEGER + 1))
    with pytest.raises(IngestError, match=r"outside \[0, 2\^53\)"):
        ingest_jsonl(outcome_with(wall_ms=10**40))
    with pytest.raises(IngestError, match=r"outside \[0, 2\^53\)"):
        ingest_jsonl(outcome_with(seq=-1))
    # The boundary itself is legal.
    assert len(ingest_jsonl(outcome_with(seq=MAX_SAFE_INTEGER)).outcomes) == 1


def test_reject_literal_null_including_nested() -> None:
    """Absent fields are omitted, never null — and the models claim as much."""
    with pytest.raises(IngestError, match="literal null"):
        ingest_jsonl(outcome_with(grant_id=None))
    with pytest.raises(IngestError, match="literal null"):
        ingest_jsonl(outcome_with(decision_axes={"capability": None}))
    with pytest.raises(IngestError, match="literal null"):
        ingest_jsonl(outcome_with(wall_ms=None))
    # Booleans are not numbers and are not null; they must survive.
    assert len(ingest_jsonl(outcome_with(some_future_flag=True)).outcomes) == 1


@pytest.mark.parametrize(
    "prev_hash",
    [
        "ab",  # too short
        "AB" * 32,  # uppercase: rejected, not normalized (SPEC §2)
        "zz" * 32,  # not hex
        "ab" * 33,  # too long
        "",
    ],
)
def test_reject_prev_hash_that_is_not_a_digest(prev_hash: str) -> None:
    """Checked in the chain gate, so it covers skipped line types too."""
    with pytest.raises(IngestError, match="not a digest"):
        ingest_jsonl(outcome_with(prev_hash=prev_hash))


def test_reject_malformed_digest_and_signature_fields() -> None:
    """Empty-string-as-absent is the same mistake as null-as-absent."""
    for field in ("request_digest", "policy_set_hash", "key_id"):
        with pytest.raises(IngestError, match="invalid audit record"):
            ingest_jsonl(outcome_with(**{field: ""}))
        with pytest.raises(IngestError, match="invalid audit record"):
            ingest_jsonl(outcome_with(**{field: "NOTADIGEST"}))
    with pytest.raises(IngestError, match="invalid audit record"):
        ingest_jsonl(outcome_with(signature=""))
    # A signature is 128 hex, not 64 — length is part of the wire form.
    with pytest.raises(IngestError, match="invalid audit record"):
        ingest_jsonl(outcome_with(signature="ab" * 32))
    for field in ("call_id", "tool_id"):
        with pytest.raises(IngestError, match="invalid audit record"):
            ingest_jsonl(outcome_with(**{field: ""}))


def test_ignore_unknown_fields_forward_compat() -> None:
    """Unknown *members* are ignored; unknown *line types* are skipped."""
    line = json.loads((FIXTURES / "intent.json").read_text())
    line["future_field"] = True
    batch = ingest_jsonl(json.dumps(line) + "\n")
    assert len(batch.intents) == 1


def test_reject_malformed_json() -> None:
    with pytest.raises(IngestError):
        ingest_jsonl("{not json}\n")
