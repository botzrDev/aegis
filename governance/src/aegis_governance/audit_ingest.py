"""Parse untrusted audit JSONL into typed schema-v2 models.

Three rejection classes, deliberately distinct (SPEC §5, §5.2, §12):

* **Wrong version** — `schema_version != 2` is refused outright. v1 is not
  compatible and is not accepted (DECISIONS.md D25).
* **Format violation** — a line missing or mistyping `line_type`, `seq` or
  `prev_hash` is not a chain line at all. It aborts the batch.
* **Unrecognised line type** — a type this service does not consume, including
  one a newer emitter invented. It is **skipped and counted**, never an abort.

That third class is the whole point of the extension story: an emitter may add
line types within version 2, so treating an unfamiliar one as corruption would
make every future addition a breaking change. The token is preserved verbatim
(SPEC §5.2) — collapsing unknowns to a single "other" can tell an operator that
something was unreadable but not *what*, which is the half of the message they
need.

Skipping is not verifying. This module never reports a verdict over what it
skipped; a consumer that needs `Verified` over a whole file needs `aegis verify`
(AILAB-621), which caps at `Indeterminate` on exactly these lines.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from aegis_governance.models import (
    INGESTED_LINE_TYPES,
    AuditIntent,
    AuditLineType,
    AuditRecord,
)

SUPPORTED_SCHEMA_VERSION = 2

#: SPEC §3.2 — integers are non-negative and strictly below 2^53. The bound is
#: for a JavaScript verifier reading `seq` as a `Number`; accepting a larger one
#: here would mean governance ingests a line that `aegis verify` calls
#: `Tampered`, which is the disagreement the bound exists to prevent.
MAX_SAFE_INTEGER = 2**53 - 1

#: SPEC §2 — a digest is 64 lowercase hex characters. Uppercase is *rejected,
#: not normalized*: one digest must have exactly one spelling, or two canonical
#: forms of the same line hash differently.
DIGEST_RE = re.compile(r"\A[0-9a-f]{64}\Z")

logger = logging.getLogger(__name__)


class IngestError(ValueError):
    """Raised when a JSONL line fails validation or the schema pin.

    Never raised for an unrecognised `line_type` — that is `SkippedLine`.
    """


@dataclass(frozen=True)
class SkippedLine:
    """A line ingest read, understood the position of, and did not consume.

    `line_type` holds the emitter's token exactly as written, including one
    this version has no name for.
    """

    lineno: int
    line_type: str

    @property
    def is_known_type(self) -> bool:
        """True for a spec-defined type we simply do not consume."""
        return self.line_type in {member.value for member in AuditLineType}


@dataclass
class IngestBatch:
    """One parse result — and, on `GovernanceState.buffer`, the accumulator.

    Those two roles differ in one place: `skipped` is populated only by a
    parse. On the long-lived buffer it stays empty, because `extend` does not
    merge it (see below). Read `skipped` off the batch `ingest_jsonl` returned,
    never off the buffer, where `{}` would read as "nothing was ever skipped"
    rather than "not tracked here".
    """

    intents: list[AuditIntent] = field(default_factory=list)
    outcomes: list[AuditRecord] = field(default_factory=list)
    #: Per-parse only — see `extend`.
    skipped: list[SkippedLine] = field(default_factory=list)

    def extend(self, other: IngestBatch) -> None:
        """Merge another batch's records into this one.

        `skipped` is deliberately **not** merged. Its `lineno` is an offset
        into one request body, so accumulating skips across requests in the
        long-lived buffer would produce line numbers that point at nothing.
        Skips are reported per parse, where they still mean something.
        """
        self.intents.extend(other.intents)
        self.outcomes.extend(other.outcomes)

    def skipped_by_type(self) -> dict[str, int]:
        """Counts keyed by the verbatim `line_type` token."""
        return dict(Counter(s.line_type for s in self.skipped))


def _check_value_space(value: Any, lineno: int, path: str) -> None:
    """Enforce the normative value space (SPEC §3.2), recursively.

    These are requirements, not style: they are what make JCS safe to use as
    the hash input, so a line that violates one is outside the format. A
    consumer that accepts it disagrees with the verifier about what the file
    contains, which is worse than rejecting the line.
    """
    where = path or "the line root"

    if value is None:
        raise IngestError(
            f"line {lineno}: literal null at {where}; absent fields are omitted, "
            f"never null (SPEC §3.2)"
        )
    # Check bool before int: `isinstance(True, int)` is True in Python, but a
    # JSON boolean is not a number and is not bounded by 2^53.
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        raise IngestError(
            f"line {lineno}: floating-point value {value!r} at {where}; no floats "
            f"anywhere in a line, and an integral float is not an escape hatch "
            f"(SPEC §3.2)"
        )
    if isinstance(value, int):
        if value < 0 or value > MAX_SAFE_INTEGER:
            raise IngestError(
                f"line {lineno}: integer {value} at {where} is outside "
                f"[0, 2^53); a JavaScript verifier reads these as Number "
                f"(SPEC §3.2)"
            )
        return
    if isinstance(value, dict):
        for key, member in value.items():
            _check_value_space(member, lineno, f"{path}.{key}" if path else key)
        return
    if isinstance(value, list):
        for index, member in enumerate(value):
            _check_value_space(member, lineno, f"{where}[{index}]")


def _require_chain_fields(obj: dict[str, Any], lineno: int) -> str:
    """Check the chain fields every line MUST carry; return `line_type`.

    `schema_version` is the fourth, pinned by the caller before this runs.

    A line that fails here is a format violation, not an unknown extension: a
    future line type may add anything, but it may not opt out of its position
    in the chain (SPEC §5). Checked by hand rather than through pydantic
    because lax coercion would let `"seq": "3"` pass as an integer, and these
    three are checked for *every* line type — including the ones this service
    skips, which never reach a model at all.
    """
    line_type = obj.get("line_type")
    if not isinstance(line_type, str) or not line_type:
        raise IngestError(
            f"line {lineno}: missing or non-string line_type; not a chain line"
        )

    seq = obj.get("seq")
    # bool is a subclass of int in Python, and `True` is not a sequence number.
    # Range is already bounded by the §3.2 value-space walk.
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise IngestError(
            f"line {lineno}: missing or invalid seq={obj.get('seq')!r}; "
            f"every line carries a non-negative position within its Session"
        )

    prev_hash = obj.get("prev_hash")
    if not isinstance(prev_hash, str) or not DIGEST_RE.match(prev_hash):
        raise IngestError(
            f"line {lineno}: prev_hash={obj.get('prev_hash')!r} is not a digest; "
            f"expected 64 lowercase hex characters (SPEC §2)"
        )

    return line_type


def ingest_jsonl(text: str) -> IngestBatch:
    """Parse newline-delimited JSON. Reject `schema_version != 2`.

    Intents and outcomes become typed records; every other line type is
    skipped and recorded on `batch.skipped`.
    """
    batch = IngestBatch()
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj: Any = json.loads(line)
        except json.JSONDecodeError as e:
            raise IngestError(f"line {lineno}: malformed JSON: {e}") from e

        if not isinstance(obj, dict):
            raise IngestError(f"line {lineno}: expected JSON object")

        version = obj.get("schema_version")
        # `is not True` guards the bool-is-int trap; `type(...) is int` rejects
        # `2.0`, which `!= 2` alone would let through (2.0 == 2 in Python) and
        # which SPEC §3.2 calls a float, not an escape hatch.
        if type(version) is not int or version != SUPPORTED_SCHEMA_VERSION:
            raise IngestError(
                f"line {lineno}: unsupported schema_version={version!r}; "
                f"only {SUPPORTED_SCHEMA_VERSION} is accepted "
                f"(schema 1 is not compatible — see spec/SPEC.md §12)"
            )

        _check_value_space(obj, lineno, "")
        line_type = _require_chain_fields(obj, lineno)

        if line_type not in INGESTED_LINE_TYPES:
            # open / close / decision / checkpoint / anything newer. Recorded,
            # not refused: this service consumes outcomes, and a line type it
            # does not consume is not a corrupt file.
            batch.skipped.append(SkippedLine(lineno=lineno, line_type=line_type))
            continue

        try:
            if line_type == AuditLineType.INTENT.value:
                batch.intents.append(AuditIntent.model_validate(obj))
            else:
                batch.outcomes.append(AuditRecord.model_validate(obj))
        except ValidationError as e:
            raise IngestError(f"line {lineno}: invalid audit record: {e}") from e

    if batch.skipped:
        # One line per parse, not per skip: a Session file opens and closes, so
        # per-skip logging would be mostly noise on every well-formed batch.
        logger.info(
            "audit ingest skipped %d line(s) it does not consume: %s",
            len(batch.skipped),
            batch.skipped_by_type(),
        )

    return batch
