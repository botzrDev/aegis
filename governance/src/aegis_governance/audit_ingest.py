"""Parse untrusted audit JSONL into typed schema-v1 models."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from aegis_governance.models import AuditIntent, AuditRecord

SUPPORTED_SCHEMA_VERSION = 1


class IngestError(ValueError):
    """Raised when a JSONL line fails validation or schema pin."""


@dataclass
class IngestBatch:
    intents: list[AuditIntent] = field(default_factory=list)
    outcomes: list[AuditRecord] = field(default_factory=list)

    def extend(self, other: IngestBatch) -> None:
        self.intents.extend(other.intents)
        self.outcomes.extend(other.outcomes)


def ingest_jsonl(text: str) -> IngestBatch:
    """Parse newline-delimited JSON. Reject schema_version != 1."""
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
        if version != SUPPORTED_SCHEMA_VERSION:
            raise IngestError(
                f"line {lineno}: unsupported schema_version={version!r}; "
                f"only {SUPPORTED_SCHEMA_VERSION} is accepted"
            )

        phase = obj.get("phase")
        try:
            if phase == "intent":
                batch.intents.append(AuditIntent.model_validate(obj))
            elif phase == "outcome":
                batch.outcomes.append(AuditRecord.model_validate(obj))
            else:
                raise IngestError(f"line {lineno}: unknown or missing phase={phase!r}")
        except ValidationError as e:
            raise IngestError(f"line {lineno}: invalid audit record: {e}") from e

    return batch
