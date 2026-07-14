"""Guardian interface stub — no network, no API keys in this slice.

Deferred / out of scope: LiteLLM-backed guardian. NullGuardian is the
default and must never widen policy or auto-apply into the Rust runtime.
"""

from __future__ import annotations

from typing import Protocol

from aegis_governance.audit_ingest import IngestBatch
from aegis_governance.detect import Finding


class Guardian(Protocol):
    def review(self, findings: list[Finding], batch: IngestBatch) -> list[Finding]:
        """Optional second pass over detector findings. Must not widen policy."""
        ...


class NullGuardian:
    """Passthrough stub for later LLM guardian (out of scope for AEG-24)."""

    def review(self, findings: list[Finding], batch: IngestBatch) -> list[Finding]:
        return list(findings)
