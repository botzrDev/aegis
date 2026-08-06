"""Deterministic feature schema v1 for the learning fabric (AEG-32 slice 4).

Audit schema v1 carries no raw prompt/input/output text, no agent, and no
project identity (`models.AuditRecord`). The learning fabric therefore encodes
*only* shipped schema-v1 fields into a fixed 16-dimensional vector with a
documented, versioned layout — no live embedding provider, no API key, and no
network call. That keeps stored vectors reproducible for published findings and
keeps the store replayable from the same JSONL.

Nearest patterns are **evidence only**. They never mint policy YAML, never
relax the floor, and never auto-apply into the Rust runtime (D24).
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass
from typing import Any, Optional, Protocol, Sequence

from aegis_governance.models import AuditRecord

FEATURE_SCHEMA_VERSION = 1
VECTOR_DIMENSIONS = 16
AUDIT_SCHEMA_VERSION = 1

DEFAULT_SEARCH_LIMIT = 10
MIN_SEARCH_LIMIT = 1
MAX_SEARCH_LIMIT = 50

# Fixed upper bounds for the log1p axes. Documented and frozen with
# FEATURE_SCHEMA_VERSION: changing one changes stored vectors, so it requires a
# new feature schema version, not an edit in place.
WALL_MS_BOUND = 60_000  # 60 s
PEAK_MEMORY_BYTES_BOUND = 1_073_741_824  # 1 GiB
MAX_OUTPUT_BYTES_BOUND = 1_073_741_824  # 1 GiB

# Vector layout (feature schema v1). Order is load-bearing — index == meaning.
POLICY_STATUSES: tuple[str, ...] = (
    "allowed",
    "denied",
    "rate_limited",
    "pending_approval",
)
CAPABILITY_STATUSES: tuple[str, ...] = ("granted", "denied")
EXECUTION_STATUSES: tuple[str, ...] = (
    "success",
    "trap",
    "resource_exceeded",
    "host_denied",
)

# Stable UUIDv5 namespace so re-encoding the same call_id yields the same
# pattern_id in every store (re-ingest stays idempotent across processes).
PATTERN_NAMESPACE = uuid.UUID("6f5f4f22-0f1c-5a3e-9b7a-2f0d1e6c8a41")


class LearningStoreError(RuntimeError):
    """Durable store is configured but unavailable. Maps to HTTP 503.

    Raised *before* the in-memory ingest buffer is extended, so a store failure
    never leaves governance holding half a batch.
    """


class SourcePatternNotFoundError(LookupError):
    """No stored pattern for the requested source call. Maps to HTTP 404.

    Never fall back to a zero or random probe vector — an unknown source has no
    neighbors, and inventing one would fabricate evidence.
    """


def pattern_id_for(call_id: str) -> uuid.UUID:
    """Deterministic pattern identity derived from the audit call id."""
    return uuid.uuid5(PATTERN_NAMESPACE, call_id)


def clamp_search_limit(limit: int) -> int:
    """Clamp a neighbor count into [1, 50]."""
    return max(MIN_SEARCH_LIMIT, min(MAX_SEARCH_LIMIT, int(limit)))


def _log1p_norm(value: Optional[int], bound: int) -> float:
    """Bounded log1p normalization into [0, 1]. Missing/negative encode as 0."""
    if value is None or value <= 0:
        return 0.0
    capped = min(float(value), float(bound))
    return max(0.0, min(1.0, math.log1p(capped) / math.log1p(float(bound))))


def _one_hot(status: str, statuses: Sequence[str]) -> list[float]:
    return [1.0 if status == candidate else 0.0 for candidate in statuses]


def _granted_grant(record: AuditRecord) -> Any:
    """The CapabilityGrant when capability was granted, else None."""
    if record.capability.status != "granted":
        return None
    return getattr(record.capability, "grant", None)


def encode_pattern(record: AuditRecord) -> tuple[float, ...]:
    """Encode a schema-v1 outcome into the fixed 16-dim feature vector.

    Layout (feature schema v1):

    | Dims  | Meaning                                                   |
    |-------|-----------------------------------------------------------|
    | 0–3   | policy one-hot: allowed/denied/rate_limited/pending_approval |
    | 4–5   | capability one-hot: granted/denied                        |
    | 6–9   | execution one-hot: success/trap/resource_exceeded/host_denied |
    | 10    | granted filesystem read paths present                     |
    | 11    | granted filesystem write paths present                    |
    | 12    | granted HTTP entries present                              |
    | 13    | bounded log1p(wall_ms)                                    |
    | 14    | bounded log1p(peak_memory_bytes)                          |
    | 15    | bounded log1p(grant.max_output_bytes)                     |

    ``tool_id`` is deliberately *not* hashed into the vector: it stays a
    first-class column and an exact-match filter, so similarity never blurs
    tool identity.
    """
    grant = _granted_grant(record)
    fs = getattr(grant, "fs", None) if grant is not None else None
    net = getattr(grant, "net", None) if grant is not None else None

    vector: list[float] = []
    vector += _one_hot(record.policy.status, POLICY_STATUSES)
    vector += _one_hot(record.capability.status, CAPABILITY_STATUSES)
    vector += _one_hot(record.execution.status, EXECUTION_STATUSES)
    vector.append(1.0 if fs is not None and fs.read_paths else 0.0)
    vector.append(1.0 if fs is not None and fs.write_paths else 0.0)
    vector.append(1.0 if net is not None and net.http else 0.0)
    vector.append(_log1p_norm(record.wall_ms, WALL_MS_BOUND))
    vector.append(_log1p_norm(record.peak_memory_bytes, PEAK_MEMORY_BYTES_BOUND))
    vector.append(
        _log1p_norm(
            getattr(grant, "max_output_bytes", None) if grant is not None else None,
            MAX_OUTPUT_BYTES_BOUND,
        )
    )

    if len(vector) != VECTOR_DIMENSIONS:  # pragma: no cover - frozen layout
        # A real check, not an assert: `python -O` must not be able to strip
        # the guard on a width the `vector(16)` column depends on.
        raise ValueError(
            f"feature schema v{FEATURE_SCHEMA_VERSION} must emit "
            f"{VECTOR_DIMENSIONS} dims, got {len(vector)}"
        )
    return tuple(vector)


def canonical_content(record: AuditRecord) -> dict[str, Any]:
    """JSON-safe summary of a schema-v1 outcome.

    Identifiers, status *strings*, grant shape, and resource metrics only.
    Free-text reasons/messages are excluded alongside the fields audit schema
    v1 never carried in the first place, so the durable store cannot become a
    back door for prompt or output content.
    """
    grant = _granted_grant(record)
    grant_shape: Optional[dict[str, Any]] = None
    if grant is not None:
        fs = grant.fs
        net = grant.net
        grant_shape = {
            "grant_id": grant.grant_id,
            "fs_read_path_count": len(fs.read_paths) if fs is not None else 0,
            "fs_write_path_count": len(fs.write_paths) if fs is not None else 0,
            "net_http_entry_count": len(net.http) if net is not None else 0,
            "max_memory_bytes": grant.max_memory_bytes,
            "max_wall_ms": grant.max_wall_ms,
            "max_output_bytes": grant.max_output_bytes,
        }

    return {
        "call_id": record.call_id,
        "tool_id": record.tool_id,
        "input_digest": record.input_digest,
        "audit_schema_version": record.schema_version,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "policy_status": record.policy.status,
        "capability_status": record.capability.status,
        "execution_status": record.execution.status,
        "grant": grant_shape,
        "wall_ms": record.wall_ms,
        "peak_memory_bytes": record.peak_memory_bytes,
    }


@dataclass(frozen=True)
class Pattern:
    """One durable learning row. The only governance state that persists."""

    pattern_id: str
    call_id: str
    tool_id: str
    audit_schema_version: int
    feature_schema_version: int
    embedding: tuple[float, ...]
    content: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "call_id": self.call_id,
            "tool_id": self.tool_id,
            "audit_schema_version": self.audit_schema_version,
            "feature_schema_version": self.feature_schema_version,
            "content": dict(self.content),
        }


@dataclass(frozen=True)
class PatternNeighbor:
    """A nearest stored pattern. Evidence for a human — never policy input."""

    pattern_id: str
    call_id: str
    tool_id: str
    distance: float
    feature_schema_version: int
    content: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "call_id": self.call_id,
            "tool_id": self.tool_id,
            "distance": self.distance,
            "feature_schema_version": self.feature_schema_version,
            "content": dict(self.content),
        }

    def to_evidence(self) -> dict[str, Any]:
        """Compact form attached to a proposal as `learning_evidence`."""
        return {
            "pattern_id": self.pattern_id,
            "call_id": self.call_id,
            "tool_id": self.tool_id,
            "distance": self.distance,
        }


def pattern_from_record(record: AuditRecord) -> Pattern:
    return Pattern(
        pattern_id=str(pattern_id_for(record.call_id)),
        call_id=record.call_id,
        tool_id=record.tool_id,
        audit_schema_version=record.schema_version,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        embedding=encode_pattern(record),
        content=canonical_content(record),
    )


def cosine_distance(a: Sequence[float], b: Sequence[float]) -> float:
    """1 - cosine similarity, matching pgvector's `<=>` operator."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        # pgvector returns NaN here; governance treats it as "maximally far".
        return 1.0
    return 1.0 - (dot / (norm_a * norm_b))


class LearningStore(Protocol):
    """Durable-ish store for learning patterns only.

    Implementations must not persist the ingest buffer, drift findings, or
    policy packs — those stay in-process on `GovernanceState` (D21–D23, D24).
    """

    mode: str

    def upsert_patterns(self, records: Sequence[AuditRecord]) -> int:
        """Idempotently store one batch by `call_id`. All-or-nothing."""
        ...

    def search_neighbors(
        self,
        call_id: str,
        *,
        tool_id: Optional[str] = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
    ) -> list[PatternNeighbor]:
        """Nearest patterns by cosine distance, excluding the source row.

        Raises `SourcePatternNotFoundError` when `call_id` is unknown.
        """
        ...

    def search_neighbors_batch(
        self,
        call_ids: Sequence[str],
        *,
        tool_id: Optional[str] = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
    ) -> dict[str, list[PatternNeighbor]]:
        """Same, for many sources at once. Unknown sources are omitted.

        Exists so a proposal over an unbounded ingest buffer costs one round
        trip, not one per source call.
        """
        ...


class InMemoryLearningStore:
    """Process-local `LearningStore` for unit and API tests.

    Mirrors the Postgres semantics exactly — upsert by `call_id`, cosine
    ordering, source excluded — so the same assertions hold in both stores.
    """

    mode = "memory"

    def __init__(self) -> None:
        self._patterns: dict[str, Pattern] = {}

    def upsert_patterns(self, records: Sequence[AuditRecord]) -> int:
        # Build the whole batch first: a mid-batch encode failure must not
        # leave a partial batch behind, matching the single-transaction store.
        staged = {rec.call_id: pattern_from_record(rec) for rec in records}
        self._patterns.update(staged)
        return len(staged)

    def search_neighbors(
        self,
        call_id: str,
        *,
        tool_id: Optional[str] = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
    ) -> list[PatternNeighbor]:
        source = self._patterns.get(call_id)
        # Mirrors the SQL pin: a stale-layout row is not a valid probe.
        if source is None or source.feature_schema_version != FEATURE_SCHEMA_VERSION:
            raise SourcePatternNotFoundError(f"no stored pattern for call {call_id!r}")

        candidates = [
            p
            for p in self._patterns.values()
            if p.call_id != call_id
            and p.feature_schema_version == FEATURE_SCHEMA_VERSION
            and (tool_id is None or p.tool_id == tool_id)
        ]
        scored = [
            PatternNeighbor(
                pattern_id=p.pattern_id,
                call_id=p.call_id,
                tool_id=p.tool_id,
                distance=cosine_distance(source.embedding, p.embedding),
                feature_schema_version=p.feature_schema_version,
                content=p.content,
            )
            for p in candidates
        ]
        # call_id tie-break keeps ordering deterministic for published findings.
        scored.sort(key=lambda n: (n.distance, n.call_id))
        return scored[: clamp_search_limit(limit)]

    def search_neighbors_batch(
        self,
        call_ids: Sequence[str],
        *,
        tool_id: Optional[str] = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
    ) -> dict[str, list[PatternNeighbor]]:
        grouped: dict[str, list[PatternNeighbor]] = {}
        for call_id in dict.fromkeys(call_ids):
            try:
                grouped[call_id] = self.search_neighbors(
                    call_id, tool_id=tool_id, limit=limit
                )
            except SourcePatternNotFoundError:
                continue  # unknown sources are omitted, never invented
        return grouped

    def get(self, call_id: str) -> Optional[Pattern]:
        return self._patterns.get(call_id)

    def count(self) -> int:
        return len(self._patterns)
