"""Pydantic mirrors of Aegis audit schema v1 (intent + outcome).

Audit ingest is untrusted: validate strictly on required fields; ignore unknown
keys for forward-compat; reject schema_version != 1.

============================================================================
BREAK — THESE MODELS NO LONGER MATCH THE RUNTIME.  MIGRATION OWNER: AILAB-624
============================================================================

AILAB-619 bumped the Rust audit schema to version 2.  Because this module
rejects ``schema_version != 1`` (see ``AuditIntent`` / ``AuditRecord`` below and
the ingest path in ``app.py``), **every line the runtime writes today is refused
by /v1/ingest**.  Nothing here has been migrated, deliberately: the models, the
validation and the feature extractor move together under AILAB-624.  Do not
patch a single field to make one test pass.

What changed, all of it breaking for this module:

* ``phase`` -> ``line_type``, and two phases became **six** line types:
  ``open``, ``intent``, ``outcome``, ``decision``, ``close``, ``checkpoint``
  (reserved, never emitted by v0).  ``AuditPhase`` below no longer describes the
  wire at all; an unknown line type must not be silently dropped, because a
  newer emitter's line is exactly what a consumer must not claim to understand.
* ``input_digest`` -> ``request_digest`` (SHA-256 over the verbatim request
  bytes).
* New chain fields on every line: ``seq`` (per line, per Session, restarting at
  0 each Session) and ``prev_hash``.
* New signature fields on every signed line: ``signature`` and ``key_id``
  (ed25519 over the line's canonical form with ``signature`` omitted).
* New outcome fields: ``policy_set_hash`` (a real SHA-256 content hash, not the
  FNV YAML digest), ``grant_id``, ``response_digest``.
* New ``decision_axes`` object, **always present and possibly ``{}``**, carrying
  ``capability``, ``role``, ``session``, ``matched_rule``, ``approval_ref`` and
  the derived ``fs`` / ``net`` parameters.  Its members are omitted, never null.
* Lines hash under RFC 8785 (JCS) and rows on disk are already in canonical
  (key-sorted, whitespace-free) form.

Also note for the migration: ``FEATURE_SCHEMA_VERSION`` in the learning fabric
is documented as vectorising a "validated schema-v1 outcome".  A v2 outcome is a
different input; a vector layout pinned to one audit schema cannot silently
accept the other.

Format reference: ``spec/SPEC.md`` at the repo root.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class AuditPhase(str, Enum):
    # BREAK (AILAB-619, migration owner AILAB-624): schema 2 replaced `phase`
    # with `line_type` and these two values with six —  open / intent / outcome
    # / decision / close / checkpoint. Left unchanged on purpose; renaming this
    # enum without migrating ingest, validation and the feature extractor would
    # give the service a v2 vocabulary and v1 behaviour.
    INTENT = "intent"
    OUTCOME = "outcome"


class HttpGrant(BaseModel):
    model_config = ConfigDict(extra="ignore")

    host: str
    ports: list[int]
    methods: list[str]


class FsGrant(BaseModel):
    model_config = ConfigDict(extra="ignore")

    read_paths: list[str] = Field(default_factory=list)
    write_paths: list[str] = Field(default_factory=list)


class NetGrant(BaseModel):
    model_config = ConfigDict(extra="ignore")

    http: list[HttpGrant] = Field(default_factory=list)


class CapabilityGrant(BaseModel):
    model_config = ConfigDict(extra="ignore")

    grant_id: str
    tool_id: str
    fs: Optional[FsGrant] = None
    net: Optional[NetGrant] = None
    max_memory_bytes: int
    max_wall_ms: int
    max_output_bytes: int


class PolicyAllowed(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: Literal["allowed"]


class PolicyDenied(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: Literal["denied"]
    reason: str


class PolicyRateLimited(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: Literal["rate_limited"]
    reason: str


class PolicyPendingApproval(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: Literal["pending_approval"]
    approval_id: str


PolicyOutcome = Annotated[
    Union[PolicyAllowed, PolicyDenied, PolicyRateLimited, PolicyPendingApproval],
    Field(discriminator="status"),
]


class CapabilityGranted(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: Literal["granted"]
    grant: CapabilityGrant


class CapabilityDenied(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: Literal["denied"]
    reason: str
    denied_capability: Optional[str] = None


CapabilityOutcome = Annotated[
    Union[CapabilityGranted, CapabilityDenied],
    Field(discriminator="status"),
]


class ExecutionSuccess(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: Literal["success"]


class ExecutionTrap(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: Literal["trap"]
    message: str


class ExecutionResourceExceeded(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: Literal["resource_exceeded"]
    kind: str


class ExecutionHostDenied(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: Literal["host_denied"]
    reason: str


ExecutionOutcome = Annotated[
    Union[
        ExecutionSuccess,
        ExecutionTrap,
        ExecutionResourceExceeded,
        ExecutionHostDenied,
    ],
    Field(discriminator="status"),
]


class AuditIntent(BaseModel):
    # BREAK (AILAB-619, migration owner AILAB-624): a schema-2 intent line
    # carries `line_type: "intent"` instead of `phase`, `request_digest` instead
    # of `input_digest`, and the chain fields `seq` + `prev_hash`. It is never
    # signed. This model matches none of that and will reject every current
    # line.
    model_config = ConfigDict(extra="ignore")

    schema_version: int
    phase: Literal["intent"]
    call_id: str
    tool_id: str
    input_digest: str


class AuditRecord(BaseModel):
    """Outcome line — required fields match botzr-aegis-core AuditRecord.

    BREAK (AILAB-619, migration owner AILAB-624): stale for schema 2. A current
    outcome line carries `line_type: "outcome"`, `request_digest`,
    `policy_set_hash`, `seq`, `prev_hash`, `signature`, `key_id`, an
    always-present `decision_axes` object, and optional `grant_id` /
    `response_digest`. `phase` and `input_digest` no longer exist on the wire.
    """

    model_config = ConfigDict(extra="ignore")

    schema_version: int
    phase: Literal["outcome"]
    call_id: str
    tool_id: str
    input_digest: str
    policy: PolicyOutcome
    capability: CapabilityOutcome
    execution: ExecutionOutcome
    wall_ms: Optional[int] = None
    peak_memory_bytes: Optional[int] = None


# Convenience for type checkers / proposers
def outcome_execution_status(record: AuditRecord) -> str:
    return record.execution.status  # type: ignore[union-attr]


def as_dict(model: BaseModel) -> dict[str, Any]:
    return model.model_dump()
