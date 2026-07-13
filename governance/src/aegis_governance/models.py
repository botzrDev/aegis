"""Pydantic mirrors of Aegis audit schema v1 (intent + outcome).

Audit ingest is untrusted: validate strictly on required fields; ignore unknown
keys for forward-compat; reject schema_version != 1.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class AuditPhase(str, Enum):
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
    model_config = ConfigDict(extra="ignore")

    schema_version: int
    phase: Literal["intent"]
    call_id: str
    tool_id: str
    input_digest: str


class AuditRecord(BaseModel):
    """Outcome line — required fields match botzr-aegis-core AuditRecord."""

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
