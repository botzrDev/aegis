"""Pydantic mirrors of the Agent Action Record, schema version 2.

Audit ingest is untrusted: validate strictly on required fields; ignore unknown
*members* for forward-compat (SPEC §12); reject `schema_version != 2`.

Schema version 1 is **not** accepted. `spec/SPEC.md` §12 states v1 is not
compatible, and a v1 line carries no `seq`, no `prev_hash` and no signature —
admitting one would put a record with no integrity evidence into a store whose
purpose is verifiable audit. `audit_ingest.SUPPORTED_SCHEMA_VERSION` is the
single pin; see `governance/DECISIONS.md` D25.

What these models do and do not claim
-------------------------------------
They parse. They do **not** verify. `signature` and `key_id` are validated as
present and well-formed on the **outcome** line — the only signed line type
this service consumes — because a missing one is a missing required field and
ingest fails closed on those. `open`, `decision` and `close` are signed too and
are skipped without any field check at all. No ed25519 check, no `prev_hash`
chain walk, and no `line_hash` recomputation happens here: a line with a
present-but-forged signature parses cleanly. Verification is `aegis verify`
(AILAB-621); until it lands, nothing downstream of this module may be described
as verified.

Unknown line types are the format's extensibility story (SPEC §5.2) and are
handled in `audit_ingest`, not here: an unrecognised `line_type` is skipped with
its token preserved verbatim, never coerced into a known type and never treated
as corruption.

Format reference: `spec/SPEC.md` at the repo root.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

#: SPEC §2 — 64 lowercase hex characters (SHA-256). Uppercase is *rejected, not
#: normalized*: one digest must have exactly one spelling, or two canonical
#: forms of the same line hash differently and a verifier disagrees with the
#: emitter for no visible reason.
#:
#: The spec's SHOULD — make transposing `prev_hash` / `policy_set_hash` /
#: `request_digest` / `response_digest` / `key_id` a *type* error — is met in
#: the Rust newtypes, not here: this alias constrains the wire form they share,
#: so a swap between two of them still parses. Treat these as validated
#: strings, not as distinct types.
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

#: SPEC §2 — 128 lowercase hex characters (64-byte ed25519 signature).
#: Well-formed, not verified; see the module docstring.
Signature = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$")]

#: An identifier that is present. Empty-string-as-absent is the same mistake as
#: null-as-absent, and the chain gate already rejects it for `line_type`.
Identifier = Annotated[str, StringConstraints(min_length=1)]


class AuditLineType(str, Enum):
    """The six line types schema 2 defines (SPEC §5.1).

    This enum is *not* the parser's vocabulary check. A `line_type` outside it
    is a newer emitter's line, not a bad line, and `audit_ingest` preserves the
    unrecognised token rather than mapping it onto a member here.
    """

    OPEN = "open"
    INTENT = "intent"
    OUTCOME = "outcome"
    DECISION = "decision"
    CLOSE = "close"
    CHECKPOINT = "checkpoint"  # reserved by the spec; no emitter produces one


#: Line types this service turns into typed records. Everything else — the rest
#: of `AuditLineType` plus anything a newer emitter invents — is skipped and
#: counted (SPEC §5.2). Downstream (`detect`, `propose`, `learning`) is
#: outcome-centric, so widening this set is a behaviour change, not a parser
#: detail.
INGESTED_LINE_TYPES: frozenset[str] = frozenset(
    {AuditLineType.INTENT.value, AuditLineType.OUTCOME.value}
)


class ChainLine(BaseModel):
    """The four fields every line of every type MUST carry (SPEC §5).

    A line missing or mistyping one of these is a format violation, **not** an
    unknown extension — that distinction is what bounds the extension story, so
    `audit_ingest` checks it before it looks at `line_type` at all.
    """

    model_config = ConfigDict(extra="ignore")

    schema_version: int
    line_type: str
    seq: int
    prev_hash: Digest


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


class FsAxis(BaseModel):
    """Derived filesystem parameter (SPEC §5.3, ADR-0006).

    Both members are required together: the *difference* between the raw and
    the canonical path is the evidence, so a shape carrying only one of them
    would record the axis while dropping the reason it exists. In schema 2 they
    carry the same string, because the capability resolver canonicalizes at
    mint time.
    """

    model_config = ConfigDict(extra="ignore")

    path_raw: str
    path_canonical: str


class NetAxis(BaseModel):
    """Derived network parameter (SPEC §5.3, ADR-0006)."""

    model_config = ConfigDict(extra="ignore")

    host: str
    port: int


class DecisionAxes(BaseModel):
    """The inputs the verdict actually turned on (SPEC §5.3).

    Always present on an outcome, possibly `{}` — `{}` says *this emitter
    recorded no axes*, an absent member says nothing at all, and collapsing the
    two would lose that distinction. Members follow omit-never-null, so every
    one is optional here; the null half of that rule is enforced at the ingest
    boundary (SPEC §3.2), because `Optional[str] = None` alone cannot tell an
    omitted member from an explicit `null`.

    Parsed but not yet consumed: the detectors and the feature vector stay on
    the axes they already used (AILAB-624 is a migration, not a detector
    rewrite). Encoding these into the embedding is a `FEATURE_SCHEMA_VERSION`
    bump, not an edit in place.
    """

    model_config = ConfigDict(extra="ignore")

    capability: Optional[str] = None
    role: Optional[str] = None
    #: The policy session scope — the `PolicyRequest` scalar, **not** the audit
    #: Session that `seq` counts within. Two different things, one word.
    session: Optional[str] = None
    matched_rule: Optional[str] = None
    approval_ref: Optional[str] = None
    fs: Optional[FsAxis] = None
    net: Optional[NetAxis] = None


class AuditIntent(ChainLine):
    """Pre-execution line for a call (SPEC §5.3).

    Never signed: the intent line is appended and fsynced *ahead of* execution,
    so a signature computation would land on the pre-execution critical path.
    It is authenticated transitively — the next signed line commits to
    `prev_hash`, which chains back through it. `signature` and `key_id` are
    therefore absent by design, not missing.
    """

    line_type: Literal["intent"]
    call_id: Identifier
    tool_id: Identifier
    request_digest: Digest


class AuditRecord(ChainLine):
    """Outcome line — the Agent Action Record itself (SPEC §5.3).

    One per call, on every exit path, including denial and trap. Required
    fields mirror `botzr-aegis-core`'s `AuditRecord`; `grant_id`,
    `response_digest`, `wall_ms` and `peak_memory_bytes` are omitted (never
    null) when the call never reached the station that produces them.

    `signature` and `key_id` are required because an outcome is in the signed
    set and ingest fails closed on missing required fields. Their *presence* is
    all this model asserts — see the module docstring.
    """

    line_type: Literal["outcome"]
    call_id: Identifier
    tool_id: Identifier
    request_digest: Digest
    policy_set_hash: Digest
    policy: PolicyOutcome
    capability: CapabilityOutcome
    execution: ExecutionOutcome
    decision_axes: DecisionAxes
    signature: Signature
    key_id: Digest
    grant_id: Optional[Identifier] = None
    response_digest: Optional[Digest] = None
    wall_ms: Optional[int] = None
    peak_memory_bytes: Optional[int] = None


# Convenience for type checkers / proposers
def outcome_execution_status(record: AuditRecord) -> str:
    return record.execution.status  # type: ignore[union-attr]


def as_dict(model: BaseModel) -> dict[str, Any]:
    return model.model_dump()
