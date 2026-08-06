"""Minimal FastAPI surface for governance slices 1–4.

Proposals and findings are never written into the Rust runtime.
Buffer, findings, and packs stay in-process (D21–D23); only learning patterns
are durable (D24), and nearest patterns are evidence, never policy authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from aegis_governance.audit_ingest import IngestBatch, IngestError, ingest_jsonl
from aegis_governance.detect import Finding, run_detectors
from aegis_governance.guardian import Guardian, NullGuardian
from aegis_governance.learning import (
    DEFAULT_SEARCH_LIMIT,
    MAX_SEARCH_LIMIT,
    MIN_SEARCH_LIMIT,
    InMemoryLearningStore,
    LearningStore,
    LearningStoreError,
    PatternNeighbor,
    SourcePatternNotFoundError,
)
from aegis_governance.learning_postgres import PostgresLearningStore
from aegis_governance.packs import (
    PackAlreadyRatifiedError,
    PackFloorError,
    PackNotFoundError,
    PackRegistry,
)
from aegis_governance.policy_floor import (
    FloorDecision,
    check_floor,
    load_default_floor,
)
from aegis_governance.propose import propose_narrowing

# Evidence budget for /v1/propose. Small on purpose: neighbors are a reading
# aid for the human reviewer, not an input to the decision.
EVIDENCE_PER_SOURCE_CALL = 3
EVIDENCE_TOTAL = 5


@dataclass
class GovernanceState:
    buffer: IngestBatch = field(default_factory=IngestBatch)
    findings: list[Finding] = field(default_factory=list)
    packs: PackRegistry = field(default_factory=PackRegistry)


class ProposeRequest(BaseModel):
    current_policy_yaml: str = Field(
        ...,
        description="Current runtime policy YAML (compiler of truth remains Rust).",
    )


class CreatePackRequest(BaseModel):
    current_policy_yaml: str = Field(
        ..., description="Current runtime policy YAML (base for the floor check)."
    )
    policy_yaml: str = Field(..., description="Proposed policy snapshot for the pack.")
    rationale: str = ""
    source_call_ids: list[str] = Field(default_factory=list)
    pack_id: Optional[str] = None
    parent_version: Optional[int] = None


class RatifyRequest(BaseModel):
    accept: bool = Field(..., description="True → accepted; False → rejected.")


class PatternSearchRequest(BaseModel):
    call_id: str = Field(..., min_length=1, description="Stored source call id.")
    tool_id: Optional[str] = Field(
        None, description="Optional exact tool_id filter (never fuzzy)."
    )
    limit: int = Field(
        DEFAULT_SEARCH_LIMIT,
        ge=MIN_SEARCH_LIMIT,
        le=MAX_SEARCH_LIMIT,
        description="Neighbor count; outside [1, 50] is a 422.",
    )


def default_learning_store() -> LearningStore:
    """Postgres when `AEGIS_GOVERNANCE_DATABASE_URL` is set, else in-process.

    Schema is never created here — run the migrate command explicitly.
    """
    return PostgresLearningStore.from_env() or InMemoryLearningStore()


def _store_unavailable(e: LearningStoreError) -> HTTPException:
    """Durable store configured but broken → 503, never a policy decision."""
    return HTTPException(
        status_code=503,
        detail={"error": "learning_store_unavailable", "reason": str(e)},
    )


def create_app(
    state: Optional[GovernanceState] = None,
    guardian: Optional[Guardian] = None,
    learning_store: Optional[LearningStore] = None,
) -> FastAPI:
    app = FastAPI(title="aegis-governance", version="0.3.0")
    app.state.governance = state or GovernanceState()
    app.state.guardian = guardian or NullGuardian()
    app.state.learning_store = learning_store or default_learning_store()

    @app.get("/health")
    def health() -> dict[str, str]:
        store: LearningStore = app.state.learning_store
        # Mode only — never echo the database URL.
        return {"status": "ok", "learning_store": store.mode}

    @app.get("/v1/floor")
    def get_floor() -> dict[str, Any]:
        floor = load_default_floor()
        return {
            "version": floor.version,
            "never_auto_grant": sorted(floor.never_auto_grant),
            "forbid_default_allow": floor.forbid_default_allow,
        }

    @app.post("/v1/ingest")
    async def ingest(request: Request) -> dict[str, Any]:
        body = (await request.body()).decode("utf-8")
        try:
            batch = ingest_jsonl(body)
        except IngestError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        gov: GovernanceState = app.state.governance
        store: LearningStore = app.state.learning_store

        # Order is load-bearing: validate → persist patterns in one transaction
        # → only then extend the in-memory buffer. A store failure therefore
        # leaves *neither* side partially updated (503, nothing buffered).
        # psycopg is synchronous, so it goes through the threadpool rather than
        # blocking the event loop.
        try:
            persisted = await run_in_threadpool(store.upsert_patterns, batch.outcomes)
        except LearningStoreError as e:
            raise _store_unavailable(e) from e

        gov.buffer.extend(batch)
        return {
            "intents": len(batch.intents),
            "outcomes": len(batch.outcomes),
            "patterns_persisted": persisted,
            "buffer_outcomes": len(gov.buffer.outcomes),
        }

    def _learning_evidence(source_call_ids: list[str]) -> list[dict[str, Any]]:
        """Nearest stored patterns for a proposal's source calls.

        Evidence only: this runs *after* the proposal and the floor check, and
        its result is never fed back into either. Unknown sources contribute
        nothing rather than an invented probe vector.

        One batched round trip: `source_call_ids` grows with the unbounded
        ingest buffer, so a per-source query would open a connection per call.
        """
        store: LearningStore = app.state.learning_store
        grouped = store.search_neighbors_batch(
            source_call_ids, limit=EVIDENCE_PER_SOURCE_CALL
        )
        best: dict[str, PatternNeighbor] = {}
        for neighbors in grouped.values():
            for neighbor in neighbors:
                current = best.get(neighbor.pattern_id)
                if current is None or neighbor.distance < current.distance:
                    best[neighbor.pattern_id] = neighbor
        ordered = sorted(best.values(), key=lambda n: (n.distance, n.call_id))
        return [n.to_evidence() for n in ordered[:EVIDENCE_TOTAL]]

    @app.post("/v1/propose")
    def propose(req: ProposeRequest) -> dict[str, Any]:
        gov: GovernanceState = app.state.governance
        proposal = propose_narrowing(gov.buffer, req.current_policy_yaml)
        if proposal is None:
            raise HTTPException(status_code=404, detail="no narrowing proposal")

        floor = check_floor(req.current_policy_yaml, proposal.policy_yaml)
        if floor.decision == FloorDecision.REJECT:
            # Widen = human-gated; never auto-apply. Surface as 409 — before
            # any neighbor lookup, so evidence can never soften a rejection.
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "floor_violation",
                    "reason": floor.reason,
                    "status": "pending_human",
                },
            )

        # A broken store fails loudly rather than presenting "no similar past
        # patterns", which a human reviewer would read as a real signal.
        try:
            evidence = _learning_evidence(proposal.source_call_ids)
        except LearningStoreError as e:
            raise _store_unavailable(e) from e

        return {
            "status": proposal.status.value,
            "rationale": proposal.rationale,
            "source_call_ids": proposal.source_call_ids,
            # Unchanged by neighbors — the rule-based proposer is the only
            # thing that writes this field.
            "policy_yaml": proposal.policy_yaml,
            "learning_evidence": evidence,
        }

    @app.post("/v1/patterns/search")
    def search_patterns(req: PatternSearchRequest) -> dict[str, Any]:
        """Nearest stored patterns for a source call. Read-only, no policy."""
        store: LearningStore = app.state.learning_store
        try:
            neighbors = store.search_neighbors(
                req.call_id, tool_id=req.tool_id, limit=req.limit
            )
        except SourcePatternNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        except LearningStoreError as e:
            raise _store_unavailable(e) from e
        return {
            "call_id": req.call_id,
            "count": len(neighbors),
            "neighbors": [n.to_dict() for n in neighbors],
        }

    @app.post("/v1/detect")
    def detect() -> dict[str, Any]:
        gov: GovernanceState = app.state.governance
        g: Guardian = app.state.guardian
        emitted = g.review(run_detectors(gov.buffer), gov.buffer)
        gov.findings.extend(emitted)
        return {
            "emitted": len(emitted),
            "findings": [f.to_dict() for f in emitted],
            "buffer_findings": len(gov.findings),
        }

    @app.get("/v1/findings")
    def list_findings() -> dict[str, Any]:
        gov: GovernanceState = app.state.governance
        return {
            "findings": [f.to_dict() for f in gov.findings],
            "count": len(gov.findings),
        }

    @app.post("/v1/packs")
    def create_pack(req: CreatePackRequest) -> dict[str, Any]:
        gov: GovernanceState = app.state.governance
        try:
            pack = gov.packs.create_from_proposal(
                current_policy_yaml=req.current_policy_yaml,
                proposed_policy_yaml=req.policy_yaml,
                rationale=req.rationale,
                source_call_ids=req.source_call_ids,
                pack_id=req.pack_id,
                parent_version=req.parent_version,
            )
        except PackFloorError as e:
            # Widen = human-gated; never store, never auto-apply. Surface as 409.
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "floor_violation",
                    "reason": str(e),
                    "status": "pending_human",
                },
            ) from e
        return pack.to_dict()

    @app.get("/v1/packs")
    def list_packs() -> dict[str, Any]:
        gov: GovernanceState = app.state.governance
        packs = gov.packs.list_packs()
        return {"packs": [p.to_dict() for p in packs], "count": len(packs)}

    @app.get("/v1/packs/{pack_id}")
    def get_pack(pack_id: str) -> dict[str, Any]:
        gov: GovernanceState = app.state.governance
        pack = gov.packs.get(pack_id)
        if pack is None:
            raise HTTPException(status_code=404, detail="pack not found")
        return pack.to_dict()

    @app.get("/v1/packs/{pack_id}/versions/{version}")
    def get_pack_version(pack_id: str, version: int) -> dict[str, Any]:
        gov: GovernanceState = app.state.governance
        pack = gov.packs.get(pack_id, version)
        if pack is None:
            raise HTTPException(status_code=404, detail="pack version not found")
        return pack.to_dict()

    @app.post("/v1/packs/{pack_id}/versions/{version}/ratify")
    def ratify_pack(pack_id: str, version: int, req: RatifyRequest) -> dict[str, Any]:
        gov: GovernanceState = app.state.governance
        try:
            # Governance-only status flip — never writes into the Rust runtime.
            pack = gov.packs.ratify(pack_id, version, req.accept)
        except PackNotFoundError as e:
            raise HTTPException(status_code=404, detail="pack version not found") from e
        except PackAlreadyRatifiedError as e:
            raise HTTPException(
                status_code=409,
                detail={"error": "already_ratified", "reason": str(e)},
            ) from e
        return pack.to_dict()

    return app


app = create_app()
