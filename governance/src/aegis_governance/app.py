"""Minimal FastAPI surface for governance slices 1–2.

Proposals and findings are never written into the Rust runtime.
In-process state only (D21, D22).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from aegis_governance.audit_ingest import IngestBatch, IngestError, ingest_jsonl
from aegis_governance.detect import Finding, run_detectors
from aegis_governance.guardian import Guardian, NullGuardian
from aegis_governance.policy_floor import (
    FloorDecision,
    check_floor,
    load_default_floor,
)
from aegis_governance.propose import propose_narrowing


@dataclass
class GovernanceState:
    buffer: IngestBatch = field(default_factory=IngestBatch)
    findings: list[Finding] = field(default_factory=list)


class ProposeRequest(BaseModel):
    current_policy_yaml: str = Field(
        ...,
        description="Current runtime policy YAML (compiler of truth remains Rust).",
    )


def create_app(
    state: Optional[GovernanceState] = None,
    guardian: Optional[Guardian] = None,
) -> FastAPI:
    app = FastAPI(title="aegis-governance", version="0.2.0")
    app.state.governance = state or GovernanceState()
    app.state.guardian = guardian or NullGuardian()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/floor")
    def get_floor() -> dict[str, Any]:
        floor = load_default_floor()
        return {
            "version": floor.version,
            "never_auto_grant": sorted(floor.never_auto_grant),
            "forbid_default_allow": floor.forbid_default_allow,
        }

    @app.post("/v1/ingest")
    async def ingest(request: Request) -> dict[str, int]:
        body = (await request.body()).decode("utf-8")
        try:
            batch = ingest_jsonl(body)
        except IngestError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        gov: GovernanceState = app.state.governance
        gov.buffer.extend(batch)
        return {
            "intents": len(batch.intents),
            "outcomes": len(batch.outcomes),
            "buffer_outcomes": len(gov.buffer.outcomes),
        }

    @app.post("/v1/propose")
    def propose(req: ProposeRequest) -> dict[str, Any]:
        gov: GovernanceState = app.state.governance
        proposal = propose_narrowing(gov.buffer, req.current_policy_yaml)
        if proposal is None:
            raise HTTPException(status_code=404, detail="no narrowing proposal")

        floor = check_floor(req.current_policy_yaml, proposal.policy_yaml)
        if floor.decision == FloorDecision.REJECT:
            # Widen = human-gated; never auto-apply. Surface as 409.
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "floor_violation",
                    "reason": floor.reason,
                    "status": "pending_human",
                },
            )

        return {
            "status": proposal.status.value,
            "rationale": proposal.rationale,
            "source_call_ids": proposal.source_call_ids,
            "policy_yaml": proposal.policy_yaml,
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

    return app


app = create_app()
