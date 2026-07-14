"""Rule-based immune/drift detectors over ingested audit outcomes.

Emit pending_human findings only. Never widen policy. Never auto-apply into Rust.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional

from aegis_governance.audit_ingest import IngestBatch
from aegis_governance.models import AuditRecord, CapabilityGrant

# Aligned with propose.REPEAT_THRESHOLD.
REPEAT_THRESHOLD = 3


class FindingKind(str, Enum):
    CAPABILITY_CREEP = "capability_creep"
    RATE_SPIKE = "rate_spike"
    ANOMALOUS_ALLOW_DENY = "anomalous_allow_deny"


class FindingStatus(str, Enum):
    PENDING_HUMAN = "pending_human"


@dataclass(frozen=True)
class Finding:
    kind: FindingKind
    status: FindingStatus
    rationale: str
    source_call_ids: list[str]
    tool_id: Optional[str] = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["status"] = self.status.value
        return d


def run_detectors(batch: IngestBatch) -> list[Finding]:
    """Scan outcomes; at most one finding per (kind, tool_id)."""
    outcomes = batch.outcomes
    if not outcomes:
        return []

    findings: list[Finding] = []
    findings.extend(_detect_capability_creep(outcomes))
    findings.extend(_detect_rate_spikes(outcomes))
    findings.extend(_detect_anomalous_allow_deny(outcomes))
    return findings


def _detect_capability_creep(outcomes: list[AuditRecord]) -> list[Finding]:
    by_tool: dict[str, list[AuditRecord]] = defaultdict(list)
    for rec in outcomes:
        if rec.capability.status == "granted":
            by_tool[rec.tool_id].append(rec)

    findings: list[Finding] = []
    for tool_id, records in by_tool.items():
        if len(records) < 2:
            continue
        # Compare each later grant to the earliest grant for this tool.
        baseline = records[0]
        assert baseline.capability.status == "granted"
        base_grant = baseline.capability.grant
        for later in records[1:]:
            assert later.capability.status == "granted"
            later_grant = later.capability.grant
            widened = _grant_widens(base_grant, later_grant)
            if not widened:
                continue
            findings.append(
                Finding(
                    kind=FindingKind.CAPABILITY_CREEP,
                    status=FindingStatus.PENDING_HUMAN,
                    rationale=(
                        f"Capability grant for tool {tool_id!r} widened relative "
                        f"to earlier grant in the ingest buffer ({', '.join(widened)})."
                    ),
                    source_call_ids=[baseline.call_id, later.call_id],
                    tool_id=tool_id,
                    evidence={
                        "axes": widened,
                        "baseline_call_id": baseline.call_id,
                        "later_call_id": later.call_id,
                    },
                )
            )
            break  # one finding per tool
    return findings


def _grant_widens(earlier: CapabilityGrant, later: CapabilityGrant) -> list[str]:
    """Return list of axes where `later` strictly expands authority vs `earlier`."""
    axes: list[str] = []

    earlier_fs = earlier.fs
    later_fs = later.fs
    earlier_reads = set(earlier_fs.read_paths if earlier_fs else [])
    later_reads = set(later_fs.read_paths if later_fs else [])
    earlier_writes = set(earlier_fs.write_paths if earlier_fs else [])
    later_writes = set(later_fs.write_paths if later_fs else [])
    if not later_reads.issubset(earlier_reads) and later_reads - earlier_reads:
        axes.append("fs.read_paths")
    if not later_writes.issubset(earlier_writes) and later_writes - earlier_writes:
        axes.append("fs.write_paths")

    earlier_hosts = {
        (h.host, tuple(h.ports), tuple(h.methods))
        for h in (earlier.net.http if earlier.net else [])
    }
    later_hosts = {
        (h.host, tuple(h.ports), tuple(h.methods))
        for h in (later.net.http if later.net else [])
    }
    if later_hosts - earlier_hosts:
        axes.append("net.http")

    if later.max_memory_bytes > earlier.max_memory_bytes:
        axes.append("max_memory_bytes")
    if later.max_wall_ms > earlier.max_wall_ms:
        axes.append("max_wall_ms")
    if later.max_output_bytes > earlier.max_output_bytes:
        axes.append("max_output_bytes")

    return axes


def _detect_rate_spikes(outcomes: list[AuditRecord]) -> list[Finding]:
    by_tool: dict[str, list[str]] = defaultdict(list)
    for rec in outcomes:
        if rec.policy.status == "rate_limited":
            by_tool[rec.tool_id].append(rec.call_id)

    findings: list[Finding] = []
    for tool_id, call_ids in by_tool.items():
        if len(call_ids) < REPEAT_THRESHOLD:
            continue
        unique = list(dict.fromkeys(call_ids))
        findings.append(
            Finding(
                kind=FindingKind.RATE_SPIKE,
                status=FindingStatus.PENDING_HUMAN,
                rationale=(
                    f"Observed {len(call_ids)} rate_limited outcomes for tool "
                    f"{tool_id!r} (threshold {REPEAT_THRESHOLD})."
                ),
                source_call_ids=unique,
                tool_id=tool_id,
                evidence={"count": len(call_ids), "threshold": REPEAT_THRESHOLD},
            )
        )
    return findings


def _detect_anomalous_allow_deny(outcomes: list[AuditRecord]) -> list[Finding]:
    allows: dict[str, list[str]] = defaultdict(list)
    denies: dict[str, list[str]] = defaultdict(list)
    for rec in outcomes:
        if rec.policy.status == "allowed":
            allows[rec.tool_id].append(rec.call_id)
        elif rec.policy.status == "denied":
            denies[rec.tool_id].append(rec.call_id)

    findings: list[Finding] = []
    tools = set(allows) | set(denies)
    for tool_id in tools:
        allow_ids = allows.get(tool_id, [])
        deny_ids = denies.get(tool_id, [])
        if len(allow_ids) < REPEAT_THRESHOLD or len(deny_ids) < REPEAT_THRESHOLD:
            continue
        source = list(dict.fromkeys([*allow_ids, *deny_ids]))
        findings.append(
            Finding(
                kind=FindingKind.ANOMALOUS_ALLOW_DENY,
                status=FindingStatus.PENDING_HUMAN,
                rationale=(
                    f"Tool {tool_id!r} has mixed policy signals in buffer: "
                    f"{len(allow_ids)} allowed and {len(deny_ids)} denied "
                    f"(each ≥ {REPEAT_THRESHOLD})."
                ),
                source_call_ids=source,
                tool_id=tool_id,
                evidence={
                    "allowed_count": len(allow_ids),
                    "denied_count": len(deny_ids),
                    "threshold": REPEAT_THRESHOLD,
                },
            )
        )
    return findings
