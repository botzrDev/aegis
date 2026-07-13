"""Rule-based narrow-only policy proposals.

Never proposes action: allow that expands ambient authority.
Never auto-applies into the Rust runtime — status is always pending_human.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import yaml

from aegis_governance.audit_ingest import IngestBatch
from aegis_governance.models import AuditRecord

# Threshold before emitting a proposal for a given signal.
REPEAT_THRESHOLD = 3
# When tightening wall clock after resource_exceeded, use this fraction of prior.
WALL_MS_TIGHTEN_FACTOR = 0.5
DEFAULT_TIGHTENED_WALL_MS = 2500


class ProposalStatus(str, Enum):
    PENDING_HUMAN = "pending_human"


@dataclass
class Proposal:
    status: ProposalStatus
    rationale: str
    source_call_ids: list[str]
    policy_yaml: str


def propose_narrowing(
    batch: IngestBatch,
    current_policy_yaml: str,
) -> Optional[Proposal]:
    """Emit at most one narrowing proposal from the ingest buffer, or None."""
    if not batch.outcomes:
        return None

    # Prefer resource_exceeded tightening, then capability-deny rules.
    resource = _collect_resource_exceeded(batch.outcomes)
    for tool_id, call_ids in resource.items():
        if len(call_ids) < REPEAT_THRESHOLD:
            continue
        proposal = _propose_tighten_wall(tool_id, call_ids, current_policy_yaml)
        if proposal is not None:
            return proposal

    cap_denies = _collect_capability_denies(batch.outcomes)
    for tool_id, call_ids in cap_denies.items():
        if len(call_ids) < REPEAT_THRESHOLD:
            continue
        proposal = _propose_deny_tool(tool_id, call_ids, current_policy_yaml)
        if proposal is not None:
            return proposal

    return None


def _collect_resource_exceeded(outcomes: list[AuditRecord]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for rec in outcomes:
        if rec.execution.status == "resource_exceeded":
            out[rec.tool_id].append(rec.call_id)
    return out


def _collect_capability_denies(outcomes: list[AuditRecord]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for rec in outcomes:
        if rec.capability.status == "denied":
            # Skip pure policy-block-before-capability noise when policy already denied.
            if rec.policy.status == "denied":
                continue
            out[rec.tool_id].append(rec.call_id)
    return out


def _load_policy_dict(yaml_text: str) -> dict:
    raw = yaml.safe_load(yaml_text)
    if not isinstance(raw, dict):
        raise ValueError("current policy must be a mapping")
    rules = raw.get("rules") or []
    if not isinstance(rules, list):
        raise ValueError("rules must be a list")
    return raw


def _propose_tighten_wall(
    tool_id: str,
    call_ids: list[str],
    current_policy_yaml: str,
) -> Optional[Proposal]:
    current = _load_policy_dict(current_policy_yaml)
    rules = list(current.get("rules") or [])
    found = False
    new_wall: Optional[int] = None
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("action") != "allow" or rule.get("tool") != tool_id:
            continue
        limits = dict(rule.get("limits") or {})
        old = limits.get("max_wall_ms")
        if isinstance(old, int) and old > 0:
            new_wall = max(1, int(old * WALL_MS_TIGHTEN_FACTOR))
        else:
            new_wall = DEFAULT_TIGHTENED_WALL_MS
        limits["max_wall_ms"] = new_wall
        rule["limits"] = limits
        found = True
        break

    if not found:
        return None

    proposed = {
        "version": current.get("version", 1),
        "default": current.get("default", "deny"),
        "rules": rules,
    }
    policy_yaml = yaml.safe_dump(proposed, sort_keys=False)
    # Floor is enforced by the API (409 on widen). Proposer only emits narrows.
    return Proposal(
        status=ProposalStatus.PENDING_HUMAN,
        rationale=(
            f"Observed {len(call_ids)} resource_exceeded outcomes for tool "
            f"{tool_id!r}; propose lowering max_wall_ms to {new_wall}."
        ),
        source_call_ids=list(dict.fromkeys(call_ids)),
        policy_yaml=policy_yaml,
    )


def _propose_deny_tool(
    tool_id: str,
    call_ids: list[str],
    current_policy_yaml: str,
) -> Optional[Proposal]:
    current = _load_policy_dict(current_policy_yaml)
    rules = list(current.get("rules") or [])
    deny_id = f"deny-{tool_id}"
    if any(isinstance(r, dict) and r.get("id") == deny_id for r in rules):
        return None
    # Never emit action: allow here — only deny.
    rules.append(
        {
            "id": deny_id,
            "action": "deny",
            "tool": tool_id,
            "reason": "repeated capability denials observed in audit ingest",
        }
    )
    proposed = {
        "version": current.get("version", 1),
        "default": current.get("default", "deny"),
        "rules": rules,
    }
    policy_yaml = yaml.safe_dump(proposed, sort_keys=False)
    return Proposal(
        status=ProposalStatus.PENDING_HUMAN,
        rationale=(
            f"Observed {len(call_ids)} capability denials for tool {tool_id!r}; "
            "propose an explicit deny rule (narrowing only)."
        ),
        source_call_ids=list(dict.fromkeys(call_ids)),
        policy_yaml=policy_yaml,
    )
