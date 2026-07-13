"""Policy floor checks — never relaxable; never blind-load proposed YAML.

Validated parse of current + proposed policy documents. Any widen past the
floor → reject. Auto-apply paths must only accept narrows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml

_FLOOR_PATH = Path(__file__).with_name("floor.default.yaml")


class FloorDecision(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"


@dataclass(frozen=True)
class PolicyFloor:
    version: int
    never_auto_grant: frozenset[str]
    forbid_default_allow: bool


@dataclass
class FloorResult:
    decision: FloorDecision
    reason: Optional[str] = None


@dataclass
class _RuleView:
    id: str
    action: str
    tool: Optional[str] = None
    capability: Optional[str] = None
    max_memory_bytes: Optional[int] = None
    max_wall_ms: Optional[int] = None
    max_output_bytes: Optional[int] = None


@dataclass
class _PolicyView:
    default: str
    rules: list[_RuleView] = field(default_factory=list)

    def rule_by_id(self) -> dict[str, _RuleView]:
        return {r.id: r for r in self.rules}


def load_default_floor() -> PolicyFloor:
    """Load the packaged floor document (validated; never blind-load)."""
    return load_floor_yaml(_FLOOR_PATH.read_text(encoding="utf-8"))


def load_floor_yaml(text: str) -> PolicyFloor:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ValueError(f"invalid floor YAML: {e}") from e
    if not isinstance(raw, dict):
        raise ValueError("floor YAML must be a mapping")
    version = raw.get("version")
    if version != 1:
        raise ValueError(f"unsupported floor version: {version!r}")
    never = raw.get("never_auto_grant") or []
    if not isinstance(never, list) or not all(isinstance(x, str) for x in never):
        raise ValueError("never_auto_grant must be a list of strings")
    return PolicyFloor(
        version=1,
        never_auto_grant=frozenset(never),
        forbid_default_allow=bool(raw.get("forbid_default_allow", True)),
    )


def _parse_policy(yaml_text: str) -> _PolicyView:
    """Parse runtime-compatible policy YAML into a view for floor comparison.

    Never blind-loads: requires a mapping with version + default + rules shape.
    """
    try:
        raw = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise ValueError(f"invalid policy YAML: {e}") from e
    if not isinstance(raw, dict):
        raise ValueError("policy YAML must be a mapping")
    version = raw.get("version", 1)
    if version != 1:
        raise ValueError(f"unsupported policy version: {version!r}")
    default = str(raw.get("default", "allow")).lower()
    if default not in ("allow", "deny"):
        raise ValueError(f"invalid default: {default!r}")
    rules_raw = raw.get("rules") or []
    if not isinstance(rules_raw, list):
        raise ValueError("rules must be a list")
    rules: list[_RuleView] = []
    for item in rules_raw:
        if not isinstance(item, dict):
            raise ValueError("each rule must be a mapping")
        rid = item.get("id")
        action = item.get("action")
        if not isinstance(rid, str) or not isinstance(action, str):
            raise ValueError("rule requires string id and action")
        limits = item.get("limits") or {}
        if limits is None:
            limits = {}
        if not isinstance(limits, dict):
            raise ValueError("limits must be a mapping")
        rules.append(
            _RuleView(
                id=rid,
                action=action.lower(),
                tool=item.get("tool"),
                capability=item.get("capability"),
                max_memory_bytes=_opt_int(limits.get("max_memory_bytes")),
                max_wall_ms=_opt_int(limits.get("max_wall_ms")),
                max_output_bytes=_opt_int(limits.get("max_output_bytes")),
            )
        )
    return _PolicyView(default=default, rules=rules)


def _opt_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    return int(value)


def _axis_blocked(capability: Optional[str], floor: PolicyFloor) -> bool:
    if not capability:
        return False
    cap = capability.lower()
    for axis in floor.never_auto_grant:
        a = axis.lower()
        if cap == a or cap.startswith(a + ".") or a.startswith(cap + "."):
            return True
        # bare "net" blocks "net.http"; bare "exec" blocks "exec.command"
        if a in cap.split("."):
            return True
    return False


def check_floor(
    current_policy: str,
    proposed_policy: str,
    floor: Optional[PolicyFloor] = None,
) -> FloorResult:
    """Reject any widen past the floor relative to current policy."""
    active = floor or load_default_floor()
    try:
        current = _parse_policy(current_policy)
        proposed = _parse_policy(proposed_policy)
    except ValueError as e:
        return FloorResult(FloorDecision.REJECT, reason=str(e))

    if active.forbid_default_allow:
        if current.default == "deny" and proposed.default == "allow":
            return FloorResult(
                FloorDecision.REJECT,
                reason="floor forbids relaxing default deny → allow",
            )

    cur_by_id = current.rule_by_id()

    for rule in proposed.rules:
        if rule.action == "allow" and _axis_blocked(rule.capability, active):
            return FloorResult(
                FloorDecision.REJECT,
                reason=(
                    f"floor forbids auto-grant of capability axis "
                    f"{rule.capability!r} (rule {rule.id})"
                ),
            )

        # Raising limits on an existing allow rule is a widen.
        prev = cur_by_id.get(rule.id)
        if prev is not None and rule.action == "allow" and prev.action == "allow":
            if _limit_raised(prev.max_wall_ms, rule.max_wall_ms):
                return FloorResult(
                    FloorDecision.REJECT,
                    reason=f"raising max_wall_ms on rule {rule.id} is a widen",
                )
            if _limit_raised(prev.max_memory_bytes, rule.max_memory_bytes):
                return FloorResult(
                    FloorDecision.REJECT,
                    reason=f"raising max_memory_bytes on rule {rule.id} is a widen",
                )
            if _limit_raised(prev.max_output_bytes, rule.max_output_bytes):
                return FloorResult(
                    FloorDecision.REJECT,
                    reason=f"raising max_output_bytes on rule {rule.id} is a widen",
                )

        # New allow without a matching current allow for same tool = ambient expand
        # unless it only tightens via limits on an existing allow (handled above).
        if rule.action == "allow" and prev is None:
            # Adding a brand-new allow expands authority — reject unless it is
            # purely a deny/limit path. Floor: no new allows under auto-apply.
            # Narrow-only proposals should copy existing allows and add denies /
            # tighten limits, not mint new allows.
            # Exception: identical tool allow already present under another id.
            if not _has_allow_for_tool(current, rule.tool):
                return FloorResult(
                    FloorDecision.REJECT,
                    reason=f"new allow rule {rule.id} expands ambient authority",
                )

    return FloorResult(FloorDecision.ACCEPT)


def _has_allow_for_tool(policy: _PolicyView, tool: Optional[str]) -> bool:
    if tool is None:
        return False
    return any(r.action == "allow" and r.tool == tool for r in policy.rules)


def _limit_raised(old: Optional[int], new: Optional[int]) -> bool:
    if old is None or new is None:
        return False
    return new > old
