"""Policy floor — never relaxable; widen past floor → reject."""

from __future__ import annotations

from aegis_governance.policy_floor import FloorDecision, check_floor, load_default_floor

CURRENT = """\
version: 1
default: deny
rules:
  - id: allow-reader
    action: allow
    tool: reader
    limits: { max_memory_bytes: 1048576, max_wall_ms: 5000 }
"""


def test_load_default_floor_forbids_net_and_exec() -> None:
    floor = load_default_floor()
    assert "net" in floor.never_auto_grant
    assert "exec" in floor.never_auto_grant or "exec.command" in floor.never_auto_grant


def test_narrow_deny_rule_passes_floor() -> None:
    proposed = """\
version: 1
default: deny
rules:
  - id: allow-reader
    action: allow
    tool: reader
    limits: { max_memory_bytes: 1048576, max_wall_ms: 5000 }
  - id: deny-missing
    action: deny
    tool: missing
    reason: "capability denials observed"
"""
    result = check_floor(CURRENT, proposed)
    assert result.decision == FloorDecision.ACCEPT


def test_tighten_limits_passes_floor() -> None:
    proposed = """\
version: 1
default: deny
rules:
  - id: allow-reader
    action: allow
    tool: reader
    limits: { max_memory_bytes: 1048576, max_wall_ms: 1000 }
"""
    result = check_floor(CURRENT, proposed)
    assert result.decision == FloorDecision.ACCEPT


def test_widen_net_allow_rejected() -> None:
    proposed = """\
version: 1
default: deny
rules:
  - id: allow-reader
    action: allow
    tool: reader
    limits: { max_memory_bytes: 1048576, max_wall_ms: 5000 }
  - id: allow-net
    action: allow
    tool: fetcher
    capability: net.http
"""
    result = check_floor(CURRENT, proposed)
    assert result.decision == FloorDecision.REJECT
    assert result.reason


def test_raise_wall_ms_rejected_as_widen() -> None:
    proposed = """\
version: 1
default: deny
rules:
  - id: allow-reader
    action: allow
    tool: reader
    limits: { max_memory_bytes: 1048576, max_wall_ms: 9000 }
"""
    result = check_floor(CURRENT, proposed)
    assert result.decision == FloorDecision.REJECT


def test_default_deny_to_allow_rejected() -> None:
    proposed = """\
version: 1
default: allow
rules: []
"""
    result = check_floor(CURRENT, proposed)
    assert result.decision == FloorDecision.REJECT


def test_exec_allow_rejected() -> None:
    proposed = """\
version: 1
default: deny
rules:
  - id: allow-shell
    action: allow
    tool: shell
    capability: exec.command
"""
    result = check_floor(CURRENT, proposed)
    assert result.decision == FloorDecision.REJECT
