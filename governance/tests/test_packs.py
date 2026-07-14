"""Versioned in-process policy packs — floor-checked, human-ratified, no Rust I/O."""

from __future__ import annotations

import pytest

from aegis_governance.packs import (
    PackAlreadyRatifiedError,
    PackFloorError,
    PackNotFoundError,
    PackRegistry,
    PackStatus,
)

# Baseline runtime policy (compiler of truth stays Rust). Matches test_api / propose.
BASELINE = """\
version: 1
default: deny
rules:
  - id: allow-reader
    action: allow
    tool: reader
    limits: { max_memory_bytes: 1048576, max_wall_ms: 5000, max_output_bytes: 1048576 }
"""

# Narrow snapshot: keeps the allow untouched, adds an explicit deny. Floor ACCEPTs.
NARROW = """\
version: 1
default: deny
rules:
  - id: allow-reader
    action: allow
    tool: reader
    limits: { max_memory_bytes: 1048576, max_wall_ms: 5000, max_output_bytes: 1048576 }
  - id: deny-fetcher
    action: deny
    tool: fetcher
    reason: repeated capability denials observed in audit ingest
"""

# Widen snapshot: mints a fresh net.http allow — a floor axis. Floor REJECTs.
WIDEN = """\
version: 1
default: deny
rules:
  - id: allow-reader
    action: allow
    tool: reader
    limits: { max_memory_bytes: 1048576, max_wall_ms: 5000, max_output_bytes: 1048576 }
  - id: allow-net
    action: allow
    tool: fetcher
    capability: net.http
"""

PACK_KEYS = {
    "pack_id",
    "version",
    "parent_version",
    "status",
    "rationale",
    "source_call_ids",
    "policy_yaml",
}


def _create(reg: PackRegistry, proposed: str = NARROW, **kw):
    return reg.create_from_proposal(
        current_policy_yaml=BASELINE,
        proposed_policy_yaml=proposed,
        rationale=kw.pop("rationale", "tighten fetcher"),
        source_call_ids=kw.pop("source_call_ids", ["c1"]),
        **kw,
    )


def test_create_narrow_pack_starts_pending_human() -> None:
    reg = PackRegistry()
    pack = _create(reg, source_call_ids=["call-a", "call-b"])
    assert pack.status == PackStatus.PENDING_HUMAN
    assert pack.version == 1
    assert pack.parent_version is None
    assert pack.pack_id
    assert pack.policy_yaml == NARROW
    assert pack.source_call_ids == ["call-a", "call-b"]
    assert pack.rationale


def test_widen_raises_floor_error_and_is_not_stored() -> None:
    reg = PackRegistry()
    with pytest.raises(PackFloorError):
        _create(reg, proposed=WIDEN)
    # REJECT must not store anything.
    assert reg.list_packs() == []


def test_version_lineage_defaults_parent_to_latest() -> None:
    reg = PackRegistry()
    p1 = _create(reg, pack_id="pack-reader")
    p2 = _create(reg, pack_id="pack-reader")
    p3 = _create(reg, pack_id="pack-reader")
    assert (p1.version, p1.parent_version) == (1, None)
    assert (p2.version, p2.parent_version) == (2, 1)
    assert (p3.version, p3.parent_version) == (3, 2)


def test_explicit_parent_version_is_honored_for_successor() -> None:
    reg = PackRegistry()
    _create(reg, pack_id="pack-reader")  # v1
    _create(reg, pack_id="pack-reader")  # v2
    p3 = _create(reg, pack_id="pack-reader", parent_version=1)  # fork off v1
    assert p3.version == 3
    assert p3.parent_version == 1


def test_get_latest_and_exact_version() -> None:
    reg = PackRegistry()
    _create(reg, pack_id="pack-reader")
    v2 = _create(reg, pack_id="pack-reader")
    assert reg.get("pack-reader").version == 2  # default = latest
    assert reg.get("pack-reader", 1).version == 1
    assert reg.get("pack-reader", 2) is v2


def test_get_missing_returns_none() -> None:
    reg = PackRegistry()
    _create(reg, pack_id="pack-reader")
    assert reg.get("no-such-pack") is None
    assert reg.get("pack-reader", 99) is None


def test_list_packs_all_versions_newest_first() -> None:
    reg = PackRegistry()
    _create(reg, pack_id="pack-a")
    _create(reg, pack_id="pack-b")
    _create(reg, pack_id="pack-a")  # pack-a v2, newest
    listed = reg.list_packs()
    assert len(listed) == 3
    assert (listed[0].pack_id, listed[0].version) == ("pack-a", 2)
    assert (listed[-1].pack_id, listed[-1].version) == ("pack-a", 1)


def test_ratify_accept_flips_status() -> None:
    reg = PackRegistry()
    pack = _create(reg, pack_id="pack-reader")
    out = reg.ratify("pack-reader", 1, accept=True)
    assert out.status == PackStatus.ACCEPTED
    assert reg.get("pack-reader", 1).status == PackStatus.ACCEPTED
    assert out is pack


def test_ratify_reject_flips_status() -> None:
    reg = PackRegistry()
    _create(reg, pack_id="pack-reader")
    out = reg.ratify("pack-reader", 1, accept=False)
    assert out.status == PackStatus.REJECTED


def test_double_ratify_raises_already_ratified() -> None:
    reg = PackRegistry()
    _create(reg, pack_id="pack-reader")
    reg.ratify("pack-reader", 1, accept=True)
    with pytest.raises(PackAlreadyRatifiedError):
        reg.ratify("pack-reader", 1, accept=False)


def test_ratify_missing_raises_not_found() -> None:
    reg = PackRegistry()
    with pytest.raises(PackNotFoundError):
        reg.ratify("no-such-pack", 1, accept=True)
    _create(reg, pack_id="pack-reader")
    with pytest.raises(PackNotFoundError):
        reg.ratify("pack-reader", 99, accept=True)


def test_ratify_is_governance_only_never_claims_rust_apply() -> None:
    """Ratify flips in-process status only — no runtime/apply signaling."""
    reg = PackRegistry()
    _create(reg, pack_id="pack-reader")
    out = reg.ratify("pack-reader", 1, accept=True)
    d = out.to_dict()
    assert set(d) == PACK_KEYS  # no "applied"/"rust"/"runtime" keys leak
    assert out.status.value == "accepted"
    # The pack carries a policy snapshot, not an apply receipt.
    assert d["policy_yaml"] == NARROW


def test_to_dict_is_json_friendly() -> None:
    reg = PackRegistry()
    pack = _create(reg, pack_id="pack-reader", source_call_ids=["c1", "c2"])
    d = pack.to_dict()
    assert d["pack_id"] == "pack-reader"
    assert d["version"] == 1
    assert d["parent_version"] is None
    assert d["status"] == "pending_human"
    assert d["source_call_ids"] == ["c1", "c2"]
    assert isinstance(d["policy_yaml"], str)
