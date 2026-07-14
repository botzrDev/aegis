"""Versioned in-process policy packs (AEG-26 slice 3).

A pack is a floor-checked policy YAML snapshot with identity, a monotonic
version, lineage (parent_version), rationale, and the audit ``source_call_ids``
that motivated it. Packs are minted ``pending_human`` and a human ratifies
(accept/reject) them **inside governance only** — ratifying never writes into
the Rust runtime (`botzr-aegis-*`). No durable store: everything lives in
memory on the `PackRegistry` (D21/D22/D23).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from aegis_governance.policy_floor import FloorDecision, check_floor


class PackStatus(str, Enum):
    PENDING_HUMAN = "pending_human"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class PackError(Exception):
    """Base for pack registry errors."""


class PackFloorError(PackError):
    """Proposed pack widens past the floor; it is not stored. Maps to HTTP 409."""


class PackNotFoundError(PackError):
    """No pack for the given (pack_id, version). Maps to HTTP 404."""


class PackAlreadyRatifiedError(PackError):
    """Pack is already accepted/rejected; ratify is terminal. Maps to HTTP 409."""


@dataclass
class PolicyPack:
    pack_id: str
    version: int
    parent_version: Optional[int]
    policy_yaml: str
    status: PackStatus
    rationale: str
    source_call_ids: list[str]
    # Optional provenance, e.g. {"from_propose": True}. Not part of the API contract.
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly view. Governance-only fields — no apply/runtime receipt."""
        return {
            "pack_id": self.pack_id,
            "version": self.version,
            "parent_version": self.parent_version,
            "status": self.status.value,
            "rationale": self.rationale,
            "source_call_ids": list(self.source_call_ids),
            "policy_yaml": self.policy_yaml,
        }


class PackRegistry:
    """In-process versioned packs. Never persists to disk/DB in this slice."""

    def __init__(self) -> None:
        # Insertion order; newest last. All versions retained (research instrument).
        self._packs: list[PolicyPack] = []

    def create_from_proposal(
        self,
        *,
        current_policy_yaml: str,
        proposed_policy_yaml: str,
        rationale: str,
        source_call_ids: list[str],
        pack_id: Optional[str] = None,
        parent_version: Optional[int] = None,
    ) -> PolicyPack:
        """Floor-check; on ACCEPT mint at pending_human; on REJECT raise PackFloorError.

        The floor is enforced *before* anything is stored: a widen never lands.
        """
        result = check_floor(current_policy_yaml, proposed_policy_yaml)
        if result.decision == FloorDecision.REJECT:
            raise PackFloorError(result.reason or "floor violation")

        if pack_id is None:
            pack_id = uuid.uuid4().hex

        latest = self._latest(pack_id)
        if latest is None:
            version = 1
            parent: Optional[int] = None
        else:
            version = latest.version + 1
            parent = parent_version if parent_version is not None else latest.version

        pack = PolicyPack(
            pack_id=pack_id,
            version=version,
            parent_version=parent,
            policy_yaml=proposed_policy_yaml,
            status=PackStatus.PENDING_HUMAN,  # human still ratifies after floor ACCEPT
            rationale=rationale,
            source_call_ids=list(source_call_ids),
            evidence={"from_propose": True},
        )
        self._packs.append(pack)
        return pack

    def list_packs(self) -> list[PolicyPack]:
        """All packs, all versions, newest first."""
        return list(reversed(self._packs))

    def get(self, pack_id: str, version: Optional[int] = None) -> Optional[PolicyPack]:
        """Exact version, or the latest version when ``version`` is None."""
        if version is None:
            return self._latest(pack_id)
        for pack in self._packs:
            if pack.pack_id == pack_id and pack.version == version:
                return pack
        return None

    def ratify(self, pack_id: str, version: int, accept: bool) -> PolicyPack:
        """Flip a pending pack to accepted/rejected — governance-only, no Rust I/O."""
        pack = self.get(pack_id, version)
        if pack is None:
            raise PackNotFoundError(f"no pack {pack_id!r} version {version}")
        if pack.status != PackStatus.PENDING_HUMAN:
            raise PackAlreadyRatifiedError(
                f"pack {pack_id!r} version {version} already {pack.status.value}"
            )
        pack.status = PackStatus.ACCEPTED if accept else PackStatus.REJECTED
        return pack

    def _latest(self, pack_id: str) -> Optional[PolicyPack]:
        found = [p for p in self._packs if p.pack_id == pack_id]
        if not found:
            return None
        return max(found, key=lambda p: p.version)
