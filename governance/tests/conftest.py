"""Shared pytest setup for the governance suite.

The README tells an operator to `export AEGIS_GOVERNANCE_DATABASE_URL=...` and
then run `pytest -q` in the same shell. Without this fixture, every bare
`TestClient(create_app())` in the pre-existing tests would pick that URL up and
either 503 (un-migrated database) or silently write learning rows into the
operator's live database. Tests that want the real store construct it
explicitly from `AEGIS_GOVERNANCE_TEST_DATABASE_URL` instead.
"""

from __future__ import annotations

import pytest

from aegis_governance.learning_postgres import DATABASE_URL_ENV


@pytest.fixture(autouse=True)
def isolate_learning_store_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep `create_app()`'s default store in-process for every test."""
    monkeypatch.delenv(DATABASE_URL_ENV, raising=False)
