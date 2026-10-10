"""Shared test fixtures.

Every test runs against databases in a temporary directory, so the suite
never reads or writes the real data/app.db or vault/registry.db.
"""

import pytest

from backend import config, database


@pytest.fixture(autouse=True)
def temp_databases(tmp_path, monkeypatch):
    """Point both databases at a per-test temporary directory.

    database.py reads these paths from config at call time rather than
    binding them at import, which is what makes this redirection work.
    """
    monkeypatch.setattr(config, "APP_DB", tmp_path / "app.db")
    monkeypatch.setattr(config, "REGISTRY_DB", tmp_path / "registry.db")
    yield


@pytest.fixture()
def run_id():
    """An initialised app database with one open demo run."""
    database.init_app_db()
    return database.create_demo_run(notes="test run").run_id


@pytest.fixture()
def session(run_id):
    """An active Claude session in protect mode."""
    return database.create_session(
        run_id=run_id,
        agent_mode="claude",
        protection_mode="protect",
        task_context={
            "requester": "mei.ling.tan@example.com",
            "authorised_recipients": ["mei.ling.tan@example.com"],
        },
    )
