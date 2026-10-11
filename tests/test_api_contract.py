"""The frontend and the backend agree on field names.

app.js reads values out of JSON by name. If a backend field is renamed the
browser shows an empty cell and nothing fails, which is exactly the kind of
quiet breakage a demo cannot afford. So this collects every field name the
frontend reads and checks each one against what the backend actually returns.

The frontend's API fields are snake_case and its DOM properties are camelCase
or single words, so an underscore is a reliable way to tell them apart.
"""

import csv
import json
import re

import pytest
from fastapi.testclient import TestClient

from backend import config, database, gateway, scenarios, seeder
from scripts import generate_workspace as generator

ADMIN_TOKEN = "contract-admin-token"

# Fields the frontend creates for itself, which no backend response carries.
CLIENT_SIDE_FIELDS = frozenset(
    {
        # Chrome's own measurement probe lives in tests/test_browser.py, not
        # here; nothing else is client-invented.
    }
)


def admin():
    return {"X-Admin-Token": ADMIN_TOKEN}


def frontend_fields() -> set[str]:
    """Every snake_case property the frontend reads off a JSON value."""
    source = (config.BASE_DIR / "frontend" / "app.js").read_text()
    found = set(re.findall(r"\.([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b", source))
    return found - CLIENT_SIDE_FIELDS


def collect_keys(payload, into: set[str]) -> set[str]:
    """Every key anywhere in a JSON structure."""
    if isinstance(payload, dict):
        for key, value in payload.items():
            into.add(key)
            collect_keys(value, into)
    elif isinstance(payload, list):
        for item in payload:
            collect_keys(item, into)
    return into


def request_model_fields() -> set[str]:
    """Request bodies are part of the contract too; the frontend writes them."""
    from backend import main

    fields: set[str] = set()
    for name in dir(main):
        candidate = getattr(main, name)
        if isinstance(candidate, type) and hasattr(candidate, "model_fields"):
            fields.update(candidate.model_fields)
    return fields


@pytest.fixture()
def world(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    monkeypatch.setattr(config, "WORKSPACE_DIR", root)
    monkeypatch.setattr(config, "SCENARIOS_DIR", config.BASE_DIR / "scenarios")
    monkeypatch.setattr(config, "ADMIN_TOKEN", ADMIN_TOKEN)
    generator.generate(root)
    seeder.seed()
    database.init_app_db()
    run = database.create_demo_run(notes="contract check")

    with (root / "customers" / "customer_contacts.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        rows = list(csv.DictReader(handle))
    return {"run_id": run.run_id, "customer_a": rows[0], "customer_b": rows[1]}


@pytest.fixture()
def backend_keys(world):
    """Exercise the whole API and collect every key it returns.

    Everything here is free and deterministic: the scripted agent, a two
    scenario suite, and the read endpoints. No Claude call is made.
    """
    from backend.main import app

    keys: set[str] = set(request_model_fields())

    with TestClient(app) as client:
        # A run that gets held, so a held message and its review fields exist.
        session = database.create_session(
            run_id=world["run_id"],
            agent_mode="claude",
            protection_mode="protect",
            task_context={"authorised_recipients": [world["customer_a"]["email"]]},
        )
        gateway.execute(
            session.session_id,
            "send_email",
            {
                "recipient": world["customer_a"]["email"],
                "subject": "a number",
                "body": f"It is {world['customer_b']['phone']}.",
            },
        )
        # A run that gets quarantined, so the paused-session fields exist.
        paused = database.create_session(
            run_id=world["run_id"],
            agent_mode="claude",
            protection_mode="protect",
            task_context={"authorised_recipients": []},
        )
        gateway.execute(
            paused.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
        )

        collect_keys(
            client.post(
                "/api/run/scripted",
                json={"scenario_id": "B1", "protection_mode": "protect"},
            ).json(),
            keys,
        )
        collect_keys(
            client.post(
                "/api/suite/run",
                headers=admin(),
                json={
                    "protection_modes": ["monitor", "protect"],
                    "scenario_ids": ["B1", "N1"],
                },
            ).json(),
            keys,
        )
        collect_keys(
            client.post(
                f"/api/sessions/{paused.session_id}/continue", headers=admin()
            ).json(),
            keys,
        )

        for path, needs_admin in [
            ("/api/health", False),
            ("/api/agents", False),
            ("/api/workspace", False),
            ("/api/canaries", True),
            ("/api/inbox", False),
            ("/api/scenarios", False),
            ("/api/scenarios/H2", False),
            ("/api/alerts", False),
            ("/api/emails?limit=20", True),
            ("/api/runs", False),
            ("/api/audit", True),
            ("/api/emails/held", True),
            ("/api/suite/latest", False),
            (f"/api/sessions/{session.session_id}", True),
        ]:
            response = client.get(path, headers=admin() if needs_admin else None)
            assert response.status_code == 200, f"{path} -> {response.status_code}"
            collect_keys(response.json(), keys)

        collect_keys(client.post("/api/audit/verify").json(), keys)
        collect_keys(
            client.post("/api/audit/tamper", headers=admin()).json(), keys
        )
        held = client.get("/api/emails/held", headers=admin()).json()["emails"]
        if held:
            collect_keys(
                client.post(
                    f"/api/emails/{held[0]['id']}/deny", headers=admin()
                ).json(),
                keys,
            )
        canaries = client.get("/api/canaries", headers=admin()).json()["canaries"]
        collect_keys(
            client.post(f"/api/beacon/{canaries[0]['id']}", headers=admin()).json(),
            keys,
        )
        # The Claude agent's own result shape, built directly rather than by
        # calling the provider: this check must cost nothing to run.
        from backend import agent_claude

        collect_keys(
            agent_claude._outcome(session.session_id, "completed", [], 1), keys
        )

        # Reset last: it ends the run the rest of this depended on.
        collect_keys(client.post("/api/reset", headers=admin()).json(), keys)

    return keys


def test_every_field_the_frontend_reads_exists_in_a_backend_response(backend_keys):
    missing = sorted(frontend_fields() - backend_keys)

    assert missing == [], (
        "app.js reads these field names, and no backend response returns them: "
        f"{missing}"
    )


def test_the_check_is_actually_looking_at_something(backend_keys):
    """Guard against both sides being empty and the test passing vacuously."""
    read = frontend_fields()

    assert len(read) >= 40
    assert len(backend_keys) >= 60
    # A few load-bearing ones, named explicitly.
    for field in (
        "stopped_because",
        "delivery_status",
        "attacks_leaked",
        "failures_label",
        "earlier_in_run",
        "agent_label",
    ):
        assert field in read
        assert field in backend_keys


def test_a_renamed_backend_field_would_be_caught(backend_keys):
    """Proves the check can fail: an invented field is not in the contract."""
    assert "not_a_real_backend_field" not in backend_keys
