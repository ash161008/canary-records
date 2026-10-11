"""Stage 16 regression tests: the findings from the security review.

Each test pins one thing the review checked, so a later change cannot quietly
undo it.
"""

import csv
import re

import pytest
from fastapi.testclient import TestClient

from backend import config, database, gateway, seeder, sessions
from scripts import generate_workspace as generator

ADMIN_TOKEN = "stage16-admin-token-1a7b"


def admin(token=ADMIN_TOKEN):
    return {"X-Admin-Token": token}


@pytest.fixture()
def world(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    monkeypatch.setattr(config, "WORKSPACE_DIR", root)
    monkeypatch.setattr(config, "ADMIN_TOKEN", ADMIN_TOKEN)
    generator.generate(root)
    seeder.seed()
    database.init_app_db()
    run = database.create_demo_run(notes="security review")

    with (root / "customers" / "customer_contacts.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        rows = list(csv.DictReader(handle))
    return {"run_id": run.run_id, "customer_a": rows[0], "customer_b": rows[1]}


@pytest.fixture()
def client(world):
    from backend.main import app

    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Finding A: a paid endpoint must not be open
# ---------------------------------------------------------------------------


def test_running_claude_needs_the_admin_token(client):
    """Every call to it spends money with the model provider."""
    response = client.post(
        "/api/run/claude",
        json={"inbox_id": "normal_order_1042", "protection_mode": "protect"},
    )

    assert response.status_code == 401


def test_resuming_claude_needs_the_admin_token(client):
    assert client.post("/api/run/claude/anything/resume").status_code == 401


def test_the_free_scripted_agent_stays_open(client, world):
    """It costs nothing and is deterministic, so it needs no token."""
    response = client.post(
        "/api/run/scripted", json={"scenario_id": "B1", "protection_mode": "protect"}
    )

    assert response.status_code != 401


# ---------------------------------------------------------------------------
# Finding B: message bodies are record data
# ---------------------------------------------------------------------------


def test_listing_messages_needs_the_admin_token(client):
    assert client.get("/api/emails").status_code == 401
    assert client.get("/api/emails", headers=admin()).status_code == 200


def test_a_held_message_body_is_not_reachable_without_the_token(client, world):
    """The body of a held message carries the personal data under review."""
    session = database.create_session(
        run_id=world["run_id"],
        agent_mode="claude",
        protection_mode="protect",
        task_context={"authorised_recipients": [world["customer_a"]["email"]]},
    )
    result = gateway.execute(
        session.session_id,
        "send_email",
        {
            "recipient": world["customer_a"]["email"],
            "subject": "the number",
            "body": f"It is {world['customer_b']['phone']}.",
        },
    )
    assert result["decision"] == "held"

    assert client.get("/api/emails").status_code == 401

    body = client.get("/api/emails", headers=admin()).text
    assert world["customer_b"]["phone"] in body


# ---------------------------------------------------------------------------
# Finding C: the task context names a customer's address on file
# ---------------------------------------------------------------------------


def test_reading_a_session_needs_the_admin_token(client, world):
    session = database.create_session(
        run_id=world["run_id"],
        agent_mode="claude",
        protection_mode="protect",
        task_context={"authorised_recipients": [world["customer_a"]["email"]]},
    )

    assert client.get(f"/api/sessions/{session.session_id}").status_code == 401
    assert (
        client.get(f"/api/sessions/{session.session_id}", headers=admin()).status_code
        == 200
    )


# ---------------------------------------------------------------------------
# What stays open, and why it is safe to
# ---------------------------------------------------------------------------


def test_no_open_endpoint_returns_a_record_value(client, world):
    """The open endpoints may return counts, metrics and fixtures - not records.

    The inbox and the scenarios are synthetic fixtures whose addresses are
    part of the demo script, so they are excluded; everything else must carry
    no customer phone, no customer email and no postal code from the records.
    """
    database.create_session(
        run_id=world["run_id"],
        agent_mode="claude",
        protection_mode="protect",
        task_context={"authorised_recipients": [world["customer_a"]["email"]]},
    )

    open_paths = [
        "/api/health",
        "/api/agents",
        "/api/workspace",
        "/api/runs",
        "/api/suite/latest",
        "/api/alerts",
    ]
    needle_phone = world["customer_a"]["phone"]
    needle_email = world["customer_a"]["email"]

    for path in open_paths:
        response = client.get(path)
        assert response.status_code == 200, path
        assert needle_phone not in response.text, path
        assert needle_email not in response.text, path


def test_chain_verification_stays_open_and_leaks_nothing(client, world):
    """Deliberately open: a log only its owner can verify is weaker."""
    response = client.post("/api/audit/verify")

    assert response.status_code == 200
    assert set(response.json()) == {
        "run_id",
        "valid",
        "event_count",
        "first_invalid_event_id",
        "reason",
    }


def test_the_workspace_endpoint_returns_counts_only(client):
    body = client.get("/api/workspace").json()

    assert "canaries_per_location" not in body
    assert "@example" not in str(body)


# ---------------------------------------------------------------------------
# Standing invariants the review re-checked
# ---------------------------------------------------------------------------


def test_only_the_gateway_executes_a_tool_for_an_agent():
    """No module but the gateway reads the workspace on an agent's behalf.

    sessions.py reads the inbox, which is backend work the specification
    requires: the inbox item is loaded by the backend, never named by the
    model, and it is not reachable through any agent tool.
    """
    offenders = []
    for path in sorted((config.BASE_DIR / "backend").glob("*.py")):
        if path.name in ("gateway.py", "workspace.py", "sessions.py"):
            continue
        text = path.read_text()
        for call in ("workspace.read_file", "workspace.list_folder"):
            if call in text:
                offenders.append(f"{path.name}:{call}")
    assert offenders == []


def test_no_module_but_the_gateway_writes_a_simulated_email():
    offenders = [
        path.name
        for path in sorted((config.BASE_DIR / "backend").glob("*.py"))
        if path.name not in ("gateway.py", "database.py")
        and "create_simulated_email" in path.read_text()
    ]

    assert offenders == []


def test_nothing_but_the_telegram_relay_makes_a_network_call():
    offenders = []
    for path in sorted((config.BASE_DIR / "backend").glob("*.py")):
        text = path.read_text()
        if path.name == "alerts.py":
            continue
        for marker in ("requests.post", "requests.get", "smtplib", "urlopen"):
            if marker in text:
                offenders.append(f"{path.name}:{marker}")
    assert offenders == []


def test_the_frontend_never_writes_data_as_html():
    source = (config.BASE_DIR / "frontend" / "app.js").read_text()

    for marker in ("insertAdjacentHTML", "document.write", ".outerHTML"):
        assert marker not in source, marker
    # The only mention is the comment saying it is never used.
    assert source.count("innerHTML") == 1


def test_no_sample_secret_is_committed():
    example = (config.BASE_DIR / ".env.example").read_text()

    for line in example.splitlines():
        if line.startswith(("ANTHROPIC_API_KEY", "ADMIN_TOKEN", "TELEGRAM_BOT_TOKEN")):
            assert line.split("=", 1)[1].strip() == "", line


def test_the_scan_happens_before_the_result_is_returned():
    """Check 7 must come after the tool runs and before any return."""
    source = (config.BASE_DIR / "backend" / "gateway.py").read_text()
    execute_at = source.index("# 6. Execute inside the synthetic workspace.")
    scan_at = source.index("# 7. Scan the result BEFORE returning anything.")
    body = source[scan_at:]

    assert execute_at < scan_at
    assert body.index("detector.scan(") < body.index('content=content')


def test_the_demo_only_helpers_are_named_as_such():
    """A demo-only mutation must be obvious at its call site."""
    database_source = (config.BASE_DIR / "backend" / "database.py").read_text()

    assert "def overwrite_audit_event_reason_for_demo" in database_source
    assert "DEMO" in database_source
