"""Stage 7 checks: the tamper-evident audit chain.

One behaviour per test. The audit endpoints require the administrator token
from Stage 9 onwards: the log holds references that are linkable to a person,
so it is admin data in its own right.
"""

import importlib
import json
import threading

import pytest
from fastapi.testclient import TestClient

from backend import audit, config, database

ADMIN_TOKEN = "test-admin-token-7f3a"


def append(run_id, **kwargs):
    defaults = {"event_type": "TOOL_CALL", "decision": "allowed"}
    return audit.append_audit_event(run_id=run_id, **{**defaults, **kwargs})


@pytest.fixture()
def client(monkeypatch):
    """A test client with the admin token configured."""
    monkeypatch.setattr(config, "ADMIN_TOKEN", ADMIN_TOKEN)
    from backend.main import app

    with TestClient(app) as test_client:
        yield test_client


def admin(token=ADMIN_TOKEN):
    return {"X-Admin-Token": token}


# ---------------------------------------------------------------------------
# A valid chain
# ---------------------------------------------------------------------------


def test_an_empty_chain_is_valid(run_id):
    result = audit.verify_audit_chain(run_id)

    assert result["valid"] is True
    assert result["event_count"] == 0
    assert result["first_invalid_event_id"] is None


def test_one_event_is_valid(run_id):
    append(run_id, event_type="SESSION_CREATED")

    assert audit.verify_audit_chain(run_id)["valid"] is True


def test_the_first_event_of_a_run_links_to_genesis(run_id):
    event = append(run_id, event_type="SESSION_CREATED")

    assert event.previous_hash == "GENESIS"


def test_many_events_are_valid(run_id):
    for index in range(25):
        append(run_id, resource=f"workspace/customers/file_{index}.csv")

    result = audit.verify_audit_chain(run_id)

    assert result["valid"] is True
    assert result["event_count"] == 25


def test_each_event_links_to_the_previous_one(run_id):
    first = append(run_id, event_type="A")
    second = append(run_id, event_type="B")
    third = append(run_id, event_type="C")

    assert second.previous_hash == first.event_hash
    assert third.previous_hash == second.event_hash


def test_an_events_hash_covers_its_own_fields(run_id):
    event = append(
        run_id,
        tool="read_file",
        resource="workspace/customers/customer_contacts.csv",
        decision="quarantined",
        rule="read_time_quarantine",
        reason="A decoy record was present in the requested file.",
    )

    assert audit.event_hash_of(event) == event.event_hash


def test_hashes_are_stable_for_identical_content():
    payload = {field: "x" for field in audit.HASHED_FIELDS}

    assert audit.compute_event_hash(payload) == audit.compute_event_hash(dict(payload))


def test_changing_any_hashed_field_changes_the_hash():
    payload = {field: "x" for field in audit.HASHED_FIELDS}
    baseline = audit.compute_event_hash(payload)

    for field in audit.HASHED_FIELDS:
        altered = dict(payload)
        altered[field] = "y"
        assert audit.compute_event_hash(altered) != baseline, field


def test_canary_ids_are_stored_as_a_sorted_list(run_id):
    event = append(run_id, canary_ids=["zzz", "aaa", "mmm"])

    assert json.loads(event.canary_ids) == ["aaa", "mmm", "zzz"]


def test_the_log_stores_references_not_file_contents(run_id):
    """An event names the file and the decoys, never what the file said."""
    event = append(
        run_id,
        tool="read_file",
        resource="workspace/customers/customer_contacts.csv",
        decision="quarantined",
        canary_ids=["canary-1"],
    )

    stored = " ".join(str(value) for value in event.model_dump().values())
    assert "workspace/customers/customer_contacts.csv" in stored
    assert "@example.com" not in stored
    assert "+65" not in stored


# ---------------------------------------------------------------------------
# Detecting an edit
# ---------------------------------------------------------------------------


def test_editing_an_old_event_is_detected(run_id):
    first = append(run_id, event_type="A", reason="Blocked an outbound message.")
    append(run_id, event_type="B")
    append(run_id, event_type="C")
    assert audit.verify_audit_chain(run_id)["valid"] is True

    database.overwrite_audit_event_reason_for_demo(first.id, "Nothing unusual.")

    result = audit.verify_audit_chain(run_id)
    assert result["valid"] is False
    assert result["first_invalid_event_id"] == first.id


def test_editing_the_newest_event_is_detected(run_id):
    append(run_id, event_type="A")
    last = append(run_id, event_type="B", reason="Original reason.")

    database.overwrite_audit_event_reason_for_demo(last.id, "Edited.")

    assert audit.verify_audit_chain(run_id)["first_invalid_event_id"] == last.id


def test_a_broken_previous_hash_is_detected(run_id):
    append(run_id, event_type="A")
    second = append(run_id, event_type="B")

    with database.app_connection() as connection:
        connection.execute(
            "UPDATE audit_events SET previous_hash = ? WHERE id = ?",
            ("0" * 64, second.id),
        )

    result = audit.verify_audit_chain(run_id)
    assert result["valid"] is False
    assert result["first_invalid_event_id"] == second.id
    assert "does not follow" in result["reason"]


def test_the_first_invalid_event_is_the_one_reported(run_id):
    """With two edits, verification names the earlier one."""
    first = append(run_id, event_type="A", reason="first")
    append(run_id, event_type="B")
    third = append(run_id, event_type="C", reason="third")

    database.overwrite_audit_event_reason_for_demo(third.id, "edited")
    database.overwrite_audit_event_reason_for_demo(first.id, "edited")

    assert audit.verify_audit_chain(run_id)["first_invalid_event_id"] == first.id


def test_an_edit_invalidates_the_chain_after_it_too(run_id):
    """The later events' links no longer match the edited event."""
    first = append(run_id, event_type="A", reason="original")
    append(run_id, event_type="B")
    database.overwrite_audit_event_reason_for_demo(first.id, "edited")

    events = audit.list_audit_events(run_id=run_id)
    assert audit.event_hash_of(events[0]) != events[0].event_hash
    assert events[1].previous_hash == events[0].event_hash


def test_deleting_an_event_breaks_the_chain(run_id):
    append(run_id, event_type="A")
    second = append(run_id, event_type="B")
    append(run_id, event_type="C")

    with database.app_connection() as connection:
        connection.execute("DELETE FROM audit_events WHERE id = ?", (second.id,))

    assert audit.verify_audit_chain(run_id)["valid"] is False


def test_the_reason_for_failure_is_plain_english(run_id):
    event = append(run_id, event_type="A", reason="original")
    database.overwrite_audit_event_reason_for_demo(event.id, "edited")

    reason = audit.verify_audit_chain(run_id)["reason"]

    assert "fingerprint" in reason
    assert "hash" not in reason.lower()


# ---------------------------------------------------------------------------
# One chain per run
# ---------------------------------------------------------------------------


def test_each_run_has_its_own_chain(run_id):
    append(run_id, event_type="A")
    other = database.create_demo_run()
    first_of_other = append(other.run_id, event_type="A")

    assert first_of_other.previous_hash == "GENESIS"
    assert audit.verify_audit_chain(run_id)["valid"] is True
    assert audit.verify_audit_chain(other.run_id)["valid"] is True


def test_tampering_with_one_run_leaves_another_valid(run_id):
    event = append(run_id, event_type="A", reason="original")
    other = database.create_demo_run()
    append(other.run_id, event_type="A")

    database.overwrite_audit_event_reason_for_demo(event.id, "edited")

    assert audit.verify_audit_chain(run_id)["valid"] is False
    assert audit.verify_audit_chain(other.run_id)["valid"] is True


def test_events_can_be_listed_per_session(run_id, session):
    append(run_id, session_id=session.session_id, event_type="TOOL_CALL")
    append(run_id, event_type="ADMIN_ACTION")

    events = audit.list_audit_events(session_id=session.session_id)

    assert [event.event_type for event in events] == ["TOOL_CALL"]


# ---------------------------------------------------------------------------
# Concurrent appends
# ---------------------------------------------------------------------------


def test_concurrent_appends_produce_one_valid_chain(run_id):
    """Each event reads the tip and inserts in one immediate transaction."""
    errors = []

    def worker(index):
        try:
            for step in range(5):
                append(run_id, event_type=f"T{index}_{step}")
        except Exception as error:  # pragma: no cover - reported below
            errors.append(error)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    result = audit.verify_audit_chain(run_id)
    assert result["event_count"] == 20
    assert result["valid"] is True


# ---------------------------------------------------------------------------
# The demo tamper helper
# ---------------------------------------------------------------------------


def test_the_demo_tamper_helper_edits_the_oldest_event(run_id):
    oldest = append(run_id, event_type="A", reason="original reason")
    append(run_id, event_type="B")

    result = audit.tamper_with_oldest_event_for_demo(run_id)

    assert result["tampered_event_id"] == oldest.id
    assert result["original_reason"] == "original reason"
    assert audit.verify_audit_chain(run_id)["first_invalid_event_id"] == oldest.id


def test_the_demo_tamper_records_itself_in_the_log(run_id):
    append(run_id, event_type="A")

    result = audit.tamper_with_oldest_event_for_demo(run_id)
    recorded = database.get_audit_event(result["recorded_as_event_id"])

    assert recorded.event_type == "AUDIT_TAMPERED_FOR_DEMO"
    assert str(result["tampered_event_id"]) in recorded.resource


def test_the_demo_tamper_needs_an_event_to_edit(run_id):
    with pytest.raises(ValueError, match="no audit entries"):
        audit.tamper_with_oldest_event_for_demo(run_id)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


def test_get_audit_returns_the_current_runs_events(client):
    run = database.get_or_create_active_demo_run()
    append(run.run_id, event_type="A", resource="workspace/customers/orders.json")

    response = client.get("/api/audit", headers=admin())

    assert response.status_code == 200
    body = response.json()
    assert body["run_id"] == run.run_id
    assert body["count"] == 1
    assert body["events"][0]["resource"] == "workspace/customers/orders.json"


def test_get_audit_accepts_a_run_id(client):
    other = database.create_demo_run()
    append(other.run_id, event_type="A")

    response = client.get(
        "/api/audit", params={"run_id": other.run_id}, headers=admin()
    )

    assert response.json()["count"] == 1


def test_verify_endpoint_reports_a_valid_chain(client):
    run = database.get_or_create_active_demo_run()
    append(run.run_id, event_type="A")

    body = client.post("/api/audit/verify").json()

    assert body["valid"] is True
    assert body["run_id"] == run.run_id


def test_verify_endpoint_reports_the_broken_entry(client):
    run = database.get_or_create_active_demo_run()
    event = append(run.run_id, event_type="A", reason="original")
    database.overwrite_audit_event_reason_for_demo(event.id, "edited")

    body = client.post("/api/audit/verify").json()

    assert body["valid"] is False
    assert body["first_invalid_event_id"] == event.id


def test_tamper_endpoint_requires_the_admin_token(client):
    run = database.get_or_create_active_demo_run()
    append(run.run_id, event_type="A")

    assert client.post("/api/audit/tamper").status_code == 401
    assert client.post("/api/audit/tamper", headers=admin("wrong")).status_code == 401
    assert audit.verify_audit_chain(run.run_id)["valid"] is True


def test_tamper_endpoint_works_with_the_token(client):
    run = database.get_or_create_active_demo_run()
    event = append(run.run_id, event_type="A", reason="original")

    response = client.post("/api/audit/tamper", headers=admin())

    assert response.status_code == 200
    assert response.json()["tampered_event_id"] == event.id
    assert client.post("/api/audit/verify").json()["valid"] is False


def test_tamper_endpoint_records_which_run_was_tampered(client):
    run = database.get_or_create_active_demo_run()
    append(run.run_id, event_type="A")

    body = client.post("/api/audit/tamper", headers=admin()).json()

    assert body["run_id"] == run.run_id


def test_tamper_endpoint_on_an_empty_chain_is_a_conflict(client):
    assert client.post("/api/audit/tamper", headers=admin()).status_code == 409


def test_admin_endpoints_fail_closed_without_a_configured_token(monkeypatch):
    monkeypatch.setattr(config, "ADMIN_TOKEN", "")
    from backend.main import app

    with TestClient(app) as test_client:
        response = test_client.post("/api/audit/tamper", headers=admin())

    assert response.status_code == 503


def test_the_admin_token_is_never_echoed_back(client):
    response = client.post("/api/audit/tamper", headers=admin("wrong-token"))

    assert ADMIN_TOKEN not in response.text
    assert "wrong-token" not in response.text


def test_tamper_endpoint_is_absent_when_demo_mode_is_off(monkeypatch):
    """The route does not exist, not merely refuse."""
    monkeypatch.setattr(config, "DEMO_MODE", False)
    monkeypatch.setattr(config, "ADMIN_TOKEN", ADMIN_TOKEN)

    from backend import main as main_module

    reloaded = importlib.reload(main_module)
    try:
        paths = {route.path for route in reloaded.app.routes}
        assert "/api/audit/tamper" not in paths

        with TestClient(reloaded.app) as test_client:
            response = test_client.post("/api/audit/tamper", headers=admin())
        assert response.status_code == 404
    finally:
        monkeypatch.setattr(config, "DEMO_MODE", True)
        importlib.reload(main_module)


def test_tamper_endpoint_is_present_when_demo_mode_is_on(client):
    from backend.main import app

    paths = {route.path for route in app.routes}

    assert "/api/audit/tamper" in paths
