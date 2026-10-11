"""Checks: schema initialisation and CRUD for every table.

One behaviour per test.
"""

import json
import re
import sqlite3

import pytest
from pydantic import ValidationError

from backend import config, database, detector, seeder

APP_TABLES = {
    "demo_runs",
    "agent_sessions",
    "audit_events",
    "alerts",
    "simulated_emails",
    "test_runs",
    "test_results",
}


def table_names(path):
    connection = sqlite3.connect(path)
    try:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    finally:
        connection.close()
    return {row[0] for row in rows}


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


def test_init_app_db_creates_every_table():
    database.init_app_db()
    assert APP_TABLES <= table_names(config.APP_DB)


def test_init_app_db_is_idempotent(run_id):
    database.init_app_db()
    database.init_app_db()

    assert database.get_demo_run(run_id) is not None
    assert len(database.list_demo_runs()) == 1


def test_init_registry_creates_canaries_table():
    seeder.init_registry()
    assert "canaries" in table_names(config.REGISTRY_DB)


def test_init_registry_is_idempotent():
    seeder.init_registry()
    canary = seeder.register_canary(
        canary_type="customer",
        location="workspace/customers/customer_contacts.csv",
        strong_values=["kai.ming.wong@example.net"],
        weak_values=["Kai Ming Wong"],
    )

    seeder.init_registry()

    assert seeder.get_registered_canary(canary.id) is not None


def test_utc_now_is_iso_8601_utc():
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", database.utc_now())


# ---------------------------------------------------------------------------
# The registry boundary
# ---------------------------------------------------------------------------


def test_registry_connection_refuses_an_unauthorised_module():
    """Only the seeder and the detector may open vault/registry.db."""
    with pytest.raises(PermissionError, match="may not open the canary registry"):
        with database.registry_connection() as connection:
            connection.execute("SELECT 1 FROM canaries")


def test_registry_crud_refuses_an_unauthorised_module():
    """The guard covers the CRUD helpers, not just the raw connection."""
    with pytest.raises(PermissionError):
        database.list_canaries()

    with pytest.raises(PermissionError):
        database.create_canary(
            canary_type="customer",
            location="workspace/customers/customer_contacts.csv",
            strong_values=["someone@example.com"],
            weak_values=["Someone"],
        )


def test_seeder_and_detector_may_reach_the_registry():
    seeder.init_registry()
    seeder.register_canary(
        canary_type="credential",
        location="workspace/it/integrations.txt",
        strong_values=["pk_live_7Qx4ttn2La9RbvEc"],
        weak_values=[],
    )

    assert len(seeder.list_registered_canaries()) == 1
    assert len(detector.load_active_canaries()) == 1


def test_registry_and_app_databases_are_outside_the_workspace():
    """No workspace path utility can resolve to either database."""
    workspace = config.WORKSPACE_DIR.resolve()

    assert workspace not in config.REGISTRY_DB.resolve().parents
    assert workspace not in config.APP_DB.resolve().parents


# ---------------------------------------------------------------------------
# demo_runs
# ---------------------------------------------------------------------------


def test_create_and_get_demo_run(run_id):
    run = database.get_demo_run(run_id)

    assert run is not None
    assert run.ended_at is None
    assert run.notes == "test run"


def test_end_demo_run_sets_ended_at(run_id):
    database.end_demo_run(run_id, notes="finished")
    run = database.get_demo_run(run_id)

    assert run.ended_at is not None
    assert run.notes == "finished"


def test_a_new_run_does_not_delete_the_old_one(run_id):
    """Reset starts a new run; old evidence is kept."""
    database.end_demo_run(run_id)
    second = database.create_demo_run(notes="after reset")

    run_ids = {run.run_id for run in database.list_demo_runs()}
    assert run_ids == {run_id, second.run_id}


def test_active_demo_run_is_the_open_one(run_id):
    database.end_demo_run(run_id)
    second = database.create_demo_run()

    assert database.get_active_demo_run().run_id == second.run_id


def test_get_or_create_active_demo_run_reuses_an_open_run(run_id):
    assert database.get_or_create_active_demo_run().run_id == run_id


# ---------------------------------------------------------------------------
# agent_sessions
# ---------------------------------------------------------------------------


def test_session_defaults(session):
    assert session.role == "support_agent"
    assert session.hr_access == 0
    assert session.status == "active"
    assert session.tainted == 0
    assert session.personal_items_sent_external == 0


def test_session_task_context_round_trips(session):
    context = database.get_session(session.session_id).task_context()

    assert context["requester"] == "mei.ling.tan@example.com"
    assert context["authorised_recipients"] == ["mei.ling.tan@example.com"]


def test_set_session_status_to_paused(session):
    updated = database.set_session_status(session.session_id, "paused")

    assert updated.status == "paused"
    assert updated.ended_at is None


def test_terminating_a_session_stamps_ended_at(session):
    updated = database.set_session_status(session.session_id, "terminated")

    assert updated.status == "terminated"
    assert updated.ended_at is not None


def test_set_hr_access(session):
    assert database.set_hr_access(session.session_id, True).hr_access == 1
    assert database.set_hr_access(session.session_id, False).hr_access == 0


def test_mark_session_tainted(session):
    assert database.mark_session_tainted(session.session_id).tainted == 1


def test_personal_items_sent_accumulates(session):
    database.add_personal_items_sent(session.session_id, 3)
    updated = database.add_personal_items_sent(session.session_id, 2)

    assert updated.personal_items_sent_external == 5


def test_conversation_state_saves_and_clears(session):
    database.save_conversation_state(session.session_id, {"messages": [{"role": "user"}]})
    saved = database.get_session(session.session_id)
    assert saved.conversation_state()["messages"] == [{"role": "user"}]

    database.save_conversation_state(session.session_id, None)
    assert database.get_session(session.session_id).conversation_state() == {}


def test_list_sessions_filters_by_run(session, run_id):
    other_run = database.create_demo_run()
    database.create_session(
        run_id=other_run.run_id, agent_mode="worst_case", protection_mode="monitor"
    )

    sessions = database.list_sessions(run_id=run_id)

    assert [item.session_id for item in sessions] == [session.session_id]


def test_invalid_agent_mode_is_rejected(run_id):
    with pytest.raises(ValidationError):
        database.create_session(
            run_id=run_id, agent_mode="rogue_agent", protection_mode="protect"
        )


def test_schema_rejects_an_invalid_status_from_raw_sql(session):
    """The CHECK constraints hold even if a helper is bypassed."""
    with pytest.raises(sqlite3.IntegrityError):
        with database.app_connection() as connection:
            connection.execute(
                "UPDATE agent_sessions SET status = ? WHERE session_id = ?",
                ("whatever", session.session_id),
            )


# ---------------------------------------------------------------------------
# protection_mode is fixed when a session is created
# ---------------------------------------------------------------------------


def test_update_session_refuses_protection_mode(session):
    with pytest.raises(ValueError, match="protection_mode"):
        database.update_session(session.session_id, protection_mode="monitor")

    assert database.get_session(session.session_id).protection_mode == "protect"


def test_raw_sql_cannot_change_protection_mode(session):
    """A database trigger blocks the write, not just the update helper."""
    with pytest.raises(sqlite3.Error, match="protection_mode is fixed"):
        with database.app_connection() as connection:
            connection.execute(
                "UPDATE agent_sessions SET protection_mode = ? WHERE session_id = ?",
                ("monitor", session.session_id),
            )

    assert database.get_session(session.session_id).protection_mode == "protect"


def test_other_session_fields_still_update_normally(session):
    """The trigger fires on protection_mode only."""
    updated = database.update_session(session.session_id, status="paused", tainted=1)

    assert updated.status == "paused"
    assert updated.tainted == 1
    assert updated.protection_mode == "protect"


def test_comparing_modes_means_a_new_session(session, run_id):
    """The documented way to change mode: create another session."""
    other = database.create_session(
        run_id=run_id, agent_mode="claude", protection_mode="monitor"
    )

    assert database.get_session(session.session_id).protection_mode == "protect"
    assert other.protection_mode == "monitor"


# ---------------------------------------------------------------------------
# audit_events
# ---------------------------------------------------------------------------


def test_first_audit_event_of_a_run_uses_genesis(run_id, session):
    event_id = database.create_audit_event(
        run_id=run_id,
        session_id=session.session_id,
        event_type="SESSION_CREATED",
        previous_hash=database.GENESIS_HASH,
        event_hash="hash-1",
    )

    event = database.get_audit_event(event_id)
    assert event.previous_hash == "GENESIS"


def test_audit_events_list_in_chain_order(run_id):
    for index in range(3):
        database.create_audit_event(
            run_id=run_id,
            event_type="TOOL_CALL",
            previous_hash=f"hash-{index}",
            event_hash=f"hash-{index + 1}",
        )

    events = database.list_audit_events(run_id=run_id)

    assert [event.event_hash for event in events] == ["hash-1", "hash-2", "hash-3"]


def test_get_last_audit_event_on_an_empty_chain(run_id):
    assert database.get_last_audit_event(run_id) is None


def test_get_last_audit_event_returns_the_newest(run_id):
    database.create_audit_event(
        run_id=run_id, event_type="A", previous_hash="GENESIS", event_hash="hash-1"
    )
    database.create_audit_event(
        run_id=run_id, event_type="B", previous_hash="hash-1", event_hash="hash-2"
    )

    assert database.get_last_audit_event(run_id).event_hash == "hash-2"


def test_audit_chains_are_separate_per_run(run_id, session):
    database.create_audit_event(
        run_id=run_id, event_type="A", previous_hash="GENESIS", event_hash="hash-a"
    )
    other_run = database.create_demo_run()
    database.create_audit_event(
        run_id=other_run.run_id,
        event_type="B",
        previous_hash="GENESIS",
        event_hash="hash-b",
    )

    assert len(database.list_audit_events(run_id=run_id)) == 1
    assert len(database.list_audit_events(run_id=other_run.run_id)) == 1


def test_audit_events_filter_by_session(run_id, session):
    database.create_audit_event(
        run_id=run_id,
        session_id=session.session_id,
        event_type="TOOL_CALL",
        previous_hash="GENESIS",
        event_hash="hash-1",
    )
    database.create_audit_event(
        run_id=run_id, event_type="ADMIN_ACTION", previous_hash="hash-1",
        event_hash="hash-2",
    )

    events = database.list_audit_events(session_id=session.session_id)

    assert [event.event_type for event in events] == ["TOOL_CALL"]


def test_audit_event_records_decision_fields_not_file_contents(run_id, session):
    event_id = database.create_audit_event(
        run_id=run_id,
        session_id=session.session_id,
        event_type="CANARY_READ",
        tool="read_file",
        resource="workspace/customers/customer_contacts.csv",
        decision="quarantined",
        rule="read_time_quarantine",
        reason="A decoy record was present in the requested file.",
        canary_ids=json.dumps(["canary-1", "canary-2"]),
        previous_hash="GENESIS",
        event_hash="hash-1",
    )

    event = database.get_audit_event(event_id)

    assert event.resource == "workspace/customers/customer_contacts.csv"
    assert json.loads(event.canary_ids) == ["canary-1", "canary-2"]


def test_audit_event_can_append_inside_a_caller_transaction(run_id):
    """Each event is appended inside one immediate transaction."""
    with database.app_transaction() as connection:
        previous = database.get_last_audit_event(run_id, connection=connection)
        database.create_audit_event(
            run_id=run_id,
            event_type="TOOL_CALL",
            previous_hash=previous.event_hash if previous else database.GENESIS_HASH,
            event_hash="hash-1",
            connection=connection,
        )

    assert database.get_last_audit_event(run_id).event_hash == "hash-1"


# ---------------------------------------------------------------------------
# alerts
# ---------------------------------------------------------------------------


def test_create_alert_starts_open(run_id, session):
    alert = database.create_alert(
        run_id=run_id,
        session_id=session.session_id,
        severity="critical",
        title="A decoy record was read",
        message="The agent requested a file containing a decoy record.",
    )

    assert alert.status == "open"
    assert alert.severity == "critical"


def test_resolve_alert(run_id):
    alert = database.create_alert(
        run_id=run_id, severity="warning", title="Held email", message="Awaiting review."
    )

    assert database.resolve_alert(alert.id).status == "resolved"


def test_list_alerts_filters_by_status(run_id):
    first = database.create_alert(
        run_id=run_id, severity="info", title="One", message="."
    )
    database.create_alert(run_id=run_id, severity="info", title="Two", message=".")
    database.resolve_alert(first.id)

    assert len(database.list_alerts(run_id=run_id, status="open")) == 1
    assert len(database.list_alerts(run_id=run_id, status="resolved")) == 1


def test_list_alerts_newest_first(run_id):
    database.create_alert(run_id=run_id, severity="info", title="First", message=".")
    database.create_alert(run_id=run_id, severity="info", title="Second", message=".")

    assert database.list_alerts(run_id=run_id)[0].title == "Second"


# ---------------------------------------------------------------------------
# simulated_emails
# ---------------------------------------------------------------------------


def test_create_simulated_email(run_id, session):
    email = database.create_simulated_email(
        run_id=run_id,
        session_id=session.session_id,
        recipient="mei.ling.tan@example.com",
        subject="Your order 1042",
        body="Your order has shipped.",
        delivery_status="simulated_sent",
    )

    assert email.delivery_status == "simulated_sent"
    assert email.hard_deny == 0


def test_blocked_email_records_the_rule_and_hard_deny(run_id, session):
    email = database.create_simulated_email(
        run_id=run_id,
        session_id=session.session_id,
        recipient="audit-team@audit-review.test",
        subject="Customer list",
        body="(withheld)",
        delivery_status="blocked",
        rule="strong_canary_outbound",
        hard_deny=True,
    )

    assert email.hard_deny == 1
    assert email.rule == "strong_canary_outbound"


def test_list_held_emails_returns_only_held(run_id, session):
    database.create_simulated_email(
        run_id=run_id,
        session_id=session.session_id,
        recipient="lawyer@law-office.test",
        subject="Order history",
        body="(withheld)",
        delivery_status="held",
        rule="owner_not_authorised",
    )
    database.create_simulated_email(
        run_id=run_id,
        session_id=session.session_id,
        recipient="mei.ling.tan@example.com",
        subject="Your order",
        body="Shipped.",
        delivery_status="simulated_sent",
    )

    held = database.list_held_emails(run_id=run_id)

    assert [email.delivery_status for email in held] == ["held"]


def test_update_email_status_to_approved(run_id, session):
    email = database.create_simulated_email(
        run_id=run_id,
        session_id=session.session_id,
        recipient="manager@limco.example",
        subject="Summary",
        body="Order 1042 and 1043.",
        delivery_status="held",
    )

    updated = database.update_email_status(
        email.id, "approved_sent", rule="admin_approved_revalidated"
    )

    assert updated.delivery_status == "approved_sent"
    assert updated.rule == "admin_approved_revalidated"


def test_schema_rejects_an_invalid_delivery_status(run_id):
    with pytest.raises(sqlite3.IntegrityError):
        with database.app_connection() as connection:
            connection.execute(
                "INSERT INTO simulated_emails ("
                "run_id, recipient, subject, body, delivery_status, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, "a@example.com", "s", "b", "delivered", database.utc_now()),
            )


# ---------------------------------------------------------------------------
# test_runs and test_results
# ---------------------------------------------------------------------------


def test_create_test_run_links_to_the_demo_run(run_id):
    suite_run = database.create_test_run(
        agent_mode="worst_case",
        protection_mode="protect",
        demo_run_id=run_id,
        repeats=1,
    )

    assert suite_run.run_id != run_id
    assert database.get_test_run(suite_run.run_id).demo_run_id == run_id


def test_finish_test_run_sets_finished_at(run_id):
    suite_run = database.create_test_run(
        agent_mode="claude", protection_mode="monitor", demo_run_id=run_id
    )

    assert database.finish_test_run(suite_run.run_id).finished_at is not None


def test_latest_test_run_prefers_the_finished_one(run_id):
    first = database.create_test_run(
        agent_mode="claude", protection_mode="protect", demo_run_id=run_id
    )
    database.finish_test_run(first.run_id)
    database.create_test_run(
        agent_mode="claude", protection_mode="monitor", demo_run_id=run_id
    )

    assert database.get_latest_test_run().run_id == first.run_id


def test_create_and_list_test_results(run_id):
    suite_run = database.create_test_run(
        agent_mode="worst_case", protection_mode="protect", demo_run_id=run_id
    )
    database.create_test_result(
        run_id=suite_run.run_id,
        scenario_id="B1",
        scenario_type="attack",
        category="bulk",
        expected="blocked",
        outcome="blocked",
        caught_at="read_quarantine",
        duration_ms=12,
    )
    database.create_test_result(
        run_id=suite_run.run_id,
        scenario_id="N1",
        scenario_type="normal",
        category="normal",
        expected="sent",
        outcome="sent",
        caught_at="none",
        duration_ms=8,
    )

    results = database.list_test_results(suite_run.run_id)

    assert [result.scenario_id for result in results] == ["B1", "N1"]


def test_test_result_measures_default_to_zero(run_id):
    suite_run = database.create_test_run(
        agent_mode="worst_case", protection_mode="protect", demo_run_id=run_id
    )
    result = database.create_test_result(
        run_id=suite_run.run_id,
        scenario_id="T1",
        scenario_type="attack",
        category="targeted",
    )

    assert result.unauthorised_disclosure == 0
    assert result.canary_exposure == 0
    assert result.forbidden_access == 0
    assert result.false_hold == 0
    assert result.task_failed == 0
    assert result.model_refused == 0


def test_test_result_records_each_measure_separately(run_id):
    suite_run = database.create_test_run(
        agent_mode="worst_case", protection_mode="monitor", demo_run_id=run_id
    )
    result = database.create_test_result(
        run_id=suite_run.run_id,
        scenario_id="B2",
        scenario_type="attack",
        category="bulk",
        unauthorised_disclosure=True,
        canary_exposure=True,
        caught_at="none",
    )

    assert result.unauthorised_disclosure == 1
    assert result.canary_exposure == 1
    assert result.forbidden_access == 0


# ---------------------------------------------------------------------------
# canaries
# ---------------------------------------------------------------------------


def test_register_and_get_a_canary():
    seeder.init_registry()
    canary = seeder.register_canary(
        canary_type="customer",
        location="workspace/customers/customer_contacts.csv",
        record_ref="row 118",
        strong_values=["siti.aisyah.rahman@example.org", "+6598231764"],
        weak_values=["Siti Aisyah Rahman", "520318"],
    )

    stored = seeder.get_registered_canary(canary.id)

    assert stored.canary_type == "customer"
    assert stored.record_ref == "row 118"
    assert "siti.aisyah.rahman@example.org" in stored.strong_values()
    assert "Siti Aisyah Rahman" in stored.weak_values()


def test_list_canaries_filters_by_status():
    seeder.init_registry()
    active = seeder.register_canary(
        canary_type="salary",
        location="workspace/hr/salaries.csv",
        strong_values=["LC-0318"],
        weak_values=["7400"],
    )
    removed = seeder.register_canary(
        canary_type="trade_secret",
        location="workspace/product_docs/supplier_terms_2026.txt",
        strong_values=["SUP-2026-0417"],
        weak_values=[],
    )
    seeder.set_canary_status(removed.id, "removed")

    assert [item.id for item in seeder.list_registered_canaries("active")] == [active.id]
    assert [item.id for item in seeder.list_registered_canaries("removed")] == [removed.id]


def test_detector_sees_only_active_canaries():
    seeder.init_registry()
    canary = seeder.register_canary(
        canary_type="customer",
        location="workspace/customers/customer_contacts.csv",
        strong_values=["jun.hao.teo@example.com"],
        weak_values=["Jun Hao Teo"],
    )

    assert len(detector.load_active_canaries()) == 1

    seeder.set_canary_status(canary.id, "removed")

    assert detector.load_active_canaries() == []


def test_clearing_the_registry_leaves_nothing_to_match():
    """After an unseed, previously planted values stop matching."""
    seeder.init_registry()
    seeder.register_canary(
        canary_type="customer",
        location="workspace/customers/customer_contacts.csv",
        strong_values=["removed.decoy@example.net"],
        weak_values=[],
    )

    assert seeder.clear_registry() == 1
    assert detector.load_active_canaries() == []


def test_invalid_canary_type_is_rejected():
    seeder.init_registry()
    with pytest.raises(ValidationError):
        seeder.register_canary(
            canary_type="password",
            location="workspace/it/integrations.txt",
            strong_values=["x"],
            weak_values=[],
        )


# ---------------------------------------------------------------------------
# SQL safety
# ---------------------------------------------------------------------------


def test_updates_reject_column_names_that_are_not_allowlisted(session):
    """Column names never come from caller data."""
    with pytest.raises(ValueError, match="cannot be updated"):
        database.update_session(
            session.session_id, **{"status = 'terminated' --": "injected"}
        )


def test_an_apostrophe_in_data_is_stored_literally(run_id, session):
    """Parameterised SQL: content is data, never statement text."""
    body = "Robert'); DROP TABLE agent_sessions;--"
    email = database.create_simulated_email(
        run_id=run_id,
        session_id=session.session_id,
        recipient="someone@example.com",
        subject="O'Brien's order",
        body=body,
        delivery_status="held",
    )

    stored = database.get_simulated_email(email.id)

    assert stored.body == body
    assert stored.subject == "O'Brien's order"
    assert database.get_session(session.session_id) is not None
