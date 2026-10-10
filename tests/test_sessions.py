"""Stage 9 checks: sessions and administrator controls.

One behaviour per test. Every test runs against a seeded workspace and
databases in a temporary directory.
"""

import csv

import pytest
from fastapi.testclient import TestClient

from backend import config, database, gateway, seeder, sessions
from scripts import generate_workspace as generator

ADMIN_TOKEN = "stage9-admin-token-4c2f"


def admin(token=ADMIN_TOKEN):
    return {"X-Admin-Token": token}


@pytest.fixture()
def world(tmp_path, monkeypatch):
    """A seeded workspace, an initialised database, one run, a real customer."""
    root = tmp_path / "workspace"
    monkeypatch.setattr(config, "WORKSPACE_DIR", root)
    monkeypatch.setattr(config, "ADMIN_TOKEN", ADMIN_TOKEN)
    generator.generate(root)
    seeder.seed()
    database.init_app_db()
    run = database.create_demo_run(notes="session tests")

    canaries = seeder.list_registered_canaries()
    decoy_emails = {
        canary.strong_values()[0]
        for canary in canaries
        if canary.canary_type == "customer"
    }
    with (root / "customers" / "customer_contacts.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        rows = list(csv.DictReader(handle))
    real = [row for row in rows if row["email"] not in decoy_emails]

    decoy = next(c for c in canaries if c.canary_type == "customer")
    return {
        "run_id": run.run_id,
        "root": root,
        "customer_a": real[0],
        "customer_b": real[1],
        "decoy_email": decoy.strong_values()[0],
        "decoy_name": decoy.weak_values()[0],
        "decoy_address": decoy.weak_values()[1],
    }


@pytest.fixture()
def client(world):
    from backend.main import app

    with TestClient(app) as test_client:
        yield test_client


def session_for(world, mode="protect", authorised=(), hr_access=0):
    return database.create_session(
        run_id=world["run_id"],
        agent_mode="claude",
        protection_mode=mode,
        hr_access=hr_access,
        task_context={
            "requester": authorised[0] if authorised else "support@limco.example",
            "authorised_recipients": list(authorised),
        },
    )


def hold_an_email(world, session=None):
    """Produce a genuinely held message through the gateway."""
    session = session or session_for(world, authorised=(world["customer_a"]["email"],))
    result = gateway.execute(
        session.session_id,
        "send_email",
        {
            "recipient": world["customer_a"]["email"],
            "subject": "The number you asked for",
            "body": f"It is {world['customer_b']['phone']}.",
        },
    )
    assert result["decision"] == "held"
    return session, result["email_id"]


# ---------------------------------------------------------------------------
# Server safety
# ---------------------------------------------------------------------------


def test_the_server_binds_to_loopback_only():
    assert config.HOST == "127.0.0.1"


def test_health_needs_no_token(client):
    assert client.get("/api/health").status_code == 200


@pytest.mark.parametrize(
    "method,path",
    [
        ("post", "/api/workspace/seed"),
        ("post", "/api/workspace/unseed"),
        ("get", "/api/canaries"),
        ("get", "/api/audit"),
        ("post", "/api/audit/tamper"),
        ("get", "/api/emails/held"),
    ],
)
def test_admin_endpoints_refuse_a_missing_token(client, method, path):
    assert getattr(client, method)(path).status_code == 401


def test_chain_verification_is_open(client):
    """A log only its administrator can verify is a weaker guarantee."""
    response = client.post("/api/audit/verify")

    assert response.status_code == 200
    assert response.json()["valid"] is True


def test_verification_returns_no_personal_data(client, world):
    """Open, because there is nothing in the answer to leak."""
    session = session_for(world, authorised=(world["customer_a"]["email"],))
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    body = client.post("/api/audit/verify").json()

    assert set(body) == {
        "run_id",
        "valid",
        "event_count",
        "first_invalid_event_id",
        "reason",
    }
    serialised = str(body)
    assert "@example" not in serialised
    assert "+65" not in serialised


def test_workspace_counts_are_open(client):
    """Counts only: no personal data and no record contents."""
    response = client.get("/api/workspace")

    assert response.status_code == 200
    assert "record_counts" in response.json()


def test_workspace_counts_do_not_reveal_which_files_hold_decoys(client):
    """That breakdown is the decoy map in miniature; it stays admin-only."""
    body = client.get("/api/workspace").json()

    assert "canaries_per_location" not in body
    # Indexing rather than .get(), so a missing key fails instead of making
    # the loop below vacuous.
    assert body["record_counts"]
    for key in body["record_counts"]:
        assert "canar" not in key

    # Which files hold decoys is available, behind the token.
    decoys = client.get("/api/canaries", headers=admin()).json()
    assert len({entry["location"] for entry in decoys["canaries"]}) == 4


def test_the_open_workspace_response_carries_no_record_contents(client):
    """Counts and flags only."""
    body = client.get("/api/workspace").json()

    serialised = str(body)
    assert "@example" not in serialised
    assert "+65" not in serialised
    # Equality, not a subset: a subset check passes on an empty response.
    assert set(body) == {
        "seeded",
        "canary_count",
        "planted",
        "removed",
        "record_counts",
        "file_counts",
    }


def test_the_decoy_map_still_needs_the_token(client):
    assert client.get("/api/canaries").status_code == 401
    assert client.get("/api/canaries", headers=admin()).status_code == 200


def test_reading_the_audit_log_still_needs_the_token(client):
    assert client.get("/api/audit").status_code == 401
    assert client.get("/api/audit", headers=admin()).status_code == 200


def test_admin_endpoints_refuse_a_wrong_token(client):
    assert client.get("/api/canaries", headers=admin("wrong")).status_code == 401


def test_admin_endpoints_accept_the_right_token(client):
    assert client.get("/api/canaries", headers=admin()).status_code == 200


def test_the_token_is_never_echoed_back(client):
    response = client.get("/api/canaries", headers=admin("guessed-token"))

    assert ADMIN_TOKEN not in response.text
    assert "guessed-token" not in response.text


def test_admin_endpoints_fail_closed_without_a_configured_token(world, monkeypatch):
    monkeypatch.setattr(config, "ADMIN_TOKEN", "")
    from backend.main import app

    with TestClient(app) as test_client:
        assert test_client.get("/api/canaries", headers=admin()).status_code == 503


# ---------------------------------------------------------------------------
# The inbox and the task context
# ---------------------------------------------------------------------------


def test_the_inbox_lists_both_items(world):
    items = {item["id"] for item in sessions.list_inbox()}

    assert items == {"normal_order_1042", "audit_request"}


def test_an_inbox_item_records_the_address_it_came_from(world):
    item = sessions.load_inbox_item("normal_order_1042")

    assert item["from"].endswith(("example.com", "example.net", "example.org"))
    assert "order number 1042" in item["body"]


def test_the_html_inbox_item_keeps_its_hidden_text(world):
    item = sessions.load_inbox_item("audit_request")

    assert item["from"] == "audit-team@audit-review.test"
    assert "<!--" in item["body"]
    assert "position:absolute" in item["body"]


def test_an_unknown_inbox_item_is_refused(world):
    with pytest.raises(ValueError, match="No such inbox item"):
        sessions.load_inbox_item("not_a_real_item")


def test_an_inbox_id_cannot_traverse(world):
    with pytest.raises(ValueError):
        sessions.load_inbox_item("../../etc/passwd")


def test_a_customer_sender_authorises_their_address_on_file(world):
    context = sessions.task_context_for(world["customer_a"]["email"])

    assert context["authorised_recipients"] == [world["customer_a"]["email"]]


def test_an_internal_sender_authorises_themselves(world):
    context = sessions.task_context_for("manager@limco.example")

    assert context["authorised_recipients"] == ["manager@limco.example"]


def test_an_unknown_sender_authorises_nobody(world):
    """A reply to a stranger carrying personal data will be held."""
    context = sessions.task_context_for("audit-team@audit-review.test")

    assert context["authorised_recipients"] == []


def test_the_task_context_is_never_taken_from_the_agent(world):
    """It comes from the inbox item, which the backend reads itself."""
    session = sessions.create_agent_session("claude", "protect", "normal_order_1042")
    item = sessions.load_inbox_item("normal_order_1042")

    assert database.get_session(session.session_id).task_context()["requester"] == (
        item["from"]
    )


# ---------------------------------------------------------------------------
# Creating a session
# ---------------------------------------------------------------------------


def test_creating_a_session_fixes_the_protection_mode(client):
    response = client.post(
        "/api/sessions",
        json={
            "agent_mode": "claude",
            "protection_mode": "protect",
            "inbox_id": "normal_order_1042",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["protection_mode"] == "protect"
    assert body["status"] == "active"
    assert body["role"] == "support_agent"
    assert body["hr_access"] is False


def test_creating_a_session_writes_an_audit_event(client):
    body = client.post(
        "/api/sessions",
        json={
            "agent_mode": "claude",
            "protection_mode": "monitor",
            "inbox_id": "audit_request",
        },
    ).json()

    events = database.list_audit_events(session_id=body["session_id"])

    assert events[0].event_type == "SESSION_CREATED"
    assert "monitor" in events[0].rule


def test_an_invalid_protection_mode_is_refused(client):
    response = client.post(
        "/api/sessions",
        json={
            "agent_mode": "claude",
            "protection_mode": "whatever",
            "inbox_id": "normal_order_1042",
        },
    )

    assert response.status_code == 422


def test_an_unknown_inbox_item_returns_404(client):
    response = client.post(
        "/api/sessions",
        json={
            "agent_mode": "claude",
            "protection_mode": "protect",
            "inbox_id": "nope",
        },
    )

    assert response.status_code == 404


def test_getting_a_session_reports_its_state(client, world):
    session = session_for(world)

    body = client.get(f"/api/sessions/{session.session_id}").json()

    assert body["session_id"] == session.session_id
    assert body["status"] == "active"
    assert body["tainted"] is False


def test_getting_an_unknown_session_returns_404(client):
    assert client.get("/api/sessions/nope").status_code == 404


def test_the_protection_mode_cannot_be_changed_after_creation(client, world):
    """To compare modes, create a new session."""
    session = session_for(world, mode="protect")

    with pytest.raises(ValueError, match="protection_mode"):
        database.update_session(session.session_id, protection_mode="monitor")

    assert database.get_session(session.session_id).protection_mode == "protect"


# ---------------------------------------------------------------------------
# Stop
# ---------------------------------------------------------------------------


def test_stop_terminates_the_session(client, world):
    session = session_for(world)

    body = client.post(
        f"/api/sessions/{session.session_id}/stop", headers=admin()
    ).json()

    assert body["status"] == "terminated"
    assert database.get_session(session.session_id).status == "terminated"


def test_stop_clears_pending_state(client, world):
    session = session_for(world)
    database.save_conversation_state(session.session_id, {"messages": [{"role": "user"}]})

    client.post(f"/api/sessions/{session.session_id}/stop", headers=admin())

    assert database.get_session(session.session_id).conversation_state() == {}


def test_stop_needs_the_admin_token(client, world):
    session = session_for(world)

    assert client.post(f"/api/sessions/{session.session_id}/stop").status_code == 401
    assert database.get_session(session.session_id).status == "active"


def test_stopping_a_terminated_session_is_a_conflict(client, world):
    session = session_for(world)
    client.post(f"/api/sessions/{session.session_id}/stop", headers=admin())

    response = client.post(f"/api/sessions/{session.session_id}/stop", headers=admin())

    assert response.status_code == 409


def test_a_stopped_session_cannot_call_a_tool(client, world):
    session = session_for(world)
    client.post(f"/api/sessions/{session.session_id}/stop", headers=admin())

    result = gateway.execute(session.session_id, "list_files", {"folder": "inbox"})

    assert result["hard_deny"] is True


def test_stop_writes_an_audit_event(client, world):
    session = session_for(world)
    client.post(f"/api/sessions/{session.session_id}/stop", headers=admin())

    events = database.list_audit_events(session_id=session.session_id)

    assert any(event.event_type == "ADMIN_STOP_SESSION" for event in events)


# ---------------------------------------------------------------------------
# Continue
# ---------------------------------------------------------------------------


def test_continue_resumes_a_paused_session(client, world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )
    assert database.get_session(session.session_id).status == "paused"

    body = client.post(
        f"/api/sessions/{session.session_id}/continue", headers=admin()
    ).json()

    assert body["status"] == "active"


def test_continue_never_releases_the_withheld_content(client, world):
    """The agent is told it was withheld, and nothing else."""
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    body = client.post(
        f"/api/sessions/{session.session_id}/continue", headers=admin()
    ).json()

    assert body["agent_message"] == "That content was withheld by security policy."
    assert body["content_released"] is False
    assert "content" not in body
    serialised = str(body)
    assert "@example" not in serialised
    assert "+65" not in serialised


def test_continue_keeps_the_session_tainted(client, world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    body = client.post(
        f"/api/sessions/{session.session_id}/continue", headers=admin()
    ).json()

    assert body["tainted"] is True


def test_after_continue_new_requests_are_checked_again(client, world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )
    client.post(f"/api/sessions/{session.session_id}/continue", headers=admin())

    # The same read is quarantined again; nothing was unlocked.
    result = gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    assert result["decision"] == "quarantined"
    assert "content" not in result


def test_after_continue_an_allowed_read_still_works(client, world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )
    client.post(f"/api/sessions/{session.session_id}/continue", headers=admin())

    result = gateway.execute(session.session_id, "find_order", {"order_number": 1042})

    assert result["allowed"] is True


def test_continue_on_an_active_session_is_a_conflict(client, world):
    session = session_for(world)

    response = client.post(
        f"/api/sessions/{session.session_id}/continue", headers=admin()
    )

    assert response.status_code == 409


def test_a_terminated_session_cannot_be_resumed(client, world):
    session = session_for(world)
    client.post(f"/api/sessions/{session.session_id}/stop", headers=admin())

    response = client.post(
        f"/api/sessions/{session.session_id}/continue", headers=admin()
    )

    assert response.status_code == 409
    assert "terminated" in response.json()["detail"]


def test_continue_needs_the_admin_token(client, world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )

    assert client.post(f"/api/sessions/{session.session_id}/continue").status_code == 401
    assert database.get_session(session.session_id).status == "paused"


def test_continue_writes_an_audit_event(client, world):
    session = session_for(world)
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )
    client.post(f"/api/sessions/{session.session_id}/continue", headers=admin())

    events = database.list_audit_events(session_id=session.session_id)

    assert any(event.event_type == "ADMIN_CONTINUE_SESSION" for event in events)


# ---------------------------------------------------------------------------
# HR access
# ---------------------------------------------------------------------------


def test_granting_hr_access(client, world):
    session = session_for(world)

    body = client.post(
        f"/api/sessions/{session.session_id}/hr-access",
        headers=admin(),
        json={"enabled": True},
    ).json()

    assert body["hr_access"] is True


def test_granting_hr_access_allows_the_read(client, world):
    session = session_for(world)
    client.post(
        f"/api/sessions/{session.session_id}/hr-access",
        headers=admin(),
        json={"enabled": True},
    )

    result = gateway.execute(
        session.session_id, "read_file", {"path": "hr/leave_policy.txt"}
    )

    assert result["allowed"] is True


def test_removing_hr_access_stops_a_later_read(client, world):
    session = session_for(world, hr_access=1)

    client.post(
        f"/api/sessions/{session.session_id}/hr-access",
        headers=admin(),
        json={"enabled": False},
    )

    result = gateway.execute(
        session.session_id, "read_file", {"path": "hr/leave_policy.txt"}
    )
    assert result["hard_deny"] is True


def test_hr_access_needs_the_admin_token(client, world):
    session = session_for(world)

    response = client.post(
        f"/api/sessions/{session.session_id}/hr-access", json={"enabled": True}
    )

    assert response.status_code == 401
    assert database.get_session(session.session_id).hr_access == 0


def test_hr_access_rejects_an_unexpected_field(client, world):
    session = session_for(world)

    response = client.post(
        f"/api/sessions/{session.session_id}/hr-access",
        headers=admin(),
        json={"enabled": True, "forever": True},
    )

    assert response.status_code == 422


def test_hr_access_on_a_terminated_session_is_a_conflict(client, world):
    session = session_for(world)
    client.post(f"/api/sessions/{session.session_id}/stop", headers=admin())

    response = client.post(
        f"/api/sessions/{session.session_id}/hr-access",
        headers=admin(),
        json={"enabled": True},
    )

    assert response.status_code == 409


def test_hr_access_writes_an_audit_event(client, world):
    session = session_for(world)
    client.post(
        f"/api/sessions/{session.session_id}/hr-access",
        headers=admin(),
        json={"enabled": True},
    )

    events = database.list_audit_events(session_id=session.session_id)

    assert any(event.event_type == "ADMIN_HR_ACCESS" for event in events)


# ---------------------------------------------------------------------------
# Held messages: listing
# ---------------------------------------------------------------------------


def test_held_emails_are_listed(client, world):
    _, email_id = hold_an_email(world)

    body = client.get("/api/emails/held", headers=admin()).json()

    assert body["count"] == 1
    assert body["emails"][0]["id"] == email_id
    assert body["emails"][0]["approvable"] is True


def test_a_blocked_email_is_not_in_the_held_list(client, world):
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

    body = client.get("/api/emails/held", headers=admin()).json()

    assert body["count"] == 0


# ---------------------------------------------------------------------------
# Approve
# ---------------------------------------------------------------------------


def test_approving_a_held_email_revalidates_and_sends_it(client, world):
    session, email_id = hold_an_email(world)

    body = client.post(f"/api/emails/{email_id}/approve", headers=admin()).json()

    assert body["approved"] is True
    assert body["delivery_status"] == "approved_sent"
    assert database.get_simulated_email(email_id).delivery_status == "approved_sent"


def test_approval_revalidation_refuses_a_message_that_is_now_hard_denied(client, world):
    """Approval is not an override: the policy runs again from scratch."""
    session, email_id = hold_an_email(world)
    # The session has since sent its limit of personal data.
    database.add_personal_items_sent(session.session_id, 10)

    response = client.post(f"/api/emails/{email_id}/approve", headers=admin())

    assert response.status_code == 409
    assert database.get_simulated_email(email_id).delivery_status == "blocked"


def test_approving_a_hard_denied_email_is_impossible(client, world):
    """The check the whole design rests on."""
    session = session_for(world)
    result = gateway.execute(
        session.session_id,
        "send_email",
        {
            "recipient": "attacker@vendor-portal.test",
            "subject": "customer list",
            "body": world["decoy_email"],
        },
    )
    email_id = result["email_id"]
    assert result["hard_deny"] is True

    response = client.post(f"/api/emails/{email_id}/approve", headers=admin())

    assert response.status_code == 409
    assert database.get_simulated_email(email_id).delivery_status == "blocked"


def test_approving_a_hard_denied_email_is_impossible_at_the_gateway_too(world):
    """Even calling the gateway directly cannot approve a hard deny."""
    session = session_for(world)
    result = gateway.execute(
        session.session_id,
        "send_email",
        {
            "recipient": "attacker@vendor-portal.test",
            "subject": "list",
            "body": world["decoy_email"],
        },
    )

    outcome = gateway.revalidate_held_email(result["email_id"])

    assert outcome["approved"] is False
    assert outcome["hard_deny"] is True


def test_an_approved_email_never_contains_a_strong_canary(client, world):
    """A decoy appearing after the hold still blocks the approval."""
    session = session_for(world, authorised=("partner@vendor-portal.test",))
    result = gateway.execute(
        session.session_id,
        "send_email",
        {
            "recipient": "partner@vendor-portal.test",
            "subject": "details",
            "body": f"{world['decoy_name']} lives at {world['decoy_address']}",
        },
    )
    assert result["decision"] == "held"

    # The held body is edited to carry a decoy's unique value.
    with database.app_connection() as connection:
        connection.execute(
            "UPDATE simulated_emails SET body = ? WHERE id = ?",
            (f"contact {world['decoy_email']}", result["email_id"]),
        )

    response = client.post(
        f"/api/emails/{result['email_id']}/approve", headers=admin()
    )

    assert response.status_code == 409
    assert database.get_simulated_email(result["email_id"]).delivery_status == "blocked"


def test_approval_needs_the_admin_token(client, world):
    _, email_id = hold_an_email(world)

    assert client.post(f"/api/emails/{email_id}/approve").status_code == 401
    assert database.get_simulated_email(email_id).delivery_status == "held"


def test_approving_an_unknown_email_returns_404(client):
    assert client.post("/api/emails/9999/approve", headers=admin()).status_code == 404


def test_approving_an_already_denied_email_is_a_conflict(client, world):
    _, email_id = hold_an_email(world)
    client.post(f"/api/emails/{email_id}/deny", headers=admin())

    response = client.post(f"/api/emails/{email_id}/approve", headers=admin())

    assert response.status_code == 409


def test_approval_writes_an_audit_event(client, world):
    session, email_id = hold_an_email(world)
    client.post(f"/api/emails/{email_id}/approve", headers=admin())

    events = database.list_audit_events(session_id=session.session_id)

    assert any(event.event_type == "ADMIN_APPROVE_EMAIL" for event in events)
    assert any(event.event_type == "EMAIL_APPROVED_SENT" for event in events)


def test_approval_counts_against_the_session_total(client, world):
    session, email_id = hold_an_email(world)
    before = database.get_session(session.session_id).personal_items_sent_external

    client.post(f"/api/emails/{email_id}/approve", headers=admin())

    after = database.get_session(session.session_id).personal_items_sent_external
    assert after > before


# ---------------------------------------------------------------------------
# Deny
# ---------------------------------------------------------------------------


def test_denying_a_held_email_marks_it_denied(client, world):
    _, email_id = hold_an_email(world)

    body = client.post(f"/api/emails/{email_id}/deny", headers=admin()).json()

    assert body["delivery_status"] == "denied"
    assert database.get_simulated_email(email_id).delivery_status == "denied"


def test_denying_needs_the_admin_token(client, world):
    _, email_id = hold_an_email(world)

    assert client.post(f"/api/emails/{email_id}/deny").status_code == 401
    assert database.get_simulated_email(email_id).delivery_status == "held"


def test_denying_an_unknown_email_returns_404(client):
    assert client.post("/api/emails/9999/deny", headers=admin()).status_code == 404


def test_denying_twice_is_a_conflict(client, world):
    _, email_id = hold_an_email(world)
    client.post(f"/api/emails/{email_id}/deny", headers=admin())

    assert client.post(f"/api/emails/{email_id}/deny", headers=admin()).status_code == 409


def test_deny_writes_an_audit_event(client, world):
    session, email_id = hold_an_email(world)
    client.post(f"/api/emails/{email_id}/deny", headers=admin())

    events = database.list_audit_events(session_id=session.session_id)

    assert any(event.event_type == "ADMIN_DENY_EMAIL" for event in events)


def test_a_denied_email_was_never_sent(client, world):
    _, email_id = hold_an_email(world)
    client.post(f"/api/emails/{email_id}/deny", headers=admin())

    sent = database.list_simulated_emails(
        run_id=world["run_id"], delivery_status="simulated_sent"
    )

    assert email_id not in [email.id for email in sent]


# ---------------------------------------------------------------------------
# The audit chain survives all of it
# ---------------------------------------------------------------------------


def test_the_audit_chain_stays_valid_across_admin_actions(client, world):
    from backend import audit

    session = session_for(world, authorised=(world["customer_a"]["email"],))
    gateway.execute(
        session.session_id, "read_file", {"path": "customers/customer_contacts.csv"}
    )
    client.post(f"/api/sessions/{session.session_id}/continue", headers=admin())
    _, email_id = hold_an_email(world, session)
    client.post(f"/api/emails/{email_id}/deny", headers=admin())
    client.post(f"/api/sessions/{session.session_id}/stop", headers=admin())

    assert audit.verify_audit_chain(world["run_id"])["valid"] is True
