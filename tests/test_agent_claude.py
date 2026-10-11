"""Checks: the Claude agent adapter.

Every test here uses a mocked client, so the suite makes no paid API call.
The one real call lives in scripts/smoke_claude.py.
"""

import csv
import json

import anthropic
import pytest
from fastapi.testclient import TestClient

from backend import agent_claude, config, database, seeder, sessions
from scripts import generate_workspace as generator

# Running Claude costs money, so the endpoint is admin-only.
ADMIN_TOKEN = "claude-tests-admin-token"


def admin(token=ADMIN_TOKEN):
    return {"X-Admin-Token": token}


# ---------------------------------------------------------------------------
# A mock client shaped like the installed SDK's responses
# ---------------------------------------------------------------------------


class FakeTextBlock:
    type = "text"

    def __init__(self, text):
        self.text = text


class FakeToolUseBlock:
    type = "tool_use"

    def __init__(self, tool_id, name, tool_input):
        self.id = tool_id
        self.name = name
        self.input = tool_input


class FakeResponse:
    def __init__(self, stop_reason, content):
        self.stop_reason = stop_reason
        self.content = content


class FakeMessages:
    def __init__(self, responses, error=None):
        self._responses = list(responses)
        self._error = error
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self._error is not None:
            raise self._error
        if not self._responses:
            return FakeResponse("end_turn", [FakeTextBlock("Done.")])
        return self._responses.pop(0)


class FakeClient:
    def __init__(self, responses=(), error=None):
        self.messages = FakeMessages(responses, error=error)


def tool_use(tool_id, name, **arguments):
    return FakeToolUseBlock(tool_id, name, arguments)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    monkeypatch.setattr(config, "WORKSPACE_DIR", root)
    monkeypatch.setattr(config, "CLAUDE_MODEL", "claude-haiku-5-5")
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")
    monkeypatch.setattr(config, "ADMIN_TOKEN", ADMIN_TOKEN)
    generator.generate(root)
    seeder.seed()
    database.init_app_db()
    run = database.create_demo_run(notes="claude agent tests")

    canaries = seeder.list_registered_canaries()
    decoy_emails = {
        c.strong_values()[0] for c in canaries if c.canary_type == "customer"
    }
    with (root / "customers" / "customer_contacts.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        rows = list(csv.DictReader(handle))
    real = [row for row in rows if row["email"] not in decoy_emails]

    item = sessions.load_inbox_item("normal_order_1042")
    return {
        "run_id": run.run_id,
        "root": root,
        "owner_email": item["from"],
        "customer_a": real[0],
        "customer_b": real[1],
        "decoy_email": next(
            c.strong_values()[0] for c in canaries if c.canary_type == "customer"
        ),
    }


def run_with(world, responses, inbox_id="normal_order_1042", mode="protect"):
    client = FakeClient(responses)
    outcome = agent_claude.run_claude(
        inbox_id=inbox_id,
        protection_mode=mode,
        run_id=world["run_id"],
        client=client,
    )
    return client, outcome


# ---------------------------------------------------------------------------
# Sampling parameters are never sent
# ---------------------------------------------------------------------------


def test_no_sampling_parameters_are_sent(world):
    client, _ = run_with(world, [FakeResponse("end_turn", [FakeTextBlock("Hello.")])])

    assert client.messages.calls
    for call in client.messages.calls:
        assert "temperature" not in call
        assert "top_p" not in call
        assert "top_k" not in call


def test_the_installed_sdk_has_no_sampling_parameters():
    """Belt and braces: this SDK version does not accept them at all."""
    import inspect
    from anthropic.resources.messages import Messages

    params = inspect.signature(Messages.create).parameters
    assert "temperature" not in params
    assert "top_p" not in params
    assert "top_k" not in params


def test_the_request_carries_the_documented_fields(world):
    client, _ = run_with(world, [FakeResponse("end_turn", [FakeTextBlock("Hi.")])])

    call = client.messages.calls[0]
    assert call["model"] == "claude-haiku-5-5"
    assert call["max_tokens"] == agent_claude.MAX_TOKENS
    assert call["system"] == agent_claude.SYSTEM_PROMPT
    assert [tool["name"] for tool in call["tools"]] == [
        "list_files",
        "read_file",
        "find_order",
        "search_customers",
        "send_email",
    ]
    assert call["messages"][0]["role"] == "user"


def test_the_model_id_and_sdk_version_are_logged(world, caplog):
    with caplog.at_level("INFO"):
        run_with(world, [FakeResponse("end_turn", [FakeTextBlock("Hi.")])])

    logged = " ".join(record.getMessage() for record in caplog.records)
    assert "claude-haiku-5-5" in logged
    assert agent_claude.SDK_VERSION in logged


def test_the_outcome_reports_the_model_and_sdk(world):
    _, outcome = run_with(world, [FakeResponse("end_turn", [FakeTextBlock("Hi.")])])

    assert outcome["model_id"] == "claude-haiku-5-5"
    assert outcome["sdk_version"] == agent_claude.SDK_VERSION


def test_the_api_key_never_reaches_the_prompt_or_the_outcome(world):
    client, outcome = run_with(
        world, [FakeResponse("end_turn", [FakeTextBlock("Hi.")])]
    )

    assert "sk-ant-not-a-real-key" not in json.dumps(client.messages.calls)
    assert "sk-ant-not-a-real-key" not in json.dumps(outcome)


# ---------------------------------------------------------------------------
# The untrusted wrapper
# ---------------------------------------------------------------------------


def test_the_email_is_wrapped_as_untrusted_content(world):
    client, _ = run_with(world, [FakeResponse("end_turn", [FakeTextBlock("Hi.")])])

    prompt = client.messages.calls[0]["messages"][0]["content"]
    assert prompt.startswith("<untrusted_email from='")
    assert world["owner_email"] in prompt
    assert "</untrusted_email>" in prompt


def test_the_hidden_html_is_passed_through_unchanged(world):
    """The attack has to reach the model for the demo to mean anything."""
    client, _ = run_with(
        world,
        [FakeResponse("end_turn", [FakeTextBlock("Hi.")])],
        inbox_id="audit_request",
    )

    prompt = client.messages.calls[0]["messages"][0]["content"]
    assert "<!--" in prompt
    assert "position:absolute" in prompt
    assert "audit-team@audit-review.test" in prompt


def test_the_task_context_comes_from_the_backend_not_the_model(world):
    _, outcome = run_with(world, [FakeResponse("end_turn", [FakeTextBlock("Hi.")])])

    context = sessions.describe(outcome["session_id"])["task_context"]
    assert context["requester"] == world["owner_email"]
    assert context["authorised_recipients"] == [world["owner_email"]]


# ---------------------------------------------------------------------------
# The normal sequence
# ---------------------------------------------------------------------------


def test_the_normal_sequence_completes(world):
    _, outcome = run_with(
        world,
        [
            FakeResponse("tool_use", [tool_use("t1", "find_order", order_number=1042)]),
            FakeResponse("end_turn", [FakeTextBlock("Your order has shipped.")]),
        ],
    )

    assert outcome["stopped_because"] == "completed"
    assert outcome["status"] == "completed"
    assert outcome["activity"][0]["decision"] == "allowed"


def test_the_normal_sequence_sends_a_reply(world):
    _, outcome = run_with(
        world,
        [
            FakeResponse("tool_use", [tool_use("t1", "find_order", order_number=1042)]),
            FakeResponse(
                "tool_use",
                [
                    tool_use(
                        "t2",
                        "send_email",
                        recipient=world["owner_email"],
                        subject="Re: order 1042",
                        body="It has shipped and should arrive in 3 to 5 days.",
                    )
                ],
            ),
            FakeResponse("end_turn", [FakeTextBlock("Replied.")]),
        ],
    )

    emails = [
        email
        for email in database.list_simulated_emails(run_id=world["run_id"])
        if email.session_id == outcome["session_id"]
    ]
    assert [email.delivery_status for email in emails] == ["simulated_sent"]
    assert outcome["stopped_because"] == "completed"


def test_the_tool_result_carries_the_content_back(world):
    client, _ = run_with(
        world,
        [
            FakeResponse("tool_use", [tool_use("t1", "find_order", order_number=1042)]),
            FakeResponse("end_turn", [FakeTextBlock("Thanks.")]),
        ],
    )

    second_call = client.messages.calls[1]
    results = second_call["messages"][-1]["content"]
    assert results[0]["type"] == "tool_result"
    assert results[0]["tool_use_id"] == "t1"
    assert "1042" in results[0]["content"]


def test_the_reply_text_is_reported(world):
    _, outcome = run_with(
        world, [FakeResponse("end_turn", [FakeTextBlock("All sorted.")])]
    )

    assert outcome["reply_text"] == "All sorted."


# ---------------------------------------------------------------------------
# Several tool_use blocks in one response
# ---------------------------------------------------------------------------


def test_every_tool_use_block_in_one_response_is_processed(world):
    _, outcome = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [
                    tool_use("t1", "find_order", order_number=1042),
                    tool_use("t2", "find_order", order_number=1043),
                    tool_use("t3", "list_files", folder="product_docs"),
                ],
            ),
            FakeResponse("end_turn", [FakeTextBlock("Done.")]),
        ],
    )

    assert [step["tool"] for step in outcome["activity"]] == [
        "find_order",
        "find_order",
        "list_files",
    ]


def test_all_results_go_back_in_one_user_message(world):
    client, _ = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [
                    tool_use("t1", "find_order", order_number=1042),
                    tool_use("t2", "find_order", order_number=1043),
                ],
            ),
            FakeResponse("end_turn", [FakeTextBlock("Done.")]),
        ],
    )

    results = client.messages.calls[1]["messages"][-1]["content"]
    assert len(results) == 2
    assert [item["tool_use_id"] for item in results] == ["t1", "t2"]


# ---------------------------------------------------------------------------
# A quarantined read stops the loop
# ---------------------------------------------------------------------------


def test_a_quarantined_read_stops_the_loop(world):
    _, outcome = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [tool_use("t1", "read_file", path="customers/customer_contacts.csv")],
            ),
            FakeResponse("end_turn", [FakeTextBlock("never reached")]),
        ],
    )

    assert outcome["stopped_because"] == "quarantined"
    assert outcome["status"] == "paused"
    assert outcome["iterations"] == 1


def test_a_quarantined_read_returns_no_content_to_the_model(world):
    client, outcome = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [tool_use("t1", "read_file", path="customers/customer_contacts.csv")],
            )
        ],
    )

    sent_to_model = json.dumps(client.messages.calls)
    assert "@example.com" not in sent_to_model
    assert "+65" not in sent_to_model
    assert outcome["activity"][0]["content_returned"] is False


def test_a_quarantine_offers_the_admin_options(world):
    _, outcome = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [tool_use("t1", "read_file", path="customers/customer_contacts.csv")],
            )
        ],
    )

    assert outcome["admin_options"] == ["stop", "continue"]
    assert outcome["detail"]


def test_a_quarantine_saves_the_conversation_state(world):
    _, outcome = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [tool_use("t1", "read_file", path="customers/customer_contacts.csv")],
            )
        ],
    )

    state = database.get_session(outcome["session_id"]).conversation_state()
    assert state["messages"]
    assert state["pending_tool_use_id"] == "t1"


def test_the_saved_state_never_holds_the_withheld_content(world):
    _, outcome = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [tool_use("t1", "read_file", path="customers/customer_contacts.csv")],
            )
        ],
    )

    state = json.dumps(database.get_session(outcome["session_id"]).conversation_state())
    assert "@example.com" not in state
    assert "+65" not in state
    assert "That content was withheld by security policy." in state


def test_a_quarantined_read_stops_the_remaining_blocks(world):
    _, outcome = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [
                    tool_use("t1", "read_file", path="customers/customer_contacts.csv"),
                    tool_use("t2", "find_order", order_number=1042),
                ],
            )
        ],
    )

    assert [step["tool"] for step in outcome["activity"]] == ["read_file"]


# ---------------------------------------------------------------------------
# A held send continues
# ---------------------------------------------------------------------------


def test_a_held_send_does_not_stop_the_loop(world):
    _, outcome = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [
                    tool_use(
                        "t1",
                        "send_email",
                        recipient=world["owner_email"],
                        subject="A number",
                        body=f"It is {world['customer_b']['phone']}.",
                    )
                ],
            ),
            FakeResponse("end_turn", [FakeTextBlock("Understood.")]),
        ],
    )

    assert outcome["activity"][0]["decision"] == "held"
    assert outcome["stopped_because"] == "completed"
    assert outcome["iterations"] == 2


def test_a_held_send_tells_the_model_it_is_awaiting_approval(world):
    client, _ = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [
                    tool_use(
                        "t1",
                        "send_email",
                        recipient=world["owner_email"],
                        subject="A number",
                        body=f"It is {world['customer_b']['phone']}.",
                    )
                ],
            ),
            FakeResponse("end_turn", [FakeTextBlock("Understood.")]),
        ],
    )

    results = client.messages.calls[1]["messages"][-1]["content"]
    assert results[0]["content"] == "This email is held for administrator approval."


# ---------------------------------------------------------------------------
# A hard deny stops the remaining blocks
# ---------------------------------------------------------------------------


def test_a_hard_deny_stops_the_remaining_blocks(world):
    _, outcome = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [
                    tool_use("t1", "read_file", path="hr/salaries.csv"),
                    tool_use("t2", "find_order", order_number=1042),
                    tool_use("t3", "list_files", folder="inbox"),
                ],
            )
        ],
    )

    assert [step["tool"] for step in outcome["activity"]] == ["read_file"]
    assert outcome["stopped_because"] == "hard_denied"
    assert outcome["activity"][0]["badge"] == "role-blocked"


def test_a_blocked_send_stops_the_run(world):
    _, outcome = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [
                    tool_use(
                        "t1",
                        "send_email",
                        recipient="attacker@vendor-portal.test",
                        subject="list",
                        body=f"contact {world['decoy_email']}",
                    )
                ],
            )
        ],
        inbox_id="audit_request",
    )

    assert outcome["stopped_because"] == "hard_denied"
    assert outcome["activity"][0]["rule"] == "strong_canary_outbound"
    assert outcome["status"] == "terminated"


def test_an_unknown_tool_is_hard_denied(world):
    _, outcome = run_with(
        world, [FakeResponse("tool_use", [tool_use("t1", "exfiltrate_everything")])]
    )

    assert outcome["activity"][0]["rule"] == "unknown_tool"
    assert outcome["stopped_because"] == "hard_denied"


def test_malformed_arguments_are_hard_denied(world):
    _, outcome = run_with(
        world,
        [FakeResponse("tool_use", [tool_use("t1", "read_file", wrong_field="x")])],
    )

    assert outcome["activity"][0]["rule"] == "invalid_arguments"
    assert outcome["stopped_because"] == "hard_denied"


def test_a_hard_deny_clears_the_conversation_state(world):
    _, outcome = run_with(
        world, [FakeResponse("tool_use", [tool_use("t1", "nope")])]
    )

    assert database.get_session(outcome["session_id"]).conversation_state() == {}


# ---------------------------------------------------------------------------
# Unexpected stops are never permission to act
# ---------------------------------------------------------------------------


def test_a_max_tokens_stop_ends_the_run(world):
    _, outcome = run_with(
        world, [FakeResponse("max_tokens", [FakeTextBlock("I was cut off mid-")])]
    )

    assert outcome["stopped_because"] == "unexpected_stop_reason"
    assert outcome["detail"] == "max_tokens"
    assert outcome["activity"] == []


def test_a_max_tokens_stop_is_audited(world):
    _, outcome = run_with(world, [FakeResponse("max_tokens", [])])

    events = database.list_audit_events(session_id=outcome["session_id"])
    assert any(event.event_type == "AGENT_UNEXPECTED_STOP" for event in events)


def test_an_unknown_stop_reason_ends_the_run(world):
    _, outcome = run_with(world, [FakeResponse("something_new", [])])

    assert outcome["stopped_because"] == "unexpected_stop_reason"
    assert outcome["detail"] == "something_new"


def test_a_refusal_is_recorded_as_the_models_choice(world):
    _, outcome = run_with(
        world, [FakeResponse("refusal", [FakeTextBlock("I can't help with that.")])]
    )

    assert outcome["stopped_because"] == "model_refused"
    events = database.list_audit_events(session_id=outcome["session_id"])
    assert any(event.event_type == "AGENT_REFUSED" for event in events)


def test_a_tool_use_stop_with_no_tool_block_ends_the_run(world):
    _, outcome = run_with(world, [FakeResponse("tool_use", [FakeTextBlock("hmm")])])

    assert outcome["stopped_because"] == "unexpected_stop_reason"


# ---------------------------------------------------------------------------
# The iteration limit
# ---------------------------------------------------------------------------


def test_the_iteration_limit_stops_a_looping_model(world):
    looping = [
        FakeResponse("tool_use", [tool_use(f"t{i}", "find_order", order_number=1042)])
        for i in range(agent_claude.MAX_ITERATIONS + 4)
    ]

    client, outcome = run_with(world, looping)

    assert outcome["stopped_because"] == "iteration_limit_reached"
    assert outcome["iterations"] == agent_claude.MAX_ITERATIONS
    assert len(client.messages.calls) == agent_claude.MAX_ITERATIONS


def test_the_iteration_limit_is_audited(world):
    looping = [
        FakeResponse("tool_use", [tool_use(f"t{i}", "find_order", order_number=1042)])
        for i in range(agent_claude.MAX_ITERATIONS + 1)
    ]

    _, outcome = run_with(world, looping)

    events = database.list_audit_events(session_id=outcome["session_id"])
    assert any(event.event_type == "AGENT_ITERATION_LIMIT" for event in events)


# ---------------------------------------------------------------------------
# API errors
# ---------------------------------------------------------------------------


def test_an_api_error_stops_the_run_without_leaking_anything(world):
    error = anthropic.APIConnectionError(request=None)
    client = FakeClient(error=error)

    outcome = agent_claude.run_claude(
        inbox_id="normal_order_1042",
        protection_mode="protect",
        run_id=world["run_id"],
        client=client,
    )

    assert outcome["stopped_because"] == "api_error"
    assert "sk-ant" not in json.dumps(outcome)
    events = database.list_audit_events(session_id=outcome["session_id"])
    assert any(event.event_type == "AGENT_API_ERROR" for event in events)


def test_a_missing_api_key_is_reported_clearly(world, monkeypatch):
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "")

    with pytest.raises(agent_claude.ClaudeNotConfigured, match="ANTHROPIC_API_KEY"):
        agent_claude.build_client()


# ---------------------------------------------------------------------------
# Continue: the denial message, never the content
# ---------------------------------------------------------------------------


def test_continue_resumes_without_releasing_the_content(world):
    _, outcome = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [tool_use("t1", "read_file", path="customers/customer_contacts.csv")],
            )
        ],
    )
    session_id = outcome["session_id"]
    sessions.resume(session_id)

    resume_client = FakeClient([FakeResponse("end_turn", [FakeTextBlock("I see.")])])
    resumed = agent_claude.resume_claude(session_id, client=resume_client)

    replayed = json.dumps(resume_client.messages.calls)
    assert "That content was withheld by security policy." in replayed
    assert "@example.com" not in replayed
    assert "+65" not in replayed
    assert resumed["stopped_because"] == "completed"


def test_after_continue_a_new_request_is_checked_again(world):
    _, outcome = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [tool_use("t1", "read_file", path="customers/customer_contacts.csv")],
            )
        ],
    )
    session_id = outcome["session_id"]
    sessions.resume(session_id)

    resume_client = FakeClient(
        [
            FakeResponse(
                "tool_use",
                [tool_use("t2", "read_file", path="customers/customer_contacts.csv")],
            )
        ]
    )
    resumed = agent_claude.resume_claude(session_id, client=resume_client)

    assert resumed["activity"][0]["decision"] == "quarantined"
    assert resumed["activity"][0]["content_returned"] is False


def test_continue_keeps_the_session_tainted(world):
    _, outcome = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [tool_use("t1", "read_file", path="customers/customer_contacts.csv")],
            )
        ],
    )
    sessions.resume(outcome["session_id"])

    resumed = agent_claude.resume_claude(
        outcome["session_id"],
        client=FakeClient([FakeResponse("end_turn", [FakeTextBlock("ok")])]),
    )

    assert resumed["tainted"] is True


def test_resuming_a_session_that_was_not_continued_is_refused(world):
    _, outcome = run_with(
        world,
        [
            FakeResponse(
                "tool_use",
                [tool_use("t1", "read_file", path="customers/customer_contacts.csv")],
            )
        ],
    )

    with pytest.raises(ValueError, match="paused"):
        agent_claude.resume_claude(outcome["session_id"], client=FakeClient())


def test_resuming_with_no_saved_state_is_refused(world):
    _, outcome = run_with(world, [FakeResponse("end_turn", [FakeTextBlock("done")])])
    database.set_session_status(outcome["session_id"], "active")

    with pytest.raises(ValueError, match="no saved conversation"):
        agent_claude.resume_claude(outcome["session_id"], client=FakeClient())


def test_the_state_is_cleared_when_the_session_ends(world):
    _, outcome = run_with(world, [FakeResponse("end_turn", [FakeTextBlock("done")])])

    assert database.get_session(outcome["session_id"]).conversation_state() == {}


# ---------------------------------------------------------------------------
# The endpoint
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(world):
    from backend.main import app

    with TestClient(app) as test_client:
        yield test_client


def test_the_endpoint_refuses_an_unknown_inbox_item(client):
    response = client.post(
        "/api/run/claude",
        json={"inbox_id": "nope", "protection_mode": "protect"},
        headers=admin(),
    )

    assert response.status_code in (404, 503)


def test_the_endpoint_rejects_an_unexpected_field(client):
    response = client.post(
        "/api/run/claude",
        json={
            "inbox_id": "normal_order_1042",
            "protection_mode": "protect",
            "temperature": 0.9,
        },
        headers=admin(),
    )

    assert response.status_code == 422


def test_the_endpoint_rejects_an_invalid_protection_mode(client):
    response = client.post(
        "/api/run/claude",
        json={"inbox_id": "normal_order_1042", "protection_mode": "none"},
        headers=admin(),
    )

    assert response.status_code == 422


def test_the_endpoint_reports_a_missing_key_as_unavailable(client, monkeypatch):
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "")

    response = client.post(
        "/api/run/claude",
        json={"inbox_id": "normal_order_1042", "protection_mode": "protect"},
        headers=admin(),
    )

    assert response.status_code == 503


# ---------------------------------------------------------------------------
# Provider code stays in this one module
# ---------------------------------------------------------------------------


def test_only_the_adapter_imports_the_anthropic_sdk():
    offenders = []
    for path in sorted((config.BASE_DIR / "backend").glob("*.py")):
        if path.name == "agent_claude.py":
            continue
        if "anthropic" in path.read_text():
            offenders.append(path.name)

    assert offenders == []


def test_no_security_rule_is_written_into_a_tool_description():
    """A tool description is not a place to put policy."""
    descriptions = " ".join(tool["description"] for tool in agent_claude.TOOLS).lower()

    for phrase in ("not allowed", "forbidden", "you must not", "blocked", "canary", "decoy"):
        assert phrase not in descriptions


def test_the_system_prompt_contains_no_security_rules():
    """Security lives in the gateway, never in the prompt."""
    prompt = agent_claude.SYSTEM_PROMPT.lower()

    for phrase in ("never", "do not", "must not", "canary", "decoy", "forbidden"):
        assert phrase not in prompt
