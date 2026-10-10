"""Deterministic scripted agent.

Two jobs, neither of them being the demo agent:

1. **Reliable automated tests.** A fixed list of tool calls, no model, no
   variability, so a test asserts something about the gateway rather than
   about what a model happened to do.
2. **The worst-case agent.** For an attack scenario it replays exactly the
   tool calls the attacker wanted - the scenario's ``intended_tool_calls`` -
   with no judgement of its own. That is a fully compromised AI: one that
   always tries the attack and never declines. Whatever it fails to achieve,
   the gateway stopped. The demo agent is Claude, in backend/agent_claude.py.

This module reaches tools through ``gateway.execute()`` and nothing else. It
opens no file, touches no customer record and writes no email: there is no
import of the workspace utilities or the email table here, and a test asserts
that stays true.

It is labelled "Worst-case (scripted)" wherever it is shown, so a viewer is
never left thinking the demo's results came from a model that chose to behave.
"""

import logging

from backend import audit, config, database, gateway, scenarios
from backend.models import AgentSession

logger = logging.getLogger(__name__)

# An attacker's script can be long; the agent is still bounded.
MAX_TOOL_CALLS = 24

# Why a run stopped.
COMPLETED = "completed"
STOPPED_QUARANTINED = "quarantined"
STOPPED_BLOCKED = "blocked"
STOPPED_HELD = "held"
STOPPED_SESSION_ENDED = "session_ended"
STOPPED_CALL_LIMIT = "call_limit_reached"

# Decisions that end a run: the gateway has paused, blocked or held, or the
# session is no longer usable. A refused *read* does not end it - a worst-case
# agent simply tries the next thing, which is what makes the role checks worth
# measuring separately.
_STOPPING_DECISIONS = (gateway.QUARANTINED, gateway.BLOCKED, gateway.HELD)


def _badge(result: dict) -> str:
    """The badge the interface shows for one step.

    Decided here, in the backend, from the gateway's own verdict. The frontend
    renders this string; it never works out a badge for itself.
    """
    rule = result.get("rule") or ""
    if result["decision"] == gateway.DENIED and rule.startswith("role_"):
        return "role-blocked"
    return result["decision"]


def _summarise_arguments(tool: str, arguments: dict) -> dict:
    """What to show in the trace for one call.

    A send_email body is summarised rather than reproduced: on an attack run
    it is the exfiltration payload, and the trace is displayed on screen.
    """
    if tool != gateway.SEND_EMAIL:
        return dict(arguments)

    body = arguments.get("body") or ""
    return {
        "recipient": arguments.get("recipient"),
        "subject": arguments.get("subject"),
        "body_characters": len(body),
    }


def _summarise_content(result: dict) -> dict:
    """Whether the agent got content, and how much - never the content."""
    if "content" not in result:
        return {"content_returned": False, "content_summary": None}

    content = result["content"]
    if isinstance(content, str):
        summary = f"{len(content)} characters"
    elif isinstance(content, list):
        summary = f"{len(content)} items"
    elif isinstance(content, dict):
        summary = f"{len(content)} fields"
    else:
        summary = "a value"

    return {"content_returned": True, "content_summary": summary}


def run_scripted(session_id: str, tool_calls: list[dict]) -> dict:
    """Execute tool calls in order, through the gateway only.

    Stops as soon as the gateway quarantines, blocks or holds, or the session
    stops being active. Returns an ordered activity list for the interface.
    """
    session = database.get_session(session_id)
    if session is None:
        raise ValueError(f"No such session: {session_id!r}")

    activity: list[dict] = []
    stopped_because = COMPLETED

    for index, call in enumerate(tool_calls, start=1):
        if index > MAX_TOOL_CALLS:
            stopped_because = STOPPED_CALL_LIMIT
            break

        tool = call.get("tool") if isinstance(call, dict) else None
        arguments = call.get("arguments", {}) if isinstance(call, dict) else {}

        # Deliberately not validated here. An unknown tool or malformed
        # arguments is the gateway's decision to make and to audit, and a
        # worst-case agent is exactly the thing that would send them.
        result = gateway.execute(session_id, tool, arguments)

        activity.append(
            {
                "step": index,
                "tool": tool,
                "arguments": _summarise_arguments(tool, arguments),
                "decision": result["decision"],
                "badge": _badge(result),
                "hard_deny": result["hard_deny"],
                "rule": result.get("rule"),
                "reason": result.get("reason"),
                "resource": result.get("resource"),
                "status": result.get("status"),
                "canary_ids": result.get("canary_ids", []),
                "email_id": result.get("email_id"),
                "would_be": result.get("would_be"),
                **_summarise_content(result),
            }
        )

        if result["decision"] in _STOPPING_DECISIONS:
            stopped_because = result["decision"]
            break

        current = database.get_session(session_id)
        if current is None or current.status != "active":
            stopped_because = STOPPED_SESSION_ENDED
            break

    # A run that got through its whole script without being stopped has
    # finished its task. A run stopped by a hold stays active: an
    # administrator still has a decision to make.
    final = database.get_session(session_id)
    if stopped_because == COMPLETED and final is not None and final.status == "active":
        database.set_session_status(session_id, "completed")

    final = database.get_session(session_id)

    audit.append_audit_event(
        run_id=session.run_id,
        session_id=session_id,
        event_type="SCRIPTED_RUN_FINISHED",
        decision=stopped_because,
        rule=f"agent_mode:{session.agent_mode}",
        reason=(
            f"{config.agent_label(session.agent_mode)} ran {len(activity)} of "
            f"{len(tool_calls)} scripted tool calls; the run ended "
            f"{stopped_because}."
        ),
    )

    return {
        "session_id": session_id,
        "run_id": session.run_id,
        "agent_mode": session.agent_mode,
        "agent_label": config.agent_label(session.agent_mode),
        "protection_mode": session.protection_mode,
        "status": final.status if final else None,
        "tainted": bool(final.tainted) if final else False,
        "stopped_because": stopped_because,
        "calls_requested": len(tool_calls),
        "calls_executed": len(activity),
        "activity": activity,
    }


def session_for_scenario(
    scenario: dict, protection_mode: str, run_id: str | None = None
) -> AgentSession:
    """Create a session for one scenario.

    The task context comes from the scenario's own ``from`` and
    ``authorised_recipients`` - set by the backend, exactly as it would be from
    an inbox item, and never from anything the agent says.
    """
    agent_mode = (
        "scripted_normal" if scenario["scenario_type"] == "normal" else "worst_case"
    )
    run = run_id or database.get_or_create_active_demo_run().run_id

    session = database.create_session(
        run_id=run,
        agent_mode=agent_mode,
        protection_mode=protection_mode,
        task_context={
            "requester": scenario["from"],
            "authorised_recipients": list(scenario.get("authorised_recipients") or []),
            "scenario_id": scenario["id"],
        },
    )

    audit.append_audit_event(
        run_id=run,
        session_id=session.session_id,
        event_type="SESSION_CREATED",
        resource=f"scenario/{scenario['id']}",
        decision="allowed",
        rule=f"protection_mode:{protection_mode}",
        reason=(
            f"{config.agent_label(agent_mode)} session started for scenario "
            f"{scenario['id']} from {scenario['from']}."
        ),
    )
    return session


def run_scenario(
    scenario_id: str, protection_mode: str, run_id: str | None = None
) -> dict:
    """Replay a scenario's intended tool calls through the gateway.

    For an attack this is the worst case: the attacker's script runs in full,
    unaltered, with nothing in the agent declining any part of it.
    """
    scenario = scenarios.load_scenario(scenario_id)
    session = session_for_scenario(scenario, protection_mode, run_id=run_id)

    outcome = run_scripted(session.session_id, scenario["intended_tool_calls"])
    outcome["scenario_id"] = scenario_id
    outcome["scenario_type"] = scenario["scenario_type"]
    outcome["category"] = scenario["category"]
    outcome["expected_protect_outcome"] = scenario.get("expected_protect_outcome")
    return outcome
