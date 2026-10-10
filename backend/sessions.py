"""Agent sessions and administrator controls.

A session is one agent run against one inbox item. Its protection mode and
its task context are fixed when it is created, and the task context is read
from the inbox item by this module - never from anything the agent says.

States: ``active``, ``paused``, ``terminated``, ``completed``.

The administrator actions are the human half of the design:

* **stop** terminates a session and clears its pending state.
* **continue** resumes a paused session *without releasing the content that
  was withheld*. The agent is told only "That content was withheld by security
  policy." The session stays tainted, and every new request it makes is
  checked again by the gateway.
* **hr-access** grants or removes HR access for a session.
* **approve** re-runs the full outbound policy on the exact held message. Only
  a HOLD can be approved; a hard deny can never be, in any mode, by anyone.
* **deny** marks a held message denied.

Every administrator action writes an audit event.
"""

import json
import logging
import re

from backend import audit, config, database, detector, gateway, workspace
from backend.models import AgentSession, SimulatedEmail

logger = logging.getLogger(__name__)

INBOX_FOLDER = "inbox"

# Lifted from the HTML inbox fixture, which records its sender in a meta tag
# so the backend never has to guess it from the visible text.
_META_FROM = re.compile(
    r"<meta\s+name=[\"']x-mail-from[\"']\s+content=[\"']([^\"']{1,320})[\"']",
    re.IGNORECASE,
)
_META_RECEIVED = re.compile(
    r"<meta\s+name=[\"']x-mail-received[\"']\s+content=[\"']([^\"']{1,64})[\"']",
    re.IGNORECASE,
)
_TITLE = re.compile(r"<title>([^<]{0,500})</title>", re.IGNORECASE)


class SessionError(Exception):
    """An administrator action that cannot be applied."""


class InvalidTransition(SessionError):
    """The session is not in a state where this action makes sense."""


class ApprovalRefused(SessionError):
    """The message cannot be approved, whoever asks."""


# ---------------------------------------------------------------------------
# The inbox
# ---------------------------------------------------------------------------


def list_inbox() -> list[dict]:
    """The inbox items available to start a session from."""
    items = []
    for name in workspace.list_folder(INBOX_FOLDER):
        try:
            items.append(load_inbox_item(name.rsplit(".", 1)[0]))
        except (workspace.WorkspaceError, ValueError, json.JSONDecodeError):
            logger.exception("could not read inbox item %s", name)
    return items


def load_inbox_item(inbox_id: str) -> dict:
    """One inbox item, with the address it came from.

    The raw body is returned unchanged, hidden HTML included: Stage 11 hands
    it to the model wrapped as untrusted content, and security never depends
    on the model honouring that wrapper.
    """
    if not inbox_id or not re.fullmatch(r"[A-Za-z0-9_\-]{1,80}", inbox_id):
        raise ValueError(f"Not a valid inbox id: {inbox_id!r}")

    available = workspace.list_folder(INBOX_FOLDER)
    for name in available:
        stem, _, extension = name.rpartition(".")
        if stem != inbox_id:
            continue

        raw = workspace.read_file(f"{INBOX_FOLDER}/{name}")

        if extension == "json":
            payload = json.loads(raw)
            return {
                "id": inbox_id,
                "from": payload.get("from", ""),
                "subject": payload.get("subject", ""),
                "received_at": payload.get("received_at"),
                "body": payload.get("body", ""),
                "format": "text",
            }

        sender = _META_FROM.search(raw)
        received = _META_RECEIVED.search(raw)
        title = _TITLE.search(raw)
        return {
            "id": inbox_id,
            "from": sender.group(1) if sender else "",
            "subject": title.group(1) if title else "",
            "received_at": received.group(1) if received else None,
            "body": raw,
            "format": "html",
        }

    raise ValueError(f"No such inbox item: {inbox_id!r}")


def task_context_for(sender: str, inbox_id: str | None = None) -> dict:
    """Who may legitimately receive data for a task from this sender.

    Decided from the records, by unique identifier only:

    * a sender that matches a customer's email on file authorises that
      customer's address on file - not the address the message came from;
    * an internal sender authorises themselves;
    * anyone else authorises nobody, so any personal data in a reply is held
      for review.

    An ambiguous match authorises nobody either. The gateway's data-owner rule
    reads this list, and its limitation - that in a real deployment it should
    come from the company's own access control rather than from the request -
    is recorded in the README.
    """
    address = (sender or "").strip().lower()
    context: dict = {
        "requester": address,
        "authorised_recipients": [],
        "inbox_id": inbox_id,
    }
    if not address:
        return context

    match = detector.owner_lookup([detector.PersonalItem("email", address)]).get(address)

    if isinstance(match, detector.Owner):
        context["authorised_recipients"] = [match.email]
        context["requester_record"] = match.record_id
    elif config.is_internal_recipient(address):
        context["authorised_recipients"] = [address]

    return context


# ---------------------------------------------------------------------------
# Creating and reading a session
# ---------------------------------------------------------------------------


def create_agent_session(
    agent_mode: str, protection_mode: str, inbox_id: str, run_id: str | None = None
) -> AgentSession:
    """Start a session for one inbox item.

    The protection mode is fixed from here on; to compare modes, create
    another session.
    """
    item = load_inbox_item(inbox_id)
    run = run_id or database.get_or_create_active_demo_run().run_id

    session = database.create_session(
        run_id=run,
        agent_mode=agent_mode,
        protection_mode=protection_mode,
        task_context=task_context_for(item["from"], inbox_id=inbox_id),
    )

    audit.append_audit_event(
        run_id=run,
        session_id=session.session_id,
        event_type="SESSION_CREATED",
        resource=f"workspace/inbox/{inbox_id}",
        decision="allowed",
        rule=f"protection_mode:{protection_mode}",
        reason=(
            f"A {agent_mode} session was started for inbox item {inbox_id} "
            f"from {item['from']}."
        ),
    )
    return session


def describe(session_id: str) -> dict:
    """A session's state, for the interface. Carries no file contents."""
    session = database.get_session(session_id)
    if session is None:
        raise ValueError(f"No such session: {session_id!r}")

    return {
        "session_id": session.session_id,
        "run_id": session.run_id,
        "agent_mode": session.agent_mode,
        "protection_mode": session.protection_mode,
        "role": session.role,
        "hr_access": bool(session.hr_access),
        "status": session.status,
        "tainted": bool(session.tainted),
        "personal_items_sent_external": session.personal_items_sent_external,
        "task_context": session.task_context(),
        "created_at": session.created_at,
        "ended_at": session.ended_at,
        "held_email_count": len(
            [
                email
                for email in database.list_held_emails(run_id=session.run_id)
                if email.session_id == session.session_id
            ]
        ),
    }


def _require(session_id: str) -> AgentSession:
    session = database.get_session(session_id)
    if session is None:
        raise ValueError(f"No such session: {session_id!r}")
    return session


def _admin_event(session: AgentSession, event_type: str, reason: str, decision: str):
    audit.append_audit_event(
        run_id=session.run_id,
        session_id=session.session_id,
        event_type=event_type,
        decision=decision,
        rule="admin_action",
        reason=reason,
    )


# ---------------------------------------------------------------------------
# Administrator actions
# ---------------------------------------------------------------------------


def stop(session_id: str) -> dict:
    """Terminate a session and clear its pending state."""
    session = _require(session_id)

    if session.status in ("terminated", "completed"):
        raise InvalidTransition(
            f"This session is already {session.status} and cannot be stopped again."
        )

    # Clearing the saved conversation is what makes this final: there is
    # nothing left to resume from, and no pending tool call to answer.
    database.save_conversation_state(session_id, None)
    database.set_session_status(session_id, "terminated")

    _admin_event(
        session,
        "ADMIN_STOP_SESSION",
        "An administrator stopped the session and cleared its pending state.",
        "terminated",
    )
    logger.info("admin stopped session %s", session_id)
    return describe(session_id)


def resume(session_id: str) -> dict:
    """Resume a paused session without releasing what was withheld.

    The agent is handed a refusal, not the content. The session stays tainted,
    so the outbound rules keep treating it as having touched withheld data,
    and every new request is checked again from scratch.
    """
    session = _require(session_id)

    if session.status == "terminated":
        raise InvalidTransition("A terminated session cannot be resumed.")
    if session.status != "paused":
        raise InvalidTransition(
            f"Only a paused session can be continued; this one is {session.status}."
        )

    database.set_session_status(session_id, "active")

    _admin_event(
        session,
        "ADMIN_CONTINUE_SESSION",
        (
            "An administrator let the session continue. The withheld content "
            "was not released; the agent was told only that it was withheld."
        ),
        "active",
    )
    logger.info("admin resumed session %s (content not released)", session_id)

    state = describe(session_id)
    # The only thing the agent ever receives in place of the content.
    state["agent_message"] = gateway.WITHHELD_MESSAGE
    state["content_released"] = False
    return state


def set_hr_access(session_id: str, enabled: bool) -> dict:
    """Grant or remove HR access for a session."""
    session = _require(session_id)

    if session.status in ("terminated", "completed"):
        raise InvalidTransition(
            f"This session is {session.status}; its access cannot be changed."
        )

    database.set_hr_access(session_id, enabled)

    _admin_event(
        session,
        "ADMIN_HR_ACCESS",
        f"An administrator {'granted' if enabled else 'removed'} HR access.",
        "granted" if enabled else "removed",
    )
    return describe(session_id)


# ---------------------------------------------------------------------------
# Held messages
# ---------------------------------------------------------------------------


def list_held(run_id: str | None = None) -> list[dict]:
    """Messages waiting for review.

    ``hard_deny`` is reported so the interface can leave the Approve button
    off entirely; the backend refuses regardless.
    """
    emails = database.list_held_emails(run_id=run_id)
    return [_describe_email(email) for email in emails]


def _describe_email(email: SimulatedEmail) -> dict:
    return {
        "id": email.id,
        "run_id": email.run_id,
        "session_id": email.session_id,
        "recipient": email.recipient,
        "subject": email.subject,
        "body": email.body,
        "delivery_status": email.delivery_status,
        "rule": email.rule,
        "hard_deny": bool(email.hard_deny),
        "approvable": email.delivery_status == "held" and not email.hard_deny,
        "created_at": email.created_at,
    }


def approve_email(email_id: int) -> dict:
    """Approve a held message, after the gateway revalidates it.

    Approval is not an override. The gateway re-runs the whole outbound policy
    on exactly the stored message; the administrator's approval satisfies the
    *review* requirement that put it on hold, and nothing else. If
    revalidation now produces a hard deny, the message is blocked and the
    approval is refused.
    """
    email = database.get_simulated_email(email_id)
    if email is None:
        raise ValueError(f"No such message: {email_id!r}")

    if email.hard_deny or email.delivery_status == "blocked":
        raise ApprovalRefused(
            "This message was blocked outright, not held for review. A blocked "
            "message can never be approved."
        )
    if email.delivery_status != "held":
        raise InvalidTransition(
            f"This message is {email.delivery_status}, not held for review."
        )

    outcome = gateway.revalidate_held_email(email_id)

    session = database.get_session(email.session_id) if email.session_id else None
    if session is not None:
        _admin_event(
            session,
            "ADMIN_APPROVE_EMAIL",
            (
                f"An administrator approved held message {email_id}; the gateway "
                f"revalidated it and the outcome was {outcome['delivery_status']}."
            ),
            outcome["delivery_status"],
        )

    if outcome["delivery_status"] != "approved_sent":
        raise ApprovalRefused(outcome["reason"])

    return outcome


def deny_email(email_id: int) -> dict:
    """Mark a held message denied. Nothing is sent."""
    email = database.get_simulated_email(email_id)
    if email is None:
        raise ValueError(f"No such message: {email_id!r}")
    if email.delivery_status != "held":
        raise InvalidTransition(
            f"This message is {email.delivery_status}, not held for review."
        )

    updated = database.update_email_status(email_id, "denied", rule="admin_denied")

    session = database.get_session(email.session_id) if email.session_id else None
    if session is not None:
        _admin_event(
            session,
            "ADMIN_DENY_EMAIL",
            f"An administrator denied held message {email_id}. Nothing was sent.",
            "denied",
        )

    return _describe_email(updated)
