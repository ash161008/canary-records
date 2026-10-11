"""Administrator alerts, the beacon simulation and the demo reset.

Every alert is built here, from something that actually happened in the
backend. Nothing in the interface invents one, and nothing on the model's side
can raise or suppress one.

**An alert never carries file contents.** It names the file, the destination,
the decision and the time, because that is what an administrator needs in
order to act. What the file said is not in the alert, not in the log, and not
in the Telegram message.

If TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are both set, the same plain-English
text is also sent through the Telegram Bot API. That is optional and
best-effort: a failure is logged and the in-app alert stands regardless. The
bot token is never logged, and never appears in an alert or an error message.
"""

import json
import logging

import requests

from backend import audit, config, database, detector
from backend.models import Alert

logger = logging.getLogger(__name__)

TELEGRAM_TIMEOUT_SECONDS = 5

# ---------------------------------------------------------------------------
# The optional Telegram relay
# ---------------------------------------------------------------------------


def telegram_configured() -> bool:
    return bool(config.TELEGRAM_BOT_TOKEN) and bool(config.TELEGRAM_CHAT_ID)


def send_to_telegram(title: str, message: str) -> bool:
    """Mirror an alert to Telegram. Returns whether it got through.

    Best-effort by design: the in-app alert is the real one. The URL contains
    the bot token, so neither the URL nor the exception is ever logged.
    """
    if not telegram_configured():
        return False

    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        response = requests.post(
            url,
            json={
                "chat_id": config.TELEGRAM_CHAT_ID,
                "text": f"{title}\n\n{message}",
            },
            timeout=TELEGRAM_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            logger.warning(
                "Telegram refused the alert (HTTP %s); the in-app alert stands.",
                response.status_code,
            )
            return False
        return True
    except Exception as error:  # noqa: BLE001
        # Deliberately every exception, not just requests' own. This relay is
        # best-effort and sits on the path that raises a security alert: if
        # mirroring fails for any reason at all, the in-app alert must still
        # stand rather than the failure propagating into the gateway.
        #
        # Only the exception's type is logged: its text can contain the URL,
        # and the URL contains the bot token.
        logger.warning(
            "Telegram alert failed (%s); the in-app alert stands.",
            type(error).__name__,
        )
        return False


# ---------------------------------------------------------------------------
# Raising an alert
# ---------------------------------------------------------------------------


def raise_alert(
    run_id: str,
    severity: str,
    title: str,
    message: str,
    session_id: str | None = None,
    canary_ids: list[str] | None = None,
) -> Alert:
    """Record an alert and mirror it to Telegram if that is configured."""
    alert = database.create_alert(
        run_id=run_id,
        session_id=session_id,
        severity=severity,
        title=title,
        message=message,
        canary_ids=json.dumps(sorted(canary_ids)) if canary_ids else None,
    )
    if telegram_configured():
        send_to_telegram(title, message)
    return alert


def _agent_name(session_id: str | None) -> str:
    if not session_id:
        return "The assistant"
    session = database.get_session(session_id)
    return config.agent_label(session.agent_mode) if session else "The assistant"


def quarantined_read(
    run_id: str,
    session_id: str,
    resource: str,
    canary_ids: list[str] | None = None,
    scan_limit: bool = False,
) -> Alert:
    """A read was withheld before the agent saw it.

    Names the agent, the file and what happened to the session. Says nothing
    about what the file contained.
    """
    agent = _agent_name(session_id)
    session = database.get_session(session_id)
    status = session.status if session else "paused"

    if scan_limit:
        title = "A file was too large to check"
        message = (
            f"{agent} asked to read {resource}, which is too large to scan in "
            "full. The contents were withheld rather than returned unchecked, "
            f"and the session is {status}. You can stop the session or let it "
            "continue; continuing does not release the content."
        )
    else:
        title = "A decoy record was read"
        message = (
            f"{agent} asked to read {resource}. That file holds a decoy "
            "record, so the contents were withheld and never reached the AI. "
            f"The session is {status}. You can stop the session or let it "
            "continue; continuing does not release the content."
        )

    return raise_alert(
        run_id=run_id,
        severity="critical",
        title=title,
        message=message,
        session_id=session_id,
        canary_ids=canary_ids,
    )


def blocked_send(
    run_id: str,
    session_id: str,
    recipient: str,
    locations: list[str] | None = None,
    canary_ids: list[str] | None = None,
) -> Alert:
    """An outgoing message carrying a decoy was refused."""
    agent = _agent_name(session_id)
    session = database.get_session(session_id)
    status = session.status if session else "terminated"
    where = ", ".join(locations or []) or "a company file"

    return raise_alert(
        run_id=run_id,
        severity="critical",
        title="An attempt to send a decoy record was blocked",
        message=(
            f"{agent} tried to email data to {recipient}. The message "
            f"contained a decoy record, which only existed in {where} - so "
            "that file has been read. Nothing was sent, and the session is "
            f"{status}."
        ),
        session_id=session_id,
        canary_ids=canary_ids,
    )


def bulk_send_blocked(
    run_id: str, session_id: str, recipient: str, item_count: int
) -> Alert:
    """An outgoing message carrying too much personal data was refused."""
    agent = _agent_name(session_id)
    session = database.get_session(session_id)
    status = session.status if session else "active"

    return raise_alert(
        run_id=run_id,
        severity="critical",
        title="A bulk disclosure was blocked",
        message=(
            f"{agent} tried to email {item_count} pieces of personal data to "
            f"{recipient}, over the permitted limit. Nothing was sent. The "
            f"session is {status}."
        ),
        session_id=session_id,
    )


def approval_refused(run_id: str, session_id: str | None, recipient: str) -> Alert:
    """An administrator approved a message that revalidation then refused."""
    return raise_alert(
        run_id=run_id,
        severity="critical",
        title="An approval was refused",
        message=(
            f"A held message to {recipient} was approved, but rechecking it "
            "found something that can never be sent. Nothing was sent."
        ),
        session_id=session_id,
    )


# ---------------------------------------------------------------------------
# Reading alerts
# ---------------------------------------------------------------------------


def describe(alert: Alert) -> dict:
    """One alert as the panel shows it, with the actions it allows.

    The actions come from the session's current state, so a paused session
    offers Stop and Continue and a terminated one offers neither.
    """
    session = (
        database.get_session(alert.session_id) if alert.session_id else None
    )
    return {
        **alert.model_dump(),
        "agent_label": (
            config.agent_label(session.agent_mode) if session else None
        ),
        "session_status": session.status if session else None,
        "actions": config.admin_actions(session.status) if session else [],
        "simulated": True,
    }


def list_alerts(run_id: str, status: str | None = None) -> list[dict]:
    return [
        describe(alert) for alert in database.list_alerts(run_id=run_id, status=status)
    ]


def resolve(alert_id: int) -> dict:
    """Mark an alert dealt with. The alert itself is never deleted."""
    alert = database.get_alert(alert_id)
    if alert is None:
        raise ValueError(f"No such alert: {alert_id!r}")

    updated = database.resolve_alert(alert_id)
    audit.append_audit_event(
        run_id=alert.run_id,
        session_id=alert.session_id,
        event_type="ADMIN_RESOLVE_ALERT",
        decision="resolved",
        rule="admin_action",
        reason=f"An administrator marked alert {alert_id} resolved.",
    )
    return describe(updated)


# ---------------------------------------------------------------------------
# The beacon simulation
# ---------------------------------------------------------------------------


def simulate_beacon(canary_id: str) -> dict:
    """Simulate someone outside contacting a decoy.

    A decoy's address exists in exactly one place. If anyone ever contacts it,
    that file has left the company - which is the whole point of planting it.
    Nothing here touches the network: the contact is simulated, and the alert
    says so.
    """
    canary = detector.load_canary(canary_id)
    if canary is None:
        raise ValueError(f"No such decoy: {canary_id!r}")

    run_id = database.get_or_create_active_demo_run().run_id

    alert = raise_alert(
        run_id=run_id,
        severity="critical",
        title="A decoy was contacted (simulated)",
        message=(
            f"Someone outside the company contacted a decoy record. It only "
            f"ever existed in {canary.location}, so that file has leaked. "
            "This contact is simulated for the demonstration; no real message "
            "was received."
        ),
        canary_ids=[canary.id],
    )

    audit.append_audit_event(
        run_id=run_id,
        event_type="BEACON_SIMULATED",
        resource=canary.location,
        decision="alerted",
        rule="demo_only",
        reason=(
            f"A simulated contact to decoy {canary.id} indicates "
            f"{canary.location} has leaked."
        ),
        canary_ids=[canary.id],
    )

    return {
        "canary_id": canary.id,
        "canary_type": canary.canary_type,
        "location": canary.location,
        "record_ref": canary.record_ref,
        "alert_id": alert.id,
        "simulated": True,
    }


# ---------------------------------------------------------------------------
# The demo reset
# ---------------------------------------------------------------------------


def reset_demo(notes: str | None = None) -> dict:
    """End the current demo run and start a clean one.

    Nothing is deleted. The databases are never removed and no source file is
    touched: the workspace is restored by regenerating it, the old run's open
    business is finalised and recorded in that run's own chain, and then the
    run is closed and a new one opened with a fresh chain starting at GENESIS.

    Earlier runs keep their audit events, alerts, messages and suite results,
    and all of it stays attributable to the run id it happened under.
    """
    from backend import seeder

    old = database.get_or_create_active_demo_run()

    # Finalise what was still open, in the old run's chain, before it closes.
    terminated = 0
    for session in database.list_sessions(run_id=old.run_id):
        if session.status in ("active", "paused"):
            database.save_conversation_state(session.session_id, None)
            database.set_session_status(session.session_id, "terminated")
            terminated += 1

    denied = 0
    for email in database.list_held_emails(run_id=old.run_id):
        database.update_email_status(email.id, "denied", rule="reset_never_reviewed")
        denied += 1

    resolved = 0
    for alert in database.list_alerts(run_id=old.run_id, status="open"):
        database.resolve_alert(alert.id)
        resolved += 1

    audit.append_audit_event(
        run_id=old.run_id,
        event_type="RUN_RESET",
        decision="ended",
        rule="admin_action",
        reason=(
            f"An administrator reset the demo. {terminated} session(s) were "
            f"terminated, {denied} held message(s) denied and {resolved} "
            "alert(s) resolved. This run's evidence is kept."
        ),
    )

    # Remove the decoys and put the workspace files back as generated. The
    # registry is emptied; no file is deleted.
    unseeded = seeder.unseed()

    database.end_demo_run(old.run_id, notes=notes or "ended by reset")
    new = database.create_demo_run(notes="started by reset")

    # The new run's chain begins at GENESIS with this entry.
    audit.append_audit_event(
        run_id=new.run_id,
        event_type="RUN_STARTED",
        decision="allowed",
        rule="admin_action",
        reason=f"A new demo run was started by reset; the previous run was {old.run_id}.",
    )

    logger.info("demo reset: run %s ended, run %s started", old.run_id, new.run_id)

    return {
        "previous_run_id": old.run_id,
        "run_id": new.run_id,
        "sessions_terminated": terminated,
        "held_emails_denied": denied,
        "alerts_resolved": resolved,
        "canaries_removed": unseeded["removed"],
        "workspace_restored": True,
        "previous_evidence_kept": True,
    }
