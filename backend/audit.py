"""Tamper-evident audit log.

Every gateway decision and every administrator action is appended to a
hash-chained log, one chain per demo run. Each event's hash covers its own
fields plus the previous event's hash, so changing a stored value invalidates
that event and every event after it, and verification reports exactly where
the break is.

This is not a blockchain: there is no network, no consensus, no proof of work
and no distribution. It is a local hash chain, and its guarantee is
correspondingly modest - it makes an edit *detectable*, provided the verifier
is trusted. Anyone able to rewrite the whole table could recompute every hash.

**What is stored.** Decisions, rules, reasons, decoy ids and resource
references. Never file contents: an audit event says that
``workspace/customers/customer_contacts.csv`` was quarantined and which decoy
ids were involved, not what the file said. Note that a resource reference and
a decoy id can still be linked back to a person, so this log is not anonymous;
that is stated in the README.
"""

import hashlib
import json
import logging

from backend import database
from backend.models import AuditEvent

logger = logging.getLogger(__name__)

GENESIS = database.GENESIS_HASH

# The fields covered by an event's hash. ``id`` is excluded because SQLite
# assigns it, and ``event_hash`` because it is the output.
HASHED_FIELDS = (
    "run_id",
    "session_id",
    "event_type",
    "tool",
    "resource",
    "decision",
    "rule",
    "reason",
    "canary_ids",
    "created_at",
    "previous_hash",
)


def compute_event_hash(payload: dict) -> str:
    """SHA-256 over the event's hashed fields, canonically serialised.

    ``sort_keys`` and the tight separators make the serialisation stable, so
    the same event always produces the same hash.
    """
    canonical = json.dumps(
        {field: payload.get(field) for field in HASHED_FIELDS},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def event_hash_of(event: AuditEvent) -> str:
    """Recompute the hash a stored event should have."""
    return compute_event_hash(
        {field: getattr(event, field) for field in HASHED_FIELDS}
    )


def _serialise_canary_ids(canary_ids) -> str | None:
    """Decoy ids as a stable JSON list, or None.

    Sorted so that the same set of decoys always hashes identically.
    """
    if not canary_ids:
        return None
    if isinstance(canary_ids, str):
        return canary_ids
    return json.dumps(sorted(str(value) for value in canary_ids))


def append_audit_event(
    run_id: str,
    event_type: str,
    session_id: str | None = None,
    tool: str | None = None,
    resource: str | None = None,
    decision: str | None = None,
    rule: str | None = None,
    reason: str | None = None,
    canary_ids=None,
) -> AuditEvent:
    """Append one event to a run's chain and return it.

    Reading the previous hash and inserting the new event happen inside one
    immediate transaction, so two concurrent writers cannot both build on the
    same tip and fork the chain.
    """
    created_at = database.utc_now()
    serialised_ids = _serialise_canary_ids(canary_ids)

    with database.app_transaction() as connection:
        previous = database.get_last_audit_event(run_id, connection=connection)
        previous_hash = previous.event_hash if previous else GENESIS

        payload = {
            "run_id": run_id,
            "session_id": session_id,
            "event_type": event_type,
            "tool": tool,
            "resource": resource,
            "decision": decision,
            "rule": rule,
            "reason": reason,
            "canary_ids": serialised_ids,
            "created_at": created_at,
            "previous_hash": previous_hash,
        }
        event_hash = compute_event_hash(payload)

        event_id = database.create_audit_event(
            run_id=run_id,
            event_type=event_type,
            previous_hash=previous_hash,
            event_hash=event_hash,
            session_id=session_id,
            tool=tool,
            resource=resource,
            decision=decision,
            rule=rule,
            reason=reason,
            canary_ids=serialised_ids,
            created_at=created_at,
            connection=connection,
        )

    event = database.get_audit_event(event_id)
    if event is None:
        raise RuntimeError("audit event did not persist")

    logger.info(
        "audit %s: %s %s decision=%s rule=%s",
        event.id,
        event.event_type,
        event.resource or "",
        event.decision or "",
        event.rule or "",
    )
    return event


def list_audit_events(
    run_id: str | None = None, session_id: str | None = None
) -> list[AuditEvent]:
    """Events in chain order, oldest first."""
    return database.list_audit_events(run_id=run_id, session_id=session_id)


def verify_audit_chain(run_id: str) -> dict:
    """Check a run's chain end to end.

    Returns the validity flag, how many events were checked, and the id of the
    first event that failed, with the reason it failed. An empty chain is
    valid.
    """
    events = list_audit_events(run_id=run_id)

    expected_previous = GENESIS
    for event in events:
        if event.previous_hash != expected_previous:
            return {
                "valid": False,
                "event_count": len(events),
                "first_invalid_event_id": event.id,
                "reason": (
                    "This entry does not follow the one before it: its recorded "
                    "link does not match the previous entry's fingerprint."
                ),
            }

        if event_hash_of(event) != event.event_hash:
            return {
                "valid": False,
                "event_count": len(events),
                "first_invalid_event_id": event.id,
                "reason": (
                    "This entry's contents have changed since it was written: "
                    "its fingerprint no longer matches what it holds."
                ),
            }

        expected_previous = event.event_hash

    return {
        "valid": True,
        "event_count": len(events),
        "first_invalid_event_id": None,
        "reason": None,
    }


def tamper_with_oldest_event_for_demo(run_id: str) -> dict:
    """Edit the oldest event in a run, to demonstrate that it is detectable.

    Demo only, and gated by DEMO_MODE and the admin token at the endpoint. It
    rewrites a hashed field of the oldest event without touching any hash,
    which is exactly what someone quietly editing the log would do, then
    records the tampering as a new event so the run's own log shows that an
    administrator did this.
    """
    events = list_audit_events(run_id=run_id)
    if not events:
        raise ValueError("This run has no audit entries to edit.")

    target = events[0]
    original_reason = target.reason
    database.overwrite_audit_event_reason_for_demo(
        target.id, "Routine check, nothing unusual."
    )

    logger.warning(
        "DEMO: audit event %s in run %s was edited on purpose", target.id, run_id
    )

    record = append_audit_event(
        run_id=run_id,
        event_type="AUDIT_TAMPERED_FOR_DEMO",
        decision="tampered",
        rule="demo_only",
        resource=f"audit_events/{target.id}",
        reason=(
            f"An administrator edited audit entry {target.id} of this run to "
            "demonstrate that verification detects it."
        ),
    )

    return {
        "run_id": run_id,
        "tampered_event_id": target.id,
        "original_reason": original_reason,
        "recorded_as_event_id": record.id,
    }
