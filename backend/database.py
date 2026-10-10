"""SQLite data layer. Built-in sqlite3 only, no ORM.

Two databases, deliberately separate:

* ``data/app.db`` - demo runs, agent sessions, audit events, alerts,
  simulated emails and scenario-suite results.
* ``vault/registry.db`` - the canary registry: the only record of which
  workspace values are decoys.

Rules enforced here:

* Parameterised SQL only. No query is ever assembled from caller data;
  column names used in UPDATE statements come from fixed internal
  allowlists.
* ``row_factory`` is set on every connection and rows are returned as
  validated Pydantic models.
* Initialisation is idempotent: calling it repeatedly is safe.
* Every timestamp is UTC ISO 8601.
* ``protection_mode`` cannot change after a session is created. This is
  enforced twice: the update helper refuses the column, and a SQLite trigger
  aborts the write even if raw SQL attempts it.
* Only ``backend/seeder.py`` and ``backend/detector.py`` may reach the canary
  registry. Every registry function checks its caller and raises
  ``PermissionError`` otherwise.

Paths are read from ``config`` at call time, not bound at import, so tests can
point both databases at a temporary directory.
"""

import inspect
import json
import logging
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from backend import config
from backend.models import (
    Alert,
    AgentSession,
    AuditEvent,
    Canary,
    DemoRun,
    SimulatedEmail,
    TestResult,
    TestRun,
)

logger = logging.getLogger(__name__)

GENESIS_HASH = "GENESIS"

# Modules permitted to open vault/registry.db. A separate file plus this
# allowlist is a code-level boundary, not an OS-level one: it stops the
# agent's tool paths from reaching the registry, but any backend code could
# be changed to add itself here. Stated as a limitation in the README.
_REGISTRY_CALLERS = frozenset({"backend.seeder", "backend.detector"})

# Frames skipped when identifying the caller of a registry function.
_GUARD_SKIP_MODULES = frozenset({__name__, "contextlib"})


# ---------------------------------------------------------------------------
# Time and identifiers
# ---------------------------------------------------------------------------


def utc_now() -> str:
    """Current UTC time as ISO 8601 with milliseconds, e.g.
    ``2026-10-10T12:30:00.123Z``. Milliseconds are kept because the
    scoreboard measures alert latency."""
    stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    return stamp.replace("+00:00", "Z")


def new_id() -> str:
    """A fresh opaque identifier for a run, session or canary."""
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------


def _open(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def app_connection() -> Iterator[sqlite3.Connection]:
    """A connection to data/app.db, committed on success."""
    connection = _open(config.APP_DB)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


@contextmanager
def app_transaction() -> Iterator[sqlite3.Connection]:
    """A connection that takes the write lock immediately.

    Used where two concurrent writers must not interleave - notably
    appending to the audit chain, where each event depends on the previous
    event's hash.
    """
    connection = _open(config.APP_DB)
    try:
        connection.isolation_level = None
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def _assert_registry_caller() -> None:
    """Allow only the seeder and the detector to reach the registry."""
    frame = inspect.currentframe()
    try:
        caller = frame.f_back if frame else None
        while caller is not None:
            module = caller.f_globals.get("__name__", "")
            if module not in _GUARD_SKIP_MODULES:
                if module not in _REGISTRY_CALLERS:
                    raise PermissionError(
                        f"{module} may not open the canary registry; only "
                        f"{', '.join(sorted(_REGISTRY_CALLERS))} may."
                    )
                return
            caller = caller.f_back
        raise PermissionError("Could not identify the caller of the canary registry.")
    finally:
        del frame


@contextmanager
def registry_connection() -> Iterator[sqlite3.Connection]:
    """A connection to vault/registry.db. Caller-restricted."""
    _assert_registry_caller()
    connection = _open(config.REGISTRY_DB)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_APP_SCHEMA = """
CREATE TABLE IF NOT EXISTS demo_runs (
    run_id      TEXT PRIMARY KEY,
    started_at  TEXT NOT NULL,
    ended_at    TEXT,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS agent_sessions (
    session_id                   TEXT PRIMARY KEY,
    run_id                       TEXT NOT NULL REFERENCES demo_runs(run_id),
    agent_mode                   TEXT NOT NULL
        CHECK (agent_mode IN ('claude', 'worst_case', 'scripted_normal')),
    role                         TEXT NOT NULL DEFAULT 'support_agent',
    hr_access                    INTEGER NOT NULL DEFAULT 0
        CHECK (hr_access IN (0, 1)),
    protection_mode              TEXT NOT NULL
        CHECK (protection_mode IN ('protect', 'outbound_only', 'monitor')),
    status                       TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'paused', 'terminated', 'completed')),
    tainted                      INTEGER NOT NULL DEFAULT 0
        CHECK (tainted IN (0, 1)),
    personal_items_sent_external INTEGER NOT NULL DEFAULT 0,
    task_context_json            TEXT,
    conversation_state_json      TEXT,
    created_at                   TEXT NOT NULL,
    ended_at                     TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_run ON agent_sessions(run_id);

/* protection_mode is fixed when a session is created. To compare modes,
   create a new session. The trigger makes this true for any writer,
   including raw SQL, not just the update helper below. */
CREATE TRIGGER IF NOT EXISTS trg_protection_mode_immutable
BEFORE UPDATE OF protection_mode ON agent_sessions
FOR EACH ROW WHEN NEW.protection_mode IS NOT OLD.protection_mode
BEGIN
    SELECT RAISE(ABORT, 'protection_mode is fixed when a session is created');
END;

CREATE TABLE IF NOT EXISTS audit_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT NOT NULL REFERENCES demo_runs(run_id),
    session_id    TEXT REFERENCES agent_sessions(session_id),
    event_type    TEXT NOT NULL,
    tool          TEXT,
    resource      TEXT,
    decision      TEXT,
    rule          TEXT,
    reason        TEXT,
    canary_ids    TEXT,
    created_at    TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_run ON audit_events(run_id, id);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events(session_id, id);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     TEXT NOT NULL REFERENCES demo_runs(run_id),
    session_id TEXT REFERENCES agent_sessions(session_id),
    severity   TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    title      TEXT NOT NULL,
    message    TEXT NOT NULL,
    canary_ids TEXT,
    status     TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'resolved')),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_run ON alerts(run_id, id);

CREATE TABLE IF NOT EXISTS simulated_emails (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL REFERENCES demo_runs(run_id),
    session_id      TEXT REFERENCES agent_sessions(session_id),
    recipient       TEXT NOT NULL,
    subject         TEXT NOT NULL,
    body            TEXT NOT NULL,
    delivery_status TEXT NOT NULL CHECK (delivery_status IN
        ('simulated_sent', 'blocked', 'held', 'approved_sent', 'denied')),
    rule            TEXT,
    hard_deny       INTEGER NOT NULL DEFAULT 0 CHECK (hard_deny IN (0, 1)),
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_emails_run ON simulated_emails(run_id, id);

CREATE TABLE IF NOT EXISTS test_runs (
    run_id          TEXT PRIMARY KEY,
    demo_run_id     TEXT REFERENCES demo_runs(run_id),
    agent_mode      TEXT NOT NULL
        CHECK (agent_mode IN ('claude', 'worst_case', 'scripted_normal')),
    protection_mode TEXT NOT NULL
        CHECK (protection_mode IN ('protect', 'outbound_only', 'monitor')),
    model_id        TEXT,
    sdk_version     TEXT,
    repeats         INTEGER NOT NULL DEFAULT 1,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS test_results (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                  TEXT NOT NULL REFERENCES test_runs(run_id),
    scenario_id             TEXT NOT NULL,
    scenario_type           TEXT NOT NULL
        CHECK (scenario_type IN ('attack', 'normal')),
    category                TEXT NOT NULL
        CHECK (category IN ('bulk', 'targeted', 'normal')),
    repeat_index            INTEGER NOT NULL DEFAULT 0,
    expected                TEXT,
    outcome                 TEXT,
    caught_at               TEXT CHECK (caught_at IS NULL OR caught_at IN
        ('role', 'read_quarantine', 'outbound_block', 'outbound_hold', 'none')),
    unauthorised_disclosure INTEGER NOT NULL DEFAULT 0,
    canary_exposure         INTEGER NOT NULL DEFAULT 0,
    forbidden_access        INTEGER NOT NULL DEFAULT 0,
    false_hold              INTEGER NOT NULL DEFAULT 0,
    task_failed             INTEGER NOT NULL DEFAULT 0,
    model_refused           INTEGER NOT NULL DEFAULT 0,
    details                 TEXT,
    duration_ms             INTEGER,
    created_at              TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_results_run ON test_results(run_id, id);
"""

_REGISTRY_SCHEMA = """
CREATE TABLE IF NOT EXISTS canaries (
    id                 TEXT PRIMARY KEY,
    canary_type        TEXT NOT NULL CHECK (canary_type IN
        ('customer', 'salary', 'credential', 'trade_secret')),
    location           TEXT NOT NULL,
    record_ref         TEXT,
    strong_values_json TEXT NOT NULL,
    weak_values_json   TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'removed')),
    created_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_canaries_status ON canaries(status);
"""


def init_app_db() -> None:
    """Create data/app.db and its tables if they do not exist."""
    with app_connection() as connection:
        connection.executescript(_APP_SCHEMA)
    logger.info("app database ready at %s", config.APP_DB.name)


def init_registry_db() -> None:
    """Create vault/registry.db and its table if they do not exist.

    Caller-restricted: reachable only through the seeder or the detector.
    """
    with registry_connection() as connection:
        connection.executescript(_REGISTRY_SCHEMA)
    logger.info("canary registry ready at %s", config.REGISTRY_DB.name)


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _one(connection: sqlite3.Connection, sql: str, params: tuple, model):
    row = connection.execute(sql, params).fetchone()
    return model.model_validate(dict(row)) if row else None


def _many(connection: sqlite3.Connection, sql: str, params: tuple, model) -> list:
    rows = connection.execute(sql, params).fetchall()
    return [model.model_validate(dict(row)) for row in rows]


def _apply_updates(
    connection: sqlite3.Connection,
    table: str,
    key_column: str,
    key_value: str,
    updates: dict,
    allowed: frozenset,
) -> None:
    """Apply an UPDATE built only from allowlisted column names.

    Column names never come from caller input: an unrecognised key raises
    rather than reaching the SQL. Values are always bound parameters.
    """
    unknown = set(updates) - allowed
    if unknown:
        raise ValueError(
            f"{table}: these columns cannot be updated: {', '.join(sorted(unknown))}"
        )
    if not updates:
        return

    columns = [column for column in sorted(updates) if column in allowed]
    assignments = ", ".join(f"{column} = ?" for column in columns)
    params = tuple(updates[column] for column in columns) + (key_value,)
    connection.execute(
        f"UPDATE {table} SET {assignments} WHERE {key_column} = ?", params
    )


# ---------------------------------------------------------------------------
# demo_runs
# ---------------------------------------------------------------------------


def create_demo_run(notes: str | None = None) -> DemoRun:
    """Start a new demo run. Earlier runs are never deleted."""
    run = DemoRun(run_id=new_id(), started_at=utc_now(), notes=notes)
    with app_connection() as connection:
        connection.execute(
            "INSERT INTO demo_runs (run_id, started_at, ended_at, notes) "
            "VALUES (?, ?, ?, ?)",
            (run.run_id, run.started_at, run.ended_at, run.notes),
        )
    logger.info("demo run %s started", run.run_id)
    return run


def get_demo_run(run_id: str) -> DemoRun | None:
    with app_connection() as connection:
        return _one(
            connection, "SELECT * FROM demo_runs WHERE run_id = ?", (run_id,), DemoRun
        )


def list_demo_runs() -> list[DemoRun]:
    """All runs, newest first."""
    with app_connection() as connection:
        return _many(
            connection,
            "SELECT * FROM demo_runs ORDER BY started_at DESC, rowid DESC",
            (),
            DemoRun,
        )


def end_demo_run(run_id: str, notes: str | None = None) -> None:
    updates: dict = {"ended_at": utc_now()}
    if notes is not None:
        updates["notes"] = notes
    with app_connection() as connection:
        _apply_updates(
            connection,
            "demo_runs",
            "run_id",
            run_id,
            updates,
            frozenset({"ended_at", "notes"}),
        )


def get_active_demo_run() -> DemoRun | None:
    """The most recently started run that has not ended."""
    with app_connection() as connection:
        return _one(
            connection,
            "SELECT * FROM demo_runs WHERE ended_at IS NULL "
            "ORDER BY started_at DESC, rowid DESC LIMIT 1",
            (),
            DemoRun,
        )


def get_or_create_active_demo_run() -> DemoRun:
    """The current run, starting one if none is open."""
    return get_active_demo_run() or create_demo_run(notes="auto-started")


# ---------------------------------------------------------------------------
# agent_sessions
# ---------------------------------------------------------------------------

# protection_mode, agent_mode, run_id, role and created_at are absent on
# purpose: they are fixed when the session is created.
_SESSION_MUTABLE = frozenset(
    {
        "status",
        "hr_access",
        "tainted",
        "personal_items_sent_external",
        "task_context_json",
        "conversation_state_json",
        "ended_at",
    }
)


def create_session(
    run_id: str,
    agent_mode: str,
    protection_mode: str,
    role: str = "support_agent",
    hr_access: int = 0,
    task_context: dict | None = None,
) -> AgentSession:
    """Create a session. protection_mode is fixed from this point on."""
    session = AgentSession(
        session_id=new_id(),
        run_id=run_id,
        agent_mode=agent_mode,
        role=role,
        hr_access=1 if hr_access else 0,
        protection_mode=protection_mode,
        status="active",
        task_context_json=json.dumps(task_context) if task_context else None,
        created_at=utc_now(),
    )
    with app_connection() as connection:
        connection.execute(
            "INSERT INTO agent_sessions ("
            "session_id, run_id, agent_mode, role, hr_access, protection_mode, "
            "status, tainted, personal_items_sent_external, task_context_json, "
            "conversation_state_json, created_at, ended_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                session.session_id,
                session.run_id,
                session.agent_mode,
                session.role,
                session.hr_access,
                session.protection_mode,
                session.status,
                session.tainted,
                session.personal_items_sent_external,
                session.task_context_json,
                session.conversation_state_json,
                session.created_at,
                session.ended_at,
            ),
        )
    logger.info(
        "session %s created (agent_mode=%s, protection_mode=%s)",
        session.session_id,
        session.agent_mode,
        session.protection_mode,
    )
    return session


def get_session(session_id: str) -> AgentSession | None:
    with app_connection() as connection:
        return _one(
            connection,
            "SELECT * FROM agent_sessions WHERE session_id = ?",
            (session_id,),
            AgentSession,
        )


def list_sessions(run_id: str | None = None) -> list[AgentSession]:
    with app_connection() as connection:
        if run_id is None:
            return _many(
                connection,
                "SELECT * FROM agent_sessions ORDER BY created_at DESC, rowid DESC",
                (),
                AgentSession,
            )
        return _many(
            connection,
            "SELECT * FROM agent_sessions WHERE run_id = ? "
            "ORDER BY created_at DESC, rowid DESC",
            (run_id,),
            AgentSession,
        )


def update_session(session_id: str, **updates) -> AgentSession | None:
    """Update mutable session fields.

    Refuses protection_mode and every other field fixed at creation. The
    SQLite trigger blocks protection_mode writes independently of this check.
    """
    with app_connection() as connection:
        _apply_updates(
            connection,
            "agent_sessions",
            "session_id",
            session_id,
            updates,
            _SESSION_MUTABLE,
        )
    return get_session(session_id)


def set_session_status(session_id: str, status: str) -> AgentSession | None:
    """Set the session state, stamping ended_at for terminal states."""
    updates: dict = {"status": status}
    if status in ("terminated", "completed"):
        updates["ended_at"] = utc_now()
    return update_session(session_id, **updates)


def set_hr_access(session_id: str, enabled: bool) -> AgentSession | None:
    return update_session(session_id, hr_access=1 if enabled else 0)


def mark_session_tainted(session_id: str) -> AgentSession | None:
    return update_session(session_id, tainted=1)


def add_personal_items_sent(session_id: str, count: int) -> AgentSession | None:
    """Add to the running total of personal items sent outside the task's
    authorised recipients."""
    with app_connection() as connection:
        connection.execute(
            "UPDATE agent_sessions SET personal_items_sent_external = "
            "personal_items_sent_external + ? WHERE session_id = ?",
            (count, session_id),
        )
    return get_session(session_id)


def save_conversation_state(session_id: str, state: dict | None) -> None:
    """Persist only what is needed to resume. Cleared when a session ends."""
    update_session(
        session_id,
        conversation_state_json=json.dumps(state) if state else None,
    )


# ---------------------------------------------------------------------------
# audit_events
#
# Hashing belongs to backend/audit.py (Stage 7). These helpers store and read
# rows, taking previous_hash and event_hash as given.
# ---------------------------------------------------------------------------


def create_audit_event(
    run_id: str,
    event_type: str,
    previous_hash: str,
    event_hash: str,
    session_id: str | None = None,
    tool: str | None = None,
    resource: str | None = None,
    decision: str | None = None,
    rule: str | None = None,
    reason: str | None = None,
    canary_ids: str | None = None,
    created_at: str | None = None,
    connection: sqlite3.Connection | None = None,
) -> int:
    """Insert one audit event and return its id.

    An existing connection can be passed so the caller can append inside its
    own immediate transaction, keeping the chain consistent under concurrent
    writes.
    """
    params = (
        run_id,
        session_id,
        event_type,
        tool,
        resource,
        decision,
        rule,
        reason,
        canary_ids,
        created_at or utc_now(),
        previous_hash,
        event_hash,
    )
    sql = (
        "INSERT INTO audit_events ("
        "run_id, session_id, event_type, tool, resource, decision, rule, "
        "reason, canary_ids, created_at, previous_hash, event_hash"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )

    if connection is not None:
        return int(connection.execute(sql, params).lastrowid)

    with app_connection() as own_connection:
        return int(own_connection.execute(sql, params).lastrowid)


def get_audit_event(event_id: int) -> AuditEvent | None:
    with app_connection() as connection:
        return _one(
            connection,
            "SELECT * FROM audit_events WHERE id = ?",
            (event_id,),
            AuditEvent,
        )


def list_audit_events(
    run_id: str | None = None, session_id: str | None = None
) -> list[AuditEvent]:
    """Audit events in chain order (oldest first)."""
    with app_connection() as connection:
        if run_id is not None and session_id is not None:
            return _many(
                connection,
                "SELECT * FROM audit_events WHERE run_id = ? AND session_id = ? "
                "ORDER BY id ASC",
                (run_id, session_id),
                AuditEvent,
            )
        if run_id is not None:
            return _many(
                connection,
                "SELECT * FROM audit_events WHERE run_id = ? ORDER BY id ASC",
                (run_id,),
                AuditEvent,
            )
        if session_id is not None:
            return _many(
                connection,
                "SELECT * FROM audit_events WHERE session_id = ? ORDER BY id ASC",
                (session_id,),
                AuditEvent,
            )
        return _many(
            connection, "SELECT * FROM audit_events ORDER BY id ASC", (), AuditEvent
        )


def overwrite_audit_event_reason_for_demo(event_id: int, reason: str) -> None:
    """Rewrite one event's reason WITHOUT updating any hash.

    Demo only. This exists so the interface can show that an edited log is
    detectable: it changes a hashed field and deliberately leaves the stored
    fingerprint stale, which is what verification then catches. Nothing in
    normal operation updates an audit event - the log is append-only.
    """
    with app_connection() as connection:
        connection.execute(
            "UPDATE audit_events SET reason = ? WHERE id = ?", (reason, event_id)
        )
    logger.warning("DEMO: audit event %s was edited deliberately", event_id)


def get_last_audit_event(
    run_id: str, connection: sqlite3.Connection | None = None
) -> AuditEvent | None:
    """The newest event in a run's chain, or None for an empty chain."""
    sql = "SELECT * FROM audit_events WHERE run_id = ? ORDER BY id DESC LIMIT 1"
    if connection is not None:
        return _one(connection, sql, (run_id,), AuditEvent)
    with app_connection() as own_connection:
        return _one(own_connection, sql, (run_id,), AuditEvent)


# ---------------------------------------------------------------------------
# alerts
# ---------------------------------------------------------------------------


def create_alert(
    run_id: str,
    severity: str,
    title: str,
    message: str,
    session_id: str | None = None,
    canary_ids: str | None = None,
) -> Alert:
    created_at = utc_now()
    with app_connection() as connection:
        cursor = connection.execute(
            "INSERT INTO alerts ("
            "run_id, session_id, severity, title, message, canary_ids, status, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, 'open', ?)",
            (run_id, session_id, severity, title, message, canary_ids, created_at),
        )
        alert_id = int(cursor.lastrowid)
    logger.info("alert %s raised: %s", alert_id, title)
    alert = get_alert(alert_id)
    if alert is None:
        raise RuntimeError("alert insert did not persist")
    return alert


def get_alert(alert_id: int) -> Alert | None:
    with app_connection() as connection:
        return _one(connection, "SELECT * FROM alerts WHERE id = ?", (alert_id,), Alert)


def list_alerts(run_id: str | None = None, status: str | None = None) -> list[Alert]:
    """Alerts newest first, optionally filtered by run and status."""
    clauses: list[str] = []
    params: list = []
    if run_id is not None:
        clauses.append("run_id = ?")
        params.append(run_id)
    if status is not None:
        clauses.append("status = ?")
        params.append(status)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    with app_connection() as connection:
        return _many(
            connection,
            f"SELECT * FROM alerts{where} ORDER BY id DESC",
            tuple(params),
            Alert,
        )


def resolve_alert(alert_id: int) -> Alert | None:
    with app_connection() as connection:
        _apply_updates(
            connection,
            "alerts",
            "id",
            alert_id,
            {"status": "resolved"},
            frozenset({"status"}),
        )
    return get_alert(alert_id)


# ---------------------------------------------------------------------------
# simulated_emails
#
# Nothing here contacts a mail service. The row is the whole of the send.
# ---------------------------------------------------------------------------

_EMAIL_MUTABLE = frozenset({"delivery_status", "rule"})


def create_simulated_email(
    run_id: str,
    recipient: str,
    subject: str,
    body: str,
    delivery_status: str,
    session_id: str | None = None,
    rule: str | None = None,
    hard_deny: bool = False,
) -> SimulatedEmail:
    created_at = utc_now()
    with app_connection() as connection:
        cursor = connection.execute(
            "INSERT INTO simulated_emails ("
            "run_id, session_id, recipient, subject, body, delivery_status, "
            "rule, hard_deny, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                session_id,
                recipient,
                subject,
                body,
                delivery_status,
                rule,
                1 if hard_deny else 0,
                created_at,
            ),
        )
        email_id = int(cursor.lastrowid)
    email = get_simulated_email(email_id)
    if email is None:
        raise RuntimeError("simulated email insert did not persist")
    return email


def get_simulated_email(email_id: int) -> SimulatedEmail | None:
    with app_connection() as connection:
        return _one(
            connection,
            "SELECT * FROM simulated_emails WHERE id = ?",
            (email_id,),
            SimulatedEmail,
        )


def list_simulated_emails(
    run_id: str | None = None, delivery_status: str | None = None
) -> list[SimulatedEmail]:
    clauses: list[str] = []
    params: list = []
    if run_id is not None:
        clauses.append("run_id = ?")
        params.append(run_id)
    if delivery_status is not None:
        clauses.append("delivery_status = ?")
        params.append(delivery_status)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    with app_connection() as connection:
        return _many(
            connection,
            f"SELECT * FROM simulated_emails{where} ORDER BY id DESC",
            tuple(params),
            SimulatedEmail,
        )


def list_held_emails(run_id: str | None = None) -> list[SimulatedEmail]:
    """Emails awaiting administrator review."""
    return list_simulated_emails(run_id=run_id, delivery_status="held")


def update_email_status(
    email_id: int, delivery_status: str, rule: str | None = None
) -> SimulatedEmail | None:
    """Record the outcome of an administrator decision.

    Whether a held email may be approved at all is decided by the gateway's
    revalidation in Stage 9, not here.
    """
    updates: dict = {"delivery_status": delivery_status}
    if rule is not None:
        updates["rule"] = rule
    with app_connection() as connection:
        _apply_updates(
            connection, "simulated_emails", "id", email_id, updates, _EMAIL_MUTABLE
        )
    return get_simulated_email(email_id)


# ---------------------------------------------------------------------------
# test_runs and test_results
# ---------------------------------------------------------------------------


def create_test_run(
    agent_mode: str,
    protection_mode: str,
    demo_run_id: str | None = None,
    model_id: str | None = None,
    sdk_version: str | None = None,
    repeats: int = 1,
    notes: str | None = None,
) -> TestRun:
    run = TestRun(
        run_id=new_id(),
        demo_run_id=demo_run_id,
        agent_mode=agent_mode,
        protection_mode=protection_mode,
        model_id=model_id,
        sdk_version=sdk_version,
        repeats=repeats,
        started_at=utc_now(),
        notes=notes,
    )
    with app_connection() as connection:
        connection.execute(
            "INSERT INTO test_runs ("
            "run_id, demo_run_id, agent_mode, protection_mode, model_id, "
            "sdk_version, repeats, started_at, finished_at, notes"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run.run_id,
                run.demo_run_id,
                run.agent_mode,
                run.protection_mode,
                run.model_id,
                run.sdk_version,
                run.repeats,
                run.started_at,
                run.finished_at,
                run.notes,
            ),
        )
    return run


def get_test_run(run_id: str) -> TestRun | None:
    with app_connection() as connection:
        return _one(
            connection, "SELECT * FROM test_runs WHERE run_id = ?", (run_id,), TestRun
        )


def list_test_runs() -> list[TestRun]:
    with app_connection() as connection:
        return _many(
            connection,
            "SELECT * FROM test_runs ORDER BY started_at DESC, rowid DESC",
            (),
            TestRun,
        )


def finish_test_run(run_id: str, notes: str | None = None) -> TestRun | None:
    updates: dict = {"finished_at": utc_now()}
    if notes is not None:
        updates["notes"] = notes
    with app_connection() as connection:
        _apply_updates(
            connection,
            "test_runs",
            "run_id",
            run_id,
            updates,
            frozenset({"finished_at", "notes"}),
        )
    return get_test_run(run_id)


def get_latest_test_run() -> TestRun | None:
    """The newest finished suite run, falling back to the newest started."""
    with app_connection() as connection:
        finished = _one(
            connection,
            "SELECT * FROM test_runs WHERE finished_at IS NOT NULL "
            "ORDER BY finished_at DESC, rowid DESC LIMIT 1",
            (),
            TestRun,
        )
        if finished:
            return finished
        return _one(
            connection,
            "SELECT * FROM test_runs ORDER BY started_at DESC, rowid DESC LIMIT 1",
            (),
            TestRun,
        )


def create_test_result(
    run_id: str,
    scenario_id: str,
    scenario_type: str,
    category: str,
    repeat_index: int = 0,
    expected: str | None = None,
    outcome: str | None = None,
    caught_at: str | None = None,
    unauthorised_disclosure: bool = False,
    canary_exposure: bool = False,
    forbidden_access: bool = False,
    false_hold: bool = False,
    task_failed: bool = False,
    model_refused: bool = False,
    details: str | None = None,
    duration_ms: int | None = None,
) -> TestResult:
    with app_connection() as connection:
        cursor = connection.execute(
            "INSERT INTO test_results ("
            "run_id, scenario_id, scenario_type, category, repeat_index, "
            "expected, outcome, caught_at, unauthorised_disclosure, "
            "canary_exposure, forbidden_access, false_hold, task_failed, "
            "model_refused, details, duration_ms, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                scenario_id,
                scenario_type,
                category,
                repeat_index,
                expected,
                outcome,
                caught_at,
                1 if unauthorised_disclosure else 0,
                1 if canary_exposure else 0,
                1 if forbidden_access else 0,
                1 if false_hold else 0,
                1 if task_failed else 0,
                1 if model_refused else 0,
                details,
                duration_ms,
                utc_now(),
            ),
        )
        result_id = int(cursor.lastrowid)
    with app_connection() as connection:
        result = _one(
            connection,
            "SELECT * FROM test_results WHERE id = ?",
            (result_id,),
            TestResult,
        )
    if result is None:
        raise RuntimeError("test result insert did not persist")
    return result


def list_test_results(run_id: str) -> list[TestResult]:
    with app_connection() as connection:
        return _many(
            connection,
            "SELECT * FROM test_results WHERE run_id = ? ORDER BY id ASC",
            (run_id,),
            TestResult,
        )


# ---------------------------------------------------------------------------
# canaries (vault/registry.db)
#
# Every function below is caller-restricted to the seeder and the detector.
# ---------------------------------------------------------------------------


def create_canary(
    canary_type: str,
    location: str,
    strong_values: list[str],
    weak_values: list[str],
    record_ref: str | None = None,
    canary_id: str | None = None,
) -> Canary:
    canary = Canary(
        id=canary_id or new_id(),
        canary_type=canary_type,
        location=location,
        record_ref=record_ref,
        strong_values_json=json.dumps(strong_values),
        weak_values_json=json.dumps(weak_values),
        status="active",
        created_at=utc_now(),
    )
    with registry_connection() as connection:
        connection.execute(
            "INSERT INTO canaries ("
            "id, canary_type, location, record_ref, strong_values_json, "
            "weak_values_json, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                canary.id,
                canary.canary_type,
                canary.location,
                canary.record_ref,
                canary.strong_values_json,
                canary.weak_values_json,
                canary.status,
                canary.created_at,
            ),
        )
    return canary


def get_canary(canary_id: str) -> Canary | None:
    with registry_connection() as connection:
        return _one(
            connection, "SELECT * FROM canaries WHERE id = ?", (canary_id,), Canary
        )


def list_canaries(status: str | None = None) -> list[Canary]:
    with registry_connection() as connection:
        if status is None:
            return _many(
                connection, "SELECT * FROM canaries ORDER BY created_at ASC", (), Canary
            )
        return _many(
            connection,
            "SELECT * FROM canaries WHERE status = ? ORDER BY created_at ASC",
            (status,),
            Canary,
        )


def update_canary_status(canary_id: str, status: str) -> Canary | None:
    with registry_connection() as connection:
        _apply_updates(
            connection,
            "canaries",
            "id",
            canary_id,
            {"status": status},
            frozenset({"status"}),
        )
    return get_canary(canary_id)


def delete_canary(canary_id: str) -> None:
    """Remove a registry row outright, used when unseeding."""
    with registry_connection() as connection:
        connection.execute("DELETE FROM canaries WHERE id = ?", (canary_id,))


def delete_all_canaries() -> int:
    """Clear the registry, returning how many rows were removed."""
    with registry_connection() as connection:
        cursor = connection.execute("DELETE FROM canaries")
        return int(cursor.rowcount)
