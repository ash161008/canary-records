"""Pydantic models and the value vocabularies stored in the database.

Shapes for rows and API payloads. Validation here is about well formed data;
authority over whether an action happens belongs to backend/gateway.py alone.

Every timestamp is a UTC ISO 8601 string produced by database.utc_now().
"""

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict

# ---------------------------------------------------------------------------
# Value vocabularies. These are mirrored by CHECK constraints in the schema,
# so an invalid value is rejected by SQLite as well as by Pydantic.
# ---------------------------------------------------------------------------

AgentMode = Literal["claude", "worst_case", "scripted_normal"]
ProtectionMode = Literal["protect", "outbound_only", "monitor"]
SessionStatus = Literal["active", "paused", "terminated", "completed"]
DeliveryStatus = Literal["simulated_sent", "blocked", "held", "approved_sent", "denied"]
AlertStatus = Literal["open", "resolved"]
Severity = Literal["info", "warning", "critical"]
CanaryType = Literal["customer", "salary", "credential", "trade_secret"]
CanaryStatus = Literal["active", "removed"]
ScenarioType = Literal["attack", "normal"]
ScenarioCategory = Literal["bulk", "targeted", "normal"]
CaughtAt = Literal[
    "role", "read_quarantine", "outbound_block", "outbound_hold", "none"
]

ROLE_SUPPORT_AGENT = "support_agent"


class _Row(BaseModel):
    """Base for models built from a sqlite3.Row."""

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# data/app.db
# ---------------------------------------------------------------------------


class DemoRun(_Row):
    run_id: str
    started_at: str
    ended_at: str | None = None
    notes: str | None = None


class AgentSession(_Row):
    session_id: str
    run_id: str
    agent_mode: AgentMode
    role: str = ROLE_SUPPORT_AGENT
    hr_access: int = 0
    protection_mode: ProtectionMode
    status: SessionStatus = "active"
    tainted: int = 0
    personal_items_sent_external: int = 0
    task_context_json: str | None = None
    conversation_state_json: str | None = None
    created_at: str
    ended_at: str | None = None

    def task_context(self) -> dict:
        """The authorised requester and recipients for this task, as set by
        the backend from the inbox item. Never inferred from the agent."""
        return json.loads(self.task_context_json) if self.task_context_json else {}

    def conversation_state(self) -> dict:
        """Saved agent conversation, used to resume a paused session."""
        if not self.conversation_state_json:
            return {}
        return json.loads(self.conversation_state_json)


class AuditEvent(_Row):
    id: int
    run_id: str
    session_id: str | None = None
    event_type: str
    tool: str | None = None
    resource: str | None = None
    decision: str | None = None
    rule: str | None = None
    reason: str | None = None
    canary_ids: str | None = None
    created_at: str
    previous_hash: str
    event_hash: str


class Alert(_Row):
    id: int
    run_id: str
    session_id: str | None = None
    severity: Severity
    title: str
    message: str
    canary_ids: str | None = None
    status: AlertStatus = "open"
    created_at: str


class SimulatedEmail(_Row):
    """An outgoing message. Nothing here is ever delivered to a real
    recipient; the row and its delivery_status are the whole of the send."""

    id: int
    run_id: str
    session_id: str | None = None
    recipient: str
    subject: str
    body: str
    delivery_status: DeliveryStatus
    rule: str | None = None
    hard_deny: int = 0
    created_at: str


class TestRun(_Row):
    """One execution of the scenario suite.

    run_id identifies the suite run; demo_run_id links it to the demo run
    whose audit evidence it produced.
    """

    run_id: str
    demo_run_id: str | None = None
    agent_mode: AgentMode
    protection_mode: ProtectionMode
    model_id: str | None = None
    sdk_version: str | None = None
    repeats: int = 1
    started_at: str
    finished_at: str | None = None
    notes: str | None = None


class TestResult(_Row):
    id: int
    run_id: str
    scenario_id: str
    scenario_type: ScenarioType
    category: ScenarioCategory
    repeat_index: int = 0
    expected: str | None = None
    outcome: str | None = None
    caught_at: CaughtAt | None = None
    unauthorised_disclosure: int = 0
    canary_exposure: int = 0
    forbidden_access: int = 0
    attempted_by_model: int = 0
    false_hold: int = 0
    task_failed: int = 0
    model_refused: int = 0
    details: str | None = None
    duration_ms: int | None = None
    created_at: str


# ---------------------------------------------------------------------------
# vault/registry.db
# ---------------------------------------------------------------------------


class Canary(_Row):
    """A registered decoy record.

    Nothing in the workspace marks a decoy; this registry row is the only
    record that a given value is one. Reachable through backend/seeder.py and
    backend/detector.py only.
    """

    id: str
    canary_type: CanaryType
    location: str
    record_ref: str | None = None
    strong_values_json: str
    weak_values_json: str
    status: CanaryStatus = "active"
    created_at: str

    def strong_values(self) -> list[str]:
        """Values unique to this decoy: email, phone, staff id, API key,
        contract number."""
        return json.loads(self.strong_values_json)

    def weak_values(self) -> list[str]:
        """Values this decoy shares in style with real records: name,
        address, postal code, salary amount."""
        return json.loads(self.weak_values_json)
