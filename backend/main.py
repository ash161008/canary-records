"""FastAPI application: serves the Canary Records frontend and API.

One app serves both the static frontend and the JSON API from the same
origin, so the browser makes no cross-origin requests and no CORS
configuration is needed.

Stage 2 provides the skeleton and GET /api/health. The security system, the
agent endpoints and the admin surface are added in later stages.
"""

import logging
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from backend import (
    __version__,
    agent_claude,
    alerts,
    agent_scripted,
    audit,
    config,
    database,
    scenarios,
    seeder,
    sessions,
)
from backend.models import AgentMode, ProtectionMode

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("canary_records")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Prepare the data layer and log what the process is running.

    Initialisation is idempotent, so a restart neither loses nor duplicates
    anything. The canary registry is not touched here: only the seeder and
    the detector may open it.
    """
    database.init_app_db()
    run = database.get_or_create_active_demo_run()
    logger.info(
        "Canary Records %s starting (demo_mode=%s, claude_configured=%s, run=%s)",
        __version__,
        config.DEMO_MODE,
        config.has_claude_credentials(),
        run.run_id,
    )
    yield
    logger.info("Canary Records shutting down")


app = FastAPI(
    title="Canary Records",
    description=(
        "Security gateway for AI agents working with confidential small-business "
        "data. All data in this application is synthetic."
    ),
    version=__version__,
    lifespan=lifespan,
)


def require_admin(x_admin_token: str | None = Header(default=None)) -> None:
    """Require the administrator token on an admin endpoint.

    Fails closed: if ADMIN_TOKEN is not configured, no admin endpoint works.
    The token is compared with ``secrets.compare_digest`` and is never
    returned, logged or echoed in an error. Stage 9 applies this to the rest
    of the admin surface.
    """
    expected = config.ADMIN_TOKEN
    if not expected:
        raise HTTPException(
            status_code=503,
            detail=(
                "Administrator actions are unavailable: ADMIN_TOKEN is not "
                "configured on the server."
            ),
        )
    if not x_admin_token or not secrets.compare_digest(x_admin_token, expected):
        raise HTTPException(
            status_code=401, detail="A valid administrator token is required."
        )


@app.get("/api/health")
def health() -> dict:
    """Liveness check. Reports no configuration values and no secrets."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Workspace administration
#
# These are administrator endpoints, not agent tools. They are not in the
# gateway's tool list, so no agent can reach seeding, unseeding or the decoy
# map however it is prompted. The X-Admin-Token requirement is added in
# Stage 9 along with the rest of the admin surface.
# ---------------------------------------------------------------------------


@app.post("/api/workspace/seed", dependencies=[Depends(require_admin)])
def seed_workspace() -> dict:
    """Plant the decoy records. Idempotent: seeding twice changes nothing."""
    try:
        return seeder.seed()
    except Exception:
        logger.exception("seeding failed")
        raise HTTPException(status_code=500, detail="Seeding failed; see server log.")


@app.post("/api/workspace/unseed", dependencies=[Depends(require_admin)])
def unseed_workspace() -> dict:
    """Remove every planted decoy and restore the original files."""
    try:
        return seeder.unseed()
    except Exception:
        logger.exception("unseeding failed")
        raise HTTPException(status_code=500, detail="Unseeding failed; see server log.")


@app.get("/api/workspace")
def workspace_state() -> dict:
    """Counts per location, and whether decoys are currently planted.

    Open, because it returns counts and nothing else: no personal data and no
    record contents. The per-location breakdown of *which* files hold decoys
    is removed here - that is the decoy map in miniature, and it belongs with
    the rest of it behind the admin token on GET /api/canaries.
    """
    try:
        state = seeder.summary()
    except Exception:
        logger.exception("reading workspace state failed")
        raise HTTPException(
            status_code=500, detail="Could not read the workspace; see server log."
        )
    state.pop("canaries_per_location", None)
    return state


@app.get("/api/canaries", dependencies=[Depends(require_admin)])
def list_canaries() -> dict:
    """The administrator's decoy map. Never exposed to an agent."""
    try:
        canaries = seeder.decoy_map()
    except Exception:
        logger.exception("reading the decoy map failed")
        raise HTTPException(
            status_code=500, detail="Could not read the decoy map; see server log."
        )
    return {"count": len(canaries), "canaries": canaries}


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def _resolve_run_id(run_id: str | None) -> str:
    """The run being asked about, defaulting to the current one."""
    if run_id:
        return run_id
    return database.get_or_create_active_demo_run().run_id


@app.get("/api/audit", dependencies=[Depends(require_admin)])
def get_audit(run_id: str | None = None, session_id: str | None = None) -> dict:
    """The audit log for one run, oldest first.

    Returns stored decisions and references only. File contents are never in
    the log, so they cannot be read back out of it.
    """
    resolved = _resolve_run_id(run_id)
    events = audit.list_audit_events(run_id=resolved, session_id=session_id)

    return {
        "run_id": resolved,
        "count": len(events),
        "events": [event.model_dump() for event in events],
    }


@app.post("/api/audit/verify")
def verify_audit(run_id: str | None = None) -> dict:
    """Verify a run's chain, reporting the first entry that fails.

    Deliberately open. A log that only its administrator can verify is a
    weaker guarantee than one anybody can check: the point of the chain is
    that tampering is detectable by someone who does not have to be trusted.
    Verification returns a validity flag, a count and an entry id - no
    personal data, no references and no log contents - so reading the log
    still needs the token even though checking it does not.
    """
    resolved = _resolve_run_id(run_id)
    result = audit.verify_audit_chain(resolved)
    return {"run_id": resolved, **result}


if config.DEMO_MODE:

    @app.post("/api/audit/tamper", dependencies=[Depends(require_admin)])
    def tamper_audit(run_id: str | None = None) -> dict:
        """Edit the oldest entry of a run, to show that it is detected.

        Present only when DEMO_MODE=1, and requires the administrator token.
        """
        resolved = _resolve_run_id(run_id)
        try:
            return audit.tamper_with_oldest_event_for_demo(resolved)
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error))


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> FileResponse:
    """The site icon.

    Declared in the page as an SVG, and served here as well because some
    browsers request /favicon.ico regardless - which would be a 404 in the
    console during a demo.
    """
    return FileResponse(
        config.FRONTEND_DIR / "favicon.svg", media_type="image/svg+xml"
    )


@app.get("/")
def index() -> FileResponse:
    """Serve the single-page frontend."""
    return FileResponse(config.FRONTEND_DIR / "index.html")


# Static assets are mounted after the routes above so /api and / keep
# precedence over file lookups.
app.mount(
    "/static",
    StaticFiles(directory=config.FRONTEND_DIR),
    name="static",
)


# ---------------------------------------------------------------------------
# Sessions and administrator controls
#
# An agent never reaches any of this. Agents run in-process against
# CanaryGateway.execute(); they make no HTTP request, see no admin endpoint
# and never hold the admin token.
# ---------------------------------------------------------------------------


class CreateSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_mode: AgentMode
    protection_mode: ProtectionMode
    inbox_id: str = Field(min_length=1, max_length=80)


class HrAccessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool


def _session_error(error: Exception) -> HTTPException:
    """Map a session error onto its status code.

    An invalid transition is a 409: the request was well formed, the session
    is simply not in a state where it makes sense.
    """
    if isinstance(error, sessions.InvalidTransition):
        return HTTPException(status_code=409, detail=str(error))
    if isinstance(error, sessions.ApprovalRefused):
        return HTTPException(status_code=409, detail=str(error))
    return HTTPException(status_code=404, detail=str(error))


@app.post("/api/sessions")
def create_session(request: CreateSessionRequest) -> dict:
    """Start a session for one inbox item.

    The protection mode is fixed here. To compare modes, create another
    session.
    """
    try:
        session = sessions.create_agent_session(
            agent_mode=request.agent_mode,
            protection_mode=request.protection_mode,
            inbox_id=request.inbox_id,
        )
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))
    except Exception:
        logger.exception("creating a session failed")
        raise HTTPException(
            status_code=500, detail="Could not create the session; see server log."
        )
    return sessions.describe(session.session_id)


@app.get("/api/sessions/{session_id}", dependencies=[Depends(require_admin)])
def get_session(session_id: str) -> dict:
    """One session's state.

    Admin-only: the task context names the customer's address on file, which
    is a record value rather than a count.
    """
    try:
        return sessions.describe(session_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))


@app.post("/api/sessions/{session_id}/stop", dependencies=[Depends(require_admin)])
def stop_session(session_id: str) -> dict:
    try:
        return sessions.stop(session_id)
    except (sessions.SessionError, ValueError) as error:
        raise _session_error(error)


@app.post("/api/sessions/{session_id}/continue", dependencies=[Depends(require_admin)])
def continue_session(session_id: str) -> dict:
    """Resume a paused session without releasing the withheld content."""
    try:
        return sessions.resume(session_id)
    except (sessions.SessionError, ValueError) as error:
        raise _session_error(error)


@app.post("/api/sessions/{session_id}/hr-access", dependencies=[Depends(require_admin)])
def set_session_hr_access(session_id: str, request: HrAccessRequest) -> dict:
    try:
        return sessions.set_hr_access(session_id, request.enabled)
    except (sessions.SessionError, ValueError) as error:
        raise _session_error(error)


@app.get("/api/emails/held", dependencies=[Depends(require_admin)])
def get_held_emails(run_id: str | None = None) -> dict:
    """Messages waiting for review, with whether each may be approved."""
    held = sessions.list_held(run_id=run_id)
    return {"count": len(held), "emails": held}


@app.post("/api/emails/{email_id}/approve", dependencies=[Depends(require_admin)])
def approve_email(email_id: int) -> dict:
    """Approve a held message. The gateway revalidates it first."""
    try:
        return sessions.approve_email(email_id)
    except (sessions.SessionError, ValueError) as error:
        raise _session_error(error)


@app.post("/api/emails/{email_id}/deny", dependencies=[Depends(require_admin)])
def deny_email(email_id: int) -> dict:
    try:
        return sessions.deny_email(email_id)
    except (sessions.SessionError, ValueError) as error:
        raise _session_error(error)


# ---------------------------------------------------------------------------
# Agent runs
# ---------------------------------------------------------------------------


class RunScriptedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1, max_length=40)
    protection_mode: ProtectionMode


@app.post("/api/run/scripted")
def run_scripted(request: RunScriptedRequest) -> dict:
    """Replay a scenario's intended tool calls through the gateway.

    This is the worst-case agent, labelled "Worst-case (scripted)" wherever it
    is shown. It is not the demo agent: it replays an attacker's script with
    no judgement of its own, so whatever the run fails to achieve was stopped
    by the gateway rather than declined by a model.
    """
    try:
        scenario = _find_scenario(request.scenario_id)
        session = agent_scripted.session_for_scenario(
            scenario, request.protection_mode
        )
        outcome = agent_scripted.run_scripted(
            session.session_id, scenario["intended_tool_calls"]
        )
        outcome["scenario_id"] = scenario["id"]
        outcome["scenario_type"] = scenario["scenario_type"]
        outcome["category"] = scenario["category"]
        outcome["expected_protect_outcome"] = scenario.get("expected_protect_outcome")
        return outcome
    except scenarios.ScenarioError as error:
        raise HTTPException(status_code=404, detail=str(error))
    except Exception:
        logger.exception("scripted run failed")
        raise HTTPException(
            status_code=500, detail="The scripted run failed; see server log."
        )


class RunClaudeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # One or the other. An inbox item is the ordinary demo path; a scenario id
    # runs one entry from the suite, which is how the live demo drives the
    # harder injection scenes.
    inbox_id: str | None = Field(default=None, min_length=1, max_length=80)
    scenario_id: str | None = Field(default=None, min_length=1, max_length=40)
    protection_mode: ProtectionMode


@app.post("/api/run/claude", dependencies=[Depends(require_admin)])
def run_claude(request: RunClaudeRequest) -> dict:
    """Run the Claude agent once against one inbox item.

    The inbox item is loaded by the backend, not named by the model. Every
    tool the model asks for is executed by the gateway.

    Admin-only, because every call to it spends money with the model
    provider. Left open, anyone who could reach the loopback port could run
    up a bill; the scripted agent stays open because it is free.
    """
    if bool(request.inbox_id) == bool(request.scenario_id):
        raise HTTPException(
            status_code=422,
            detail="Give exactly one of inbox_id or scenario_id.",
        )

    try:
        if request.scenario_id:
            scenario = _find_scenario(request.scenario_id)
            return agent_claude.run_claude_for_scenario(
                scenario, protection_mode=request.protection_mode
            )
        return agent_claude.run_claude(
            inbox_id=request.inbox_id,
            protection_mode=request.protection_mode,
        )
    except scenarios.ScenarioError as error:
        raise HTTPException(status_code=404, detail=str(error))
    except agent_claude.ClaudeNotConfigured as error:
        raise HTTPException(status_code=503, detail=str(error))
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))
    except Exception:
        logger.exception("Claude run failed")
        raise HTTPException(
            status_code=500, detail="The agent run failed; see server log."
        )


@app.post(
    "/api/run/claude/{session_id}/resume",
    dependencies=[Depends(require_admin)],
)
def resume_claude(session_id: str) -> dict:
    """Carry on a session an administrator has continued.

    The pending tool call is answered with the refusal. The withheld content
    is not in the saved state, so there is nothing to release.
    """
    try:
        return agent_claude.resume_claude(session_id)
    except agent_claude.ClaudeNotConfigured as error:
        raise HTTPException(status_code=503, detail=str(error))
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error))


# ---------------------------------------------------------------------------
# The scenario suite
# ---------------------------------------------------------------------------


class SuiteRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Defaults to the free, deterministic half of the matrix. Running Claude
    # costs money per scenario, so it has to be asked for explicitly and is
    # never triggered by loading a page.
    agent_mode: AgentMode = "worst_case"
    protection_modes: list[ProtectionMode] | None = None
    repeats: int = Field(default=1, ge=1, le=5)
    scenario_ids: list[str] | None = None


@app.post("/api/suite/run", dependencies=[Depends(require_admin)])
def run_suite(request: SuiteRunRequest) -> dict:
    """Run the scenario suite for one agent across one or more modes."""
    if request.protection_modes:
        modes = list(request.protection_modes)
    elif request.agent_mode == "claude":
        modes = [mode for _, mode in scenarios.CLAUDE_MATRIX]
    else:
        modes = [mode for _, mode in scenarios.WORST_CASE_MATRIX]

    repeats = request.repeats
    if request.agent_mode == "claude" and repeats == 1:
        repeats = scenarios.CLAUDE_REPEATS

    boards = []
    for mode in modes:
        boards.append(
            scenarios.run_suite(
                agent_mode=request.agent_mode,
                protection_mode=mode,
                repeats=repeats,
                scenario_ids=request.scenario_ids,
            )
        )
    return {"count": len(boards), "scoreboards": boards}


@app.get("/api/suite/latest")
def latest_suite() -> dict:
    """The most recent suite results.

    Reading this never runs anything: a Claude suite costs money, so it is
    started only by an explicit admin request.
    """
    board = scenarios.latest_scoreboard()
    return {
        "has_results": board is not None,
        "latest": board,
        "all": scenarios.all_scoreboards(),
    }


# ---------------------------------------------------------------------------
# What the interface needs to drive a run
# ---------------------------------------------------------------------------


def _find_scenario(scenario_id: str) -> dict:
    """One scenario from the measured suite or the extra probes."""
    for scenario in scenarios.load_all() + scenarios.load_file(
        scenarios.HARD_INJECTIONS_FILE
    ):
        if scenario["id"] == scenario_id:
            return scenario
    raise scenarios.ScenarioError(f"No such scenario: {scenario_id!r}")


@app.get("/api/inbox")
def get_inbox() -> dict:
    """The inbox items a run can be started from.

    The raw body is included, hidden HTML and all: the interface shows the
    message as a reader would see it and can reveal the hidden parts on
    request. Revealing them changes presentation only.
    """
    try:
        items = sessions.list_inbox()
    except Exception:
        logger.exception("reading the inbox failed")
        raise HTTPException(
            status_code=500, detail="Could not read the inbox; see server log."
        )
    return {"count": len(items), "items": items}


@app.get("/api/scenarios")
def get_scenarios() -> dict:
    """Every scenario a run can be started from, grouped by source."""
    suite = scenarios.list_scenarios()
    try:
        extra = scenarios.load_file(scenarios.HARD_INJECTIONS_FILE)
    except scenarios.ScenarioError:
        extra = []

    return {
        "suite": suite,
        "probes": [
            {
                "id": item["id"],
                "scenario_type": item["scenario_type"],
                "category": item["category"],
                "from": item["from"],
                "subject": item["subject"],
                "expected_protect_outcome": item["expected_protect_outcome"],
                "intended_tool_call_count": len(item["intended_tool_calls"]),
            }
            for item in extra
        ],
    }


@app.get("/api/scenarios/{scenario_id}")
def get_scenario(scenario_id: str) -> dict:
    """One scenario in full, including its raw body, for display."""
    try:
        scenario = _find_scenario(scenario_id)
    except scenarios.ScenarioError as error:
        raise HTTPException(status_code=404, detail=str(error))
    return scenario


@app.get("/api/alerts")
def get_alerts(run_id: str | None = None, status: str | None = None) -> dict:
    """Administrator alerts, newest first.

    Alerts are built by the backend from what actually happened. They name
    files and decisions, never file contents.
    """
    resolved = _resolve_run_id(run_id)
    listed = alerts.list_alerts(run_id=resolved, status=status)
    return {"run_id": resolved, "count": len(listed), "alerts": listed}


@app.get("/api/emails", dependencies=[Depends(require_admin)])
def get_emails(
    run_id: str | None = None,
    session_id: str | None = None,
    external_only: bool = False,
    limit: int = 20,
) -> dict:
    """Simulated messages, newest first.

    Admin-only: a message body is record data. A held message keeps its body
    verbatim so it can be reviewed, and a sent one carries whatever was sent,
    so this returns personal data in a way the audit log deliberately does
    not.

    ``external_only`` keeps just those addressed outside the company, which is
    what the attacker outbox shows. ``session_id`` narrows it to one run of
    one agent, which is what that panel wants: a demo run accumulates every
    session's attempts, and showing all of them made the page grow without
    bound.

    The counts are worked out here so the interface can say how much it is not
    showing without doing arithmetic of its own.
    """
    resolved = _resolve_run_id(run_id)
    capped = max(1, min(limit, 200))

    in_run = database.list_simulated_emails(run_id=resolved)
    if external_only:
        in_run = [
            email
            for email in in_run
            if not config.is_internal_recipient(email.recipient)
        ]

    in_scope = (
        [email for email in in_run if email.session_id == session_id]
        if session_id
        else in_run
    )
    shown = in_scope[:capped]

    return {
        "run_id": resolved,
        "session_id": session_id,
        "count": len(shown),
        "total_in_scope": len(in_scope),
        "total_in_run": len(in_run),
        # Attempts from this run that this panel is not showing, because they
        # belong to earlier sessions.
        "earlier_in_run": len(in_run) - len(in_scope),
        "truncated": len(in_scope) > len(shown),
        "limit": capped,
        "emails": [
            {
                **email.model_dump(),
                "internal": config.is_internal_recipient(email.recipient),
            }
            for email in shown
        ],
    }


@app.get("/api/runs")
def get_runs() -> dict:
    """Every demo run, newest first, so earlier evidence stays reachable."""
    runs = database.list_demo_runs()
    current = database.get_active_demo_run()
    return {
        "current_run_id": current.run_id if current else None,
        "count": len(runs),
        "runs": [
            {
                **run.model_dump(),
                "session_count": len(database.list_sessions(run_id=run.run_id)),
                "event_count": len(database.list_audit_events(run_id=run.run_id)),
            }
            for run in runs
        ],
    }


@app.get("/api/agents")
def get_agents() -> dict:
    """The agents a run can be started with, and how each is named.

    The interface renders these names rather than spelling its own, so the
    scripted stress-test agent can never be presented as the demo agent.
    """
    return {
        "selectable": [
            {"agent_mode": mode, "agent_label": config.agent_label(mode)}
            for mode in ("claude", "worst_case")
        ],
        "labels": dict(config.AGENT_LABELS),
    }


@app.post("/api/alerts/{alert_id}/resolve", dependencies=[Depends(require_admin)])
def resolve_alert(alert_id: int) -> dict:
    """Mark an alert dealt with. The alert is never deleted."""
    try:
        return alerts.resolve(alert_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))


@app.post("/api/reset", dependencies=[Depends(require_admin)])
def reset_demo() -> dict:
    """Start a new demo run.

    Restores the workspace, removes the decoys, finalises the old run's open
    business and opens a fresh audit chain. Earlier runs are kept and stay
    attributable; no database and no source file is ever deleted.
    """
    try:
        return alerts.reset_demo()
    except Exception:
        logger.exception("reset failed")
        raise HTTPException(status_code=500, detail="The reset failed; see server log.")


if config.DEMO_MODE:

    @app.post("/api/beacon/{canary_id}", dependencies=[Depends(require_admin)])
    def simulate_beacon(canary_id: str) -> dict:
        """Simulate someone outside the company contacting a decoy.

        Present only when DEMO_MODE=1. Nothing touches the network; the alert
        says plainly that the contact is simulated.
        """
        try:
            return alerts.simulate_beacon(canary_id)
        except ValueError as error:
            raise HTTPException(status_code=404, detail=str(error))
