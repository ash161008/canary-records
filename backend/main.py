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

from backend import __version__, audit, config, database, seeder, sessions
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


@app.get("/api/sessions/{session_id}")
def get_session(session_id: str) -> dict:
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
