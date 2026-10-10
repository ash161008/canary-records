"""FastAPI application: serves the Canary Records frontend and API.

One app serves both the static frontend and the JSON API from the same
origin, so the browser makes no cross-origin requests and no CORS
configuration is needed.

Stage 2 provides the skeleton and GET /api/health. The security system, the
agent endpoints and the admin surface are added in later stages.
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend import __version__, config, database, seeder

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


@app.post("/api/workspace/seed")
def seed_workspace() -> dict:
    """Plant the decoy records. Idempotent: seeding twice changes nothing."""
    try:
        return seeder.seed()
    except Exception:
        logger.exception("seeding failed")
        raise HTTPException(status_code=500, detail="Seeding failed; see server log.")


@app.post("/api/workspace/unseed")
def unseed_workspace() -> dict:
    """Remove every planted decoy and restore the original files."""
    try:
        return seeder.unseed()
    except Exception:
        logger.exception("unseeding failed")
        raise HTTPException(status_code=500, detail="Unseeding failed; see server log.")


@app.get("/api/workspace")
def workspace_state() -> dict:
    """Counts per location, and whether decoys are currently planted."""
    try:
        return seeder.summary()
    except Exception:
        logger.exception("reading workspace state failed")
        raise HTTPException(
            status_code=500, detail="Could not read the workspace; see server log."
        )


@app.get("/api/canaries")
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
