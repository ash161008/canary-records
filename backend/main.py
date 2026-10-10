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

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend import __version__, config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("canary_records")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Log what the process is running, without any secret values."""
    logger.info(
        "Canary Records %s starting (demo_mode=%s, claude_configured=%s)",
        __version__,
        config.DEMO_MODE,
        config.has_claude_credentials(),
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
