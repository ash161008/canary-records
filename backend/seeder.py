"""Canary (decoy record) seeder.

Stage 5 adds the planting itself: 20 unlabelled decoys written into the
synthetic workspace, and an unseed() that restores the original files exactly.

What exists now is this module's half of the registry boundary. Only this
module and backend/detector.py may reach vault/registry.db, so every write to
the canary registry goes through the functions below; backend/database.py
refuses the call from anywhere else.
"""

import logging

from backend import database
from backend.models import Canary

logger = logging.getLogger(__name__)


def init_registry() -> None:
    """Create vault/registry.db and its canaries table if absent."""
    database.init_registry_db()


def register_canary(
    canary_type: str,
    location: str,
    strong_values: list[str],
    weak_values: list[str],
    record_ref: str | None = None,
    canary_id: str | None = None,
) -> Canary:
    """Record a planted decoy.

    strong_values are unique to the decoy (email, phone, staff id, API key,
    contract number); weak_values are the ones it shares in style with real
    records (name, address, postal code, salary amount).
    """
    canary = database.create_canary(
        canary_type=canary_type,
        location=location,
        strong_values=strong_values,
        weak_values=weak_values,
        record_ref=record_ref,
        canary_id=canary_id,
    )
    logger.info(
        "canary %s registered (type=%s, location=%s)",
        canary.id,
        canary.canary_type,
        canary.location,
    )
    return canary


def get_registered_canary(canary_id: str) -> Canary | None:
    return database.get_canary(canary_id)


def list_registered_canaries(status: str | None = None) -> list[Canary]:
    """The administrator's decoy map. Never exposed to an agent tool."""
    return database.list_canaries(status=status)


def set_canary_status(canary_id: str, status: str) -> Canary | None:
    return database.update_canary_status(canary_id, status)


def remove_canary(canary_id: str) -> None:
    database.delete_canary(canary_id)


def clear_registry() -> int:
    """Remove every registry row, returning how many were removed."""
    removed = database.delete_all_canaries()
    logger.info("canary registry cleared (%d rows)", removed)
    return removed
