"""Canary and personal-data detector.

Stage 6 adds the detection itself: type-specific canonicalisation, bounded
decoding of encoded candidates, STRONG/WEAK/NONE canary confidence, personal
item extraction and unique-identifier owner lookup. Pure functions, no network
calls.

What exists now is this module's half of the registry boundary. Only this
module and backend/seeder.py may reach vault/registry.db, so the detector
loads the decoy values it matches against through the functions below;
backend/database.py refuses the call from anywhere else.
"""

import logging

from backend import database
from backend.models import Canary

logger = logging.getLogger(__name__)


def load_active_canaries() -> list[Canary]:
    """Every decoy currently planted in the workspace.

    After an unseed there are none, so previously planted values stop
    matching.
    """
    return database.list_canaries(status="active")


def load_canary(canary_id: str) -> Canary | None:
    """One decoy, used to name the file a leak came from in an alert."""
    return database.get_canary(canary_id)
