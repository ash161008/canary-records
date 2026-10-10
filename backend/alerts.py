"""Administrator alerts and the beacon simulation (Stage 14).

Builds plain-English alerts from backend events for the simulated
administrator panel: what was attempted, which file a decoy came from, the
session status and the available admin actions - never file contents. An
optional Telegram relay sends the same text when configured; failures are
logged and the in-app alert still stands.
"""
