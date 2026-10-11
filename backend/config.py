"""Configuration and filesystem layout for Canary Records.

Reads settings from the environment (optionally via a .env file) and defines
the directory layout. The role permissions and outbound limits the gateway
enforces are declared here; this module stores that policy and makes no
decision itself.

Secrets are read here and never logged, never sent to the browser, and never
placed in a model prompt or an audit event.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# Project layout. Resolved from this file so the app runs from any directory.
BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
WORKSPACE_DIR = BASE_DIR / "workspace"
SCENARIOS_DIR = BASE_DIR / "scenarios"

# Databases. vault/ holds the canary registry and must never be reachable
# from a workspace path utility or an agent tool; data/ holds the app database.
VAULT_DIR = BASE_DIR / "vault"
DATA_DIR = BASE_DIR / "data"
REGISTRY_DB = VAULT_DIR / "registry.db"
APP_DB = DATA_DIR / "app.db"

load_dotenv(BASE_DIR / ".env")

# Server. Bound to loopback only.
HOST = "127.0.0.1"
PORT = int(os.getenv("PORT", "8000"))

# Claude. The model id is never defaulted to a guess: CLAUDE_MODEL is
# validated against the live models list before any paid call.
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "")

# Admin surface and demo-only endpoints. Enforced in backend/main.py.
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
DEMO_MODE = os.getenv("DEMO_MODE", "1") == "1"

# Optional Telegram alert relay. Absent values disable it.
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")


# ---------------------------------------------------------------------------
# Security policy
#
# These values are the gateway's policy. They live here, in backend Python,
# and nowhere else: never in a system prompt, never in the frontend.
# ---------------------------------------------------------------------------

INTERNAL_DOMAIN = "limco.example"

# What the support agent's role may reach. Folders are workspace folders.
ROLE_SUPPORT_AGENT = "support_agent"

ROLE_PERMISSIONS = {
    ROLE_SUPPORT_AGENT: {
        # Readable as part of the job.
        "allowed": ("inbox", "customers", "product_docs"),
        # Readable only when an administrator has granted HR access.
        "hr_gated": ("hr",),
        # Never readable, whatever the session's settings say.
        "forbidden": ("it",),
    }
}

# Outbound volume limits. A single message may carry at most this many
# distinct personal items; a session may send at most this many to recipients
# outside the company.
MAX_PERSONAL_ITEMS_PER_MESSAGE = 5
MAX_PERSONAL_ITEMS_PER_SESSION = 10

# search_customers never returns more than this many rows.
MAX_SEARCH_RESULTS = 20


# How each agent is named wherever it is shown. One source, so the scripted
# stress-test agent is never mistaken for the demo agent: a result produced by
# replaying an attacker's script says nothing about how a model behaves.
AGENT_LABELS = {
    "claude": "Claude",
    "worst_case": "Worst-case (scripted)",
    "scripted_normal": "Scripted (normal task)",
}


def agent_label(agent_mode: str) -> str:
    """The display name for an agent mode."""
    return AGENT_LABELS.get(agent_mode, agent_mode)


# What an administrator can do about a session, given its state. Kept here, in
# one place, because three callers need it - the alert panel, and both agents'
# run results - and they must not disagree: if one of them forgets, a paused
# session offers no way out of the pause.
ADMIN_ACTIONS_BY_STATUS = {
    "paused": ("stop", "continue"),
    "active": ("stop",),
    "terminated": (),
    "completed": (),
}


def admin_actions(status: str | None) -> list[str]:
    """The admin actions a session in this state allows."""
    return list(ADMIN_ACTIONS_BY_STATUS.get(status or "", ()))


def role_permissions(role: str) -> dict:
    """The folder permissions for a role.

    An unknown role gets nothing: the default is to deny.
    """
    return ROLE_PERMISSIONS.get(
        role, {"allowed": (), "hr_gated": (), "forbidden": ()}
    )


def is_internal_recipient(recipient: str) -> bool:
    """True when an address belongs to the company itself."""
    return recipient.strip().lower().endswith("@" + INTERNAL_DOMAIN)


def has_claude_credentials() -> bool:
    """True when both an API key and a model id are configured."""
    return bool(ANTHROPIC_API_KEY) and bool(CLAUDE_MODEL)
