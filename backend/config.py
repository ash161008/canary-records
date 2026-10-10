"""Configuration and filesystem layout for Canary Records.

Reads settings from the environment (optionally via a .env file) and defines
the directory layout. Role permissions and the outbound limits that the
gateway enforces are added in Stage 8; this module holds no security
decisions yet.

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

# Server. Bound to loopback only (hardened further in Stage 9).
HOST = "127.0.0.1"
PORT = int(os.getenv("PORT", "8000"))

# Claude. The model id is never defaulted to a guess: Stage 11 validates
# CLAUDE_MODEL against the live models list before any paid call.
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "")

# Admin surface and demo-only endpoints. Enforcement arrives in Stage 7/9.
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
DEMO_MODE = os.getenv("DEMO_MODE", "1") == "1"

# Optional Telegram alert relay (Stage 14). Absent values disable it.
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")


def has_claude_credentials() -> bool:
    """True when both an API key and a model id are configured."""
    return bool(ANTHROPIC_API_KEY) and bool(CLAUDE_MODEL)
