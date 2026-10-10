# Canary Records

A security gateway for AI agents working with confidential small-business data.
Built for Problem Statement 2: Safe AI Agent Environments for Confidential Data.

**All data in this project is synthetic.** See [SYNTHETIC_DATA.md](SYNTHETIC_DATA.md).
Email and administrator alerts are simulated and stored locally in SQLite; nothing
is ever sent to a real recipient.

## The idea

Canary Records plants realistic decoy records ("canaries") into the data of a
fictional company, Lim & Co Trading. An AI customer-service agent can request
tools — reading files, looking up orders and customers, sending email — but every
tool request must pass through one method, `CanaryGateway.execute()`. The gateway
checks role permissions before an action, scans every tool result for canaries
*before the AI sees it*, and inspects every outgoing message before anything
leaves the company.

> The AI may request actions, but only `CanaryGateway.execute()` has authority to
> perform them.

Security decisions live only in backend Python. Nothing is enforced by a system
prompt, and nothing is decided in the browser.

## Status

This repository is being built in stages. **Stage 4 of 18 is complete**: the
project skeleton, the five-screen frontend shell, the health endpoint, the
SQLite data layer, and Lim & Co's synthetic workspace with its safe path
utilities. The decoys, the detector, the gateway, the agents and the scenario
suite are added in later stages, and the sections below will grow with them.
Nothing in this README describes behaviour that does not yet run.

Regenerate the workspace at any time with
`.venv/bin/python scripts/generate_workspace.py` — it is deterministic (seed 42)
and overwrites the tree with identical bytes.

## Requirements

- Python 3.11 or newer (built against 3.11.9)

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env     # then fill in the values
```

## Environment variables

| Variable | Purpose |
| --- | --- |
| `ANTHROPIC_API_KEY` | Claude access. Backend only; never reaches the browser, a prompt, or a log. |
| `CLAUDE_MODEL` | Model id for the Claude agent. Validated against the live models list before any paid call. |
| `ADMIN_TOKEN` | Shared secret for admin endpoints, sent as the `X-Admin-Token` header. |
| `DEMO_MODE` | `1` enables demo-only endpoints (audit tamper, beacon simulation). |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Optional alert mirror. Blank disables it. |

The app runs without any of these set; Claude and the admin surface need theirs.

## Run

```bash
.venv/bin/uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Then open <http://127.0.0.1:8000>. The server binds to loopback only.

## Test

```bash
.venv/bin/pytest -q
```

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Liveness check; returns `{"status": "ok"}`. |
| `GET` | `/` | The five-screen frontend. |

## Project layout

```
frontend/    index.html, styles.css, app.js  - display only, no security logic
backend/     the application; gateway.py is the sole tool-execution authority
workspace/   Lim & Co's synthetic files, the only tree agent tools can reach
vault/        registry.db - the canary registry, unreachable from agent tools
data/         app.db - runs, sessions, audit events, alerts, simulated emails
scenarios/   the measured attack and normal-task suite
tests/       pytest suite
scripts/     generators and the Claude smoke test
docs/        the staged build specification
```

### The registry boundary, and what it is not

`vault/registry.db` holds the only record of which workspace values are decoys.
It is kept outside `workspace/`, and every function that opens it checks its
calling module and raises `PermissionError` unless the caller is
`backend/seeder.py` or `backend/detector.py`. The agent's tools reach the
workspace through path utilities that cannot resolve outside `workspace/`, so
no tool path leads to `vault/` or `data/`.

**This is a code-level boundary, not an OS-level one.** A separate file plus a
caller allowlist stops the agent's tool paths from reaching the registry; it is
not a sandbox, a separate process, a separate privilege domain, or filesystem
permissions. Any backend code could be changed to add itself to that allowlist.
A production version would put the registry behind a separate service with its
own credentials. The full limitations list is written in Stage 17.

### Databases

`data/app.db` holds demo runs, agent sessions, audit events, alerts, simulated
emails and scenario-suite results. Both databases are created on demand and
initialisation is idempotent, so restarting the server neither loses nor
duplicates anything. A session's `protection_mode` is fixed when the session is
created, enforced both by the update helper and by a SQLite trigger that aborts
the write even if raw SQL attempts it; to compare modes, create a new session.

## Team

To be completed before submission.
