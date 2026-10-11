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

This repository is being built in stages. **Stage 11 of 18 is complete**: the
project skeleton, the five-screen frontend shell, the health endpoint, the
SQLite data layer, Lim & Co's synthetic workspace with its safe path utilities,
the decoy seeder, the detector, the tamper-evident audit log, the gateway
itself, sessions with their administrator controls, the scripted agent, and the
Claude agent. The five screens and the scenario suite are added in later
stages, and the sections below will grow with them. Nothing in this README
describes behaviour that does not yet run.

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
| `POST` | `/api/workspace/seed` | Plant the 20 decoys. Idempotent. Admin. |
| `POST` | `/api/workspace/unseed` | Remove every decoy and restore the originals. Admin. |
| `GET` | `/api/workspace` | Record and file counts per location. Open. |
| `GET` | `/api/canaries` | The administrator's decoy map. Admin. |
| `GET` | `/api/audit` | The audit log for a run, oldest first. Admin. |
| `POST` | `/api/audit/verify` | Verify a run's chain; names the first broken entry. Open. |
| `POST` | `/api/audit/tamper` | Edit the oldest entry, to demonstrate detection. Admin, `DEMO_MODE=1` only. |
| `POST` | `/api/sessions` | Start a session for one inbox item. Fixes its protection mode. |
| `GET` | `/api/sessions/{id}` | A session's state. |
| `POST` | `/api/sessions/{id}/stop` | Terminate a session, clearing pending state. Admin. |
| `POST` | `/api/sessions/{id}/continue` | Resume a paused session **without** releasing withheld content. Admin. |
| `POST` | `/api/sessions/{id}/hr-access` | Grant or remove HR access. Admin. |
| `GET` | `/api/emails/held` | Messages waiting for review. Admin. |
| `POST` | `/api/emails/{id}/approve` | Approve a held message; the gateway revalidates first. Admin. |
| `POST` | `/api/emails/{id}/deny` | Deny a held message. Admin. |
| `POST` | `/api/run/scripted` | Replay a scenario's intended tool calls through the gateway. |
| `POST` | `/api/run/claude` | Run the Claude agent once against one inbox item. |
| `POST` | `/api/run/claude/{id}/resume` | Carry on after an administrator's Continue. |

Every admin endpoint requires the `X-Admin-Token` header, compared with
`secrets.compare_digest`, and fails closed with 503 if `ADMIN_TOKEN` is unset
on the server. Open endpoints are `/api/health`, `/`, the static assets,
`POST /api/sessions`, `GET /api/sessions/{id}`, `GET /api/workspace` (counts
only) and `POST /api/audit/verify`. The server binds to loopback only.

Admin endpoints are also not agent tools. An agent never makes an HTTP request
at all: it runs in-process against `CanaryGateway.execute()`, so it cannot see
an admin endpoint, cannot hold the token, and cannot reach seeding, the decoy
map, the audit controls or the approval queue however it is prompted.

`GET /api/audit` requires the token, because the log holds references that are
linkable to a person — it is admin data in its own right, as set out above.
**Chain verification is deliberately open**, though: a log only its own
administrator can verify is a weaker guarantee than one anyone can check, and
`POST /api/audit/verify` returns a validity flag, an entry count and an entry
id — no personal data, no references and no log contents.

**Approval is not an override.** Approving a held message re-runs the entire
outbound policy over exactly the stored recipient, subject and body. The
administrator's approval satisfies only the *review* requirement that caused
the hold; any rule that hard-denies still hard-denies, so a decoy that has
appeared since, or a session total that has since been exceeded, blocks the
message and refuses the approval. A message that was blocked outright can
never be approved, by anyone, in any mode.

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

### The audit log

Every gateway decision and administrator action is appended to a hash-chained
log, one chain per demo run. Each entry's SHA-256 fingerprint covers its own
fields plus the previous entry's fingerprint, so editing a stored value
invalidates that entry and every entry after it, and `POST /api/audit/verify`
reports exactly which entry broke and why. That endpoint needs no
administrator token: tampering should be detectable by someone who does not
have to be trusted.

**This is not a blockchain.** There is no network, no consensus and no
distribution; it is a local hash chain. Its guarantee is correspondingly
modest: it makes an edit *detectable* by a trusted verifier. Anyone able to
rewrite the whole table could recompute every fingerprint.

**What the log holds, and what it does not.** Entries record decisions, rules,
reasons, decoy ids and resource references — never file contents. An entry says
that `workspace/customers/customer_contacts.csv` was quarantined and which
decoy ids were involved, not what the file said, so confidential data cannot be
read back out of the log.

**The log is not anonymous.** A resource reference, a decoy id or a session id
can still be linked back to a person — the decoy registry maps a decoy id to a
specific planted record, and a file-and-row reference identifies one customer.
Treat the audit log as personal data in its own right: it tells you who was
involved, not merely that something happened.

`POST /api/audit/tamper` deliberately edits the oldest entry of a run so the
demo can show detection working. It exists only when `DEMO_MODE=1`, requires
the administrator token, and records the tampering as a new entry naming the
run and the entry it edited.

### Detector limitations

The detector is a containment layer, not a guarantee. It canonicalises values
by type (a phone is matched as a phone, inside phone-shaped tokens only), NFKC
normalises its input and strips zero-width and format characters, and looks one
level deep for base64, hex, URL-encoded and written-out (`[at]`, `[dot]`)
content. These evasions are **known gaps that it does not detect**:

- **Double encoding.** Decoding is deliberately one level only, so content
  encoded twice — base64 of base64, for example — is not recovered. Unbounded
  decoding is a denial-of-service surface, so the bound is the safer trade.
- **Reversed or transposed text.** A value written backwards, or with its
  characters otherwise rearranged, is not matched.
- **Identifiers split by spaces.** Phone numbers survive arbitrary spacing,
  and survive having other digits padded onto them, because every plausible
  eight-digit number inside a digit run is considered. An API key, staff id or
  contract number **split by spaces** between its characters is not matched;
  those are compared exactly, case-insensitively.
- **Content over the scan limit.** Only the first 200 KB is examined. The
  detector reports this as `truncated`, and the gateway fails closed on it:
  an oversized read result is withheld and an oversized outbound message is
  hard-denied, rather than acted on from a partial scan.

A `NONE` result means no registered decoy was found in what was scanned. It
never means the content is safe — the role checks, the data-owner rule, the
personal-item limits and the taint rule all still apply, and they do not depend
on detection succeeding.

### Where authorisation comes from, and its limitation

The data-owner rule asks whether the owner of a piece of personal data is an
authorised recipient of **this task**. That list is set by the backend from the
inbox item when the session is created — the customer's email address on file,
or the internal staff addresses the task legitimately involves — and never from
anything the AI says.

The rule is deliberately strict, and applies to internal recipients too:
emailing a customer's phone number to a colleague at `limco.example` is held
for review unless that customer is an authorised recipient of the task. A
colleague being inside the company is not by itself a reason they are entitled
to a particular customer's details.

**The limitation is where that list comes from.** In this prototype each task
carries its own authorised recipients, defined per scenario. A production
system would not invent them per task: it would read entitlement from the
company's own access control — the CRM's record ownership, the helpdesk ticket's
assignment, the staff directory and group membership — so that "is this person
entitled to this record?" is answered by the system of record rather than by a
field attached to the request. As built, a task context that is set wrongly
either holds legitimate work or authorises a recipient who should not be
authorised, and nothing in the gateway can tell the difference.

### The two agents

**Claude** is the demo agent. It decides what to request, and the gateway
decides what happens. All provider code lives in `backend/agent_claude.py` —
a test asserts no other module imports the SDK. Sampling is left at its
defaults: no `temperature`, `top_p` or `top_k` is ever sent, and variability
is measured by repeating runs instead. The model id and SDK version are logged
for every run and returned with every result.

The incoming email is loaded by the backend and handed to the model wrapped in
an `<untrusted_email from='…'>` element, hidden HTML included. That wrapper is
a courtesy to the model, not a control: if Claude ignores it entirely, every
tool request it makes is still checked by the gateway, which never read the
email. No security rule appears in the system prompt or in any tool
description, and tests assert that stays true.

One real API call lives in `scripts/smoke_claude.py`. It lists the available
models first and stops with a clear message if `CLAUDE_MODEL` is not among
them, rather than guessing. It leaves the workspace seeded, so unseed before
running the test suite — the script says so when it finishes.

**"Worst-case (scripted)"** is not an agent that decides anything. For an
attack scenario it replays exactly the tool calls the attacker wanted, in
order, declining nothing — a fully compromised AI. That is the point: whatever
such a run fails to achieve was stopped by the gateway, not by a model choosing
to behave. It reaches tools only through `CanaryGateway.execute()`; it opens no
file and writes no message itself, and a test asserts that stays true.

Both labels come from one place, `config.AGENT_LABELS`, and every run and
session response carries `agent_label`, so the interface renders the name
rather than spelling it. A scripted result must never be read as evidence about
how a model behaves.

### Databases

`data/app.db` holds demo runs, agent sessions, audit events, alerts, simulated
emails and scenario-suite results. Both databases are created on demand and
initialisation is idempotent, so restarting the server neither loses nor
duplicates anything. A session's `protection_mode` is fixed when the session is
created, enforced both by the update helper and by a SQLite trigger that aborts
the write even if raw SQL attempts it; to compare modes, create a new session.

## Team

To be completed before submission.
