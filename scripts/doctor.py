"""Pre-demo check. Run this before you present anything.

It answers the questions that go wrong five minutes before a demo: is the
right Python running, are the dependencies the ones this was built against,
is the port free or already serving, does the page load, are the decoys
planted, and is the audit chain intact.

It changes nothing. It does not seed, does not reset, and never touches
data/app.db or vault/registry.db - it only reads and reports, and tells you
the command to run for anything that needs doing.

Run:  .venv/bin/python scripts/doctor.py
Exit: 0 if everything needed for a demo is ready, 1 otherwise.
"""

import importlib.metadata
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend import config  # noqa: E402

MIN_PYTHON = (3, 11)
PORT = 8000
GREEN, RED, AMBER, DIM, OFF = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"

results: list[tuple[str, str, str]] = []


def record(level: str, label: str, detail: str = "") -> None:
    results.append((level, label, detail))
    mark = {"ok": f"{GREEN}ok  {OFF}", "warn": f"{AMBER}warn{OFF}", "fail": f"{RED}FAIL{OFF}"}[level]
    print(f"  [{mark}] {label}" + (f"\n         {DIM}{detail}{OFF}" if detail else ""))


# ---------------------------------------------------------------------------


def check_python() -> None:
    version = sys.version_info
    if version[:2] >= MIN_PYTHON:
        record("ok", f"Python {version.major}.{version.minor}.{version.micro}")
    else:
        record(
            "fail",
            f"Python {version.major}.{version.minor} is too old",
            f"this project needs {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer",
        )


def check_dependencies() -> None:
    """Every pin in requirements.txt is installed, at that version."""
    requirements = (BASE_DIR / "requirements.txt").read_text().splitlines()
    wanted = {}
    for line in requirements:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9_.\-]+)==(.+)$", line)
        if match:
            wanted[match.group(1)] = match.group(2)

    missing, wrong = [], []
    for name, version in wanted.items():
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            missing.append(name)
            continue
        if installed != version:
            wrong.append(f"{name} {installed} (pinned {version})")

    if missing:
        record(
            "fail",
            f"{len(missing)} dependency(ies) are not installed",
            f"{', '.join(missing)} — run: .venv/bin/pip install -r requirements.txt",
        )
    elif wrong:
        record("warn", "installed versions differ from the pins", "; ".join(wrong))
    else:
        record("ok", f"all {len(wanted)} pinned dependencies installed")


def port_state() -> str:
    """"free", "serving" (this app) or "busy" (something else)."""
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex(("127.0.0.1", PORT)) != 0:
            return "free"
    try:
        import requests

        response = requests.get(f"http://127.0.0.1:{PORT}/api/health", timeout=2)
        if response.status_code == 200 and response.json().get("status") == "ok":
            return "serving"
    except Exception:  # noqa: BLE001 - any failure means "not us"
        pass
    return "busy"


def check_port(state: str) -> None:
    if state == "free":
        record(
            "ok",
            f"port {PORT} is free",
            "start the app with: .venv/bin/uvicorn backend.main:app "
            f"--host 127.0.0.1 --port {PORT}",
        )
    elif state == "serving":
        record("ok", f"Canary Records is already serving on port {PORT}")
    else:
        record(
            "fail",
            f"port {PORT} is in use by something else",
            "stop it, or start this app on another port with --port",
        )


def check_http(base: str) -> None:
    """The two requests the browser makes first."""
    import requests

    for path, expect in [("/api/health", "json"), ("/static/app.js", "text")]:
        try:
            response = requests.get(base + path, timeout=5)
        except Exception as error:  # noqa: BLE001
            record("fail", f"GET {path} failed", type(error).__name__)
            continue
        if response.status_code != 200:
            record("fail", f"GET {path} returned {response.status_code}")
        elif expect == "json" and response.json().get("status") != "ok":
            record("fail", f"GET {path} did not report ok", response.text[:80])
        else:
            record("ok", f"GET {path} returned 200")

    # A 404 here is a console error during the demo.
    try:
        response = requests.get(base + "/favicon.ico", timeout=5)
        record(
            "ok" if response.status_code == 200 else "warn",
            f"GET /favicon.ico returned {response.status_code}",
            "" if response.status_code == 200 else "the console will show a 404",
        )
    except Exception:  # noqa: BLE001
        record("warn", "GET /favicon.ico could not be checked")


def check_environment() -> None:
    if config.ADMIN_TOKEN:
        record("ok", "ADMIN_TOKEN is set")
    else:
        record(
            "fail",
            "ADMIN_TOKEN is not set",
            "every admin action fails closed without it; set it in .env",
        )

    if config.has_claude_credentials():
        record("ok", f"Claude configured (model {config.CLAUDE_MODEL})")
    else:
        record(
            "warn",
            "Claude is not configured",
            "ANTHROPIC_API_KEY and CLAUDE_MODEL are needed for a Claude run; "
            "the worst-case scripted agent works without them",
        )

    record(
        "ok" if config.DEMO_MODE else "warn",
        f"DEMO_MODE={'1' if config.DEMO_MODE else '0'}",
        ""
        if config.DEMO_MODE
        else "the audit-tamper and beacon demonstrations are absent at 0",
    )


def check_workspace() -> None:
    from backend import seeder

    if not (config.WORKSPACE_DIR / "customers" / "customer_contacts.csv").is_file():
        record(
            "fail",
            "the workspace has not been generated",
            "run: .venv/bin/python scripts/generate_workspace.py",
        )
        return

    try:
        seeded = seeder.is_seeded()
        count = len(seeder.list_registered_canaries())
    except Exception as error:  # noqa: BLE001
        record("fail", "the decoy registry could not be read", type(error).__name__)
        return

    if seeded:
        record("ok", f"workspace seeded with {count} decoys")
    else:
        record(
            "warn",
            "the workspace is not seeded",
            'seed it on screen 2, or: curl -X POST -H "X-Admin-Token: $ADMIN_TOKEN" '
            f"http://127.0.0.1:{PORT}/api/workspace/seed",
        )


def check_audit_chain() -> None:
    from backend import audit, database

    run = database.get_active_demo_run()
    if run is None:
        record("ok", "no demo run has started yet, so there is no chain to check")
        return

    result = audit.verify_audit_chain(run.run_id)
    if result["valid"]:
        record(
            "ok",
            f"audit chain valid ({result['event_count']} entries in the current run)",
        )
    else:
        record(
            "fail",
            f"audit chain broken at entry {result['first_invalid_event_id']}",
            "if this was the tamper demonstration, reset the demo to start a "
            "fresh chain: POST /api/reset",
        )


def check_suite_results() -> None:
    from backend import scenarios

    board = scenarios.latest_scoreboard()
    if board is None:
        record(
            "warn",
            "no scenario suite results are stored",
            "screen 5 will be empty; run the worst-case suite from screen 5",
        )
    else:
        record(
            "ok",
            f"latest suite results: {board['agent_label']} / "
            f"{board['protection_mode']}, {board['runs']} run(s)",
        )


# ---------------------------------------------------------------------------


def main() -> None:
    print("Canary Records: pre-demo check\n")

    print("Environment")
    check_python()
    check_dependencies()
    check_environment()

    print("\nServer")
    state = port_state()
    check_port(state)

    started = None
    base = f"http://127.0.0.1:{PORT}"
    if state == "free":
        print(f"  {DIM}starting a server briefly to check the endpoints…{OFF}")
        started = subprocess.Popen(
            [
                sys.executable, "-m", "uvicorn", "backend.main:app",
                "--host", "127.0.0.1", "--port", str(PORT),
            ],
            cwd=BASE_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        import requests

        for _ in range(40):
            try:
                if requests.get(f"{base}/api/health", timeout=1).status_code == 200:
                    break
            except Exception:  # noqa: BLE001
                time.sleep(0.25)

    try:
        if state != "busy":
            check_http(base)
        else:
            record("warn", "the endpoints were not checked", "the port is in use")
    finally:
        if started is not None:
            started.terminate()
            started.wait(timeout=20)

    print("\nDemo data")
    check_workspace()
    check_audit_chain()
    check_suite_results()

    failures = [item for item in results if item[0] == "fail"]
    warnings = [item for item in results if item[0] == "warn"]

    print()
    if failures:
        print(f"{RED}{len(failures)} problem(s) to fix before demonstrating:{OFF}")
        for _, label, _detail in failures:
            print(f"  - {label}")
        raise SystemExit(1)

    if warnings:
        print(f"{AMBER}Ready, with {len(warnings)} thing(s) worth knowing.{OFF}")
    else:
        print(f"{GREEN}Ready.{OFF}")
    raise SystemExit(0)


if __name__ == "__main__":
    main()
