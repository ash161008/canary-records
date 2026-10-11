"""Run the normal order email once against the real Claude API.

This is the only script in the project that spends money, and it spends it
once: a single session on the ordinary "where is my order 1042?" email, in
protect mode. Everything else in the test suite uses a mocked client.

Before the call it checks that CLAUDE_MODEL is a model the account can
actually see, by listing the models through the SDK. If it is not there the
script says so and exits, rather than guessing at a model id or letting the
API return an opaque error.

Run:  .venv/bin/python scripts/smoke_claude.py
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend import agent_claude, config, database, seeder  # noqa: E402

INBOX_ID = "normal_order_1042"
PROTECTION_MODE = "protect"


def fail(message: str) -> None:
    print(f"\nSTOPPED: {message}\n")
    raise SystemExit(1)


def check_model(client) -> None:
    """Confirm CLAUDE_MODEL is in the live models list."""
    print(f"Checking that {config.CLAUDE_MODEL!r} is available...")
    try:
        available = [model.id for model in client.models.list(limit=100)]
    except Exception as error:  # noqa: BLE001 - reported, never swallowed
        fail(
            f"Could not list models ({type(error).__name__}). Check "
            "ANTHROPIC_API_KEY and network access."
        )

    if config.CLAUDE_MODEL not in available:
        fail(
            f"CLAUDE_MODEL is set to {config.CLAUDE_MODEL!r}, which is not in "
            "the list of models this API key can use.\n"
            f"  Available: {', '.join(sorted(available)) or '(none returned)'}\n"
            "  Set CLAUDE_MODEL in .env to one of those ids."
        )

    print(f"  ok: {config.CLAUDE_MODEL} is available")


def main() -> None:
    print("Canary Records: Claude smoke test")
    print(f"  SDK version: {agent_claude.SDK_VERSION}")
    print(f"  Model id:    {config.CLAUDE_MODEL or '(not set)'}")

    if not config.ANTHROPIC_API_KEY:
        fail("ANTHROPIC_API_KEY is not set, so no real call can be made.")
    if not config.CLAUDE_MODEL:
        fail("CLAUDE_MODEL is not set.")

    client = agent_claude.build_client()
    check_model(client)

    database.init_app_db()
    if not seeder.is_seeded():
        print("Seeding the workspace first...")
        seeder.seed()

    run = database.get_or_create_active_demo_run()
    print(f"\nRunning {INBOX_ID} in {PROTECTION_MODE} mode (one real API call)...")

    outcome = agent_claude.run_claude(
        inbox_id=INBOX_ID, protection_mode=PROTECTION_MODE, run_id=run.run_id
    )

    print(f"\n  session:         {outcome['session_id']}")
    print(f"  stopped because: {outcome['stopped_because']}")
    print(f"  iterations:      {outcome['iterations']}")
    print(f"  status:          {outcome['status']}")
    print(f"  model / sdk:     {outcome['model_id']} / {outcome['sdk_version']}")

    print("\n  trace:")
    for step in outcome["activity"]:
        print(
            f"    {step['step']}. {step['tool']:<17} "
            f"{step['badge']:<13} {step['rule'] or ''}"
        )
    if not outcome["activity"]:
        print("    (the model requested no tools)")

    emails = [
        email
        for email in database.list_simulated_emails(run_id=run.run_id)
        if email.session_id == outcome["session_id"]
    ]
    print("\n  simulated_emails rows for this session:")
    for email in emails:
        print(f"    #{email.id} -> {email.recipient}  [{email.delivery_status}]")
        print(f"       subject: {email.subject}")
    if not emails:
        print("    (none - the model did not send a reply)")

    print("\nDone. No real email was sent; the rows above are the whole of it.")
    print(
        "\nNote: the workspace is left seeded, which is what the demo wants. "
        "The Stage 4 tests read the real workspace and expect it unseeded, so "
        "run this before the test suite:\n"
        "  .venv/bin/python -c 'from backend import seeder; seeder.unseed()'"
    )


if __name__ == "__main__":
    main()
