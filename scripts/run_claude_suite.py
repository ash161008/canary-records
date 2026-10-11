"""Run the measured scenario suite against the real Claude API.

This is the expensive one. It runs all 35 scenarios in each protection mode of
the Claude matrix - monitor and protect - with every run making real API calls,
and each run may take up to eight model turns. Run it once, after the feature
freeze, and read the scoreboard it stores.

It prints one line per scenario as that scenario finishes, so a long run is
legible while it happens rather than only at the end. Results are written to
test_runs and test_results in data/app.db, where GET /api/suite/latest reads
them. The workspace is unseeded at the end, including if the run is
interrupted, which leaves the repository in its pristine state while the
stored results stay put.

Usage:
  .venv/bin/python scripts/run_claude_suite.py                  # 1 repeat
  .venv/bin/python scripts/run_claude_suite.py --repeats 3      # the full matrix
  .venv/bin/python scripts/run_claude_suite.py --scenarios B1 N1 --yes
  .venv/bin/python scripts/run_claude_suite.py --modes protect
"""

import argparse
import logging
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend import agent_claude, config, database, scenarios, seeder  # noqa: E402

logger = logging.getLogger("run_claude_suite")


def fail(message: str) -> None:
    print(f"\nSTOPPED: {message}\n")
    raise SystemExit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the Claude scenario suite and store the scoreboard."
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=1,
        help=(
            "How many times to run each scenario in each mode. The build "
            "specification asks for 3, so the spread between runs can be "
            "reported. Default 1."
        ),
    )
    parser.add_argument(
        "--modes",
        nargs="+",
        choices=["protect", "monitor", "outbound_only"],
        default=[mode for _, mode in scenarios.CLAUDE_MATRIX],
        help="Protection modes to run. Default: monitor and protect.",
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        default=None,
        metavar="ID",
        help="Limit to these scenario ids, for a cheap check before the real run.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt.",
    )
    parser.add_argument(
        "--keep-seeded",
        action="store_true",
        help="Leave the decoys planted afterwards instead of unseeding.",
    )
    return parser.parse_args()


def check_model(client) -> None:
    """Confirm CLAUDE_MODEL is a model this key can actually use."""
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


def confirm(scenario_count: int, modes: list[str], repeats: int) -> None:
    total = scenario_count * len(modes) * repeats
    print(
        f"\nThis will make real API calls: {scenario_count} scenario(s) x "
        f"{len(modes)} mode(s) x {repeats} repeat(s) = {total} agent run(s),\n"
        f"each up to {agent_claude.MAX_ITERATIONS} model turns. That costs money."
    )
    answer = input("Type 'run' to continue: ").strip().lower()
    if answer != "run":
        fail("Not confirmed, so nothing was run.")


def measures_of(result: dict) -> str:
    """The flags worth seeing on one line, or a dash when the run was clean."""
    flags = [
        name
        for name, value in (
            ("disclosure", result.get("unauthorised_disclosure")),
            ("canary", result.get("canary_exposure")),
            ("forbidden", result.get("forbidden_access")),
            ("false-hold", result.get("false_hold")),
            ("task-failed", result.get("task_failed")),
            ("refused", result.get("model_refused")),
        )
        if value
    ]
    return ",".join(flags) if flags else "-"


def print_header(mode: str, repeats: int, count: int) -> None:
    print(f"\n=== Claude / {mode} - {count} scenario(s) x {repeats} repeat(s) ===")
    print(
        f"  {'id':5} {'rep':>3} {'cat':9} {'expected':9} {'outcome':12} "
        f"{'caught at':16} {'ms':>6}  flags"
    )


def line_for(scenario: dict, result: dict, repeat_index: int) -> str:
    if "error" in result:
        return f"  {scenario['id']:5} {repeat_index:>3} {'':9} {'':9} ERROR        {result['error'][:40]}"
    return (
        f"  {result['scenario_id']:5} {repeat_index:>3} "
        f"{result['category']:9} {str(result['expected']):9} "
        f"{str(result['outcome']):12} {str(result['caught_at']):16} "
        f"{result['duration_ms'] or 0:>6}  {measures_of(result)}"
    )


def print_scoreboard(board: dict) -> None:
    print(f"\n  --- {board['agent_label']} / {board['protection_mode']} ---")
    print(f"  runs                      {board['runs']}")
    print(f"  unauthorised disclosures  {board['unauthorised_disclosures']}")
    print(f"  canary exposures          {board['canary_exposures']}")
    print(f"  forbidden accesses        {board['forbidden_accesses']}")
    print(f"  bulk stopped              {board['bulk_stopped']}/{board['bulk_total']}")
    print(
        f"  targeted stopped          {board['targeted_stopped']}/"
        f"{board['targeted_total']}"
    )
    print(f"  caught where (bulk)       {board['caught_where_bulk']}")
    print(f"  caught where (targeted)   {board['caught_where_targeted']}")
    print(f"  model refusals            {board['model_refusals']}")
    print(
        f"  normal completed          {board['normal_completed']}/"
        f"{board['normal_total']}"
    )
    print(f"  false holds               {board['false_holds']}")
    print(f"  task failures             {board['task_failures']}")
    print(
        f"  avg gateway decision      {board['average_gateway_decision_ms']} ms "
        f"over {board['gateway_decisions']} decisions"
    )
    print(
        f"  avg alert latency         {board['average_alert_latency_ms']} ms "
        f"over {board['alerts_measured']} alert(s)"
    )
    print(f"  model / sdk               {board['model_id']} / {board['sdk_version']}")

    if board["failed_or_unexpected"]:
        print("  failed or unexpected:")
        for item in board["failed_or_unexpected"]:
            print(
                f"    {item['scenario_id']:5} rep {item['repeat_index']} "
                f"-> {item['reason']}"
            )
    else:
        print("  failed or unexpected:     none")


def main() -> None:
    args = parse_args()

    # The per-turn INFO lines would drown the per-scenario output.
    logging.basicConfig(level=logging.WARNING)

    print("Canary Records: Claude scenario suite")
    print(f"  SDK version: {agent_claude.SDK_VERSION}")
    print(f"  Model id:    {config.CLAUDE_MODEL or '(not set)'}")

    if args.repeats < 1:
        fail("--repeats must be at least 1.")
    if not config.ANTHROPIC_API_KEY:
        fail("ANTHROPIC_API_KEY is not set, so no real call can be made.")
    if not config.CLAUDE_MODEL:
        fail("CLAUDE_MODEL is not set.")

    client = agent_claude.build_client()
    check_model(client)

    available = scenarios.load_all()
    if not available:
        fail("scenarios/attacks.json and scenarios/normal.json are empty.")

    chosen = available
    if args.scenarios:
        wanted = set(args.scenarios)
        chosen = [item for item in available if item["id"] in wanted]
        missing = wanted - {item["id"] for item in chosen}
        if missing:
            fail(f"No such scenario(s): {', '.join(sorted(missing))}")

    if not args.yes:
        confirm(len(chosen), args.modes, args.repeats)

    database.init_app_db()
    if not seeder.is_seeded():
        print("\nSeeding the workspace (the suite needs the decoys planted)...")
        seeder.seed()
    print(f"  {len(seeder.list_registered_canaries())} canaries planted")

    demo_run = database.get_or_create_active_demo_run()
    print(f"  demo run: {demo_run.run_id}")

    boards = []
    try:
        for mode in args.modes:
            print_header(mode, args.repeats, len(chosen))
            board = scenarios.run_suite(
                agent_mode="claude",
                protection_mode=mode,
                repeats=args.repeats,
                demo_run_id=demo_run.run_id,
                scenario_ids=[item["id"] for item in chosen],
                on_result=lambda scenario, result, repeat_index: print(
                    line_for(scenario, result, repeat_index), flush=True
                ),
            )
            boards.append(board)
    except KeyboardInterrupt:
        print("\n\nInterrupted. Results stored so far are kept.")
    finally:
        if args.keep_seeded:
            print("\nThe workspace is left seeded (--keep-seeded).")
        else:
            removed = seeder.unseed()["removed"]
            print(f"\nUnseeded: {removed} canaries removed, original files restored.")
            print(
                "  The stored scoreboards are unaffected; the decoy registry is "
                "now empty, so reseed before the next run."
            )

    for board in boards:
        print_scoreboard(board)

    print("\nStored. GET /api/suite/latest will report these results.")
    print("No real email was sent at any point.")


if __name__ == "__main__":
    main()
