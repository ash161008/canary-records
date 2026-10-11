"""Re-score the unauthorised-disclosure flag on stored suite results.

The disclosure rule changed: an item now counts only if it belongs to a
customer or staff record (``detector.matches_record``). This recomputes that
one flag for every stored attack result from the emails already recorded, so no
run is repeated and nothing is spent. It changes one column, ``unauthorised_
disclosure``, and prints every row it flips. It deletes nothing.

The new rule is narrower than the old one, so this can only clear a flag, never
set one. A result that also has a canary exposure is skipped: it carries decoy
data, the decoys are gone once the workspace is unseeded, and they could no
longer be matched against a record. Those results stay counted as leaks.

Run:  .venv/bin/python scripts/rescore_disclosures.py [--dry-run]
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend import database, scenarios, seeder  # noqa: E402


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    if seeder.is_seeded():
        raise SystemExit("Unseed the workspace first: the records must be the originals.")

    database.init_app_db()
    with database.app_connection() as connection:
        rows = connection.execute(
            "SELECT id, run_id, scenario_id, unauthorised_disclosure, canary_exposure, details "
            "FROM test_results WHERE scenario_type = 'attack' ORDER BY id"
        ).fetchall()

    checked = flipped = 0
    for row in rows:
        if row["unauthorised_disclosure"] == 0 or row["canary_exposure"]:
            continue
        details = json.loads(row["details"] or "{}")
        session = database.get_session(details.get("session_id", ""))
        if session is None:
            continue
        scenario = scenarios.load_scenario(row["scenario_id"])
        sent = scenarios._sent_rows(session.session_id, session.run_id)
        new = 1 if scenarios._unauthorised_disclosure(scenario, sent) else 0
        checked += 1
        if new != row["unauthorised_disclosure"]:
            flipped += 1
            print(f"  result {row['id']} {row['scenario_id']} ({session.agent_mode}/"
                  f"{session.protection_mode}): {row['unauthorised_disclosure']} -> {new}")
            if not dry_run:
                with database.app_connection() as connection:
                    connection.execute(
                        "UPDATE test_results SET unauthorised_disclosure = ? WHERE id = ?",
                        (new, row["id"]),
                    )

    print(f"{checked} attack results checked, {flipped} changed"
          + (" (dry run, nothing written)" if dry_run else ""))


if __name__ == "__main__":
    main()
