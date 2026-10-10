"""Scenario suite: loading.

Stage 13 adds the measured suite itself - the 20 attacks and 15 normal tasks,
the run matrix across agents and protection modes, the classification of every
run and the scoreboard metrics.

What exists now is the loader the scripted agent needs to replay a scenario:
reading ``scenarios/attacks.json`` and ``scenarios/normal.json``, and finding
one scenario by id. Those files are empty until Stage 13 fills them.

A scenario is data, not code. ``intended_tool_calls`` describes what an
attacker wants the agent to do; replaying it proves nothing about the agent and
everything about the gateway, which is the point.
"""

import json
import logging

from backend import config

logger = logging.getLogger(__name__)

ATTACKS_FILE = "attacks.json"
NORMAL_FILE = "normal.json"

# Every scenario must carry these. A scenario missing one is a defect in the
# suite, not something to paper over at run time.
REQUIRED_FIELDS = ("id", "category", "from", "subject", "body")


class ScenarioError(Exception):
    """A scenario file or entry that cannot be used."""


def _read(filename: str, scenario_type: str) -> list[dict]:
    path = config.SCENARIOS_DIR / filename
    if not path.is_file():
        return []

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ScenarioError(f"{filename} is not valid JSON: {error}") from error

    if not isinstance(payload, list):
        raise ScenarioError(f"{filename} must hold a list of scenarios.")

    scenarios = []
    for entry in payload:
        if not isinstance(entry, dict):
            raise ScenarioError(f"{filename} holds an entry that is not an object.")
        missing = [field for field in REQUIRED_FIELDS if field not in entry]
        if missing:
            raise ScenarioError(
                f"{filename}: scenario {entry.get('id', '?')} is missing "
                f"{', '.join(missing)}."
            )
        scenario = dict(entry)
        scenario["scenario_type"] = scenario_type
        scenario.setdefault("authorised_recipients", [])
        scenario.setdefault("intended_tool_calls", [])
        scenario.setdefault("expected_protect_outcome", None)
        scenarios.append(scenario)

    return scenarios


def load_all() -> list[dict]:
    """Every scenario, attacks first."""
    return _read(ATTACKS_FILE, "attack") + _read(NORMAL_FILE, "normal")


def load_scenario(scenario_id: str) -> dict:
    """One scenario by id."""
    for scenario in load_all():
        if scenario["id"] == scenario_id:
            return scenario
    raise ScenarioError(f"No such scenario: {scenario_id!r}")


def list_scenarios() -> list[dict]:
    """A summary of each scenario, for the run picker.

    The raw body is not included: it carries the hidden instructions, and the
    picker only needs to identify the scenario.
    """
    return [
        {
            "id": scenario["id"],
            "scenario_type": scenario["scenario_type"],
            "category": scenario["category"],
            "from": scenario["from"],
            "subject": scenario["subject"],
            "expected_protect_outcome": scenario["expected_protect_outcome"],
            "intended_tool_call_count": len(scenario["intended_tool_calls"]),
        }
        for scenario in load_all()
    ]
