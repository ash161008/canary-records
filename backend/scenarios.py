"""Scenario suite and scoreboard metrics (Stage 13).

Loads scenarios/attacks.json and scenarios/normal.json, runs the matrix of
agent and protection modes with a fresh session per run, classifies each run
(unauthorised disclosure, canary exposure, forbidden access, where it was
caught, model refusal, false hold, task failure) and stores results by run id.
Every scoreboard number is computed from runs that actually executed.
"""
