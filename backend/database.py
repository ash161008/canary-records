"""SQLite data layer (Stage 3).

Will hold the connection helpers and idempotent schema initialisation for
data/app.db (demo runs, agent sessions, audit events, alerts, simulated
emails, test runs and results) and for vault/registry.db (the canary
registry). Built-in sqlite3 only, no ORM, parameterised SQL only.
"""
