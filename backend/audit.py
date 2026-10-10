"""Tamper-evident audit chain (Stage 7).

Each event is hashed with SHA-256 over its canonically serialised fields plus
the previous event's hash, one chain per demo run. Changing a stored value
invalidates that event and every event after it, which verification reports.
Events record decoy ids, record references and decisions, never file
contents.
"""
