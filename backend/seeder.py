"""Canary (decoy record) seeder (Stage 5).

Will plant 20 unlabelled decoys into the synthetic workspace and record them
in vault/registry.db, with an unseed() that restores the original files
exactly. One of only two modules permitted to open the registry; the other is
backend/detector.py.
"""
