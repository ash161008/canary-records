"""Canary and personal-data detector (Stage 6).

Pure functions, no network calls: type-specific canonicalisation, bounded
decoding of encoded candidates, STRONG/WEAK/NONE canary confidence, personal
item extraction and unique-identifier owner lookup. One of only two modules
permitted to open vault/registry.db; the other is backend/seeder.py.
"""
