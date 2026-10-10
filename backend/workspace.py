"""Safe workspace path utilities (Stage 4).

Will resolve paths inside workspace/ only: rejecting "..", absolute paths and
symlinks, keeping vault/ and data/ unreachable, and capping file reads at
1 MB. Every agent file access is routed through these helpers by the gateway.
"""
