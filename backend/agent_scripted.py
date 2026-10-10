"""Deterministic scripted agent (Stage 10).

Used for automated tests and as the worst-case agent that stress-tests the
gateway: it replays exactly the tool calls an attacker wants, representing a
fully compromised AI, so results reflect the gateway alone. It is not the
demo agent, and it reaches tools only through CanaryGateway.execute().
"""
