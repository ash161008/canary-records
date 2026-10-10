"""CanaryGateway: the only component permitted to execute agent tools (Stage 8).

Core principle: the AI may request actions, but only
CanaryGateway.execute(session_id, tool_name, arguments) has authority to
perform them. For every call it validates the tool and arguments, checks
session state and the role, blocks path traversal, runs the tool inside the
synthetic workspace, scans read results for canaries BEFORE anything is
returned to the model, and applies the outbound policy to every message
before it leaves the company. Every call writes an audit event.
"""
