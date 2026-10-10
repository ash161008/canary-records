"""CanaryGateway: the only component permitted to execute agent tools (Stage 8).

Core principle: the AI may request actions, but only
CanaryGateway.execute(session_id, tool_name, arguments) has authority to
perform them. For every call it validates the tool and arguments, checks
session state and the role, blocks path traversal, runs the tool inside the
synthetic workspace, scans read results for canaries BEFORE anything is
returned to the model, and applies the outbound policy to every message
before it leaves the company. Every call writes an audit event.

Scanning goes through one call: ``detector.scan(text)`` returns a single
``ScanResult`` with the canary confidence, the matches, the personal items,
their count and a truncation flag.

Standing obligation from Stage 6, to be implemented here: the detector can
only scan the first ``detector.MAX_INPUT_BYTES`` of content. When a
``ScanResult`` carries ``truncated=True``, the gateway must FAIL CLOSED -
withhold the read result, hard-deny the outbound message - rather than act on
a partial scan. A truncated NONE is not a clean result.
"""
