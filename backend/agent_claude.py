"""Claude agent adapter (Stage 11) - the demo agent.

The only module that talks to the Anthropic SDK: Messages API tool use, with
the model id and SDK version logged for every run. The inbox item is loaded
by the backend and passed in wrapped as untrusted content; security never
depends on Claude honouring that label, because every tool request is
executed by CanaryGateway.execute(). No temperature, top_p or top_k is sent.
"""
