"""
Sentinel MCP Firewall - Python SDK

Provides native integration with LangChain, LangGraph, and direct API access
for AI agent security policy enforcement.

Example:
    from sentinel import SentinelClient
    from sentinel.langchain import SentinelCallbackHandler

    client = SentinelClient(url="http://localhost:8080")
    handler = SentinelCallbackHandler(client)

    chain = LLMChain(..., callbacks=[handler])
"""

from sentinel.client import SentinelClient, SentinelError, PolicyDenied, ApprovalRequired
from sentinel.types import Verdict, EvaluationResult, Action

__version__ = "0.1.0"
__all__ = [
    "SentinelClient",
    "SentinelError",
    "PolicyDenied",
    "ApprovalRequired",
    "Verdict",
    "EvaluationResult",
    "Action",
]
