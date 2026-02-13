"""
Sentinel MCP Firewall - Python SDK

Provides native integration with LangChain, LangGraph, and direct API access
for AI agent security policy enforcement.

Example:
    from sentinel import SentinelClient
    from sentinel.langchain import SentinelCallbackHandler

    client = SentinelClient(url="http://localhost:3000")
    handler = SentinelCallbackHandler(client)

    chain = LLMChain(..., callbacks=[handler])
"""

from sentinel.client import SentinelClient, SentinelError, PolicyDenied, ApprovalRequired
from sentinel.redaction import ParameterRedactor
from sentinel.types import Verdict, EvaluationResult, Action

__version__ = "2.2.1"
__all__ = [
    "SentinelClient",
    "SentinelError",
    "PolicyDenied",
    "ApprovalRequired",
    "ParameterRedactor",
    "Verdict",
    "EvaluationResult",
    "Action",
]
