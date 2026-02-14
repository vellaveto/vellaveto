"""
Vellaveto MCP Firewall - Python SDK

Provides native integration with LangChain, LangGraph, and direct API access
for AI agent security policy enforcement.

Example:
    from vellaveto import VellavetoClient
    from vellaveto.langchain import VellavetoCallbackHandler

    client = VellavetoClient(url="http://localhost:3000")
    handler = VellavetoCallbackHandler(client)

    chain = LLMChain(..., callbacks=[handler])
"""

from vellaveto.client import VellavetoClient, VellavetoError, PolicyDenied, ApprovalRequired
from vellaveto.redaction import ParameterRedactor
from vellaveto.types import Verdict, EvaluationResult, Action

__version__ = "2.2.1"
__all__ = [
    "VellavetoClient",
    "VellavetoError",
    "PolicyDenied",
    "ApprovalRequired",
    "ParameterRedactor",
    "Verdict",
    "EvaluationResult",
    "Action",
]
