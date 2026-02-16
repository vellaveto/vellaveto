"""
Composio integration for Vellaveto MCP Firewall.

Provides modifier factories and a high-level ``ComposioGuard`` for
enforcing Vellaveto security policies on Composio tool calls.  Works
with any Composio provider (OpenAI, LangChain, CrewAI, AutoGen, etc.)
via the native modifier system.

The ``composio`` package is an optional dependency.  All exports in this
module work without it — ``composio`` is only needed at runtime when
actually invoking tools.

Example::

    from composio import Composio
    from vellaveto import VellavetoClient
    from vellaveto.composio import ComposioGuard

    client = VellavetoClient(url="http://localhost:3000", api_key="key")
    guard = ComposioGuard(client, session_id="sess-1")

    composio = Composio(api_key="...")
    tools = composio.tools.get(
        user_id="default",
        toolkits=["GITHUB"],
        modifiers=[guard.before_execute_modifier(), guard.after_execute_modifier()],
    )
"""

# Check for Composio availability (informational only — not required for import)
try:
    from composio import Composio as _Composio  # noqa: F401
    HAS_COMPOSIO = True
except ImportError:
    HAS_COMPOSIO = False

from vellaveto.composio.guard import ComposioGuard
from vellaveto.composio.modifiers import (
    CallChainTracker,
    create_after_execute_modifier,
    create_before_execute_modifier,
)
from vellaveto.composio.scanner import ResponseScanner

__all__ = [
    "HAS_COMPOSIO",
    "ComposioGuard",
    "CallChainTracker",
    "create_before_execute_modifier",
    "create_after_execute_modifier",
    "ResponseScanner",
]
