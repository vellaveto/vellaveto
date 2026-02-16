"""
Composio modifier factories for Vellaveto policy enforcement.

Composio's modifier system (``@before_execute`` / ``@after_execute``)
intercepts tool calls at the execution layer, below the provider
abstraction.  This module provides factory functions that return
callables compatible with those hooks.

The returned modifiers work with **any** Composio provider — OpenAI,
LangChain, CrewAI, AutoGen — without framework-specific code.
"""

import logging
from typing import Any, Callable, Dict, List, Optional

from vellaveto.client import VellavetoClient, PolicyDenied, ApprovalRequired
from vellaveto.types import EvaluationContext

from vellaveto.composio.extractor import normalize_slug_to_tool_function, extract_targets
from vellaveto.composio.scanner import ResponseScanner, ResponseScanResult

logger = logging.getLogger(__name__)

_MAX_CALL_CHAIN = 20


class CallChainTracker:
    """Bounded call chain that mirrors ``langchain.py`` behavior.

    Maintains an ordered list of recent tool calls (max 20 entries,
    FIFO eviction).  The chain is included in the ``EvaluationContext``
    so that Vellaveto can enforce action-sequence policies.

    This class is **not** thread-safe.  Use one tracker per session.
    """

    def __init__(self) -> None:
        self._chain: List[str] = []

    def append(self, tool_call: str) -> None:
        """Record a tool call, evicting the oldest if at capacity."""
        self._chain.append(tool_call)
        if len(self._chain) > _MAX_CALL_CHAIN:
            self._chain.pop(0)

    def copy(self) -> List[str]:
        """Return a shallow copy of the current chain."""
        return self._chain.copy()

    def reset(self) -> None:
        """Clear the chain (e.g. on session reset)."""
        self._chain.clear()

    def __len__(self) -> int:
        return len(self._chain)


def create_before_execute_modifier(
    client: VellavetoClient,
    session_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    call_chain_tracker: Optional[CallChainTracker] = None,
    fail_closed: bool = True,
    tools: Optional[List[str]] = None,
) -> Callable:
    """Create a Composio ``before_execute`` modifier.

    The returned callable has the signature
    ``(tool: str, toolkit: str, params: dict) -> dict``.  It evaluates
    the tool call against Vellaveto policies and either returns *params*
    unchanged (allow) or raises ``PolicyDenied`` / ``ApprovalRequired``.

    Args:
        client: Vellaveto API client.
        session_id: Session ID for stateful evaluation.
        agent_id: Agent ID for agent-specific policies.
        tenant_id: Tenant ID for multi-tenant deployments.
        call_chain_tracker: Optional shared call-chain tracker.
        fail_closed: When *True* (default), treat API/network errors
            as denials.  When *False*, log and allow.
        tools: Optional allowlist of tool slugs to guard.  When provided,
            calls to tools not in this list pass through unchecked.

    Returns:
        A modifier callable suitable for Composio's modifier system.
    """
    tracker = call_chain_tracker if call_chain_tracker is not None else CallChainTracker()
    tools_lower = {t.lower() for t in tools} if tools else None

    def modifier(tool: str, toolkit: str, params: Dict[str, Any]) -> Dict[str, Any]:
        # Scope check — skip tools not in the allowlist
        if tools_lower is not None and tool.lower() not in tools_lower:
            return params

        tool_name, function_name = normalize_slug_to_tool_function(tool, toolkit)
        arguments = params.get("arguments", params)
        target_paths, target_domains = extract_targets(tool, arguments)

        context = EvaluationContext(
            session_id=session_id,
            agent_id=agent_id,
            tenant_id=tenant_id,
            call_chain=tracker.copy(),
        )

        # Optional client-side redaction (if client has a redactor)
        eval_params = arguments
        if client.redactor is not None:
            eval_params = client.redactor.redact(arguments)

        try:
            result = client.evaluate(
                tool=tool_name,
                function=function_name,
                parameters=eval_params,
                target_paths=target_paths,
                target_domains=target_domains,
                context=context,
            )
        except (PolicyDenied, ApprovalRequired):
            raise
        except Exception as exc:
            logger.error("Vellaveto evaluation failed for %s: %s", tool, exc)
            if fail_closed:
                raise PolicyDenied(f"Evaluation failed: {exc}")
            return params

        from vellaveto.types import Verdict

        if result.verdict == Verdict.ALLOW:
            tracker.append(tool)
            return params

        if result.verdict == Verdict.DENY:
            raise PolicyDenied(
                result.reason or "Policy denied",
                result.policy_id,
            )

        if result.verdict == Verdict.REQUIRE_APPROVAL:
            raise ApprovalRequired(
                result.reason or "Approval required",
                result.approval_id or "unknown",
            )

        # Unknown verdict — fail closed
        raise PolicyDenied(f"Unknown verdict: {result.verdict}")

    return modifier


def create_after_execute_modifier(
    scanner: Optional[ResponseScanner] = None,
    fail_closed: bool = True,
    tools: Optional[List[str]] = None,
) -> Callable:
    """Create a Composio ``after_execute`` modifier.

    The returned callable has the signature
    ``(tool: str, toolkit: str, response: dict) -> dict``.  It scans
    the tool response for secrets and injection indicators.

    Args:
        scanner: ``ResponseScanner`` instance.  When *None*, a default
            scanner (injection-only, no secret detection) is created.
        fail_closed: When *True* (default), replace the response with a
            sanitized error if findings are detected.  When *False*,
            log findings but return the response unchanged.
        tools: Optional allowlist of tool slugs to scan.

    Returns:
        A modifier callable suitable for Composio's modifier system.
    """
    effective_scanner = scanner or ResponseScanner()
    tools_lower = {t.lower() for t in tools} if tools else None

    def modifier(tool: str, toolkit: str, response: Dict[str, Any]) -> Dict[str, Any]:
        if tools_lower is not None and tool.lower() not in tools_lower:
            return response

        data = response.get("data", response)
        scan_result: ResponseScanResult = effective_scanner.scan(data)

        if not scan_result.findings:
            return response

        categories = {f.category for f in scan_result.findings}
        logger.warning(
            "Vellaveto response scan found %d finding(s) in %s: %s",
            len(scan_result.findings),
            tool,
            ", ".join(sorted(categories)),
        )

        if fail_closed:
            return {
                "data": {"error": "Response blocked by Vellaveto security scan"},
                "successful": False,
                "error": f"Security scan detected {len(scan_result.findings)} finding(s)",
            }

        return response

    return modifier
