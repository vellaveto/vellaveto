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
import threading
from typing import Any, Callable, Dict, List, Optional

from vellaveto.client import VellavetoClient, PolicyDenied, ApprovalRequired
from vellaveto.types import EvaluationContext

from vellaveto.composio.extractor import normalize_slug_to_tool_function, extract_targets
from vellaveto.composio.scanner import ResponseScanner, ResponseScanResult

logger = logging.getLogger(__name__)

_MAX_CALL_CHAIN = 20
_MAX_TOOL_NAME_LEN = 256


class CallChainTracker:
    """Bounded, thread-safe call chain tracker.

    Maintains an ordered list of recent tool calls (max 20 entries,
    FIFO eviction).  The chain is included in the ``EvaluationContext``
    so that Vellaveto can enforce action-sequence policies.

    Thread-safe via ``threading.Lock``.
    """

    def __init__(self) -> None:
        self._chain: List[str] = []
        self._lock = threading.Lock()

    def append(self, tool_call: str) -> None:
        """Record a tool call, evicting the oldest if at capacity.

        Tool names longer than 256 characters are truncated.
        """
        # Truncate oversized tool names to prevent memory abuse
        if len(tool_call) > _MAX_TOOL_NAME_LEN:
            tool_call = tool_call[:_MAX_TOOL_NAME_LEN]
        with self._lock:
            self._chain.append(tool_call)
            if len(self._chain) > _MAX_CALL_CHAIN:
                self._chain.pop(0)

    def copy(self) -> List[str]:
        """Return a shallow copy of the current chain."""
        with self._lock:
            return self._chain.copy()

    def reset(self) -> None:
        """Clear the chain (e.g. on session reset)."""
        with self._lock:
            self._chain.clear()

    def __len__(self) -> int:
        with self._lock:
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

    Raises:
        PolicyDenied: If the policy denies the action, or if the evaluation
            fails and *fail_closed* is *True*.  **Important:** callers
            should NOT catch ``PolicyDenied`` — let it propagate so that
            the tool call is aborted.
        ApprovalRequired: If the action requires human approval.
    """
    tracker = call_chain_tracker if call_chain_tracker is not None else CallChainTracker()
    tools_lower = {t.lower() for t in tools} if tools else None

    def modifier(tool: str, toolkit: str, params: Dict[str, Any]) -> Dict[str, Any]:
        # Scope check — skip tools not in the allowlist
        if tools_lower is not None and tool.lower() not in tools_lower:
            return params

        tool_name, function_name = normalize_slug_to_tool_function(tool, toolkit)
        # SECURITY (FIND-COMPOSIO-006): Validate derived names are non-empty
        if not tool_name or not function_name:
            raise PolicyDenied("Invalid tool slug: empty tool_name or function_name after normalization")
        arguments = params.get("arguments", params) if isinstance(params, dict) else {}
        if arguments is None:
            arguments = {}
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
            # SECURITY (FIND-COMPOSIO-004): Log details at debug level only to prevent info leak
            logger.debug("Vellaveto evaluation error details for %s: %s", tool, exc)
            logger.error("Vellaveto evaluation failed for %s", tool)
            if fail_closed:
                raise PolicyDenied("Policy evaluation unavailable")
            logger.warning("Proceeding without policy evaluation (fail_closed=False) for %s", tool)
            return params

        from vellaveto.types import Verdict

        if result.verdict == Verdict.ALLOW:
            # SECURITY (FIND-COMPOSIO-007): Append normalized name, not raw slug
            tracker.append(f"{tool_name}/{function_name}")
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
    effective_scanner = scanner if scanner is not None else ResponseScanner()
    tools_lower = {t.lower() for t in tools} if tools else None

    def modifier(tool: str, toolkit: str, response: Any) -> Any:
        if tools_lower is not None and tool.lower() not in tools_lower:
            return response

        # Handle non-dict responses
        if not isinstance(response, dict):
            if isinstance(response, str):
                # Scan bare string responses
                scan_data = {"_raw": response}
            else:
                logger.warning(
                    "Non-scannable response type %s from %s",
                    type(response).__name__, tool,
                )
                if fail_closed:
                    return {
                        "data": {"error": "Response blocked: non-scannable response type"},
                        "successful": False,
                    }
                return response
        else:
            scan_data = response.get("data", response)

        try:
            scan_result: ResponseScanResult = effective_scanner.scan(scan_data)
        except Exception as exc:
            logger.error("Response scan failed for %s: %s", tool, type(exc).__name__)
            if fail_closed:
                return {
                    "data": {"error": "Response blocked: scan failure"},
                    "successful": False,
                }
            return response

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
