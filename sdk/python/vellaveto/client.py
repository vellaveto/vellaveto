"""
Vellaveto API client for Python.

Provides synchronous and asynchronous HTTP client for the Vellaveto API.
"""

import asyncio
import json
import logging
import time
import unicodedata
import warnings
from typing import Optional, Dict, Any, List
from urllib.parse import quote, urljoin

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from vellaveto.types import Action, EvaluationResult, EvaluationContext, Verdict

logger = logging.getLogger(__name__)

# Maximum response body size (10 MB) — prevents OOM on malicious/runaway responses
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024

# Maximum length for approval IDs — aligned with Go/TypeScript SDKs
_MAX_APPROVAL_ID_LENGTH = 256


class VellavetoError(Exception):
    """Base exception for Vellaveto SDK errors."""
    pass


class PolicyDenied(VellavetoError):
    """Raised when a policy denies an action."""

    def __init__(self, reason: str, policy_id: Optional[str] = None):
        self.reason = reason
        self.policy_id = policy_id
        super().__init__(f"Policy denied: {reason}")


class ApprovalRequired(VellavetoError):
    """Raised when an action requires human approval."""

    def __init__(self, reason: str, approval_id: str):
        self.reason = reason
        self.approval_id = approval_id
        super().__init__(f"Approval required: {reason} (approval_id: {approval_id})")


class VellavetoConnectionError(VellavetoError):
    """Raised when unable to connect to Vellaveto server."""
    pass


# SECURITY (FIND-SDK-019): Backward-compatible alias.
# The old name shadowed Python's builtin ConnectionError.
ConnectionError = VellavetoConnectionError  # noqa: A001


# HTTP status codes considered transient (safe to retry)
_TRANSIENT_STATUS_CODES = frozenset({429, 502, 503, 504})

# Maximum length for tool name, function name, and similar string inputs
_MAX_INPUT_STRING_LEN = 1024


def _validate_approval_id(approval_id: str) -> None:
    """Validate approval_id format — shared by sync and async clients.

    SECURITY (FIND-R56-SDK-001): Aligned with Go/TypeScript SDKs.
    Rejects empty, oversized (>256), and control-character-containing IDs.

    Raises:
        VellavetoError: If approval_id is invalid.
    """
    if not isinstance(approval_id, str) or not approval_id.strip():
        raise VellavetoError("Invalid approval_id: must be a non-empty string")
    if len(approval_id) > _MAX_APPROVAL_ID_LENGTH:
        raise VellavetoError(
            f"Invalid approval_id: exceeds max length ({_MAX_APPROVAL_ID_LENGTH})"
        )
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in approval_id):
        raise VellavetoError("Invalid approval_id: contains control characters")


def _validate_evaluate_inputs(
    tool: str,
    function: Optional[str],
    parameters: Optional[Dict[str, Any]],
    target_paths: Optional[List[str]],
    target_domains: Optional[List[str]],
    resolved_ips: Optional[List[str]] = None,
) -> None:
    """Validate inputs for evaluate() — shared by sync and async clients.

    Raises:
        VellavetoError: If any input is invalid.
    """
    # SECURITY (FIND-SDK-020): Validate inputs to prevent abuse
    if not isinstance(tool, str) or not tool.strip():
        raise VellavetoError("tool must be a non-empty string")
    if len(tool) > _MAX_INPUT_STRING_LEN:
        raise VellavetoError(
            f"tool name too long: {len(tool)} > {_MAX_INPUT_STRING_LEN}"
        )
    if function is not None:
        if not isinstance(function, str):
            raise VellavetoError("function must be a string or None")
        if len(function) > _MAX_INPUT_STRING_LEN:
            raise VellavetoError(
                f"function name too long: {len(function)} > {_MAX_INPUT_STRING_LEN}"
            )
    if parameters is not None and not isinstance(parameters, dict):
        raise VellavetoError("parameters must be a dict or None")
    if target_paths is not None and not isinstance(target_paths, list):
        raise VellavetoError("target_paths must be a list or None")
    # SECURITY (FIND-R55-SDK-006): Bound target_paths count. Parity with Go SDK (100).
    if target_paths is not None and len(target_paths) > 100:
        raise VellavetoError(
            f"target_paths has {len(target_paths)} entries, max 100"
        )
    if target_domains is not None and not isinstance(target_domains, list):
        raise VellavetoError("target_domains must be a list or None")
    # SECURITY (FIND-R55-SDK-006): Bound target_domains count. Parity with Go SDK (100).
    if target_domains is not None and len(target_domains) > 100:
        raise VellavetoError(
            f"target_domains has {len(target_domains)} entries, max 100"
        )
    # SECURITY (FIND-R67-SDK-001): Bound resolved_ips count. Parity with Go SDK (100).
    if resolved_ips is not None and not isinstance(resolved_ips, list):
        raise VellavetoError("resolved_ips must be a list or None")
    if resolved_ips is not None and len(resolved_ips) > 100:
        raise VellavetoError("resolved_ips exceeds max entries (100)")


def _build_evaluate_payload(
    action: Action,
    context: Optional[EvaluationContext],
) -> Dict[str, Any]:
    """Build a flattened evaluate payload — shared by sync and async clients.

    The server expects fields at the root level (``#[serde(flatten)]``), not
    nested under an ``"action"`` key.
    """
    payload: Dict[str, Any] = {
        "tool": action.tool,
        "function": action.function or "",
        "parameters": action.parameters,
        "target_paths": action.target_paths,
        "target_domains": action.target_domains,
        # SECURITY (FIND-R63-SDK-001): Include resolved_ips for parity with Go SDK.
        "resolved_ips": action.resolved_ips,
    }
    if context:
        payload["context"] = context.to_dict()
    return payload


class VellavetoClient:
    """
    Synchronous client for the Vellaveto API.

    Example:
        client = VellavetoClient(url="http://localhost:3000", api_key="your-key")

        # Evaluate a tool call
        result = client.evaluate(
            tool="filesystem",
            function="read_file",
            parameters={"path": "/etc/passwd"}
        )

        if result.verdict == Verdict.ALLOW:
            # Proceed with tool call
            pass
        elif result.verdict == Verdict.DENY:
            print(f"Denied: {result.reason}")

    Attributes:
        url: Base URL of the Vellaveto server
        api_key: API key for authentication (optional)
        timeout: Request timeout in seconds
        redactor: Optional ParameterRedactor for client-side secret stripping
    """

    def __init__(
        self,
        url: str = "http://localhost:3000",
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        redactor: Optional["ParameterRedactor"] = None,
        max_retries: int = 1,
    ):
        """
        Initialize the Vellaveto client.

        Args:
            url: Base URL of the Vellaveto server
            api_key: API key for authentication
            timeout: Request timeout in seconds (default: 10.0, aligned with Go/TS SDKs)
            verify_ssl: Whether to verify SSL certificates
            redactor: Optional ParameterRedactor for client-side secret stripping
            max_retries: Maximum number of retries for transient failures
                (connection errors, 502/503/504). Default 1.
        """
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.redactor = redactor
        self.max_retries = max(0, max_retries)

        if not verify_ssl:
            warnings.warn(
                "SSL verification disabled - connections are vulnerable to MITM attacks",
                SecurityWarning,
                stacklevel=2,
            )

        if HAS_HTTPX:
            self._client = httpx.Client(
                timeout=timeout,
                verify=verify_ssl,
            )
            self._use_httpx = True
        elif HAS_REQUESTS:
            self._session = requests.Session()
            self._use_httpx = False
        else:
            raise ImportError(
                "Either 'httpx' or 'requests' package is required. "
                "Install with: pip install httpx"
            )

    def __repr__(self) -> str:
        """SECURITY (FIND-SDK-013): Redact api_key in repr to prevent log leakage."""
        return (
            f"VellavetoClient(base_url={self.url!r}, api_key=***, "
            f"timeout={self.timeout}, max_retries={self.max_retries})"
        )

    def __enter__(self) -> "VellavetoClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _headers(self) -> Dict[str, str]:
        """Build request headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Make an HTTP request to the Vellaveto API.

        SECURITY (FIND-SDK-014): Retries transient failures (connection errors,
        502/503/504) up to ``max_retries`` times with exponential backoff
        (0.5s, 1s, 2s, ...).  Non-transient errors are raised immediately.
        """
        url = urljoin(self.url + "/", path.lstrip("/"))

        last_exc: Optional[Exception] = None
        for attempt in range(1 + self.max_retries):
            try:
                if self._use_httpx:
                    response = self._client.request(
                        method=method,
                        url=url,
                        json=json_data,
                        params=params,
                        headers=self._headers(),
                    )
                    # SECURITY (FIND-SDK-014): Retry on transient HTTP status
                    if response.status_code in _TRANSIENT_STATUS_CODES:
                        last_exc = VellavetoError(
                            f"Transient HTTP {response.status_code}"
                        )
                        if attempt < self.max_retries:
                            time.sleep(0.5 * (2 ** attempt))
                            continue
                        # Last attempt — fall through to "all retries exhausted"
                        break
                    response.raise_for_status()
                    # SECURITY (FIND-SDK-003): Enforce response size limit to prevent OOM
                    # SECURITY (FIND-R51-005): Safe Content-Length parsing
                    content_length = response.headers.get("content-length")
                    if content_length is not None:
                        try:
                            cl = int(content_length)
                        except (ValueError, TypeError):
                            cl = None
                        if cl is not None and cl > _MAX_RESPONSE_BYTES:
                            raise VellavetoError(
                                f"Response too large: {content_length} bytes exceeds "
                                f"{_MAX_RESPONSE_BYTES} byte limit"
                            )
                    if len(response.content) > _MAX_RESPONSE_BYTES:
                        raise VellavetoError(
                            f"Response body too large: {len(response.content)} bytes exceeds "
                            f"{_MAX_RESPONSE_BYTES} byte limit"
                        )
                    return response.json()
                else:
                    response = self._session.request(
                        method=method,
                        url=url,
                        json=json_data,
                        params=params,
                        headers=self._headers(),
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                    )
                    # SECURITY (FIND-SDK-014): Retry on transient HTTP status
                    if response.status_code in _TRANSIENT_STATUS_CODES:
                        last_exc = VellavetoError(
                            f"Transient HTTP {response.status_code}"
                        )
                        if attempt < self.max_retries:
                            time.sleep(0.5 * (2 ** attempt))
                            continue
                        # Last attempt — fall through to "all retries exhausted"
                        break
                    response.raise_for_status()
                    # SECURITY (FIND-SDK-003): Enforce response size limit to prevent OOM
                    # SECURITY (FIND-R51-005): Safe Content-Length parsing
                    content_length = response.headers.get("content-length")
                    if content_length is not None:
                        try:
                            cl = int(content_length)
                        except (ValueError, TypeError):
                            cl = None
                        if cl is not None and cl > _MAX_RESPONSE_BYTES:
                            raise VellavetoError(
                                f"Response too large: {content_length} bytes exceeds "
                                f"{_MAX_RESPONSE_BYTES} byte limit"
                            )
                    if len(response.content) > _MAX_RESPONSE_BYTES:
                        raise VellavetoError(
                            f"Response body too large: {len(response.content)} bytes exceeds "
                            f"{_MAX_RESPONSE_BYTES} byte limit"
                        )
                    return response.json()

            except (VellavetoError, PolicyDenied, ApprovalRequired):
                raise
            except Exception as e:
                # SECURITY (FIND-SDK-001): Sanitize error messages to prevent API key
                # leakage. The requests/httpx libraries may include the Authorization
                # header in exception messages on connection failures.
                last_exc = e
                is_connection = "Connection" in str(type(e).__name__)
                # SECURITY (FIND-SDK-014): Retry connection errors
                if is_connection and attempt < self.max_retries:
                    time.sleep(0.5 * (2 ** attempt))
                    continue
                error_msg = str(e)
                if self.api_key and self.api_key in error_msg:
                    error_msg = error_msg.replace(self.api_key, "[REDACTED]")
                if is_connection:
                    raise ConnectionError(f"Failed to connect to Vellaveto at {url}: {error_msg}")
                raise VellavetoError(f"Request failed: {error_msg}")

        # All retries exhausted
        error_msg = str(last_exc) if last_exc else "Unknown error"
        if self.api_key and self.api_key in error_msg:
            error_msg = error_msg.replace(self.api_key, "[REDACTED]")
        raise VellavetoError(f"Request failed after {self.max_retries + 1} attempts: {error_msg}")

    def evaluate(
        self,
        tool: str,
        function: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        target_paths: Optional[List[str]] = None,
        target_domains: Optional[List[str]] = None,
        context: Optional[EvaluationContext] = None,
        trace: bool = False,
    ) -> EvaluationResult:
        """
        Evaluate a tool call against Vellaveto policies.

        Args:
            tool: Tool name (e.g., "filesystem", "http", "bash")
            function: Function name (e.g., "read_file", "fetch")
            parameters: Tool call parameters
            target_paths: File paths the tool will access
            target_domains: Network domains the tool will access
            context: Evaluation context for stateful policies
            trace: Whether to include evaluation trace

        Returns:
            EvaluationResult with verdict and details

        Raises:
            PolicyDenied: If policy denies the action (when raise_on_deny=True)
            ApprovalRequired: If action requires approval (when raise_on_deny=True)
            VellavetoError: On API errors
        """
        _validate_evaluate_inputs(tool, function, parameters, target_paths, target_domains)

        effective_params = parameters or {}
        if self.redactor is not None:
            effective_params = self.redactor.redact(effective_params)

        action = Action(
            tool=tool,
            function=function,
            parameters=effective_params,
            target_paths=target_paths or [],
            target_domains=target_domains or [],
        )

        payload = _build_evaluate_payload(action, context)

        params = {}
        if trace:
            params["trace"] = "true"

        response = self._request(
            method="POST",
            path="/api/evaluate",
            json_data=payload,
            params=params if params else None,
        )

        return EvaluationResult.from_dict(response)

    def evaluate_or_raise(
        self,
        tool: str,
        function: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        target_paths: Optional[List[str]] = None,
        target_domains: Optional[List[str]] = None,
        context: Optional[EvaluationContext] = None,
    ) -> EvaluationResult:
        """
        Evaluate a tool call, raising an exception if not allowed.

        Same as evaluate(), but raises PolicyDenied or ApprovalRequired
        instead of returning a deny/require_approval verdict.

        Returns:
            EvaluationResult (only if verdict is ALLOW)

        Raises:
            PolicyDenied: If policy denies the action
            ApprovalRequired: If action requires human approval
        """
        result = self.evaluate(
            tool=tool,
            function=function,
            parameters=parameters,
            target_paths=target_paths,
            target_domains=target_domains,
            context=context,
        )

        if result.verdict == Verdict.DENY:
            raise PolicyDenied(result.reason or "Policy denied", result.policy_id)

        if result.verdict == Verdict.REQUIRE_APPROVAL:
            raise ApprovalRequired(
                result.reason or "Approval required",
                result.approval_id or "unknown",
            )

        return result

    def health(self) -> Dict[str, Any]:
        """Check Vellaveto server health."""
        return self._request("GET", "/health")

    def list_policies(self) -> List[Dict[str, Any]]:
        """List all configured policies."""
        return self._request("GET", "/api/policies")

    def reload_policies(self) -> Dict[str, Any]:
        """Reload policies from configuration."""
        return self._request("POST", "/api/policies/reload")

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get list of pending approval requests."""
        return self._request("GET", "/api/approvals/pending")

    def resolve_approval(
        self,
        approval_id: str,
        approved: bool,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Resolve a pending approval request.

        Args:
            approval_id: ID of the approval request
            approved: Whether to approve or deny
            reason: Optional reason for the decision
        """
        # SECURITY (FIND-R56-SDK-001): Validate approval_id — aligned with Go/TS SDKs.
        _validate_approval_id(approval_id)
        action = "approve" if approved else "deny"
        json_data: Optional[Dict[str, Any]] = None
        if reason is not None:
            json_data = {"reason": reason}
        # SECURITY: URL-encode approval_id to prevent path injection (parity with Go/TS).
        encoded_id = quote(approval_id, safe="")
        return self._request(
            method="POST",
            path=f"/api/approvals/{encoded_id}/{action}",
            json_data=json_data,
        )

    def discover(
        self,
        query: str,
        max_results: int = 5,
        token_budget: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Search the tool discovery index for matching tools.

        Args:
            query: Natural language description of the desired tool
            max_results: Maximum number of results (default: 5, max: 20)
            token_budget: Optional token budget for returned schemas

        Returns:
            Discovery result with ranked tools, total candidates, and policy-filtered count
        """
        # SECURITY (FIND-R55-SDK-001): Validate query non-empty. Parity with TS/Go.
        if not isinstance(query, str) or not query.strip():
            raise VellavetoError("discovery query must not be empty")
        payload: Dict[str, Any] = {
            "query": query,
            "max_results": max_results,
        }
        if token_budget is not None:
            payload["token_budget"] = token_budget

        return self._request("POST", "/api/discovery/search", json_data=payload)

    def discovery_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the tool discovery index.

        Returns:
            Index statistics including total tools, max capacity, and enabled status
        """
        return self._request("GET", "/api/discovery/index/stats")

    def discovery_reindex(self) -> Dict[str, Any]:
        """
        Trigger a full rebuild of the IDF weights in the discovery index.

        Returns:
            Status and total tool count after reindex
        """
        return self._request("POST", "/api/discovery/reindex")

    def discovery_tools(
        self,
        server_id: Optional[str] = None,
        sensitivity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List all indexed tools, optionally filtered.

        Args:
            server_id: Filter by originating MCP server ID
            sensitivity: Filter by sensitivity level (low, medium, high)

        Returns:
            List of tool metadata objects and total count
        """
        params: Dict[str, str] = {}
        if server_id is not None:
            params["server_id"] = server_id
        if sensitivity is not None:
            params["sensitivity"] = sensitivity

        return self._request(
            "GET", "/api/discovery/tools", params=params if params else None
        )

    # ── Projector (Phase 35.3) ───────────────────────────────────

    def projector_models(self) -> Dict[str, Any]:
        """
        List supported model families in the projector registry.

        Returns:
            Dictionary with ``model_families`` list of strings
        """
        return self._request("GET", "/api/projector/models")

    def project_schema(
        self,
        schema: Dict[str, Any],
        model_family: str,
    ) -> Dict[str, Any]:
        """
        Project a canonical tool schema for a given model family.

        Args:
            schema: Canonical tool schema dict with name, description,
                input_schema, and optional output_schema
            model_family: Target model family (e.g., "claude", "openai",
                "deepseek", "qwen", "generic")

        Returns:
            Dictionary with projected_schema, token_estimate, and model_family
        """
        # SECURITY (FIND-R55-SDK-007): Validate model_family non-empty.
        if not isinstance(model_family, str) or not model_family.strip():
            raise VellavetoError("model_family must be a non-empty string")
        payload = {
            "schema": schema,
            "model_family": model_family,
        }
        return self._request("POST", "/api/projector/transform", json_data=payload)

    # ── ZK Audit (Phase 37) ────────────────────────────────────────

    def zk_status(self) -> Dict[str, Any]:
        """
        Get the ZK audit scheduler status.

        Returns:
            Dictionary with active, pending_witnesses, completed_proofs,
            last_proved_sequence, and last_proof_at
        """
        return self._request("GET", "/api/zk-audit/status")

    def zk_proofs(
        self,
        limit: int = 20,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        List stored ZK batch proofs with pagination.

        Args:
            limit: Maximum number of proofs to return (default: 20, max: 100)
            offset: Offset for pagination (default: 0)

        Returns:
            Dictionary with proofs list, total count, offset, and limit
        """
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        return self._request("GET", "/api/zk-audit/proofs", params=params)

    def zk_verify(self, batch_id: str) -> Dict[str, Any]:
        """
        Verify a stored ZK batch proof.

        Args:
            batch_id: The batch identifier to verify

        Returns:
            Dictionary with valid, batch_id, entry_range, verified_at, and error
        """
        # SECURITY (FIND-R55-SDK-002): Validate batch_id non-empty. Parity with TS/Go.
        if not isinstance(batch_id, str) or not batch_id.strip():
            raise VellavetoError("batch_id must not be empty")
        return self._request(
            "POST", "/api/zk-audit/verify", json_data={"batch_id": batch_id}
        )

    def zk_commitments(
        self,
        from_seq: int,
        to_seq: int,
    ) -> Dict[str, Any]:
        """
        List Pedersen commitments for audit entries in a sequence range.

        Args:
            from_seq: Start of the entry range (sequence number)
            to_seq: End of the entry range (sequence number, inclusive)

        Returns:
            Dictionary with commitments list, total count, and range
        """
        params = {"from": from_seq, "to": to_seq}
        return self._request("GET", "/api/zk-audit/commitments", params=params)

    def soc2_access_review(
        self,
        period: str = "30d",
        export_format: str = "json",
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a SOC 2 Type II access review report.

        Args:
            period: Review period duration (e.g. "30d", "7d", "90d")
            export_format: Export format ("json" or "html")
            agent_id: Optional agent ID filter (max 128 chars)

        Returns:
            Access review report as dictionary (JSON) or raw HTML string
        """
        # SECURITY (FIND-R72-SDK-007): Validate format parameter. Parity with Go/TS SDKs.
        if export_format not in ("json", "html"):
            raise VellavetoError(
                f'export_format must be "json" or "html", got {export_format!r}'
            )
        if agent_id is not None:
            if not isinstance(agent_id, str):
                raise VellavetoError("agent_id must be a string")
            if len(agent_id) > 128:
                raise VellavetoError("agent_id exceeds max length (128)")
            # SECURITY (FIND-R55-SDK-003): Reject control chars. Parity with federation_trust_anchors.
            if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in agent_id):
                raise VellavetoError("agent_id contains control characters")
        params: Dict[str, Any] = {"period": period, "format": export_format}
        if agent_id is not None:
            params["agent_id"] = agent_id
        return self._request("GET", "/api/compliance/soc2/access-review", params=params)

    # ── Federation (Phase 39) ─────────────────────────────────────

    def federation_status(self) -> Dict[str, Any]:
        """
        Get federation status including per-anchor cache info.

        Returns:
            Dictionary with enabled, trust_anchor_count, and anchors list
        """
        return self._request("GET", "/api/federation/status")

    def federation_trust_anchors(
        self,
        org_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List federation trust anchors.

        Args:
            org_id: Optional filter by organization ID (max 128 chars)

        Returns:
            Dictionary with anchors list and total count
        """
        params: Dict[str, str] = {}
        if org_id is not None:
            if len(org_id) > 128:
                raise VellavetoError("org_id exceeds max length (128)")
            # SECURITY (FIND-R50-037): Catch DEL (0x7F) and C1 control chars (0x80-0x9F)
            if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in org_id):
                raise VellavetoError("org_id contains control characters")
            params["org_id"] = org_id
        return self._request(
            "GET", "/api/federation/trust-anchors", params=params if params else None
        )

    def close(self):
        """Close the client and release resources."""
        if self._use_httpx and hasattr(self, "_client"):
            self._client.close()


class AsyncVellavetoClient:
    """
    Asynchronous client for the Vellaveto API.

    Example:
        async with AsyncVellavetoClient(url="http://localhost:3000") as client:
            result = await client.evaluate(
                tool="filesystem",
                function="read_file",
                parameters={"path": "/etc/passwd"}
            )

    Requires httpx to be installed: pip install httpx
    """

    def __init__(
        self,
        url: str = "http://localhost:3000",
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        redactor: Optional["ParameterRedactor"] = None,
        max_retries: int = 1,
    ):
        """
        Initialize the async Vellaveto client.

        Args:
            url: Base URL of the Vellaveto server
            api_key: API key for authentication
            timeout: Request timeout in seconds (default: 10.0, aligned with Go/TS SDKs)
            verify_ssl: Whether to verify SSL certificates
            redactor: Optional ParameterRedactor for client-side secret stripping
            max_retries: Maximum number of retries for transient failures
                (connection errors, 502/503/504). Default 1.
        """
        if not HAS_HTTPX:
            raise ImportError(
                "AsyncVellavetoClient requires 'httpx' package. "
                "Install with: pip install httpx"
            )

        self.url = url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.redactor = redactor
        self.max_retries = max(0, max_retries)
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "AsyncVellavetoClient":
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()

    def __repr__(self) -> str:
        """SECURITY (FIND-R56-SDK-002): Redact api_key in repr, matching sync client."""
        return (
            f"AsyncVellavetoClient(base_url={self.url!r}, api_key=***, "
            f"timeout={self.timeout}, max_retries={self.max_retries})"
        )

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Make an HTTP request to the Vellaveto API (async).

        SECURITY (FIND-R51-003): Retries transient failures (connection errors,
        502/503/504) up to ``max_retries`` times with exponential backoff
        (0.5s, 1s, 2s, ...).  Non-transient errors are raised immediately.
        """
        if not self._client:
            raise VellavetoError("Client not initialized. Use 'async with' context.")

        url = urljoin(self.url + "/", path.lstrip("/"))

        last_exc: Optional[Exception] = None
        for attempt in range(1 + self.max_retries):
            try:
                response = await self._client.request(
                    method=method,
                    url=url,
                    json=json_data,
                    params=params,
                    headers=self._headers(),
                )
                # SECURITY (FIND-R51-003): Retry on transient HTTP status
                if response.status_code in _TRANSIENT_STATUS_CODES:
                    last_exc = VellavetoError(
                        f"Transient HTTP {response.status_code}"
                    )
                    if attempt < self.max_retries:
                        await asyncio.sleep(0.5 * (2 ** attempt))
                        continue
                    # Last attempt — fall through to "all retries exhausted"
                    break
                response.raise_for_status()
                # SECURITY (FIND-SDK-003): Enforce response size limit to prevent OOM
                # SECURITY (FIND-R51-005): Safe Content-Length parsing
                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        cl = int(content_length)
                    except (ValueError, TypeError):
                        cl = None
                    if cl is not None and cl > _MAX_RESPONSE_BYTES:
                        raise VellavetoError(
                            f"Response too large: {content_length} bytes exceeds "
                            f"{_MAX_RESPONSE_BYTES} byte limit"
                        )
                if len(response.content) > _MAX_RESPONSE_BYTES:
                    raise VellavetoError(
                        f"Response body too large: {len(response.content)} bytes exceeds "
                        f"{_MAX_RESPONSE_BYTES} byte limit"
                    )
                return response.json()

            except (VellavetoError, PolicyDenied, ApprovalRequired):
                raise
            except Exception as e:
                # SECURITY (FIND-SDK-001): Sanitize error messages in async client too.
                last_exc = e
                is_connection = "Connection" in str(type(e).__name__)
                # SECURITY (FIND-R51-003): Retry connection errors
                if is_connection and attempt < self.max_retries:
                    await asyncio.sleep(0.5 * (2 ** attempt))
                    continue
                error_msg = str(e)
                if self.api_key and self.api_key in error_msg:
                    error_msg = error_msg.replace(self.api_key, "[REDACTED]")
                if is_connection:
                    raise ConnectionError(f"Failed to connect to Vellaveto at {url}: {error_msg}")
                raise VellavetoError(f"Request failed: {error_msg}")

        # All retries exhausted
        error_msg = str(last_exc) if last_exc else "Unknown error"
        if self.api_key and self.api_key in error_msg:
            error_msg = error_msg.replace(self.api_key, "[REDACTED]")
        raise VellavetoError(f"Request failed after {self.max_retries + 1} attempts: {error_msg}")

    async def evaluate(
        self,
        tool: str,
        function: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        target_paths: Optional[List[str]] = None,
        target_domains: Optional[List[str]] = None,
        context: Optional[EvaluationContext] = None,
        trace: bool = False,
    ) -> EvaluationResult:
        """Evaluate a tool call against Vellaveto policies (async)."""
        _validate_evaluate_inputs(tool, function, parameters, target_paths, target_domains)

        effective_params = parameters or {}
        if self.redactor is not None:
            effective_params = self.redactor.redact(effective_params)

        action = Action(
            tool=tool,
            function=function,
            parameters=effective_params,
            target_paths=target_paths or [],
            target_domains=target_domains or [],
        )

        payload = _build_evaluate_payload(action, context)

        params = {}
        if trace:
            params["trace"] = "true"

        response = await self._request(
            method="POST",
            path="/api/evaluate",
            json_data=payload,
            params=params if params else None,
        )

        return EvaluationResult.from_dict(response)

    async def evaluate_or_raise(
        self,
        tool: str,
        function: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        target_paths: Optional[List[str]] = None,
        target_domains: Optional[List[str]] = None,
        context: Optional[EvaluationContext] = None,
    ) -> EvaluationResult:
        """Evaluate and raise exception if not allowed (async)."""
        result = await self.evaluate(
            tool=tool,
            function=function,
            parameters=parameters,
            target_paths=target_paths,
            target_domains=target_domains,
            context=context,
        )

        if result.verdict == Verdict.DENY:
            raise PolicyDenied(result.reason or "Policy denied", result.policy_id)

        if result.verdict == Verdict.REQUIRE_APPROVAL:
            raise ApprovalRequired(
                result.reason or "Approval required",
                result.approval_id or "unknown",
            )

        return result

    async def health(self) -> Dict[str, Any]:
        """Check Vellaveto server health (async)."""
        return await self._request("GET", "/health")

    async def list_policies(self) -> List[Dict[str, Any]]:
        """List all configured policies (async)."""
        return await self._request("GET", "/api/policies")

    async def reload_policies(self) -> Dict[str, Any]:
        """Reload policies from configuration (async)."""
        return await self._request("POST", "/api/policies/reload")

    async def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get list of pending approval requests (async)."""
        return await self._request("GET", "/api/approvals/pending")

    async def resolve_approval(
        self,
        approval_id: str,
        approved: bool,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Resolve a pending approval request (async).

        Args:
            approval_id: ID of the approval request
            approved: Whether to approve or deny
            reason: Optional reason for the decision
        """
        # SECURITY (FIND-R56-SDK-001): Validate approval_id — aligned with Go/TS SDKs.
        _validate_approval_id(approval_id)
        action = "approve" if approved else "deny"
        json_data: Optional[Dict[str, Any]] = None
        if reason is not None:
            json_data = {"reason": reason}
        # SECURITY: URL-encode approval_id to prevent path injection (parity with Go/TS).
        encoded_id = quote(approval_id, safe="")
        return await self._request(
            method="POST",
            path=f"/api/approvals/{encoded_id}/{action}",
            json_data=json_data,
        )

    async def discover(
        self,
        query: str,
        max_results: int = 5,
        token_budget: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Search the tool discovery index for matching tools (async)."""
        # SECURITY (FIND-R55-SDK-001): Validate query non-empty.
        if not isinstance(query, str) or not query.strip():
            raise VellavetoError("discovery query must not be empty")
        payload: Dict[str, Any] = {
            "query": query,
            "max_results": max_results,
        }
        if token_budget is not None:
            payload["token_budget"] = token_budget

        return await self._request(
            "POST", "/api/discovery/search", json_data=payload
        )

    async def discovery_stats(self) -> Dict[str, Any]:
        """Get statistics about the tool discovery index (async)."""
        return await self._request("GET", "/api/discovery/index/stats")

    async def discovery_reindex(self) -> Dict[str, Any]:
        """Trigger a full rebuild of the IDF weights (async)."""
        return await self._request("POST", "/api/discovery/reindex")

    async def discovery_tools(
        self,
        server_id: Optional[str] = None,
        sensitivity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List all indexed tools, optionally filtered (async)."""
        params: Dict[str, str] = {}
        if server_id is not None:
            params["server_id"] = server_id
        if sensitivity is not None:
            params["sensitivity"] = sensitivity

        return await self._request(
            "GET", "/api/discovery/tools", params=params if params else None
        )

    # ── Projector (Phase 35.3) ───────────────────────────────────

    async def projector_models(self) -> Dict[str, Any]:
        """List supported model families in the projector registry (async)."""
        return await self._request("GET", "/api/projector/models")

    async def project_schema(
        self,
        schema: Dict[str, Any],
        model_family: str,
    ) -> Dict[str, Any]:
        """Project a canonical tool schema for a given model family (async)."""
        # SECURITY (FIND-R55-SDK-007): Validate model_family non-empty.
        if not isinstance(model_family, str) or not model_family.strip():
            raise VellavetoError("model_family must be a non-empty string")
        payload = {
            "schema": schema,
            "model_family": model_family,
        }
        return await self._request(
            "POST", "/api/projector/transform", json_data=payload
        )

    # ── ZK Audit (Phase 37) ────────────────────────────────────────

    async def zk_status(self) -> Dict[str, Any]:
        """Get the ZK audit scheduler status (async)."""
        return await self._request("GET", "/api/zk-audit/status")

    async def zk_proofs(
        self,
        limit: int = 20,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List stored ZK batch proofs with pagination (async)."""
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        return await self._request("GET", "/api/zk-audit/proofs", params=params)

    async def zk_verify(self, batch_id: str) -> Dict[str, Any]:
        """Verify a stored ZK batch proof (async)."""
        # SECURITY (FIND-R55-SDK-002): Validate batch_id non-empty.
        if not isinstance(batch_id, str) or not batch_id.strip():
            raise VellavetoError("batch_id must not be empty")
        return await self._request(
            "POST", "/api/zk-audit/verify", json_data={"batch_id": batch_id}
        )

    async def zk_commitments(
        self,
        from_seq: int,
        to_seq: int,
    ) -> Dict[str, Any]:
        """List Pedersen commitments for entries in a sequence range (async)."""
        params = {"from": from_seq, "to": to_seq}
        return await self._request(
            "GET", "/api/zk-audit/commitments", params=params
        )

    async def soc2_access_review(
        self,
        period: str = "30d",
        export_format: str = "json",
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate a SOC 2 Type II access review report (async).

        Args:
            period: Review period duration (e.g. "30d", "7d", "90d")
            export_format: Export format ("json" or "html")
            agent_id: Optional agent ID filter (max 128 chars)

        Returns:
            Access review report as dictionary (JSON) or raw HTML string
        """
        # SECURITY (FIND-R72-SDK-007): Validate format parameter. Parity with Go/TS SDKs.
        if export_format not in ("json", "html"):
            raise VellavetoError(
                f'export_format must be "json" or "html", got {export_format!r}'
            )
        if agent_id is not None:
            if not isinstance(agent_id, str):
                raise VellavetoError("agent_id must be a string")
            if len(agent_id) > 128:
                raise VellavetoError("agent_id exceeds max length (128)")
            # SECURITY (FIND-R55-SDK-003): Reject control chars.
            if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in agent_id):
                raise VellavetoError("agent_id contains control characters")
        params: Dict[str, Any] = {"period": period, "format": export_format}
        if agent_id is not None:
            params["agent_id"] = agent_id
        return await self._request(
            "GET", "/api/compliance/soc2/access-review", params=params
        )

    # ── Federation (Phase 39) ─────────────────────────────────────

    async def federation_status(self) -> Dict[str, Any]:
        """Get federation status including per-anchor cache info (async)."""
        return await self._request("GET", "/api/federation/status")

    async def federation_trust_anchors(
        self,
        org_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List federation trust anchors (async)."""
        params: Dict[str, str] = {}
        if org_id is not None:
            if len(org_id) > 128:
                raise VellavetoError("org_id exceeds max length (128)")
            # SECURITY (FIND-R50-037): Catch DEL (0x7F) and C1 control chars (0x80-0x9F)
            if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in org_id):
                raise VellavetoError("org_id contains control characters")
            params["org_id"] = org_id
        return await self._request(
            "GET", "/api/federation/trust-anchors", params=params if params else None
        )
