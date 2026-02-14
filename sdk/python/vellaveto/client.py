"""
Vellaveto API client for Python.

Provides synchronous and asynchronous HTTP client for the Vellaveto API.
"""

import json
import logging
from typing import Optional, Dict, Any, List
from urllib.parse import urljoin

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


class ConnectionError(VellavetoError):
    """Raised when unable to connect to Vellaveto server."""
    pass


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
        timeout: float = 30.0,
        verify_ssl: bool = True,
        redactor: Optional["ParameterRedactor"] = None,
    ):
        """
        Initialize the Vellaveto client.

        Args:
            url: Base URL of the Vellaveto server
            api_key: API key for authentication
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            redactor: Optional ParameterRedactor for client-side secret stripping
        """
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.redactor = redactor

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
        """Make an HTTP request to the Vellaveto API."""
        url = urljoin(self.url + "/", path.lstrip("/"))

        try:
            if self._use_httpx:
                response = self._client.request(
                    method=method,
                    url=url,
                    json=json_data,
                    params=params,
                    headers=self._headers(),
                )
                response.raise_for_status()
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
                response.raise_for_status()
                return response.json()

        except Exception as e:
            if "Connection" in str(type(e).__name__):
                raise ConnectionError(f"Failed to connect to Vellaveto at {url}: {e}")
            raise VellavetoError(f"Request failed: {e}")

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

        payload = {"action": action.to_dict()}

        if context:
            payload["context"] = context.to_dict()

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
        return self._request("GET", "/api/approvals")

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
        return self._request(
            method="POST",
            path=f"/api/approvals/{approval_id}",
            json_data={
                "approved": approved,
                "reason": reason,
            },
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
        timeout: float = 30.0,
        verify_ssl: bool = True,
        redactor: Optional["ParameterRedactor"] = None,
    ):
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
        if not self._client:
            raise VellavetoError("Client not initialized. Use 'async with' context.")

        url = urljoin(self.url + "/", path.lstrip("/"))

        try:
            response = await self._client.request(
                method=method,
                url=url,
                json=json_data,
                params=params,
                headers=self._headers(),
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            if "Connection" in str(type(e).__name__):
                raise ConnectionError(f"Failed to connect to Vellaveto at {url}: {e}")
            raise VellavetoError(f"Request failed: {e}")

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

        payload = {"action": action.to_dict()}

        if context:
            payload["context"] = context.to_dict()

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
        return await self._request("GET", "/health")

    async def list_policies(self) -> List[Dict[str, Any]]:
        return await self._request("GET", "/api/policies")
