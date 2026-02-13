"""Tests for sentinel.client module."""

import json

import pytest
import httpx

from sentinel.client import (
    ApprovalRequired,
    AsyncSentinelClient,
    ConnectionError,
    PolicyDenied,
    SentinelClient,
    SentinelError,
)
from sentinel.types import EvaluationContext, Verdict


class TestSentinelClientInit:
    """Tests for SentinelClient initialization."""

    def test_default_url(self):
        client = SentinelClient()
        assert client.url == "http://localhost:3000"
        client.close()

    def test_custom_url_trailing_slash(self):
        client = SentinelClient(url="http://example.com:9090/")
        assert client.url == "http://example.com:9090"
        client.close()

    def test_api_key(self):
        client = SentinelClient(api_key="test-key-123")
        assert client.api_key == "test-key-123"
        client.close()

    def test_custom_timeout(self):
        client = SentinelClient(timeout=5.0)
        assert client.timeout == 5.0
        client.close()

    def test_headers_without_api_key(self):
        client = SentinelClient()
        headers = client._headers()
        assert "Authorization" not in headers
        assert headers["Content-Type"] == "application/json"
        assert headers["Accept"] == "application/json"
        client.close()

    def test_headers_with_api_key(self):
        client = SentinelClient(api_key="my-key")
        headers = client._headers()
        assert headers["Authorization"] == "Bearer my-key"
        client.close()


class TestSentinelClientEvaluate:
    """Tests for SentinelClient.evaluate() with mocked HTTP."""

    def test_evaluate_allow(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow", "policy_id": "p1", "policy_name": "test-policy"},
        )

        client = SentinelClient()
        result = client.evaluate(tool="filesystem", function="read_file")
        assert result.verdict == Verdict.ALLOW
        assert result.policy_id == "p1"
        client.close()

    def test_evaluate_deny(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "deny", "reason": "Path blocked by policy"},
        )

        client = SentinelClient()
        result = client.evaluate(
            tool="filesystem",
            function="write_file",
            parameters={"path": "/etc/shadow"},
            target_paths=["/etc/shadow"],
        )
        assert result.verdict == Verdict.DENY
        assert result.reason == "Path blocked by policy"
        client.close()

    def test_evaluate_require_approval(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={
                "verdict": "require_approval",
                "reason": "Sensitive operation",
                "approval_id": "apr-456",
            },
        )

        client = SentinelClient()
        result = client.evaluate(tool="database", function="drop_table")
        assert result.verdict == Verdict.REQUIRE_APPROVAL
        assert result.approval_id == "apr-456"
        client.close()

    def test_evaluate_with_context(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = SentinelClient()
        ctx = EvaluationContext(
            session_id="sess-1",
            agent_id="agent-1",
            call_chain=["tool_a"],
        )
        result = client.evaluate(tool="http", function="fetch", context=ctx)
        assert result.verdict == Verdict.ALLOW

        # Verify context was sent in request body
        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["context"]["session_id"] == "sess-1"
        assert body["context"]["agent_id"] == "agent-1"
        assert body["context"]["call_chain"] == ["tool_a"]
        client.close()

    def test_evaluate_with_trace(self, httpx_mock):
        httpx_mock.add_response(
            json={
                "verdict": "allow",
                "trace": {"duration_ms": 0.5},
            },
        )

        client = SentinelClient()
        result = client.evaluate(tool="test", trace=True)
        assert result.trace is not None

        request = httpx_mock.get_request()
        assert "trace=true" in str(request.url)
        client.close()

    def test_evaluate_request_payload(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = SentinelClient()
        client.evaluate(
            tool="filesystem",
            function="read_file",
            parameters={"path": "/tmp/test.txt"},
            target_paths=["/tmp/test.txt"],
            target_domains=["example.com"],
        )

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["action"]["tool"] == "filesystem"
        assert body["action"]["function"] == "read_file"
        assert body["action"]["parameters"] == {"path": "/tmp/test.txt"}
        assert body["action"]["target_paths"] == ["/tmp/test.txt"]
        assert body["action"]["target_domains"] == ["example.com"]
        client.close()


class TestSentinelClientEvaluateOrRaise:
    """Tests for SentinelClient.evaluate_or_raise()."""

    def test_evaluate_or_raise_allow(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = SentinelClient()
        result = client.evaluate_or_raise(tool="filesystem", function="read_file")
        assert result.verdict == Verdict.ALLOW
        client.close()

    def test_evaluate_or_raise_deny(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "deny", "reason": "Blocked", "policy_id": "p1"},
        )

        client = SentinelClient()
        with pytest.raises(PolicyDenied) as exc_info:
            client.evaluate_or_raise(tool="filesystem", function="write_file")

        assert exc_info.value.reason == "Blocked"
        assert exc_info.value.policy_id == "p1"
        assert "Policy denied" in str(exc_info.value)
        client.close()

    def test_evaluate_or_raise_approval_required(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={
                "verdict": "require_approval",
                "reason": "Needs review",
                "approval_id": "apr-789",
            },
        )

        client = SentinelClient()
        with pytest.raises(ApprovalRequired) as exc_info:
            client.evaluate_or_raise(tool="database", function="delete")

        assert exc_info.value.reason == "Needs review"
        assert exc_info.value.approval_id == "apr-789"
        assert "apr-789" in str(exc_info.value)
        client.close()


class TestSentinelClientEndpoints:
    """Tests for other SentinelClient API methods."""

    def test_health(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/health",
            json={"status": "ok", "version": "2.2.1"},
        )

        client = SentinelClient()
        result = client.health()
        assert result["status"] == "ok"
        client.close()

    def test_list_policies(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/policies",
            json=[{"id": "p1", "name": "test"}],
        )

        client = SentinelClient()
        result = client.list_policies()
        assert len(result) == 1
        assert result[0]["id"] == "p1"
        client.close()

    def test_reload_policies(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/policies/reload",
            json={"reloaded": True, "policy_count": 5},
        )

        client = SentinelClient()
        result = client.reload_policies()
        assert result["reloaded"] is True
        client.close()

    def test_get_pending_approvals(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/approvals",
            json=[{"id": "apr-1", "tool": "database", "status": "pending"}],
        )

        client = SentinelClient()
        result = client.get_pending_approvals()
        assert len(result) == 1
        assert result[0]["id"] == "apr-1"
        client.close()

    def test_resolve_approval(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/approvals/apr-1",
            json={"resolved": True},
        )

        client = SentinelClient()
        result = client.resolve_approval("apr-1", approved=True, reason="Verified")
        assert result["resolved"] is True

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["approved"] is True
        assert body["reason"] == "Verified"
        client.close()


class TestSentinelClientErrors:
    """Tests for error handling in SentinelClient."""

    def test_http_error_raises_sentinel_error(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            status_code=500,
        )

        client = SentinelClient()
        with pytest.raises(SentinelError):
            client.evaluate(tool="test")
        client.close()

    def test_connection_error(self, httpx_mock):
        httpx_mock.add_exception(
            httpx.ConnectError("Connection refused"),
            url="http://localhost:3000/api/evaluate",
        )

        client = SentinelClient()
        with pytest.raises(SentinelError):
            client.evaluate(tool="test")
        client.close()


class TestExceptionHierarchy:
    """Tests for exception class hierarchy."""

    def test_policy_denied_is_sentinel_error(self):
        err = PolicyDenied("test reason", "p1")
        assert isinstance(err, SentinelError)
        assert isinstance(err, Exception)

    def test_approval_required_is_sentinel_error(self):
        err = ApprovalRequired("test reason", "apr-1")
        assert isinstance(err, SentinelError)

    def test_connection_error_is_sentinel_error(self):
        err = ConnectionError("failed")
        assert isinstance(err, SentinelError)

    def test_policy_denied_attributes(self):
        err = PolicyDenied("blocked by rule", "policy-123")
        assert err.reason == "blocked by rule"
        assert err.policy_id == "policy-123"

    def test_approval_required_attributes(self):
        err = ApprovalRequired("needs review", "apr-456")
        assert err.reason == "needs review"
        assert err.approval_id == "apr-456"


class TestAsyncSentinelClient:
    """Tests for AsyncSentinelClient."""

    @pytest.mark.asyncio
    async def test_async_evaluate_allow(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow", "policy_id": "p1"},
        )

        async with AsyncSentinelClient() as client:
            result = await client.evaluate(tool="filesystem", function="read_file")
            assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_async_evaluate_deny(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "deny", "reason": "Blocked"},
        )

        async with AsyncSentinelClient() as client:
            result = await client.evaluate(tool="test")
            assert result.verdict == Verdict.DENY
            assert result.reason == "Blocked"

    @pytest.mark.asyncio
    async def test_async_evaluate_or_raise_deny(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "deny", "reason": "No"},
        )

        async with AsyncSentinelClient() as client:
            with pytest.raises(PolicyDenied):
                await client.evaluate_or_raise(tool="test")

    @pytest.mark.asyncio
    async def test_async_evaluate_or_raise_approval(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={
                "verdict": "require_approval",
                "reason": "Review",
                "approval_id": "apr-1",
            },
        )

        async with AsyncSentinelClient() as client:
            with pytest.raises(ApprovalRequired):
                await client.evaluate_or_raise(tool="test")

    @pytest.mark.asyncio
    async def test_async_health(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/health",
            json={"status": "ok"},
        )

        async with AsyncSentinelClient() as client:
            result = await client.health()
            assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_async_list_policies(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/policies",
            json=[{"id": "p1"}],
        )

        async with AsyncSentinelClient() as client:
            result = await client.list_policies()
            assert len(result) == 1

    @pytest.mark.asyncio
    async def test_async_not_initialized_raises(self):
        client = AsyncSentinelClient()
        with pytest.raises(SentinelError, match="not initialized"):
            await client.evaluate(tool="test")

    def test_async_requires_httpx(self, monkeypatch):
        """AsyncSentinelClient requires httpx."""
        import sentinel.client as client_mod

        monkeypatch.setattr(client_mod, "HAS_HTTPX", False)
        with pytest.raises(ImportError, match="httpx"):
            AsyncSentinelClient()
