"""Tests for vellaveto.client module."""

import json

import pytest
import httpx

from vellaveto.client import (
    ApprovalRequired,
    AsyncVellavetoClient,
    ConnectionError,
    PolicyDenied,
    VellavetoClient,
    VellavetoError,
)
from vellaveto.types import EvaluationContext, Verdict


class TestVellavetoClientInit:
    """Tests for VellavetoClient initialization."""

    def test_default_url(self):
        client = VellavetoClient()
        assert client.url == "http://localhost:3000"
        client.close()

    def test_custom_url_trailing_slash(self):
        client = VellavetoClient(url="http://example.com:9090/")
        assert client.url == "http://example.com:9090"
        client.close()

    def test_api_key(self):
        client = VellavetoClient(api_key="test-key-123")
        assert client.api_key == "test-key-123"
        client.close()

    def test_custom_timeout(self):
        client = VellavetoClient(timeout=5.0)
        assert client.timeout == 5.0
        client.close()

    def test_headers_without_api_key(self):
        client = VellavetoClient()
        headers = client._headers()
        assert "Authorization" not in headers
        assert headers["Content-Type"] == "application/json"
        assert headers["Accept"] == "application/json"
        client.close()

    def test_headers_with_api_key(self):
        client = VellavetoClient(api_key="my-key")
        headers = client._headers()
        assert headers["Authorization"] == "Bearer my-key"
        client.close()


class TestVellavetoClientEvaluate:
    """Tests for VellavetoClient.evaluate() with mocked HTTP."""

    def test_evaluate_allow(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow", "policy_id": "p1", "policy_name": "test-policy"},
        )

        client = VellavetoClient()
        result = client.evaluate(tool="filesystem", function="read_file")
        assert result.verdict == Verdict.ALLOW
        assert result.policy_id == "p1"
        client.close()

    def test_evaluate_deny(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "deny", "reason": "Path blocked by policy"},
        )

        client = VellavetoClient()
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

        client = VellavetoClient()
        result = client.evaluate(tool="database", function="drop_table")
        assert result.verdict == Verdict.REQUIRE_APPROVAL
        assert result.approval_id == "apr-456"
        client.close()

    def test_evaluate_with_context(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient()
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

        client = VellavetoClient()
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

        client = VellavetoClient()
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


class TestVellavetoClientEvaluateOrRaise:
    """Tests for VellavetoClient.evaluate_or_raise()."""

    def test_evaluate_or_raise_allow(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient()
        result = client.evaluate_or_raise(tool="filesystem", function="read_file")
        assert result.verdict == Verdict.ALLOW
        client.close()

    def test_evaluate_or_raise_deny(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "deny", "reason": "Blocked", "policy_id": "p1"},
        )

        client = VellavetoClient()
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

        client = VellavetoClient()
        with pytest.raises(ApprovalRequired) as exc_info:
            client.evaluate_or_raise(tool="database", function="delete")

        assert exc_info.value.reason == "Needs review"
        assert exc_info.value.approval_id == "apr-789"
        assert "apr-789" in str(exc_info.value)
        client.close()


class TestVellavetoClientEndpoints:
    """Tests for other VellavetoClient API methods."""

    def test_health(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/health",
            json={"status": "ok", "version": "2.2.1"},
        )

        client = VellavetoClient()
        result = client.health()
        assert result["status"] == "ok"
        client.close()

    def test_list_policies(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/policies",
            json=[{"id": "p1", "name": "test"}],
        )

        client = VellavetoClient()
        result = client.list_policies()
        assert len(result) == 1
        assert result[0]["id"] == "p1"
        client.close()

    def test_reload_policies(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/policies/reload",
            json={"reloaded": True, "policy_count": 5},
        )

        client = VellavetoClient()
        result = client.reload_policies()
        assert result["reloaded"] is True
        client.close()

    def test_get_pending_approvals(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/approvals",
            json=[{"id": "apr-1", "tool": "database", "status": "pending"}],
        )

        client = VellavetoClient()
        result = client.get_pending_approvals()
        assert len(result) == 1
        assert result[0]["id"] == "apr-1"
        client.close()

    def test_resolve_approval(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/approvals/apr-1",
            json={"resolved": True},
        )

        client = VellavetoClient()
        result = client.resolve_approval("apr-1", approved=True, reason="Verified")
        assert result["resolved"] is True

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["approved"] is True
        assert body["reason"] == "Verified"
        client.close()


class TestVellavetoClientErrors:
    """Tests for error handling in VellavetoClient."""

    def test_http_error_raises_vellaveto_error(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            status_code=500,
        )

        client = VellavetoClient()
        with pytest.raises(VellavetoError):
            client.evaluate(tool="test")
        client.close()

    def test_connection_error(self, httpx_mock):
        httpx_mock.add_exception(
            httpx.ConnectError("Connection refused"),
            url="http://localhost:3000/api/evaluate",
        )

        client = VellavetoClient()
        with pytest.raises(VellavetoError):
            client.evaluate(tool="test")
        client.close()


class TestExceptionHierarchy:
    """Tests for exception class hierarchy."""

    def test_policy_denied_is_vellaveto_error(self):
        err = PolicyDenied("test reason", "p1")
        assert isinstance(err, VellavetoError)
        assert isinstance(err, Exception)

    def test_approval_required_is_vellaveto_error(self):
        err = ApprovalRequired("test reason", "apr-1")
        assert isinstance(err, VellavetoError)

    def test_connection_error_is_vellaveto_error(self):
        err = ConnectionError("failed")
        assert isinstance(err, VellavetoError)

    def test_policy_denied_attributes(self):
        err = PolicyDenied("blocked by rule", "policy-123")
        assert err.reason == "blocked by rule"
        assert err.policy_id == "policy-123"

    def test_approval_required_attributes(self):
        err = ApprovalRequired("needs review", "apr-456")
        assert err.reason == "needs review"
        assert err.approval_id == "apr-456"


class TestAsyncVellavetoClient:
    """Tests for AsyncVellavetoClient."""

    @pytest.mark.asyncio
    async def test_async_evaluate_allow(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow", "policy_id": "p1"},
        )

        async with AsyncVellavetoClient() as client:
            result = await client.evaluate(tool="filesystem", function="read_file")
            assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_async_evaluate_deny(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "deny", "reason": "Blocked"},
        )

        async with AsyncVellavetoClient() as client:
            result = await client.evaluate(tool="test")
            assert result.verdict == Verdict.DENY
            assert result.reason == "Blocked"

    @pytest.mark.asyncio
    async def test_async_evaluate_or_raise_deny(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "deny", "reason": "No"},
        )

        async with AsyncVellavetoClient() as client:
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

        async with AsyncVellavetoClient() as client:
            with pytest.raises(ApprovalRequired):
                await client.evaluate_or_raise(tool="test")

    @pytest.mark.asyncio
    async def test_async_health(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/health",
            json={"status": "ok"},
        )

        async with AsyncVellavetoClient() as client:
            result = await client.health()
            assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_async_list_policies(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/policies",
            json=[{"id": "p1"}],
        )

        async with AsyncVellavetoClient() as client:
            result = await client.list_policies()
            assert len(result) == 1

    @pytest.mark.asyncio
    async def test_async_not_initialized_raises(self):
        client = AsyncVellavetoClient()
        with pytest.raises(VellavetoError, match="not initialized"):
            await client.evaluate(tool="test")

    def test_async_requires_httpx(self, monkeypatch):
        """AsyncVellavetoClient requires httpx."""
        import vellaveto.client as client_mod

        monkeypatch.setattr(client_mod, "HAS_HTTPX", False)
        with pytest.raises(ImportError, match="httpx"):
            AsyncVellavetoClient()


class TestZkAuditSync:
    """Tests for VellavetoClient ZK audit methods (Phase 37)."""

    def test_zk_status(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/zk-audit/status",
            json={
                "active": True,
                "pending_witnesses": 5,
                "completed_proofs": 10,
                "last_proved_sequence": 42,
                "last_proof_at": "2026-02-16T00:00:00Z",
            },
        )
        client = VellavetoClient()
        result = client.zk_status()
        assert result["active"] is True
        assert result["completed_proofs"] == 10
        client.close()

    def test_zk_status_disabled(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/zk-audit/status",
            json={"active": False, "pending_witnesses": 0, "completed_proofs": 0},
        )
        client = VellavetoClient()
        result = client.zk_status()
        assert result["active"] is False
        client.close()

    def test_zk_proofs_default_params(self, httpx_mock):
        httpx_mock.add_response(
            url=httpx.URL(
                "http://localhost:3000/api/zk-audit/proofs",
                params={"limit": "20", "offset": "0"},
            ),
            json={"proofs": [], "total": 0, "offset": 0, "limit": 20},
        )
        client = VellavetoClient()
        result = client.zk_proofs()
        assert result["total"] == 0
        assert result["proofs"] == []
        client.close()

    def test_zk_proofs_custom_params(self, httpx_mock):
        httpx_mock.add_response(
            url=httpx.URL(
                "http://localhost:3000/api/zk-audit/proofs",
                params={"limit": "50", "offset": "10"},
            ),
            json={"proofs": [{"batch_id": "b1"}], "total": 1, "offset": 10, "limit": 50},
        )
        client = VellavetoClient()
        result = client.zk_proofs(limit=50, offset=10)
        assert result["total"] == 1
        assert len(result["proofs"]) == 1
        client.close()

    def test_zk_verify(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/zk-audit/verify",
            json={
                "valid": True,
                "batch_id": "test-batch",
                "entry_range": [0, 10],
                "verified_at": "2026-02-16T00:00:00Z",
            },
        )
        client = VellavetoClient()
        result = client.zk_verify("test-batch")
        assert result["valid"] is True
        assert result["batch_id"] == "test-batch"
        client.close()

    def test_zk_verify_invalid(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/zk-audit/verify",
            json={
                "valid": False,
                "batch_id": "bad-batch",
                "entry_range": [0, 5],
                "verified_at": "2026-02-16T00:00:00Z",
                "error": "Proof verification failed",
            },
        )
        client = VellavetoClient()
        result = client.zk_verify("bad-batch")
        assert result["valid"] is False
        assert result["error"] == "Proof verification failed"
        client.close()

    def test_zk_commitments(self, httpx_mock):
        httpx_mock.add_response(
            url=httpx.URL(
                "http://localhost:3000/api/zk-audit/commitments",
                params={"from": "0", "to": "100"},
            ),
            json={
                "commitments": [
                    {"sequence": 1, "commitment": "abc123", "timestamp": "2026-02-16T00:00:00Z"}
                ],
                "total": 1,
                "range": [0, 100],
            },
        )
        client = VellavetoClient()
        result = client.zk_commitments(from_seq=0, to_seq=100)
        assert result["total"] == 1
        assert len(result["commitments"]) == 1
        assert result["commitments"][0]["sequence"] == 1
        client.close()

    def test_zk_commitments_empty_range(self, httpx_mock):
        httpx_mock.add_response(
            url=httpx.URL(
                "http://localhost:3000/api/zk-audit/commitments",
                params={"from": "50", "to": "50"},
            ),
            json={"commitments": [], "total": 0, "range": [50, 50]},
        )
        client = VellavetoClient()
        result = client.zk_commitments(from_seq=50, to_seq=50)
        assert result["total"] == 0
        client.close()


class TestZkAuditAsync:
    """Tests for AsyncVellavetoClient ZK audit methods (Phase 37)."""

    @pytest.mark.asyncio
    async def test_async_zk_status(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/zk-audit/status",
            json={"active": False, "pending_witnesses": 0, "completed_proofs": 0},
        )
        async with AsyncVellavetoClient() as client:
            result = await client.zk_status()
            assert result["active"] is False

    @pytest.mark.asyncio
    async def test_async_zk_proofs(self, httpx_mock):
        httpx_mock.add_response(
            url=httpx.URL(
                "http://localhost:3000/api/zk-audit/proofs",
                params={"limit": "20", "offset": "0"},
            ),
            json={"proofs": [], "total": 0, "offset": 0, "limit": 20},
        )
        async with AsyncVellavetoClient() as client:
            result = await client.zk_proofs()
            assert result["total"] == 0

    @pytest.mark.asyncio
    async def test_async_zk_verify(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/zk-audit/verify",
            json={
                "valid": True,
                "batch_id": "async-batch",
                "entry_range": [0, 5],
                "verified_at": "2026-02-16T00:00:00Z",
            },
        )
        async with AsyncVellavetoClient() as client:
            result = await client.zk_verify("async-batch")
            assert result["valid"] is True

    @pytest.mark.asyncio
    async def test_async_zk_commitments(self, httpx_mock):
        httpx_mock.add_response(
            url=httpx.URL(
                "http://localhost:3000/api/zk-audit/commitments",
                params={"from": "0", "to": "50"},
            ),
            json={"commitments": [], "total": 0, "range": [0, 50]},
        )
        async with AsyncVellavetoClient() as client:
            result = await client.zk_commitments(from_seq=0, to_seq=50)
            assert result["total"] == 0
