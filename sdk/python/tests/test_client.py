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

        # Verify context was sent in flattened request body
        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["tool"] == "http"
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
        # P0-2: Payload is flattened (no "action" wrapper) to match server's
        # #[serde(flatten)] expectation.
        assert body["tool"] == "filesystem"
        assert body["function"] == "read_file"
        assert body["parameters"] == {"path": "/tmp/test.txt"}
        assert body["target_paths"] == ["/tmp/test.txt"]
        assert body["target_domains"] == ["example.com"]
        assert "action" not in body
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
            url="http://localhost:3000/api/approvals/pending",
            json=[{"id": "apr-1", "tool": "database", "status": "pending"}],
        )

        client = VellavetoClient()
        result = client.get_pending_approvals()
        assert len(result) == 1
        assert result[0]["id"] == "apr-1"
        client.close()

    def test_resolve_approval_approve(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/approvals/apr-1/approve",
            json={"resolved": True},
        )

        client = VellavetoClient()
        result = client.resolve_approval("apr-1", approved=True, reason="Verified")
        assert result["resolved"] is True

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["reason"] == "Verified"
        client.close()

    def test_resolve_approval_deny(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/approvals/apr-1/deny",
            json={"resolved": True},
        )

        client = VellavetoClient()
        result = client.resolve_approval("apr-1", approved=False, reason="Rejected")
        assert result["resolved"] is True

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["reason"] == "Rejected"
        client.close()

    def test_resolve_approval_no_reason(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/approvals/apr-1/approve",
            json={"resolved": True},
        )

        client = VellavetoClient()
        result = client.resolve_approval("apr-1", approved=True)
        assert result["resolved"] is True

        # No reason provided — json_data should be None (no body)
        request = httpx_mock.get_request()
        assert request.content == b""
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

    @pytest.mark.asyncio
    async def test_async_evaluate_input_validation_empty_tool(self):
        """P1-12: Async evaluate() validates inputs like sync does."""
        async with AsyncVellavetoClient() as client:
            with pytest.raises(VellavetoError, match="non-empty string"):
                await client.evaluate(tool="")

    @pytest.mark.asyncio
    async def test_async_evaluate_input_validation_whitespace_tool(self):
        async with AsyncVellavetoClient() as client:
            with pytest.raises(VellavetoError, match="non-empty string"):
                await client.evaluate(tool="   ")

    @pytest.mark.asyncio
    async def test_async_evaluate_input_validation_tool_too_long(self):
        async with AsyncVellavetoClient() as client:
            with pytest.raises(VellavetoError, match="too long"):
                await client.evaluate(tool="x" * 2000)

    @pytest.mark.asyncio
    async def test_async_evaluate_input_validation_bad_function_type(self):
        async with AsyncVellavetoClient() as client:
            with pytest.raises(VellavetoError, match="function must be a string"):
                await client.evaluate(tool="valid", function=123)  # type: ignore

    @pytest.mark.asyncio
    async def test_async_evaluate_input_validation_bad_parameters_type(self):
        async with AsyncVellavetoClient() as client:
            with pytest.raises(VellavetoError, match="parameters must be a dict"):
                await client.evaluate(tool="valid", parameters="bad")  # type: ignore

    @pytest.mark.asyncio
    async def test_async_evaluate_input_validation_bad_target_paths_type(self):
        async with AsyncVellavetoClient() as client:
            with pytest.raises(VellavetoError, match="target_paths must be a list"):
                await client.evaluate(tool="valid", target_paths="bad")  # type: ignore

    @pytest.mark.asyncio
    async def test_async_evaluate_input_validation_bad_target_domains_type(self):
        async with AsyncVellavetoClient() as client:
            with pytest.raises(VellavetoError, match="target_domains must be a list"):
                await client.evaluate(tool="valid", target_domains="bad")  # type: ignore

    @pytest.mark.asyncio
    async def test_async_evaluate_flattened_payload(self, httpx_mock):
        """P0-2: Async evaluate() sends flattened payload (no 'action' wrapper)."""
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        async with AsyncVellavetoClient() as client:
            await client.evaluate(
                tool="filesystem",
                function="read_file",
                parameters={"path": "/tmp/test.txt"},
                target_paths=["/tmp/test.txt"],
                target_domains=["example.com"],
            )

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["tool"] == "filesystem"
        assert body["function"] == "read_file"
        assert body["parameters"] == {"path": "/tmp/test.txt"}
        assert body["target_paths"] == ["/tmp/test.txt"]
        assert body["target_domains"] == ["example.com"]
        assert "action" not in body

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


# ── Round 46 P3 Fixes ──────────────────────────────────────────────────


class TestReprRedactsApiKey:
    """Tests for FIND-SDK-013: __repr__ should redact api_key."""

    def test_repr_redacts_api_key(self):
        client = VellavetoClient(api_key="super-secret-key-123")
        r = repr(client)
        assert "super-secret-key-123" not in r
        assert "***" in r
        client.close()

    def test_repr_without_api_key(self):
        client = VellavetoClient()
        r = repr(client)
        assert "VellavetoClient(" in r
        assert "***" in r
        client.close()


class TestRetryWithBackoff:
    """Tests for FIND-SDK-014: Retry with backoff on transient failures."""

    def test_retry_on_502(self, httpx_mock):
        # First response: 502, second: success
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            status_code=502,
        )
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient(max_retries=1)
        result = client.evaluate(tool="test")
        assert result.verdict == Verdict.ALLOW
        assert len(httpx_mock.get_requests()) == 2
        client.close()

    def test_no_retry_on_400(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            status_code=400,
        )

        client = VellavetoClient(max_retries=2)
        with pytest.raises(VellavetoError):
            client.evaluate(tool="test")
        assert len(httpx_mock.get_requests()) == 1
        client.close()

    def test_max_retries_zero_no_retry(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            status_code=503,
        )

        client = VellavetoClient(max_retries=0)
        with pytest.raises(VellavetoError):
            client.evaluate(tool="test")
        assert len(httpx_mock.get_requests()) == 1
        client.close()

    def test_all_retries_exhausted(self, httpx_mock):
        for _ in range(3):
            httpx_mock.add_response(
                url="http://localhost:3000/api/evaluate",
                status_code=503,
            )

        client = VellavetoClient(max_retries=2)
        with pytest.raises(VellavetoError, match="after 3 attempts"):
            client.evaluate(tool="test")
        assert len(httpx_mock.get_requests()) == 3
        client.close()


class TestEvaluateInputValidation:
    """Tests for FIND-SDK-020: Input validation on evaluate()."""

    def test_empty_tool_raises(self):
        client = VellavetoClient()
        with pytest.raises(VellavetoError, match="non-empty string"):
            client.evaluate(tool="")
        client.close()

    def test_whitespace_tool_raises(self):
        client = VellavetoClient()
        with pytest.raises(VellavetoError, match="non-empty string"):
            client.evaluate(tool="   ")
        client.close()

    def test_tool_too_long_raises(self):
        client = VellavetoClient()
        with pytest.raises(VellavetoError, match="too long"):
            client.evaluate(tool="x" * 2000)
        client.close()

    def test_function_too_long_raises(self):
        client = VellavetoClient()
        with pytest.raises(VellavetoError, match="too long"):
            client.evaluate(tool="valid", function="f" * 2000)
        client.close()

    def test_non_string_function_raises(self):
        client = VellavetoClient()
        with pytest.raises(VellavetoError, match="function must be a string"):
            client.evaluate(tool="valid", function=123)  # type: ignore
        client.close()

    def test_non_dict_parameters_raises(self):
        client = VellavetoClient()
        with pytest.raises(VellavetoError, match="parameters must be a dict"):
            client.evaluate(tool="valid", parameters="not-a-dict")  # type: ignore
        client.close()

    def test_non_list_target_paths_raises(self):
        client = VellavetoClient()
        with pytest.raises(VellavetoError, match="target_paths must be a list"):
            client.evaluate(tool="valid", target_paths="not-a-list")  # type: ignore
        client.close()

    def test_non_list_target_domains_raises(self):
        client = VellavetoClient()
        with pytest.raises(VellavetoError, match="target_domains must be a list"):
            client.evaluate(tool="valid", target_domains="not-a-list")  # type: ignore
        client.close()

    def test_valid_inputs_accepted(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )
        client = VellavetoClient()
        result = client.evaluate(
            tool="filesystem",
            function="read",
            parameters={"path": "/tmp"},
            target_paths=["/tmp"],
            target_domains=[],
        )
        assert result.verdict == Verdict.ALLOW
        client.close()


class TestSoc2AccessReview:
    """Tests for SOC 2 Type II access review methods (Phase 38)."""

    def test_soc2_access_review_default_params(self, httpx_mock):
        httpx_mock.add_response(
            url=httpx.URL(
                "http://localhost:3000/api/compliance/soc2/access-review",
                params={"period": "30d", "format": "json"},
            ),
            json={
                "generated_at": "2026-02-16T00:00:00Z",
                "organization_name": "Acme",
                "total_agents": 2,
                "total_evaluations": 100,
            },
        )
        client = VellavetoClient()
        result = client.soc2_access_review()
        assert result["total_agents"] == 2
        assert result["total_evaluations"] == 100
        client.close()

    def test_soc2_access_review_with_agent_filter(self, httpx_mock):
        httpx_mock.add_response(
            url=httpx.URL(
                "http://localhost:3000/api/compliance/soc2/access-review",
                params={"period": "7d", "format": "json", "agent_id": "agent-1"},
            ),
            json={
                "generated_at": "2026-02-16T00:00:00Z",
                "total_agents": 1,
                "entries": [{"agent_id": "agent-1"}],
            },
        )
        client = VellavetoClient()
        result = client.soc2_access_review(period="7d", agent_id="agent-1")
        assert result["total_agents"] == 1
        client.close()

    def test_soc2_access_review_agent_id_too_long(self):
        client = VellavetoClient()
        with pytest.raises(VellavetoError, match="agent_id exceeds max length"):
            client.soc2_access_review(agent_id="a" * 129)
        client.close()
