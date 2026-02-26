"""Tests for vellaveto.strands module."""

from unittest.mock import MagicMock

import pytest

from vellaveto.client import ApprovalRequired, PolicyDenied, VellavetoClient
from vellaveto.strands import VellavetoStrandsGuard
from vellaveto.types import EvaluationResult


def _mock_client(verdict="allow", reason="", approval_id=""):
    client = MagicMock(spec=VellavetoClient)
    client.evaluate.return_value = EvaluationResult(
        verdict=verdict,
        reason=reason,
        policy_id="p1",
        policy_name="test",
        approval_id=approval_id,
    )
    return client


class TestVellavetoStrandsGuard:
    """Tests for VellavetoStrandsGuard."""

    def test_evaluate_allow(self):
        client = _mock_client()
        guard = VellavetoStrandsGuard(client)
        guard.evaluate_call("tool", "fn", {"key": "val"})
        client.evaluate.assert_called_once()

    def test_evaluate_deny_raises(self):
        client = _mock_client(verdict="deny", reason="Blocked")
        guard = VellavetoStrandsGuard(client)
        with pytest.raises(PolicyDenied) as exc:
            guard.evaluate_call("tool", "fn", {"path": "/secret"})
        assert "Blocked" in str(exc.value)

    def test_evaluate_deny_no_raise(self):
        client = _mock_client(verdict="deny", reason="x")
        guard = VellavetoStrandsGuard(client, raise_on_deny=False)
        guard.evaluate_call("tool", "fn", {})

    def test_evaluate_approval_required(self):
        client = _mock_client(
            verdict="require_approval",
            reason="Needs approval",
            approval_id="apr-1",
        )
        guard = VellavetoStrandsGuard(client)
        with pytest.raises(ApprovalRequired):
            guard.evaluate_call("tool", "fn", {})

    def test_call_chain_appended(self):
        client = _mock_client()
        guard = VellavetoStrandsGuard(client)
        guard.evaluate_call("t1", "fn_a", {})
        guard.evaluate_call("t2", "fn_b", {})
        assert guard._get_chain() == ["fn_a", "fn_b"]

    def test_call_chain_bounded(self):
        client = _mock_client()
        guard = VellavetoStrandsGuard(client)
        for i in range(25):
            guard.evaluate_call("t", f"fn_{i}", {})
        assert len(guard._get_chain()) == 20

    def test_context_includes_sdk_marker(self):
        client = _mock_client()
        guard = VellavetoStrandsGuard(
            client, session_id="s", agent_id="a",
        )
        guard.evaluate_call("tool", "fn", {})
        ctx = client.evaluate.call_args.kwargs.get("context")
        assert ctx.metadata.get("sdk") == "strands_agents"

    def test_context_includes_agent_name(self):
        client = _mock_client()
        guard = VellavetoStrandsGuard(client)
        guard.evaluate_call("tool", "fn", {}, agent_name="my-agent")
        ctx = client.evaluate.call_args.kwargs.get("context")
        assert ctx.metadata.get("strands_agent_name") == "my-agent"

    def test_path_extraction(self):
        client = _mock_client()
        guard = VellavetoStrandsGuard(client)
        guard.evaluate_call("fs", "read", {"file": "/tmp/test.txt"})
        args = client.evaluate.call_args
        assert "/tmp/test.txt" in args.kwargs.get("target_paths", [])

    def test_domain_extraction(self):
        client = _mock_client()
        guard = VellavetoStrandsGuard(client)
        guard.evaluate_call("http", "get", {"url": "https://example.com"})
        args = client.evaluate.call_args
        assert "https://example.com" in args.kwargs.get("target_domains", [])

    def test_wrap_tool(self):
        client = _mock_client()
        guard = VellavetoStrandsGuard(client)

        def my_tool(path=""):
            return f"read:{path}"

        wrapped = guard.wrap_tool(my_tool)
        result = wrapped(path="/tmp/test")
        assert result == "read:/tmp/test"
        assert wrapped.__name__ == "my_tool"

    def test_wrap_tool_denied(self):
        client = _mock_client(verdict="deny", reason="no")
        guard = VellavetoStrandsGuard(client)

        def my_tool():
            return "ok"

        wrapped = guard.wrap_tool(my_tool)
        with pytest.raises(PolicyDenied):
            wrapped()

    def test_wrap_tools(self):
        client = _mock_client()
        guard = VellavetoStrandsGuard(client)

        def tool_a():
            return "a"

        def tool_b():
            return "b"

        wrapped = guard.wrap_tools([tool_a, tool_b])
        assert len(wrapped) == 2
        assert wrapped[0]() == "a"
        assert wrapped[1]() == "b"

    def test_to_bedrock_guardrail_config(self):
        client = _mock_client()
        guard = VellavetoStrandsGuard(
            client,
            session_id="s1",
            agent_id="a1",
            tenant_id="t1",
        )
        config = guard.to_bedrock_guardrail_config()
        assert config["guardrailIdentifier"] == "vellaveto"
        assert config["metadata"]["session_id"] == "s1"
        assert config["metadata"]["agent_id"] == "a1"
        assert config["metadata"]["tenant_id"] == "t1"

    def test_deny_on_error_fail_closed(self):
        client = MagicMock(spec=VellavetoClient)
        client.evaluate.side_effect = ConnectionError("timeout")
        guard = VellavetoStrandsGuard(client, deny_on_error=True)
        with pytest.raises(PolicyDenied):
            guard.evaluate_call("tool", "fn", {})
