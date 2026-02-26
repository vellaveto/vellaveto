"""Tests for vellaveto.claude_agent module."""

from unittest.mock import MagicMock

import pytest

from vellaveto.client import ApprovalRequired, PolicyDenied, VellavetoClient
from vellaveto.claude_agent import VellavetoToolPermission
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


class TestVellavetoToolPermission:
    """Tests for VellavetoToolPermission."""

    def test_check_allow_returns_true(self):
        client = _mock_client()
        perm = VellavetoToolPermission(client)
        assert perm.check("read_file", {"path": "/tmp/test"}) is True
        client.evaluate.assert_called_once()

    def test_check_deny_returns_false(self):
        client = _mock_client(verdict="deny", reason="Blocked")
        perm = VellavetoToolPermission(client)
        assert perm.check("read_file", {"path": "/secret"}) is False

    def test_check_approval_required_raises(self):
        client = _mock_client(
            verdict="require_approval",
            reason="Needs approval",
            approval_id="apr-1",
        )
        perm = VellavetoToolPermission(client)
        with pytest.raises(ApprovalRequired):
            perm.check("write_file", {"path": "/config"})

    def test_check_error_deny_on_error_true(self):
        client = MagicMock(spec=VellavetoClient)
        client.evaluate.side_effect = ConnectionError("timeout")
        perm = VellavetoToolPermission(client, deny_on_error=True)
        assert perm.check("tool", {}) is False

    def test_check_error_deny_on_error_false(self):
        client = MagicMock(spec=VellavetoClient)
        client.evaluate.side_effect = ConnectionError("timeout")
        perm = VellavetoToolPermission(client, deny_on_error=False)
        assert perm.check("tool", {}) is True

    def test_call_chain_appended(self):
        client = _mock_client()
        perm = VellavetoToolPermission(client)
        perm.check("tool_a", {})
        perm.check("tool_b", {})
        assert perm._get_chain() == ["tool_a", "tool_b"]

    def test_call_chain_bounded(self):
        client = _mock_client()
        perm = VellavetoToolPermission(client)
        for i in range(25):
            perm.check(f"tool_{i}", {})
        assert len(perm._get_chain()) == 20

    def test_context_includes_sdk_marker(self):
        client = _mock_client()
        perm = VellavetoToolPermission(
            client,
            session_id="s1",
            agent_id="a1",
        )
        perm.check("tool", {})
        ctx = client.evaluate.call_args.kwargs.get("context")
        assert ctx.metadata.get("sdk") == "claude_agent_sdk"

    def test_context_includes_agent_name(self):
        client = _mock_client()
        perm = VellavetoToolPermission(client)
        perm.check("tool", {}, agent_name="assistant")
        ctx = client.evaluate.call_args.kwargs.get("context")
        assert ctx.metadata.get("claude_agent_name") == "assistant"

    def test_path_extraction(self):
        client = _mock_client()
        perm = VellavetoToolPermission(client)
        perm.check("fs", {"file": "/tmp/test.txt"})
        args = client.evaluate.call_args
        assert "/tmp/test.txt" in args.kwargs.get("target_paths", [])

    def test_domain_extraction(self):
        client = _mock_client()
        perm = VellavetoToolPermission(client)
        perm.check("http", {"url": "https://example.com"})
        args = client.evaluate.call_args
        assert "https://example.com" in args.kwargs.get("target_domains", [])

    def test_auto_url_detection(self):
        client = _mock_client()
        perm = VellavetoToolPermission(client)
        perm.check("api", {"webhook": "https://hooks.slack.com/x"})
        args = client.evaluate.call_args
        assert "https://hooks.slack.com/x" in args.kwargs.get(
            "target_domains", []
        )

    def test_wrap_tool(self):
        client = _mock_client()
        perm = VellavetoToolPermission(client)

        def my_tool(path=""):
            return f"read:{path}"

        wrapped = perm.wrap_tool(my_tool)
        result = wrapped(path="/tmp/test")
        assert result == "read:/tmp/test"
        assert wrapped.__name__ == "my_tool"

    def test_wrap_tool_denied(self):
        client = _mock_client(verdict="deny", reason="no")
        perm = VellavetoToolPermission(client)

        def my_tool():
            return "ok"

        wrapped = perm.wrap_tool(my_tool)
        with pytest.raises(PolicyDenied):
            wrapped()

    def test_wrap_tools(self):
        client = _mock_client()
        perm = VellavetoToolPermission(client)

        def tool_a():
            return "a"

        def tool_b():
            return "b"

        wrapped = perm.wrap_tools([tool_a, tool_b])
        assert len(wrapped) == 2
        assert wrapped[0]() == "a"
        assert wrapped[1]() == "b"

    def test_create_allowed_tools_filter(self):
        call_count = 0
        def evaluate_side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            verdict = "allow" if call_count % 2 == 1 else "deny"
            return EvaluationResult(
                verdict=verdict,
                reason="",
                policy_id="p1",
                policy_name="test",
            )

        client = MagicMock(spec=VellavetoClient)
        client.evaluate.side_effect = evaluate_side_effect
        perm = VellavetoToolPermission(client)
        allowed = perm.create_allowed_tools_filter(
            ["tool_a", "tool_b", "tool_c"]
        )
        assert "tool_a" in allowed
        assert "tool_b" not in allowed
        assert "tool_c" in allowed

    def test_tenant_id_passed(self):
        client = _mock_client()
        perm = VellavetoToolPermission(client, tenant_id="t1")
        perm.check("tool", {})
        ctx = client.evaluate.call_args.kwargs.get("context")
        assert ctx.tenant_id == "t1"
