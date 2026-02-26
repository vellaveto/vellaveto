"""Tests for vellaveto.openai_agents module."""

from unittest.mock import MagicMock

import pytest

from vellaveto.client import ApprovalRequired, PolicyDenied, VellavetoClient
from vellaveto.openai_agents import VellavetoAgentGuard
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


class TestVellavetoAgentGuard:
    """Tests for VellavetoAgentGuard."""

    def test_evaluate_allow(self):
        client = _mock_client()
        guard = VellavetoAgentGuard(client)
        guard.evaluate_call("tool", "fn", {"key": "val"})
        client.evaluate.assert_called_once()

    def test_evaluate_deny_raises(self):
        client = _mock_client(verdict="deny", reason="Blocked")
        guard = VellavetoAgentGuard(client)
        with pytest.raises(PolicyDenied) as exc:
            guard.evaluate_call("tool", "fn", {"path": "/secret"})
        assert "Blocked" in str(exc.value)

    def test_evaluate_deny_no_raise(self):
        client = _mock_client(verdict="deny", reason="x")
        guard = VellavetoAgentGuard(client, raise_on_deny=False)
        guard.evaluate_call("tool", "fn", {})
        # Should not raise

    def test_evaluate_approval_required(self):
        client = _mock_client(
            verdict="require_approval",
            reason="Needs approval",
            approval_id="apr-1",
        )
        guard = VellavetoAgentGuard(client)
        with pytest.raises(ApprovalRequired):
            guard.evaluate_call("tool", "fn", {})

    def test_call_chain_appended(self):
        client = _mock_client()
        guard = VellavetoAgentGuard(client)
        guard.evaluate_call("t1", "fn_a", {})
        guard.evaluate_call("t2", "fn_b", {})
        assert guard._get_chain() == ["fn_a", "fn_b"]

    def test_call_chain_bounded(self):
        client = _mock_client()
        guard = VellavetoAgentGuard(client)
        for i in range(25):
            guard.evaluate_call("t", f"fn_{i}", {})
        assert len(guard._get_chain()) == 20

    def test_context_includes_agent_name(self):
        client = _mock_client()
        guard = VellavetoAgentGuard(
            client,
            session_id="s",
            metadata={"run": "1"},
        )
        guard.evaluate_call("tool", "fn", {}, agent_name="assistant")
        ctx = client.evaluate.call_args.kwargs.get("context")
        assert ctx.metadata.get("openai_agent") == "assistant"

    def test_path_extraction(self):
        client = _mock_client()
        guard = VellavetoAgentGuard(client)
        guard.evaluate_call("fs", "read", {"file": "/tmp/test.txt"})
        args = client.evaluate.call_args
        assert "/tmp/test.txt" in args.kwargs.get("target_paths", [])

    def test_domain_extraction(self):
        client = _mock_client()
        guard = VellavetoAgentGuard(client)
        guard.evaluate_call("http", "get", {"url": "https://example.com"})
        args = client.evaluate.call_args
        assert "https://example.com" in args.kwargs.get("target_domains", [])

    def test_auto_url_detection(self):
        client = _mock_client()
        guard = VellavetoAgentGuard(client)
        guard.evaluate_call(
            "api", "call", {"webhook": "https://hooks.slack.com/x"}
        )
        args = client.evaluate.call_args
        domains = args.kwargs.get("target_domains", [])
        # "webhook" is not in _DOMAIN_KEYS but starts with https://
        assert "https://hooks.slack.com/x" in domains


class TestWrapFunction:
    """Tests for wrap_function."""

    def test_wrap_allow(self):
        client = _mock_client()
        guard = VellavetoAgentGuard(client)

        def greet(name: str = "") -> str:
            return f"Hello {name}"

        wrapped = guard.wrap_function(greet)
        assert wrapped(name="World") == "Hello World"
        client.evaluate.assert_called_once()

    def test_wrap_deny(self):
        client = _mock_client(verdict="deny", reason="No")
        guard = VellavetoAgentGuard(client)

        def danger(cmd: str = "") -> str:
            return "executed"

        wrapped = guard.wrap_function(danger)
        with pytest.raises(PolicyDenied):
            wrapped(cmd="rm -rf /")

    def test_wrap_preserves_name(self):
        client = _mock_client()
        guard = VellavetoAgentGuard(client)

        def my_func() -> str:
            """My doc."""
            return ""

        wrapped = guard.wrap_function(my_func)
        assert wrapped.__name__ == "my_func"
        assert wrapped.__doc__ == "My doc."

    def test_custom_tool_name(self):
        client = _mock_client()
        guard = VellavetoAgentGuard(client)

        def helper(x: int = 0) -> int:
            return x

        wrapped = guard.wrap_function(helper, tool_name="custom_tool")
        wrapped(x=42)
        args = client.evaluate.call_args
        assert args.kwargs.get("tool") == "custom_tool"

    def test_agent_name_in_context(self):
        client = _mock_client()
        guard = VellavetoAgentGuard(client)

        def helper() -> str:
            return ""

        wrapped = guard.wrap_function(helper, agent_name="researcher")
        wrapped()
        ctx = client.evaluate.call_args.kwargs.get("context")
        assert ctx.metadata.get("openai_agent") == "researcher"


class TestWrapTools:
    """Tests for wrap_tools."""

    def test_wraps_multiple(self):
        client = _mock_client()
        guard = VellavetoAgentGuard(client)

        def tool_a() -> str:
            return "a"

        def tool_b() -> str:
            return "b"

        wrapped = guard.wrap_tools([tool_a, tool_b])
        assert len(wrapped) == 2
        assert wrapped[0]() == "a"
        assert wrapped[1]() == "b"
        assert client.evaluate.call_count == 2

    def test_wraps_with_agent_name(self):
        client = _mock_client()
        guard = VellavetoAgentGuard(client)

        def tool_a() -> str:
            return "a"

        wrapped = guard.wrap_tools([tool_a], agent_name="bot")
        wrapped[0]()
        ctx = client.evaluate.call_args.kwargs.get("context")
        assert ctx.metadata.get("openai_agent") == "bot"
