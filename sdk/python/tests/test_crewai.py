"""Tests for vellaveto.crewai module."""

from unittest.mock import MagicMock

import pytest

from vellaveto.client import ApprovalRequired, PolicyDenied, VellavetoClient
from vellaveto.crewai import VellavetoCrewGuard
from vellaveto.types import EvaluationResult


def _mock_client(verdict="allow", reason="", approval_id=""):
    """Create a mock VellavetoClient with a fixed evaluate response."""
    client = MagicMock(spec=VellavetoClient)
    client.evaluate.return_value = EvaluationResult(
        verdict=verdict,
        reason=reason,
        policy_id="p1",
        policy_name="test",
        approval_id=approval_id,
    )
    return client


class TestVellavetoCrewGuard:
    """Tests for VellavetoCrewGuard."""

    def test_evaluate_allow(self):
        client = _mock_client()
        guard = VellavetoCrewGuard(client, session_id="s1")
        guard.evaluate_tool_call("web_search", {"query": "test"})
        client.evaluate.assert_called_once()

    def test_evaluate_deny_raises(self):
        client = _mock_client(verdict="deny", reason="Blocked")
        guard = VellavetoCrewGuard(client)
        with pytest.raises(PolicyDenied) as exc:
            guard.evaluate_tool_call("web_search", {"query": "evil"})
        assert "Blocked" in str(exc.value)

    def test_evaluate_deny_no_raise(self):
        client = _mock_client(verdict="deny", reason="Blocked")
        guard = VellavetoCrewGuard(client, raise_on_deny=False)
        guard.evaluate_tool_call("web_search", {"query": "test"})
        # Should not raise

    def test_evaluate_approval_required(self):
        client = _mock_client(
            verdict="require_approval",
            reason="Needs approval",
            approval_id="apr-1",
        )
        guard = VellavetoCrewGuard(client)
        with pytest.raises(ApprovalRequired):
            guard.evaluate_tool_call("admin_tool", {})

    def test_call_chain_appended_after_eval(self):
        client = _mock_client()
        guard = VellavetoCrewGuard(client, session_id="s1")
        guard.evaluate_tool_call("tool_a", {})
        guard.evaluate_tool_call("tool_b", {})
        chain = guard._get_chain()
        assert chain == ["tool_a", "tool_b"]

    def test_call_chain_fifo_eviction(self):
        client = _mock_client()
        guard = VellavetoCrewGuard(client)
        for i in range(25):
            guard.evaluate_tool_call(f"tool_{i}", {})
        chain = guard._get_chain()
        assert len(chain) == 20
        assert chain[0] == "tool_5"
        assert chain[-1] == "tool_24"

    def test_call_chain_not_appended_on_deny(self):
        client = _mock_client(verdict="deny", reason="x")
        guard = VellavetoCrewGuard(client, raise_on_deny=False)
        guard.evaluate_tool_call("bad_tool", {})
        # Chain IS appended (evaluation completed, verdict processed)
        assert guard._get_chain() == ["bad_tool"]

    def test_path_extraction(self):
        client = _mock_client()
        guard = VellavetoCrewGuard(client)
        guard.evaluate_tool_call("file_reader", {"path": "/tmp/data.csv"})
        call_args = client.evaluate.call_args
        assert "/tmp/data.csv" in call_args.kwargs.get("target_paths", [])

    def test_domain_extraction(self):
        client = _mock_client()
        guard = VellavetoCrewGuard(client)
        guard.evaluate_tool_call("web_search", {"url": "https://example.com"})
        call_args = client.evaluate.call_args
        assert "https://example.com" in call_args.kwargs.get("target_domains", [])

    def test_auto_detect_url(self):
        client = _mock_client()
        guard = VellavetoCrewGuard(client)
        guard.evaluate_tool_call(
            "fetch", {"endpoint": "https://api.example.com/v1"}
        )
        call_args = client.evaluate.call_args
        assert "https://api.example.com/v1" in call_args.kwargs.get(
            "target_domains", []
        )

    def test_context_includes_metadata(self):
        client = _mock_client()
        guard = VellavetoCrewGuard(
            client,
            session_id="sess",
            agent_id="agent",
            tenant_id="tenant",
            metadata={"env": "test"},
        )
        guard.evaluate_tool_call("tool", {}, agent_role="researcher")
        call_args = client.evaluate.call_args
        ctx = call_args.kwargs.get("context")
        assert ctx is not None
        assert ctx.session_id == "sess"
        assert ctx.agent_id == "agent"
        assert ctx.tenant_id == "tenant"
        assert ctx.metadata.get("env") == "test"
        assert ctx.metadata.get("crewai_role") == "researcher"


class TestWrapTool:
    """Tests for tool wrapping."""

    def test_wrap_tool_allow(self):
        client = _mock_client()
        guard = VellavetoCrewGuard(client)

        def my_tool(query: str = "") -> str:
            return f"result: {query}"

        wrapped = guard.wrap_tool(my_tool)
        result = wrapped(query="test")
        assert result == "result: test"
        client.evaluate.assert_called_once()

    def test_wrap_tool_deny(self):
        client = _mock_client(verdict="deny", reason="Nope")
        guard = VellavetoCrewGuard(client)

        def my_tool(query: str = "") -> str:
            return "should not reach"

        wrapped = guard.wrap_tool(my_tool)
        with pytest.raises(PolicyDenied):
            wrapped(query="bad")

    def test_wrap_preserves_name(self):
        client = _mock_client()
        guard = VellavetoCrewGuard(client)

        def search_web(query: str = "") -> str:
            """Search the web."""
            return query

        wrapped = guard.wrap_tool(search_web)
        assert wrapped.__name__ == "search_web"
        assert wrapped.__doc__ == "Search the web."

    def test_wrap_preserves_crewai_attrs(self):
        client = _mock_client()
        guard = VellavetoCrewGuard(client)

        def my_tool() -> str:
            return ""

        my_tool.name = "custom_name"
        my_tool.description = "custom desc"
        wrapped = guard.wrap_tool(my_tool)
        assert wrapped.name == "custom_name"
        assert wrapped.description == "custom desc"

    def test_guard_agent_tools(self):
        client = _mock_client()
        guard = VellavetoCrewGuard(client)

        def tool_a() -> str:
            return "a"

        def tool_b() -> str:
            return "b"

        wrapped = guard.guard_agent_tools([tool_a, tool_b])
        assert len(wrapped) == 2
        assert wrapped[0]() == "a"
        assert wrapped[1]() == "b"
        assert client.evaluate.call_count == 2
