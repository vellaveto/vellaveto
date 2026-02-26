"""Tests for vellaveto.microsoft_agents module."""

from unittest.mock import MagicMock, patch

import pytest

from vellaveto.client import ApprovalRequired, PolicyDenied, VellavetoClient
from vellaveto.microsoft_agents import VellavetoAgentMiddleware
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


class TestVellavetoAgentMiddleware:
    """Tests for VellavetoAgentMiddleware."""

    def test_evaluate_allow(self):
        client = _mock_client()
        mw = VellavetoAgentMiddleware(client)
        mw.evaluate_call("tool", "fn", {"key": "val"})
        client.evaluate.assert_called_once()

    def test_evaluate_deny_raises(self):
        client = _mock_client(verdict="deny", reason="Blocked")
        mw = VellavetoAgentMiddleware(client)
        with pytest.raises(PolicyDenied) as exc:
            mw.evaluate_call("tool", "fn", {"path": "/secret"})
        assert "Blocked" in str(exc.value)

    def test_evaluate_deny_no_raise(self):
        client = _mock_client(verdict="deny", reason="x")
        mw = VellavetoAgentMiddleware(client, raise_on_deny=False)
        mw.evaluate_call("tool", "fn", {})

    def test_evaluate_approval_required(self):
        client = _mock_client(
            verdict="require_approval",
            reason="Needs approval",
            approval_id="apr-1",
        )
        mw = VellavetoAgentMiddleware(client)
        with pytest.raises(ApprovalRequired):
            mw.evaluate_call("tool", "fn", {})

    def test_call_chain_appended(self):
        client = _mock_client()
        mw = VellavetoAgentMiddleware(client)
        mw.evaluate_call("t1", "fn_a", {})
        mw.evaluate_call("t2", "fn_b", {})
        assert mw._get_chain() == ["fn_a", "fn_b"]

    def test_call_chain_bounded(self):
        client = _mock_client()
        mw = VellavetoAgentMiddleware(client)
        for i in range(25):
            mw.evaluate_call("t", f"fn_{i}", {})
        assert len(mw._get_chain()) == 20

    def test_context_includes_sdk_marker(self):
        client = _mock_client()
        mw = VellavetoAgentMiddleware(
            client, session_id="s", agent_id="a",
        )
        mw.evaluate_call("tool", "fn", {})
        ctx = client.evaluate.call_args.kwargs.get("context")
        assert ctx.metadata.get("sdk") == "microsoft_agent_framework"

    def test_context_includes_agent_name(self):
        client = _mock_client()
        mw = VellavetoAgentMiddleware(client)
        mw.evaluate_call("tool", "fn", {}, agent_name="my-agent")
        ctx = client.evaluate.call_args.kwargs.get("context")
        assert ctx.metadata.get("ms_agent_name") == "my-agent"

    def test_context_includes_entra_token_marker(self):
        client = _mock_client()
        mw = VellavetoAgentMiddleware(client, entra_token="token-xxx")
        mw.evaluate_call("tool", "fn", {})
        ctx = client.evaluate.call_args.kwargs.get("context")
        assert ctx.metadata.get("has_entra_token") == "true"

    def test_path_extraction(self):
        client = _mock_client()
        mw = VellavetoAgentMiddleware(client)
        mw.evaluate_call("fs", "read", {"file": "/tmp/test.txt"})
        args = client.evaluate.call_args
        assert "/tmp/test.txt" in args.kwargs.get("target_paths", [])

    def test_domain_extraction(self):
        client = _mock_client()
        mw = VellavetoAgentMiddleware(client)
        mw.evaluate_call("http", "get", {"url": "https://example.com"})
        args = client.evaluate.call_args
        assert "https://example.com" in args.kwargs.get("target_domains", [])

    def test_wrap_tool(self):
        client = _mock_client()
        mw = VellavetoAgentMiddleware(client)

        def my_tool(path=""):
            return f"read:{path}"

        wrapped = mw.wrap_tool(my_tool)
        result = wrapped(path="/tmp/test")
        assert result == "read:/tmp/test"
        assert wrapped.__name__ == "my_tool"

    def test_wrap_tool_denied(self):
        client = _mock_client(verdict="deny", reason="no")
        mw = VellavetoAgentMiddleware(client)

        def my_tool():
            return "ok"

        wrapped = mw.wrap_tool(my_tool)
        with pytest.raises(PolicyDenied):
            wrapped()

    def test_wrap_tools(self):
        client = _mock_client()
        mw = VellavetoAgentMiddleware(client)

        def tool_a():
            return "a"

        def tool_b():
            return "b"

        wrapped = mw.wrap_tools([tool_a, tool_b])
        assert len(wrapped) == 2
        assert wrapped[0]() == "a"
        assert wrapped[1]() == "b"

    def test_set_entra_token(self):
        client = _mock_client()
        mw = VellavetoAgentMiddleware(client)
        assert mw._entra_token is None
        mw.set_entra_token("new-token")
        assert mw._entra_token == "new-token"

    def test_deny_on_error_fail_closed(self):
        client = MagicMock(spec=VellavetoClient)
        client.evaluate.side_effect = ConnectionError("timeout")
        mw = VellavetoAgentMiddleware(client, deny_on_error=True)
        with pytest.raises(PolicyDenied):
            mw.evaluate_call("tool", "fn", {})

    def test_deny_on_error_fail_open(self):
        client = MagicMock(spec=VellavetoClient)
        client.evaluate.side_effect = ConnectionError("timeout")
        mw = VellavetoAgentMiddleware(
            client, deny_on_error=False, raise_on_deny=False,
        )
        mw.evaluate_call("tool", "fn", {})

    def test_otel_disabled_by_default(self):
        client = _mock_client()
        mw = VellavetoAgentMiddleware(client)
        assert mw._otel_enabled is False
        assert mw._tracer is None

    def test_tenant_id_passed(self):
        client = _mock_client()
        mw = VellavetoAgentMiddleware(client, tenant_id="t1")
        mw.evaluate_call("tool", "fn", {})
        ctx = client.evaluate.call_args.kwargs.get("context")
        assert ctx.tenant_id == "t1"
