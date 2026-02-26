"""Tests for vellaveto.google_adk module."""

from unittest.mock import MagicMock

import pytest

from vellaveto.client import ApprovalRequired, PolicyDenied, VellavetoClient
from vellaveto.google_adk import VellavetoADKGuard
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


class TestVellavetoADKGuard:
    """Tests for VellavetoADKGuard."""

    def test_evaluate_allow(self):
        client = _mock_client()
        guard = VellavetoADKGuard(client)
        guard.evaluate("tool", "search", {"query": "test"})
        client.evaluate.assert_called_once()

    def test_evaluate_deny_raises(self):
        client = _mock_client(verdict="deny", reason="Forbidden")
        guard = VellavetoADKGuard(client)
        with pytest.raises(PolicyDenied) as exc:
            guard.evaluate("tool", "delete", {"path": "/etc/passwd"})
        assert "Forbidden" in str(exc.value)

    def test_evaluate_deny_no_raise(self):
        client = _mock_client(verdict="deny", reason="Forbidden")
        guard = VellavetoADKGuard(client, raise_on_deny=False)
        guard.evaluate("tool", "delete", {})
        # Should not raise

    def test_evaluate_approval_required(self):
        client = _mock_client(
            verdict="require_approval",
            reason="Needs approval",
            approval_id="apr-1",
        )
        guard = VellavetoADKGuard(client)
        with pytest.raises(ApprovalRequired):
            guard.evaluate("tool", "admin_op", {})

    def test_call_chain_appended(self):
        client = _mock_client()
        guard = VellavetoADKGuard(client)
        guard.evaluate("tool", "fn_a", {})
        guard.evaluate("tool", "fn_b", {})
        chain = guard._get_chain()
        assert chain == ["tool.fn_a", "tool.fn_b"]

    def test_call_chain_bounded(self):
        client = _mock_client()
        guard = VellavetoADKGuard(client)
        for i in range(25):
            guard.evaluate("t", f"fn_{i}", {})
        assert len(guard._get_chain()) == 20

    def test_path_extraction(self):
        client = _mock_client()
        guard = VellavetoADKGuard(client)
        guard.evaluate("fs", "read", {"file": "/tmp/secret.txt"})
        args = client.evaluate.call_args
        assert "/tmp/secret.txt" in args.kwargs.get("target_paths", [])

    def test_domain_extraction(self):
        client = _mock_client()
        guard = VellavetoADKGuard(client)
        guard.evaluate("http", "fetch", {"url": "https://api.evil.com"})
        args = client.evaluate.call_args
        assert "https://api.evil.com" in args.kwargs.get("target_domains", [])

    def test_context_metadata(self):
        client = _mock_client()
        guard = VellavetoADKGuard(
            client,
            session_id="s1",
            agent_id="a1",
            tenant_id="t1",
            metadata={"framework": "adk"},
        )
        guard.evaluate("tool", "fn", {})
        ctx = client.evaluate.call_args.kwargs.get("context")
        assert ctx.session_id == "s1"
        assert ctx.agent_id == "a1"
        assert ctx.tenant_id == "t1"
        assert ctx.metadata.get("framework") == "adk"


class TestProtectDecorator:
    """Tests for @guard.protect decorator."""

    def test_protect_allow(self):
        client = _mock_client()
        guard = VellavetoADKGuard(client)

        @guard.protect
        def read_file(path: str = "") -> str:
            return f"content of {path}"

        result = read_file(path="/tmp/test.txt")
        assert result == "content of /tmp/test.txt"
        client.evaluate.assert_called_once()

    def test_protect_deny(self):
        client = _mock_client(verdict="deny", reason="No access")
        guard = VellavetoADKGuard(client)

        @guard.protect
        def delete_file(path: str = "") -> str:
            return "deleted"

        with pytest.raises(PolicyDenied):
            delete_file(path="/etc/shadow")

    def test_protect_preserves_metadata(self):
        client = _mock_client()
        guard = VellavetoADKGuard(client)

        def my_func(x: int = 0) -> int:
            """Compute x."""
            return x * 2

        wrapped = guard.protect(my_func)
        assert wrapped.__name__ == "my_func"
        assert wrapped.__doc__ == "Compute x."


class TestBeforeToolCallback:
    """Tests for before_tool_callback."""

    def test_callback_allow(self):
        client = _mock_client()
        guard = VellavetoADKGuard(client)
        cb = guard.before_tool_callback()
        cb("tool", "fn", {"arg": "val"})
        client.evaluate.assert_called_once()

    def test_callback_deny_raises(self):
        client = _mock_client(verdict="deny", reason="Nope")
        guard = VellavetoADKGuard(client)
        cb = guard.before_tool_callback()
        with pytest.raises(PolicyDenied):
            cb("tool", "fn", {"arg": "val"})

    def test_callback_reusable(self):
        client = _mock_client()
        guard = VellavetoADKGuard(client)
        cb = guard.before_tool_callback()
        cb("tool", "fn_a", {})
        cb("tool", "fn_b", {})
        assert client.evaluate.call_count == 2
