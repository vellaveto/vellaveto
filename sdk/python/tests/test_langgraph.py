"""Tests for vellaveto.langgraph module."""

import json
from unittest.mock import MagicMock

import pytest

from vellaveto.client import VellavetoClient
from vellaveto.types import Verdict


class TestCreateVellavetoNode:
    """Tests for create_vellaveto_node()."""

    def test_allow_sets_not_blocked(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow", "policy_id": "p1"},
        )

        client = VellavetoClient()
        from vellaveto.langgraph import create_vellaveto_node

        node = create_vellaveto_node(client)
        result = node({
            "pending_tool_name": "read_file",
            "pending_tool_input": {"path": "/tmp/test.txt"},
        })

        assert result["tool_blocked"] is False
        assert result["vellaveto_verdict"] == "allow"
        client.close()

    def test_deny_blocks_tool(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "deny", "reason": "Path blocked"},
        )

        client = VellavetoClient()
        from vellaveto.langgraph import create_vellaveto_node

        node = create_vellaveto_node(client, on_deny="block")
        result = node({
            "pending_tool_name": "write_file",
            "pending_tool_input": {"path": "/etc/shadow"},
        })

        assert result["tool_blocked"] is True
        assert result["vellaveto_verdict"] == "deny"
        assert result["vellaveto_reason"] == "Path blocked"
        client.close()

    def test_deny_continue_mode(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "deny", "reason": "Soft deny"},
        )

        client = VellavetoClient()
        from vellaveto.langgraph import create_vellaveto_node

        node = create_vellaveto_node(client, on_deny="continue")
        result = node({
            "pending_tool_name": "test",
            "pending_tool_input": {},
        })

        assert result["tool_blocked"] is False
        assert result["vellaveto_verdict"] == "deny"
        client.close()

    def test_approval_required_blocks(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={
                "verdict": "require_approval",
                "reason": "Needs review",
                "approval_id": "apr-1",
            },
        )

        client = VellavetoClient()
        from vellaveto.langgraph import create_vellaveto_node

        node = create_vellaveto_node(client, on_approval_required="block")
        result = node({
            "pending_tool_name": "delete",
            "pending_tool_input": {},
        })

        assert result["tool_blocked"] is True
        assert result["vellaveto_approval_id"] == "apr-1"
        client.close()

    def test_no_pending_tool_passes_through(self, httpx_mock):
        client = VellavetoClient()
        from vellaveto.langgraph import create_vellaveto_node

        node = create_vellaveto_node(client)
        result = node({})

        assert result["tool_blocked"] is False
        client.close()

    def test_call_chain_updated(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient()
        from vellaveto.langgraph import create_vellaveto_node

        node = create_vellaveto_node(client)
        result = node({
            "pending_tool_name": "tool_a",
            "pending_tool_input": {},
            "vellaveto_call_chain": ["tool_x"],
        })

        assert result["vellaveto_call_chain"] == ["tool_x", "tool_a"]
        client.close()

    def test_call_chain_bounded(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient()
        from vellaveto.langgraph import create_vellaveto_node

        node = create_vellaveto_node(client)
        long_chain = [f"tool_{i}" for i in range(25)]
        result = node({
            "pending_tool_name": "new_tool",
            "pending_tool_input": {},
            "vellaveto_call_chain": long_chain,
        })

        # SECURITY (FIND-SDK-010): Call chain bounded at 20 entries via slice
        assert len(result["vellaveto_call_chain"]) == 20
        assert result["vellaveto_call_chain"][-1] == "new_tool"
        client.close()

    def test_path_extraction(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient()
        from vellaveto.langgraph import create_vellaveto_node

        node = create_vellaveto_node(client)
        node({
            "pending_tool_name": "read",
            "pending_tool_input": {"path": "/secret/data.txt"},
        })

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert "/secret/data.txt" in body["action"]["target_paths"]
        client.close()

    def test_domain_extraction(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient()
        from vellaveto.langgraph import create_vellaveto_node

        node = create_vellaveto_node(client)
        node({
            "pending_tool_name": "fetch",
            "pending_tool_input": {"url": "https://evil.com/exfil"},
        })

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert "https://evil.com/exfil" in body["action"]["target_domains"]
        client.close()

    def test_url_pattern_extraction(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient()
        from vellaveto.langgraph import create_vellaveto_node

        node = create_vellaveto_node(client)
        node({
            "pending_tool_name": "http_call",
            "pending_tool_input": {"data": "http://internal.corp/api"},
        })

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert "http://internal.corp/api" in body["action"]["target_domains"]
        client.close()

    def test_fail_closed_on_error(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            status_code=500,
        )

        client = VellavetoClient()
        from vellaveto.langgraph import create_vellaveto_node

        node = create_vellaveto_node(client, on_deny="block")
        result = node({
            "pending_tool_name": "test",
            "pending_tool_input": {},
        })

        assert result["tool_blocked"] is True
        assert result["vellaveto_verdict"] == "deny"
        client.close()

    def test_context_passed_from_state(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient()
        from vellaveto.langgraph import create_vellaveto_node

        node = create_vellaveto_node(client)
        node({
            "pending_tool_name": "test",
            "pending_tool_input": {},
            "vellaveto_session_id": "sess-123",
            "vellaveto_agent_id": "agent-abc",
            "vellaveto_call_chain": ["prev_tool"],
        })

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["context"]["session_id"] == "sess-123"
        assert body["context"]["agent_id"] == "agent-abc"
        assert body["context"]["call_chain"] == ["prev_tool"]
        client.close()


class TestVellavetoState:
    """Tests for VellavetoState TypedDict."""

    def test_vellaveto_state_fields(self):
        from vellaveto.langgraph import VellavetoState

        # VellavetoState is a TypedDict - verify expected keys
        annotations = VellavetoState.__annotations__
        assert "vellaveto_verdict" in annotations
        assert "vellaveto_reason" in annotations
        assert "vellaveto_policy_id" in annotations
        assert "vellaveto_approval_id" in annotations
        assert "vellaveto_session_id" in annotations
        assert "vellaveto_agent_id" in annotations
        assert "vellaveto_call_chain" in annotations
        assert "pending_tool_name" in annotations
        assert "pending_tool_input" in annotations
        assert "tool_blocked" in annotations


# ── Round 46 P3 Fixes ──────────────────────────────────────────────────


class TestVellavetoCheckpointFixes:
    """Tests for FIND-SDK-016 and FIND-SDK-017."""

    def test_no_sessions_attribute(self):
        """FIND-SDK-016: _sessions dead code removed."""
        from vellaveto.langgraph import VellavetoCheckpoint

        client = VellavetoClient()
        base = MagicMock()
        base.get.return_value = None
        cp = VellavetoCheckpoint(client, base)
        assert not hasattr(cp, "_sessions")
        client.close()

    def test_thread_id_validation_rejects_injection(self):
        """FIND-SDK-017: thread_id with special chars should be sanitized."""
        from vellaveto.langgraph import VellavetoCheckpoint

        client = VellavetoClient()
        base = MagicMock()
        base.get.return_value = {"some": "state"}
        cp = VellavetoCheckpoint(client, base)

        result = cp.get({
            "configurable": {"thread_id": "../../../etc/passwd"}
        })
        assert result["vellaveto_session_id"] == "langgraph-invalid"
        client.close()

    def test_thread_id_valid_accepted(self):
        """FIND-SDK-017: Valid thread_id should pass through."""
        from vellaveto.langgraph import VellavetoCheckpoint

        client = VellavetoClient()
        base = MagicMock()
        base.get.return_value = {"some": "state"}
        cp = VellavetoCheckpoint(client, base)

        result = cp.get({
            "configurable": {"thread_id": "my-thread-123"}
        })
        assert result["vellaveto_session_id"] == "langgraph-my-thread-123"
        client.close()

    def test_thread_id_too_long_rejected(self):
        """FIND-SDK-017: Thread IDs longer than 256 chars should be rejected."""
        from vellaveto.langgraph import VellavetoCheckpoint

        client = VellavetoClient()
        base = MagicMock()
        base.get.return_value = {"some": "state"}
        cp = VellavetoCheckpoint(client, base)

        result = cp.get({
            "configurable": {"thread_id": "a" * 300}
        })
        assert result["vellaveto_session_id"] == "langgraph-invalid"
        client.close()

    def test_thread_id_non_string_coerced(self):
        """FIND-SDK-017: Non-string thread_id should be coerced to string."""
        from vellaveto.langgraph import VellavetoCheckpoint

        client = VellavetoClient()
        base = MagicMock()
        base.get.return_value = {"some": "state"}
        cp = VellavetoCheckpoint(client, base)

        result = cp.get({
            "configurable": {"thread_id": 42}
        })
        assert result["vellaveto_session_id"] == "langgraph-42"
        client.close()
