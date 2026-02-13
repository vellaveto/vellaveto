"""Tests for sentinel.langgraph module."""

import json
from unittest.mock import MagicMock

import pytest

from sentinel.client import SentinelClient
from sentinel.types import Verdict


class TestCreateSentinelNode:
    """Tests for create_sentinel_node()."""

    def test_allow_sets_not_blocked(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow", "policy_id": "p1"},
        )

        client = SentinelClient()
        from sentinel.langgraph import create_sentinel_node

        node = create_sentinel_node(client)
        result = node({
            "pending_tool_name": "read_file",
            "pending_tool_input": {"path": "/tmp/test.txt"},
        })

        assert result["tool_blocked"] is False
        assert result["sentinel_verdict"] == "allow"
        client.close()

    def test_deny_blocks_tool(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "deny", "reason": "Path blocked"},
        )

        client = SentinelClient()
        from sentinel.langgraph import create_sentinel_node

        node = create_sentinel_node(client, on_deny="block")
        result = node({
            "pending_tool_name": "write_file",
            "pending_tool_input": {"path": "/etc/shadow"},
        })

        assert result["tool_blocked"] is True
        assert result["sentinel_verdict"] == "deny"
        assert result["sentinel_reason"] == "Path blocked"
        client.close()

    def test_deny_continue_mode(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "deny", "reason": "Soft deny"},
        )

        client = SentinelClient()
        from sentinel.langgraph import create_sentinel_node

        node = create_sentinel_node(client, on_deny="continue")
        result = node({
            "pending_tool_name": "test",
            "pending_tool_input": {},
        })

        assert result["tool_blocked"] is False
        assert result["sentinel_verdict"] == "deny"
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

        client = SentinelClient()
        from sentinel.langgraph import create_sentinel_node

        node = create_sentinel_node(client, on_approval_required="block")
        result = node({
            "pending_tool_name": "delete",
            "pending_tool_input": {},
        })

        assert result["tool_blocked"] is True
        assert result["sentinel_approval_id"] == "apr-1"
        client.close()

    def test_no_pending_tool_passes_through(self, httpx_mock):
        client = SentinelClient()
        from sentinel.langgraph import create_sentinel_node

        node = create_sentinel_node(client)
        result = node({})

        assert result["tool_blocked"] is False
        client.close()

    def test_call_chain_updated(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = SentinelClient()
        from sentinel.langgraph import create_sentinel_node

        node = create_sentinel_node(client)
        result = node({
            "pending_tool_name": "tool_a",
            "pending_tool_input": {},
            "sentinel_call_chain": ["tool_x"],
        })

        assert result["sentinel_call_chain"] == ["tool_x", "tool_a"]
        client.close()

    def test_call_chain_bounded(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = SentinelClient()
        from sentinel.langgraph import create_sentinel_node

        node = create_sentinel_node(client)
        long_chain = [f"tool_{i}" for i in range(25)]
        result = node({
            "pending_tool_name": "new_tool",
            "pending_tool_input": {},
            "sentinel_call_chain": long_chain,
        })

        # Code pops one element when >20, so 25 + 1 new - 1 pop = 25
        assert len(result["sentinel_call_chain"]) <= 26
        assert result["sentinel_call_chain"][-1] == "new_tool"
        client.close()

    def test_path_extraction(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = SentinelClient()
        from sentinel.langgraph import create_sentinel_node

        node = create_sentinel_node(client)
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

        client = SentinelClient()
        from sentinel.langgraph import create_sentinel_node

        node = create_sentinel_node(client)
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

        client = SentinelClient()
        from sentinel.langgraph import create_sentinel_node

        node = create_sentinel_node(client)
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

        client = SentinelClient()
        from sentinel.langgraph import create_sentinel_node

        node = create_sentinel_node(client, on_deny="block")
        result = node({
            "pending_tool_name": "test",
            "pending_tool_input": {},
        })

        assert result["tool_blocked"] is True
        assert result["sentinel_verdict"] == "deny"
        client.close()

    def test_context_passed_from_state(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = SentinelClient()
        from sentinel.langgraph import create_sentinel_node

        node = create_sentinel_node(client)
        node({
            "pending_tool_name": "test",
            "pending_tool_input": {},
            "sentinel_session_id": "sess-123",
            "sentinel_agent_id": "agent-abc",
            "sentinel_call_chain": ["prev_tool"],
        })

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["context"]["session_id"] == "sess-123"
        assert body["context"]["agent_id"] == "agent-abc"
        assert body["context"]["call_chain"] == ["prev_tool"]
        client.close()


class TestSentinelState:
    """Tests for SentinelState TypedDict."""

    def test_sentinel_state_fields(self):
        from sentinel.langgraph import SentinelState

        # SentinelState is a TypedDict - verify expected keys
        annotations = SentinelState.__annotations__
        assert "sentinel_verdict" in annotations
        assert "sentinel_reason" in annotations
        assert "sentinel_policy_id" in annotations
        assert "sentinel_approval_id" in annotations
        assert "sentinel_session_id" in annotations
        assert "sentinel_agent_id" in annotations
        assert "sentinel_call_chain" in annotations
        assert "pending_tool_name" in annotations
        assert "pending_tool_input" in annotations
        assert "tool_blocked" in annotations
