"""Tests for vellaveto.langchain module."""

import json
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from vellaveto.client import PolicyDenied, ApprovalRequired, VellavetoClient
from vellaveto.types import EvaluationResult, Verdict


class TestVellavetoCallbackHandler:
    """Tests for VellavetoCallbackHandler."""

    def _make_handler(self, httpx_mock, response_json=None):
        if response_json is None:
            response_json = {"verdict": "allow"}
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json=response_json,
        )
        client = VellavetoClient()
        # Import after mock is set up
        from vellaveto.langchain import VellavetoCallbackHandler

        return VellavetoCallbackHandler(
            client=client,
            session_id="test-session",
            agent_id="test-agent",
            raise_on_deny=True,
        ), client

    def test_on_tool_start_allow(self, httpx_mock):
        handler, client = self._make_handler(httpx_mock)
        handler.on_tool_start(
            serialized={"name": "read_file"},
            input_str='{"path": "/tmp/test.txt"}',
            run_id=uuid4(),
        )
        # Should not raise
        client.close()

    def test_on_tool_start_deny_raises(self, httpx_mock):
        handler, client = self._make_handler(
            httpx_mock,
            {"verdict": "deny", "reason": "Path blocked"},
        )
        with pytest.raises(PolicyDenied) as exc_info:
            handler.on_tool_start(
                serialized={"name": "write_file"},
                input_str='{"path": "/etc/shadow"}',
                run_id=uuid4(),
            )
        assert "Path blocked" in str(exc_info.value)
        client.close()

    def test_on_tool_start_approval_required_raises(self, httpx_mock):
        handler, client = self._make_handler(
            httpx_mock,
            {"verdict": "require_approval", "reason": "Review", "approval_id": "apr-1"},
        )
        with pytest.raises(ApprovalRequired):
            handler.on_tool_start(
                serialized={"name": "delete_db"},
                input_str="{}",
                run_id=uuid4(),
            )
        client.close()

    def test_on_tool_start_deny_no_raise(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "deny", "reason": "Blocked"},
        )
        client = VellavetoClient()
        from vellaveto.langchain import VellavetoCallbackHandler

        handler = VellavetoCallbackHandler(client=client, raise_on_deny=False)
        # Should not raise when raise_on_deny=False
        handler.on_tool_start(
            serialized={"name": "test"},
            input_str="{}",
            run_id=uuid4(),
        )
        client.close()

    def test_call_chain_tracking(self, httpx_mock):
        # Allow multiple responses
        for _ in range(3):
            httpx_mock.add_response(
                url="http://localhost:3000/api/evaluate",
                json={"verdict": "allow"},
            )

        client = VellavetoClient()
        from vellaveto.langchain import VellavetoCallbackHandler

        handler = VellavetoCallbackHandler(client=client, log_evaluations=False)

        for name in ["tool_a", "tool_b", "tool_c"]:
            handler.on_tool_start(
                serialized={"name": name},
                input_str="{}",
                run_id=uuid4(),
            )

        assert handler._call_chain == ["tool_a", "tool_b", "tool_c"]
        client.close()

    def test_call_chain_max_length(self, httpx_mock):
        for _ in range(25):
            httpx_mock.add_response(
                url="http://localhost:3000/api/evaluate",
                json={"verdict": "allow"},
            )

        client = VellavetoClient()
        from vellaveto.langchain import VellavetoCallbackHandler

        handler = VellavetoCallbackHandler(client=client, log_evaluations=False)

        for i in range(25):
            handler.on_tool_start(
                serialized={"name": f"tool_{i}"},
                input_str="{}",
                run_id=uuid4(),
            )

        assert len(handler._call_chain) == 20
        assert handler._call_chain[0] == "tool_5"
        assert handler._call_chain[-1] == "tool_24"
        client.close()

    def test_extract_paths_from_input(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient()
        from vellaveto.langchain import VellavetoCallbackHandler

        handler = VellavetoCallbackHandler(client=client, log_evaluations=False)
        handler.on_tool_start(
            serialized={"name": "read_file"},
            input_str='{"path": "/tmp/test.txt", "mode": "r"}',
            run_id=uuid4(),
        )

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert "/tmp/test.txt" in body["action"]["target_paths"]
        client.close()

    def test_extract_domains_from_input(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient()
        from vellaveto.langchain import VellavetoCallbackHandler

        handler = VellavetoCallbackHandler(client=client, log_evaluations=False)
        handler.on_tool_start(
            serialized={"name": "fetch"},
            input_str='{"url": "https://example.com/api"}',
            run_id=uuid4(),
        )

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert "https://example.com/api" in body["action"]["target_domains"]
        client.close()

    def test_string_input_handled(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient()
        from vellaveto.langchain import VellavetoCallbackHandler

        handler = VellavetoCallbackHandler(client=client, log_evaluations=False)
        handler.on_tool_start(
            serialized={"name": "search"},
            input_str="plain string query",
            run_id=uuid4(),
        )

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["action"]["parameters"] == {"input": "plain string query"}
        client.close()

    def test_fail_closed_on_api_error(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            status_code=500,
        )

        client = VellavetoClient()
        from vellaveto.langchain import VellavetoCallbackHandler

        handler = VellavetoCallbackHandler(client=client, raise_on_deny=True)
        with pytest.raises(PolicyDenied, match="Evaluation failed"):
            handler.on_tool_start(
                serialized={"name": "test"},
                input_str="{}",
                run_id=uuid4(),
            )
        client.close()

    def test_inputs_kwarg_preferred(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient()
        from vellaveto.langchain import VellavetoCallbackHandler

        handler = VellavetoCallbackHandler(client=client, log_evaluations=False)
        handler.on_tool_start(
            serialized={"name": "test"},
            input_str='{"old": "data"}',
            run_id=uuid4(),
            inputs={"new": "data"},
        )

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["action"]["parameters"] == {"new": "data"}
        client.close()


class TestVellavetoToolGuard:
    """Tests for VellavetoToolGuard decorator."""

    def test_guard_allows_execution(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient()
        from vellaveto.langchain import VellavetoToolGuard

        guard = VellavetoToolGuard(client)

        @guard("filesystem", "read_file")
        def read_file(path: str) -> str:
            return f"contents of {path}"

        result = read_file(path="/tmp/test.txt")
        assert result == "contents of /tmp/test.txt"
        client.close()

    def test_guard_blocks_execution(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "deny", "reason": "Blocked"},
        )

        client = VellavetoClient()
        from vellaveto.langchain import VellavetoToolGuard

        guard = VellavetoToolGuard(client)
        call_count = 0

        @guard("filesystem", "write_file")
        def write_file(path: str, content: str) -> None:
            nonlocal call_count
            call_count += 1

        with pytest.raises(PolicyDenied):
            write_file(path="/etc/shadow", content="malicious")

        assert call_count == 0  # Function never executed
        client.close()

    def test_guard_extracts_paths(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient()
        from vellaveto.langchain import VellavetoToolGuard

        guard = VellavetoToolGuard(client)

        @guard("fs", extract_paths=["filepath"])
        def read(filepath: str) -> str:
            return "ok"

        read(filepath="/tmp/secret.txt")

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert "/tmp/secret.txt" in body["action"]["target_paths"]
        client.close()
