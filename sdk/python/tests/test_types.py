"""Tests for vellaveto.types module."""

import pytest
from vellaveto.types import (
    Action,
    DlpFinding,
    EvaluationContext,
    EvaluationResult,
    InjectionAlert,
    Verdict,
)


class TestVerdict:
    """Tests for the Verdict enum."""

    def test_verdict_values(self):
        assert Verdict.ALLOW.value == "allow"
        assert Verdict.DENY.value == "deny"
        assert Verdict.REQUIRE_APPROVAL.value == "require_approval"

    def test_verdict_from_string(self):
        assert Verdict("allow") == Verdict.ALLOW
        assert Verdict("deny") == Verdict.DENY
        assert Verdict("require_approval") == Verdict.REQUIRE_APPROVAL

    def test_verdict_invalid_string(self):
        with pytest.raises(ValueError):
            Verdict("invalid")


class TestAction:
    """Tests for the Action dataclass."""

    def test_minimal_action(self):
        action = Action(tool="filesystem")
        assert action.tool == "filesystem"
        assert action.function is None
        assert action.parameters == {}
        assert action.target_paths == []
        assert action.target_domains == []
        assert action.resolved_ips == []

    def test_full_action(self):
        action = Action(
            tool="filesystem",
            function="read_file",
            parameters={"path": "/etc/passwd"},
            target_paths=["/etc/passwd"],
            target_domains=[],
            resolved_ips=[],
        )
        assert action.tool == "filesystem"
        assert action.function == "read_file"
        assert action.parameters == {"path": "/etc/passwd"}
        assert action.target_paths == ["/etc/passwd"]

    def test_to_dict(self):
        action = Action(
            tool="http",
            function="fetch",
            parameters={"url": "https://example.com"},
            target_domains=["example.com"],
        )
        d = action.to_dict()
        assert d["tool"] == "http"
        assert d["function"] == "fetch"
        assert d["parameters"] == {"url": "https://example.com"}
        assert d["target_domains"] == ["example.com"]
        assert d["target_paths"] == []
        assert d["resolved_ips"] == []

    def test_to_dict_keys(self):
        action = Action(tool="test")
        d = action.to_dict()
        expected_keys = {
            "tool",
            "function",
            "parameters",
            "target_paths",
            "target_domains",
            "resolved_ips",
        }
        assert set(d.keys()) == expected_keys

    def test_action_mutable_defaults_isolated(self):
        """Ensure mutable default fields don't share state between instances."""
        a1 = Action(tool="test1")
        a2 = Action(tool="test2")
        a1.parameters["key"] = "value"
        a1.target_paths.append("/tmp")
        assert a2.parameters == {}
        assert a2.target_paths == []


class TestEvaluationResult:
    """Tests for the EvaluationResult dataclass."""

    def test_from_dict_allow(self):
        data = {"verdict": "allow", "policy_id": "p1", "policy_name": "test"}
        result = EvaluationResult.from_dict(data)
        assert result.verdict == Verdict.ALLOW
        assert result.policy_id == "p1"
        assert result.policy_name == "test"
        assert result.reason is None
        assert result.approval_id is None

    def test_from_dict_deny(self):
        data = {
            "verdict": "deny",
            "reason": "Path blocked",
            "policy_id": "p2",
        }
        result = EvaluationResult.from_dict(data)
        assert result.verdict == Verdict.DENY
        assert result.reason == "Path blocked"

    def test_from_dict_require_approval(self):
        data = {
            "verdict": "require_approval",
            "reason": "Needs human review",
            "approval_id": "apr-123",
        }
        result = EvaluationResult.from_dict(data)
        assert result.verdict == Verdict.REQUIRE_APPROVAL
        assert result.approval_id == "apr-123"

    def test_from_dict_case_insensitive(self):
        data = {"verdict": "ALLOW"}
        result = EvaluationResult.from_dict(data)
        assert result.verdict == Verdict.ALLOW

    def test_from_dict_missing_verdict_defaults_deny(self):
        """Fail-closed: missing verdict defaults to deny."""
        data = {}
        result = EvaluationResult.from_dict(data)
        assert result.verdict == Verdict.DENY

    def test_from_dict_with_trace(self):
        data = {
            "verdict": "allow",
            "trace": {"matched_rule": "allow-read", "duration_ms": 1.2},
        }
        result = EvaluationResult.from_dict(data)
        assert result.trace is not None
        assert result.trace["matched_rule"] == "allow-read"

    def test_from_dict_invalid_verdict_fails_closed(self):
        """SECURITY (FIND-SDK-002): Unknown verdicts fail-closed to DENY."""
        data = {"verdict": "invalid_value"}
        result = EvaluationResult.from_dict(data)
        assert result.verdict == Verdict.DENY


class TestEvaluationContext:
    """Tests for the EvaluationContext dataclass."""

    def test_empty_context(self):
        ctx = EvaluationContext()
        assert ctx.session_id is None
        assert ctx.agent_id is None
        assert ctx.tenant_id is None
        assert ctx.call_chain == []
        assert ctx.metadata == {}

    def test_full_context(self):
        ctx = EvaluationContext(
            session_id="sess-1",
            agent_id="agent-1",
            tenant_id="tenant-1",
            call_chain=["tool_a", "tool_b"],
            metadata={"key": "value"},
        )
        assert ctx.session_id == "sess-1"
        assert ctx.agent_id == "agent-1"
        assert ctx.tenant_id == "tenant-1"
        assert ctx.call_chain == ["tool_a", "tool_b"]
        assert ctx.metadata == {"key": "value"}

    def test_to_dict(self):
        ctx = EvaluationContext(
            session_id="sess-1",
            agent_id="agent-1",
        )
        d = ctx.to_dict()
        assert d["session_id"] == "sess-1"
        assert d["agent_id"] == "agent-1"
        assert d["tenant_id"] is None
        assert d["call_chain"] == []
        assert d["metadata"] == {}

    def test_to_dict_keys(self):
        ctx = EvaluationContext()
        d = ctx.to_dict()
        expected_keys = {"session_id", "agent_id", "tenant_id", "call_chain", "metadata"}
        assert set(d.keys()) == expected_keys

    def test_context_mutable_defaults_isolated(self):
        c1 = EvaluationContext()
        c2 = EvaluationContext()
        c1.call_chain.append("tool_a")
        c1.metadata["k"] = "v"
        assert c2.call_chain == []
        assert c2.metadata == {}


class TestDlpFinding:
    """Tests for the DlpFinding dataclass."""

    def test_basic_finding(self):
        finding = DlpFinding(
            pattern_name="aws_key",
            field_path="$.parameters.api_key",
            redacted_value="AKIA****XXXX",
        )
        assert finding.pattern_name == "aws_key"
        assert finding.field_path == "$.parameters.api_key"
        assert finding.redacted_value == "AKIA****XXXX"

    def test_finding_without_redacted(self):
        finding = DlpFinding(pattern_name="ssn", field_path="$.data.ssn")
        assert finding.redacted_value is None


class TestInjectionAlert:
    """Tests for the InjectionAlert dataclass."""

    def test_basic_alert(self):
        alert = InjectionAlert(
            pattern="ignore previous instructions",
            location="$.parameters.prompt",
            severity="high",
        )
        assert alert.pattern == "ignore previous instructions"
        assert alert.location == "$.parameters.prompt"
        assert alert.severity == "high"

    def test_default_severity(self):
        alert = InjectionAlert(pattern="test", location="$.input")
        assert alert.severity == "medium"
