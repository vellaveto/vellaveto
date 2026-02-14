"""Tests for vellaveto.redaction module."""

import json

import pytest
import httpx

from vellaveto.redaction import ParameterRedactor, DEFAULT_SENSITIVE_KEYS, REDACTED_PLACEHOLDER
from vellaveto.client import VellavetoClient, AsyncVellavetoClient
from vellaveto.types import Verdict


class TestParameterRedactorInit:
    """Tests for ParameterRedactor initialization."""

    def test_default_mode(self):
        r = ParameterRedactor()
        assert r.mode == "keys_only"

    def test_values_mode(self):
        r = ParameterRedactor(mode="values")
        assert r.mode == "values"

    def test_all_mode(self):
        r = ParameterRedactor(mode="all")
        assert r.mode == "all"

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError, match="Invalid redaction mode"):
            ParameterRedactor(mode="invalid")

    def test_default_sensitive_keys(self):
        r = ParameterRedactor()
        assert "password" in r.sensitive_keys
        assert "api_key" in r.sensitive_keys
        assert "token" in r.sensitive_keys
        assert "secret" in r.sensitive_keys

    def test_custom_sensitive_keys(self):
        r = ParameterRedactor(sensitive_keys={"my_field"})
        assert "my_field" in r.sensitive_keys
        assert "password" not in r.sensitive_keys

    def test_extra_keys(self):
        r = ParameterRedactor(extra_keys={"custom_secret"})
        assert "custom_secret" in r.sensitive_keys
        assert "password" in r.sensitive_keys  # defaults still present

    def test_custom_placeholder(self):
        r = ParameterRedactor(placeholder="***")
        assert r.placeholder == "***"

    def test_sensitive_keys_returns_copy(self):
        r = ParameterRedactor()
        keys = r.sensitive_keys
        keys.add("should_not_affect_original")
        assert "should_not_affect_original" not in r.sensitive_keys


class TestKeySensitivity:
    """Tests for key name sensitivity detection."""

    def test_exact_match(self):
        r = ParameterRedactor()
        assert r.is_sensitive_key("password") is True
        assert r.is_sensitive_key("api_key") is True
        assert r.is_sensitive_key("token") is True

    def test_case_insensitive(self):
        r = ParameterRedactor()
        assert r.is_sensitive_key("PASSWORD") is True
        assert r.is_sensitive_key("Api_Key") is True
        assert r.is_sensitive_key("TOKEN") is True

    def test_hyphen_normalization(self):
        r = ParameterRedactor()
        assert r.is_sensitive_key("api-key") is True
        assert r.is_sensitive_key("access-token") is True

    def test_suffix_match(self):
        r = ParameterRedactor()
        assert r.is_sensitive_key("openai_api_key") is True
        assert r.is_sensitive_key("db_password") is True
        assert r.is_sensitive_key("stripe_secret") is True
        assert r.is_sensitive_key("user.password") is True

    def test_non_sensitive_keys(self):
        r = ParameterRedactor()
        assert r.is_sensitive_key("path") is False
        assert r.is_sensitive_key("url") is False
        assert r.is_sensitive_key("name") is False
        assert r.is_sensitive_key("content") is False


class TestValueSensitivity:
    """Tests for value pattern detection."""

    def test_openai_key(self):
        r = ParameterRedactor()
        assert r.is_sensitive_value("sk-abcdefghijklmnopqrstuvwxyz1234") is True

    def test_github_pat(self):
        r = ParameterRedactor()
        assert r.is_sensitive_value("ghp_" + "a" * 36) is True

    def test_github_oauth(self):
        r = ParameterRedactor()
        assert r.is_sensitive_value("gho_" + "a" * 36) is True

    def test_gitlab_pat(self):
        r = ParameterRedactor()
        assert r.is_sensitive_value("glpat-" + "a" * 20) is True

    def test_aws_access_key(self):
        r = ParameterRedactor()
        assert r.is_sensitive_value("AKIAIOSFODNN7EXAMPLE") is True

    def test_jwt(self):
        r = ParameterRedactor()
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assert r.is_sensitive_value(jwt) is True

    def test_non_secret_values(self):
        r = ParameterRedactor()
        assert r.is_sensitive_value("/tmp/test.txt") is False
        assert r.is_sensitive_value("hello world") is False
        assert r.is_sensitive_value("https://example.com") is False
        assert r.is_sensitive_value("12345") is False  # too short

    def test_short_values_ignored(self):
        r = ParameterRedactor()
        assert r.is_sensitive_value("sk-abc") is False  # < 8 chars

    def test_non_string_values(self):
        r = ParameterRedactor()
        assert r.is_sensitive_value(12345) is False
        assert r.is_sensitive_value(None) is False


class TestRedactKeysOnly:
    """Tests for keys_only redaction mode."""

    def test_redacts_sensitive_key(self):
        r = ParameterRedactor()
        result = r.redact({"path": "/tmp/x", "api_key": "sk-secret123"})
        assert result["path"] == "/tmp/x"
        assert result["api_key"] == REDACTED_PLACEHOLDER

    def test_redacts_multiple_keys(self):
        r = ParameterRedactor()
        result = r.redact({
            "url": "https://api.example.com",
            "password": "hunter2",
            "token": "abc123",
        })
        assert result["url"] == "https://api.example.com"
        assert result["password"] == REDACTED_PLACEHOLDER
        assert result["token"] == REDACTED_PLACEHOLDER

    def test_nested_dict_redaction(self):
        r = ParameterRedactor()
        result = r.redact({
            "config": {
                "host": "db.example.com",
                "password": "secret",
            }
        })
        assert result["config"]["host"] == "db.example.com"
        assert result["config"]["password"] == REDACTED_PLACEHOLDER

    def test_list_with_dicts(self):
        r = ParameterRedactor()
        result = r.redact({
            "headers": [
                {"name": "Authorization", "token": "bearer-xyz"},
                {"name": "Content-Type", "value": "application/json"},
            ]
        })
        assert result["headers"][0]["name"] == "Authorization"
        assert result["headers"][0]["token"] == REDACTED_PLACEHOLDER
        assert result["headers"][1]["value"] == "application/json"

    def test_does_not_redact_values_in_keys_only_mode(self):
        r = ParameterRedactor(mode="keys_only")
        result = r.redact({"config": "sk-abcdefghijklmnopqrstuvwxyz1234"})
        # In keys_only mode, value patterns are NOT scanned
        assert result["config"] == "sk-abcdefghijklmnopqrstuvwxyz1234"

    def test_empty_dict(self):
        r = ParameterRedactor()
        assert r.redact({}) == {}

    def test_none_params(self):
        r = ParameterRedactor()
        assert r.redact(None) is None

    def test_custom_placeholder(self):
        r = ParameterRedactor(placeholder="***MASKED***")
        result = r.redact({"password": "hunter2"})
        assert result["password"] == "***MASKED***"


class TestRedactValues:
    """Tests for values redaction mode."""

    def test_redacts_secret_value_patterns(self):
        r = ParameterRedactor(mode="values")
        result = r.redact({
            "path": "/tmp/x",
            "config": "sk-abcdefghijklmnopqrstuvwxyz1234",
        })
        assert result["path"] == "/tmp/x"
        assert result["config"] == REDACTED_PLACEHOLDER

    def test_redacts_both_keys_and_values(self):
        r = ParameterRedactor(mode="values")
        result = r.redact({
            "api_key": "abc",       # redacted by key name
            "data": "ghp_" + "a" * 36,  # redacted by value pattern
        })
        assert result["api_key"] == REDACTED_PLACEHOLDER
        assert result["data"] == REDACTED_PLACEHOLDER

    def test_redacts_values_in_lists(self):
        r = ParameterRedactor(mode="values")
        result = r.redact({
            "tokens": ["normal", "sk-abcdefghijklmnopqrstuvwxyz1234"]
        })
        assert result["tokens"][0] == "normal"
        assert result["tokens"][1] == REDACTED_PLACEHOLDER


class TestRedactAll:
    """Tests for all redaction mode."""

    def test_redacts_everything(self):
        r = ParameterRedactor(mode="all")
        result = r.redact({
            "path": "/tmp/x",
            "query": "SELECT 1",
            "count": 42,
        })
        assert result["path"] == REDACTED_PLACEHOLDER
        assert result["query"] == REDACTED_PLACEHOLDER
        assert result["count"] == REDACTED_PLACEHOLDER

    def test_preserves_keys(self):
        r = ParameterRedactor(mode="all")
        result = r.redact({"path": "/tmp/x", "mode": "read"})
        assert set(result.keys()) == {"path", "mode"}


class TestRedactDepthLimit:
    """Tests for recursion depth protection."""

    def test_deeply_nested_dict(self):
        r = ParameterRedactor()
        # Build a 15-level nested dict
        d = {"password": "secret"}
        for _ in range(15):
            d = {"nested": d}

        result = r.redact(d)
        # Should not raise; deeply nested values get fully redacted
        assert isinstance(result, dict)


class TestRedactorOriginalUnchanged:
    """Verify redaction returns a new dict and doesn't mutate the original."""

    def test_original_unchanged(self):
        r = ParameterRedactor()
        original = {"path": "/tmp/x", "api_key": "my-secret"}
        result = r.redact(original)
        assert result["api_key"] == REDACTED_PLACEHOLDER
        assert original["api_key"] == "my-secret"  # unchanged

    def test_nested_original_unchanged(self):
        r = ParameterRedactor()
        original = {"config": {"password": "hunter2"}}
        result = r.redact(original)
        assert result["config"]["password"] == REDACTED_PLACEHOLDER
        assert original["config"]["password"] == "hunter2"


class TestClientRedactorIntegration:
    """Tests for VellavetoClient + ParameterRedactor integration."""

    def test_client_accepts_redactor(self):
        r = ParameterRedactor()
        client = VellavetoClient(redactor=r)
        assert client.redactor is r
        client.close()

    def test_client_default_no_redactor(self):
        client = VellavetoClient()
        assert client.redactor is None
        client.close()

    def test_evaluate_redacts_parameters(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        r = ParameterRedactor()
        client = VellavetoClient(redactor=r)
        client.evaluate(
            tool="http",
            function="fetch",
            parameters={"url": "https://api.example.com", "api_key": "sk-secret123"},
        )

        # Verify the request payload has redacted api_key
        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["action"]["parameters"]["url"] == "https://api.example.com"
        assert body["action"]["parameters"]["api_key"] == REDACTED_PLACEHOLDER
        client.close()

    def test_evaluate_without_redactor_sends_raw(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        client = VellavetoClient()  # no redactor
        client.evaluate(
            tool="http",
            function="fetch",
            parameters={"url": "https://api.example.com", "api_key": "sk-secret123"},
        )

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["action"]["parameters"]["api_key"] == "sk-secret123"
        client.close()

    def test_evaluate_redactor_all_mode(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        r = ParameterRedactor(mode="all")
        client = VellavetoClient(redactor=r)
        client.evaluate(
            tool="filesystem",
            function="read_file",
            parameters={"path": "/etc/passwd", "mode": "r"},
        )

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["action"]["parameters"]["path"] == REDACTED_PLACEHOLDER
        assert body["action"]["parameters"]["mode"] == REDACTED_PLACEHOLDER
        client.close()


class TestAsyncClientRedactorIntegration:
    """Tests for AsyncVellavetoClient + ParameterRedactor integration."""

    @pytest.mark.asyncio
    async def test_async_evaluate_redacts_parameters(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        r = ParameterRedactor()
        async with AsyncVellavetoClient(redactor=r) as client:
            await client.evaluate(
                tool="http",
                function="fetch",
                parameters={"url": "https://example.com", "api_key": "sk-secret"},
            )

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["action"]["parameters"]["url"] == "https://example.com"
        assert body["action"]["parameters"]["api_key"] == REDACTED_PLACEHOLDER

    @pytest.mark.asyncio
    async def test_async_evaluate_without_redactor_sends_raw(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        async with AsyncVellavetoClient() as client:
            await client.evaluate(
                tool="http",
                function="fetch",
                parameters={"api_key": "sk-secret"},
            )

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["action"]["parameters"]["api_key"] == "sk-secret"

    @pytest.mark.asyncio
    async def test_async_evaluate_redactor_values_mode(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        r = ParameterRedactor(mode="values")
        async with AsyncVellavetoClient(redactor=r) as client:
            await client.evaluate(
                tool="test",
                parameters={"data": "sk-abcdefghijklmnopqrstuvwxyz1234"},
            )

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["action"]["parameters"]["data"] == REDACTED_PLACEHOLDER

    @pytest.mark.asyncio
    async def test_async_evaluate_redactor_all_mode(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/evaluate",
            json={"verdict": "allow"},
        )

        r = ParameterRedactor(mode="all")
        async with AsyncVellavetoClient(redactor=r) as client:
            await client.evaluate(
                tool="test",
                parameters={"path": "/tmp/x", "query": "SELECT 1"},
            )

        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["action"]["parameters"]["path"] == REDACTED_PLACEHOLDER
        assert body["action"]["parameters"]["query"] == REDACTED_PLACEHOLDER


class TestUnicodeRedaction:
    """Tests for Unicode edge cases in parameter redaction."""

    def test_uppercase_key_redacted(self):
        r = ParameterRedactor()
        result = r.redact({"PASSWORD": "secret", "API_KEY": "key123"})
        assert result["PASSWORD"] == REDACTED_PLACEHOLDER
        assert result["API_KEY"] == REDACTED_PLACEHOLDER

    def test_mixed_case_suffix_match(self):
        r = ParameterRedactor()
        result = r.redact({"OPENAI_API_KEY": "sk-123", "my_Password": "hunter2"})
        assert result["OPENAI_API_KEY"] == REDACTED_PLACEHOLDER
        assert result["my_Password"] == REDACTED_PLACEHOLDER

    def test_numeric_values_not_redacted(self):
        r = ParameterRedactor()
        result = r.redact({"password": "secret", "count": 42, "flag": True})
        assert result["password"] == REDACTED_PLACEHOLDER
        assert result["count"] == 42
        assert result["flag"] is True

    def test_empty_string_value_redacted_for_sensitive_key(self):
        r = ParameterRedactor()
        result = r.redact({"password": ""})
        assert result["password"] == REDACTED_PLACEHOLDER

    def test_nested_list_of_dicts(self):
        r = ParameterRedactor()
        result = r.redact({
            "configs": [
                {"name": "prod", "token": "abc123"},
                {"name": "dev", "secret": "def456"},
            ]
        })
        assert result["configs"][0]["name"] == "prod"
        assert result["configs"][0]["token"] == REDACTED_PLACEHOLDER
        assert result["configs"][1]["name"] == "dev"
        assert result["configs"][1]["secret"] == REDACTED_PLACEHOLDER

    def test_mixed_list_types(self):
        r = ParameterRedactor(mode="values")
        result = r.redact({
            "items": [42, "normal", {"password": "secret"}, [1, 2, 3]]
        })
        assert result["items"][0] == 42
        assert result["items"][1] == "normal"
        assert result["items"][2]["password"] == REDACTED_PLACEHOLDER
        assert result["items"][3] == [1, 2, 3]

    def test_dot_notation_suffix_match(self):
        r = ParameterRedactor()
        assert r.is_sensitive_key("db.password") is True
        assert r.is_sensitive_key("config.api_key") is True
        assert r.is_sensitive_key("auth.token") is True

    def test_deeply_nested_sensitive_key(self):
        r = ParameterRedactor()
        data = {"level1": {"level2": {"level3": {"password": "deep-secret"}}}}
        result = r.redact(data)
        assert result["level1"]["level2"]["level3"]["password"] == REDACTED_PLACEHOLDER
