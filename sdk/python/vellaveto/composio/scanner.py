"""
Client-side response scanning for Composio integration.

Provides lightweight DLP (Data Loss Prevention) and prompt injection
detection on tool call responses.  This is defense-in-depth — the full
Aho-Corasick + NFKC + 5-layer decode scanning runs server-side via the
Vellaveto HTTP proxy.  The client-side scanner catches obvious leaks and
injections using regex patterns.

Reuses ``ParameterRedactor.is_sensitive_value()`` for secret-pattern
detection when a redactor is provided.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Pattern

logger = logging.getLogger(__name__)

# Injection patterns — lightweight regex for common prompt injection
# indicators in tool responses.  Not a substitute for server-side scanning.
_DEFAULT_INJECTION_PATTERNS: List[str] = [
    r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)",
    r"(?i)you\s+are\s+now\s+(a|an|in)\s+",
    r"(?i)system\s*:\s*",
    r"(?i)new\s+instructions?\s*:",
    r"(?i)\bdo\s+not\s+follow\s+(the\s+)?(original|previous|prior)\b",
    r"(?i)\b(admin|root|sudo)\s+override\b",
    r"(?i)\bact\s+as\s+(a|an|if)\b",
    r"(?i)\bforget\s+(everything|all|your)\b",
    r"(?i)\brole\s*:\s*system\b",
    r"(?i)<\s*\/?system\s*>",
]


@dataclass
class ScanFinding:
    """A single finding from response scanning.

    Attributes:
        category: ``"secret"`` or ``"injection"``.
        field_path: Dot-delimited JSON path to the finding.
        pattern: The pattern name or regex that matched.
        snippet: A truncated excerpt of the matched value (max 60 chars).
    """
    category: str
    field_path: str
    pattern: str
    snippet: str = ""


@dataclass
class ResponseScanResult:
    """Result of scanning a Composio tool response.

    Attributes:
        findings: List of individual findings.
        blocked: ``True`` if the response should be blocked.
    """
    findings: List[ScanFinding] = field(default_factory=list)
    blocked: bool = False


class ResponseScanner:
    """Scans Composio tool responses for secrets and injection indicators.

    Args:
        redactor: Optional ``ParameterRedactor`` whose
            ``is_sensitive_value()`` method is used for secret detection.
            When *None*, secret scanning is skipped.
        injection_patterns: Override the default injection regex list.
        scan_depth: Maximum recursion depth for nested structures
            (default 10).
    """

    def __init__(
        self,
        redactor: Optional[Any] = None,
        injection_patterns: Optional[List[str]] = None,
        scan_depth: int = 10,
    ):
        self._redactor = redactor
        self._scan_depth = max(1, min(scan_depth, 50))

        raw_patterns = injection_patterns if injection_patterns is not None else _DEFAULT_INJECTION_PATTERNS
        self._injection_patterns: List[Pattern[str]] = [
            re.compile(p) for p in raw_patterns
        ]

    def scan(self, response_data: Any) -> ResponseScanResult:
        """Scan *response_data* for secrets and injection indicators.

        Recursively walks dicts and lists up to ``scan_depth`` levels.

        Args:
            response_data: The Composio response payload (typically a dict).

        Returns:
            ``ResponseScanResult`` with any findings.
        """
        result = ResponseScanResult()
        self._walk(response_data, "", 0, result)
        if result.findings:
            result.blocked = True
        return result

    # ── internal helpers ─────────────────────────────────────────

    def _walk(
        self,
        value: Any,
        path: str,
        depth: int,
        result: ResponseScanResult,
    ) -> None:
        if depth > self._scan_depth:
            return

        if isinstance(value, str):
            self._scan_string(value, path, result)
        elif isinstance(value, dict):
            for k, v in value.items():
                child_path = f"{path}.{k}" if path else k
                self._walk(v, child_path, depth + 1, result)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                child_path = f"{path}[{i}]"
                self._walk(item, child_path, depth + 1, result)

    def _scan_string(
        self,
        value: str,
        path: str,
        result: ResponseScanResult,
    ) -> None:
        # Secret detection via redactor patterns
        if self._redactor is not None and self._redactor.is_sensitive_value(value):
            result.findings.append(ScanFinding(
                category="secret",
                field_path=path,
                pattern="secret_value_pattern",
                snippet=self._truncate(value),
            ))

        # Injection pattern matching
        for pattern in self._injection_patterns:
            if pattern.search(value):
                result.findings.append(ScanFinding(
                    category="injection",
                    field_path=path,
                    pattern=pattern.pattern,
                    snippet=self._truncate(value),
                ))
                # One injection finding per field is enough
                break

    @staticmethod
    def _truncate(value: str, max_len: int = 60) -> str:
        if len(value) <= max_len:
            return value
        return value[:max_len - 3] + "..."
