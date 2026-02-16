"""
Target extraction and tool slug normalization for Composio integration.

Composio uses uppercase slugs like ``GITHUB_CREATE_ISSUE`` that need to be
split into a tool name and function name for Vellaveto policy evaluation.

This module provides pure functions with no external dependencies.
"""

from typing import Dict, Any, List, Tuple


# Parameter names that indicate file-system paths
_PATH_KEYS = frozenset({
    "path", "file", "filename", "filepath", "file_path",
    "directory", "dir", "folder", "dest", "destination", "source",
})

# Parameter names that indicate network targets
_DOMAIN_KEYS = frozenset({
    "url", "uri", "endpoint", "host", "domain", "repo_url",
    "base_url", "api_url", "webhook_url", "callback_url",
})


def normalize_slug_to_tool_function(
    slug: str,
    toolkit: str = "",
) -> Tuple[str, str]:
    """Convert a Composio tool slug to a ``(tool, function)`` pair.

    Composio slugs follow the pattern ``TOOLKIT_ACTION_NAME`` (uppercase,
    underscore-delimited).  When a *toolkit* hint is provided, the toolkit
    prefix is stripped from the slug to produce the function name.  Otherwise
    the first underscore-delimited segment is assumed to be the toolkit.

    Examples::

        normalize_slug_to_tool_function("GITHUB_CREATE_ISSUE", "GITHUB")
        # => ("github", "create_issue")

        normalize_slug_to_tool_function("SLACK_SEND_MESSAGE")
        # => ("slack", "send_message")

        normalize_slug_to_tool_function("MYTOOL")
        # => ("mytool", "mytool")

    Args:
        slug: The Composio action slug (e.g. ``"GITHUB_CREATE_ISSUE"``).
        toolkit: Optional toolkit name hint.  When supplied, the toolkit
            prefix is stripped from *slug* to derive the function name.

    Returns:
        A ``(tool, function)`` tuple of lower-cased strings.
    """
    slug_lower = slug.lower()
    toolkit_lower = toolkit.lower() if toolkit else ""

    if toolkit_lower and slug_lower.startswith(toolkit_lower + "_"):
        function = slug_lower[len(toolkit_lower) + 1:]
        return (toolkit_lower, function)

    # Fall back to first-underscore split
    parts = slug_lower.split("_", 1)
    if len(parts) == 2:
        return (parts[0], parts[1])

    # Single-segment slug — use as both tool and function
    return (slug_lower, slug_lower)


def extract_targets(
    slug: str,
    arguments: Dict[str, Any],
) -> Tuple[List[str], List[str]]:
    """Extract ``target_paths`` and ``target_domains`` from Composio arguments.

    Mirrors the heuristic from ``vellaveto.langchain._extract_tool_info``:

    * Keys matching ``_PATH_KEYS`` are treated as file-system paths.
    * Keys matching ``_DOMAIN_KEYS`` are treated as network targets.
    * Any string value starting with ``http://``, ``https://``, or ``ftp://``
      is also captured as a domain target.

    Args:
        slug: The Composio action slug (unused in extraction but reserved
            for future per-tool rules).
        arguments: The tool call arguments dictionary.

    Returns:
        A ``(target_paths, target_domains)`` tuple of string lists.
    """
    target_paths: List[str] = []
    target_domains: List[str] = []

    if not isinstance(arguments, dict):
        return (target_paths, target_domains)

    for key, value in arguments.items():
        if not isinstance(value, str):
            continue

        key_lower = key.lower()

        if key_lower in _PATH_KEYS:
            target_paths.append(value)
        elif key_lower in _DOMAIN_KEYS:
            target_domains.append(value)
        elif value.startswith(("http://", "https://", "ftp://")):
            target_domains.append(value)

    return (target_paths, target_domains)
