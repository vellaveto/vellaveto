//! Tool and function pattern matching.
//!
//! This module provides pre-compiled pattern matchers for tool/function ID
//! segments, used to efficiently match policies against actions at evaluation time.

use vellaveto_types::Action;

/// Pre-compiled pattern matcher for tool/function ID segments.
#[derive(Debug, Clone)]
pub enum PatternMatcher {
    /// Matches anything ("*")
    Any,
    /// Exact string match
    Exact(String),
    /// Prefix match ("prefix*")
    Prefix(String),
    /// Suffix match ("*suffix")
    Suffix(String),
}

impl PatternMatcher {
    pub(crate) fn compile(pattern: &str) -> Self {
        if pattern == "*" {
            PatternMatcher::Any
        } else if let Some(suffix) = pattern.strip_prefix('*') {
            // SECURITY (R30-ENG-5): Validate that the suffix doesn't contain
            // another wildcard. Patterns like "*read*" would produce a suffix
            // match for the literal string "read*", which is almost certainly
            // not what the admin intended. Fail-closed: treat as Any (matches
            // all) with a warning — over-matching is safer than under-matching.
            if suffix.contains('*') {
                tracing::warn!(
                    pattern = pattern,
                    "Unsupported infix/double wildcard pattern — treating as match-all (fail-closed)"
                );
                PatternMatcher::Any
            } else {
                PatternMatcher::Suffix(suffix.to_string())
            }
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            if prefix.contains('*') {
                tracing::warn!(
                    pattern = pattern,
                    "Unsupported infix/double wildcard pattern — treating as match-all (fail-closed)"
                );
                PatternMatcher::Any
            } else {
                PatternMatcher::Prefix(prefix.to_string())
            }
        } else if pattern.contains('*') {
            // Infix wildcard like "file_*_system" — not supported
            tracing::warn!(
                pattern = pattern,
                "Unsupported infix wildcard pattern — treating as match-all (fail-closed)"
            );
            PatternMatcher::Any
        } else {
            PatternMatcher::Exact(pattern.to_string())
        }
    }

    pub(crate) fn matches(&self, value: &str) -> bool {
        match self {
            PatternMatcher::Any => true,
            PatternMatcher::Exact(s) => s == value,
            PatternMatcher::Prefix(p) => value.starts_with(p.as_str()),
            PatternMatcher::Suffix(s) => value.ends_with(s.as_str()),
        }
    }
}

/// Pre-compiled tool:function matcher derived from policy ID.
#[derive(Debug, Clone)]
pub enum CompiledToolMatcher {
    /// Matches all tools and functions ("*")
    Universal,
    /// Matches tool only (no colon in policy ID)
    ToolOnly(PatternMatcher),
    /// Matches tool:function with independent matchers
    ToolAndFunction(PatternMatcher, PatternMatcher),
}

impl CompiledToolMatcher {
    pub(crate) fn compile(id: &str) -> Self {
        if id == "*" {
            CompiledToolMatcher::Universal
        } else if let Some((tool_pat, func_remainder)) = id.split_once(':') {
            // Support qualifier suffixes: "tool:func:qualifier" → match on "tool:func" only
            let func_pat = func_remainder
                .split_once(':')
                .map_or(func_remainder, |(f, _)| f);
            CompiledToolMatcher::ToolAndFunction(
                PatternMatcher::compile(tool_pat),
                PatternMatcher::compile(func_pat),
            )
        } else {
            CompiledToolMatcher::ToolOnly(PatternMatcher::compile(id))
        }
    }

    pub(crate) fn matches(&self, action: &Action) -> bool {
        match self {
            CompiledToolMatcher::Universal => true,
            CompiledToolMatcher::ToolOnly(m) => m.matches(&action.tool),
            CompiledToolMatcher::ToolAndFunction(t, f) => {
                t.matches(&action.tool) && f.matches(&action.function)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vellaveto_types::Action;

    fn make_action(tool: &str, function: &str) -> Action {
        Action {
            tool: tool.to_string(),
            function: function.to_string(),
            parameters: serde_json::json!({}),
            target_paths: Vec::new(),
            target_domains: Vec::new(),
            resolved_ips: Vec::new(),
        }
    }

    #[test]
    fn test_pattern_matcher_any() {
        let matcher = PatternMatcher::compile("*");
        assert!(matches!(matcher, PatternMatcher::Any));
        assert!(matcher.matches("anything"));
        assert!(matcher.matches(""));
    }

    #[test]
    fn test_pattern_matcher_exact() {
        let matcher = PatternMatcher::compile("read_file");
        assert!(matches!(matcher, PatternMatcher::Exact(_)));
        assert!(matcher.matches("read_file"));
        assert!(!matcher.matches("read_file2"));
        assert!(!matcher.matches("read"));
    }

    #[test]
    fn test_pattern_matcher_prefix() {
        let matcher = PatternMatcher::compile("read_*");
        assert!(matches!(matcher, PatternMatcher::Prefix(_)));
        assert!(matcher.matches("read_file"));
        assert!(matcher.matches("read_directory"));
        assert!(!matcher.matches("write_file"));
    }

    #[test]
    fn test_pattern_matcher_suffix() {
        let matcher = PatternMatcher::compile("*_file");
        assert!(matches!(matcher, PatternMatcher::Suffix(_)));
        assert!(matcher.matches("read_file"));
        assert!(matcher.matches("write_file"));
        assert!(!matcher.matches("read_directory"));
    }

    #[test]
    fn test_pattern_matcher_infix_treated_as_any() {
        // Infix wildcards are not supported, treated as match-all (fail-closed)
        let matcher = PatternMatcher::compile("read_*_file");
        assert!(matches!(matcher, PatternMatcher::Any));
        assert!(matcher.matches("anything"));
    }

    #[test]
    fn test_compiled_tool_matcher_universal() {
        let matcher = CompiledToolMatcher::compile("*");
        assert!(matches!(matcher, CompiledToolMatcher::Universal));
        assert!(matcher.matches(&make_action("any_tool", "any_function")));
    }

    #[test]
    fn test_compiled_tool_matcher_tool_only() {
        let matcher = CompiledToolMatcher::compile("filesystem");
        assert!(matches!(matcher, CompiledToolMatcher::ToolOnly(_)));
        assert!(matcher.matches(&make_action("filesystem", "read")));
        assert!(matcher.matches(&make_action("filesystem", "write")));
        assert!(!matcher.matches(&make_action("network", "fetch")));
    }

    #[test]
    fn test_compiled_tool_matcher_tool_and_function() {
        let matcher = CompiledToolMatcher::compile("filesystem:read*");
        assert!(matches!(
            matcher,
            CompiledToolMatcher::ToolAndFunction(_, _)
        ));
        assert!(matcher.matches(&make_action("filesystem", "read")));
        assert!(matcher.matches(&make_action("filesystem", "read_file")));
        assert!(!matcher.matches(&make_action("filesystem", "write")));
        assert!(!matcher.matches(&make_action("network", "read")));
    }

    #[test]
    fn test_compiled_tool_matcher_with_qualifier() {
        // Qualifiers after second colon are ignored for matching
        let matcher = CompiledToolMatcher::compile("filesystem:read:sensitive");
        assert!(matcher.matches(&make_action("filesystem", "read")));
        assert!(!matcher.matches(&make_action("filesystem", "read:sensitive")));
    }
}
