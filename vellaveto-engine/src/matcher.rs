// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Tool and function pattern matching.
//!
//! This module provides pre-compiled pattern matchers for tool/function ID
//! segments, used to efficiently match policies against actions at evaluation time.

use crate::normalize::normalize_full;
#[cfg(test)]
use vellaveto_types::Action;

/// Pre-compiled pattern matcher for tool/function ID segments.
///
/// SECURITY (FIND-SEM-003, R227-TYP-1): Pattern strings are normalized through
/// `normalize_full()` (NFKC + lowercase + homoglyph mapping) at compile time.
/// This prevents fullwidth Unicode, circled letters, and mathematical variants
/// from bypassing exact-match Deny policies. The evaluation path must also
/// normalize action tool/function names via `normalize_full()` before matching.
#[derive(Debug, Clone)]
pub enum PatternMatcher {
    /// Matches anything ("*")
    Any,
    /// Exact string match (pattern is homoglyph-normalized at compile time)
    Exact(String),
    /// Prefix match ("prefix*") (normalize_full at compile time)
    Prefix(String),
    /// Suffix match ("*suffix") (normalize_full at compile time)
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
                // SECURITY (FIND-SEM-003, R227-TYP-1): normalize_full at compile time
                PatternMatcher::Suffix(normalize_full(suffix))
            }
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            if prefix.contains('*') {
                tracing::warn!(
                    pattern = pattern,
                    "Unsupported infix/double wildcard pattern — treating as match-all (fail-closed)"
                );
                PatternMatcher::Any
            } else {
                // SECURITY (FIND-SEM-003, R227-TYP-1): normalize_full at compile time
                PatternMatcher::Prefix(normalize_full(prefix))
            }
        } else if pattern.contains('*') {
            // Infix wildcard like "file_*_system" — not supported
            tracing::warn!(
                pattern = pattern,
                "Unsupported infix wildcard pattern — treating as match-all (fail-closed)"
            );
            PatternMatcher::Any
        } else {
            // SECURITY (FIND-SEM-003, R227-TYP-1): normalize_full at compile time
            PatternMatcher::Exact(normalize_full(pattern))
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

    /// Match against a pre-normalized value.
    ///
    /// SECURITY (FIND-SEM-003): Since patterns are normalized at compile time,
    /// callers must pass homoglyph-normalized input for consistent matching.
    /// This method is identical to `matches()` but makes the contract explicit.
    pub(crate) fn matches_normalized(&self, normalized_value: &str) -> bool {
        self.matches(normalized_value)
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

    #[cfg(test)]
    pub(crate) fn matches(&self, action: &Action) -> bool {
        match self {
            CompiledToolMatcher::Universal => true,
            CompiledToolMatcher::ToolOnly(m) => m.matches(&action.tool),
            CompiledToolMatcher::ToolAndFunction(t, f) => {
                t.matches(&action.tool) && f.matches(&action.function)
            }
        }
    }

    /// Match against pre-normalized tool and function names.
    ///
    /// SECURITY (FIND-SEM-003): Callers must pass homoglyph-normalized tool
    /// and function names to ensure fullwidth Unicode characters cannot bypass
    /// exact-match Deny policies.
    pub(crate) fn matches_normalized(
        &self,
        normalized_tool: &str,
        normalized_function: &str,
    ) -> bool {
        match self {
            CompiledToolMatcher::Universal => true,
            CompiledToolMatcher::ToolOnly(m) => m.matches_normalized(normalized_tool),
            CompiledToolMatcher::ToolAndFunction(t, f) => {
                t.matches_normalized(normalized_tool) && f.matches_normalized(normalized_function)
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

    // ═══════════════════════════════════════════════════
    // FIND-SEM-003: Homoglyph normalization tests
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_pattern_exact_normalizes_homoglyphs_at_compile() {
        // Fullwidth "ｒｅａｄ" is normalized to "read" at compile time
        let matcher = PatternMatcher::compile("\u{FF52}\u{FF45}\u{FF41}\u{FF44}");
        assert!(matcher.matches("read"));
        assert!(!matcher.matches("\u{FF52}\u{FF45}\u{FF41}\u{FF44}"));
    }

    #[test]
    fn test_pattern_prefix_normalizes_homoglyphs() {
        // Fullwidth prefix "ｒｅａｄ＿*" → normalized to "read_*"
        let matcher = PatternMatcher::compile("\u{FF52}\u{FF45}\u{FF41}\u{FF44}\u{FF3F}*");
        assert!(matches!(matcher, PatternMatcher::Prefix(_)));
        assert!(matcher.matches("read_file"));
        assert!(matcher.matches("read_dir"));
    }

    #[test]
    fn test_pattern_suffix_normalizes_homoglyphs() {
        // "*＿ｆｉｌｅ" suffix → normalized to "*_file"
        let matcher = PatternMatcher::compile("*\u{FF3F}\u{FF46}\u{FF49}\u{FF4C}\u{FF45}");
        assert!(matches!(matcher, PatternMatcher::Suffix(_)));
        assert!(matcher.matches("read_file"));
        assert!(matcher.matches("write_file"));
    }

    #[test]
    fn test_compiled_tool_matcher_normalized_method() {
        let matcher = CompiledToolMatcher::compile("read_file");
        // Normal ASCII match via matches_normalized
        assert!(matcher.matches_normalized("read_file", "any"));
        // Fullwidth input pre-normalized by caller using normalize_full
        let norm = normalize_full(
            "\u{FF52}\u{FF45}\u{FF41}\u{FF44}\u{FF3F}\u{FF46}\u{FF49}\u{FF4C}\u{FF45}",
        );
        assert_eq!(norm, "read_file");
        assert!(matcher.matches_normalized(&norm, "any"));
    }

    #[test]
    fn test_cyrillic_homoglyph_tool_name_normalized() {
        // Policy blocks "admin" — Cyrillic "аdmin" (U+0430 Cyrillic а) should also match
        let matcher = PatternMatcher::compile("admin");
        let norm = normalize_full("\u{0430}dmin");
        assert_eq!(norm, "admin");
        assert!(matcher.matches_normalized(&norm));
    }

    /// R227-TYP-1: Circled letter bypass — NFKC decomposes Ⓑash to Bash, then lowercase.
    #[test]
    fn test_r227_circled_letter_normalized() {
        let matcher = PatternMatcher::compile("bash");
        // Ⓑ = U+24B7 (circled Latin capital B) → NFKC → B → lowercase → b
        let norm = normalize_full("\u{24B7}ash");
        assert_eq!(norm, "bash");
        assert!(matcher.matches_normalized(&norm));
    }
}
