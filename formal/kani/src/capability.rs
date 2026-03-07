// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Capability delegation verification extracted from
//! `vellaveto-mcp/src/capability_token.rs`.
//!
//! Pure functions for grant subset checking, glob matching, path
//! normalization for grants. These enforce monotonic attenuation:
//! a delegated capability can never exceed its parent's permissions.
//!
//! # Verified Properties (K36-K40)
//!
//! | ID  | Property | Bridge |
//! |-----|----------|--------|
//! | K36 | grant_is_subset reflexive | S11 |
//! | K37 | No escalation (child grants ⊆ parent grants) | S11 |
//! | K38 | pattern_is_subset correctness | S11 |
//! | K39 | glob_match("*", any) == true | — |
//! | K40 | normalize_path_for_grant: no ".." in output | S11 |
//!
//! # Production Correspondence
//!
//! - `glob_match` ↔ `vellaveto-mcp/src/capability_token.rs:555-585`
//! - `pattern_is_subset` ↔ `vellaveto-mcp/src/capability_token.rs:610-630`
//! - `normalize_path_for_grant` ↔ `vellaveto-mcp/src/capability_token.rs:459-482`
//! - `grant_is_subset` ↔ `vellaveto-mcp/src/capability_token.rs:598-696`

/// Return true when the pattern contains capability delegation metacharacters.
pub fn has_glob_metacharacters(pattern: &str) -> bool {
    pattern.as_bytes().iter().any(|b| *b == b'*' || *b == b'?')
}

/// Literal-only fast path from production `pattern_matches`.
pub fn literal_pattern_matches(
    pattern_has_metacharacters: bool,
    pattern_equals_value_ignore_ascii_case: bool,
) -> bool {
    !pattern_has_metacharacters && pattern_equals_value_ignore_ascii_case
}

/// Conservative child-glob guard from production `grant_is_subset`.
pub fn pattern_subset_guard(
    parent_is_wildcard: bool,
    parent_equals_child_ignore_ascii_case: bool,
    child_has_metacharacters: bool,
) -> bool {
    parent_is_wildcard || parent_equals_child_ignore_ascii_case || !child_has_metacharacters
}

/// Literal-child subset fast path from production `grant_is_subset`.
pub fn literal_child_pattern_subset(
    child_has_metacharacters: bool,
    parent_matches_child_literal: bool,
) -> bool {
    !child_has_metacharacters && parent_matches_child_literal
}

/// Restriction-shape and invocation attenuation gate from production
/// `grant_is_subset`.
pub fn grant_restrictions_attenuated(
    parent_has_allowed_paths: bool,
    child_has_allowed_paths: bool,
    parent_has_allowed_domains: bool,
    child_has_allowed_domains: bool,
    parent_max_invocations: u32,
    child_max_invocations: u32,
) -> bool {
    (!parent_has_allowed_paths || child_has_allowed_paths)
        && (!parent_has_allowed_domains || child_has_allowed_domains)
        && (parent_max_invocations == 0
            || (child_max_invocations > 0 && child_max_invocations <= parent_max_invocations))
}

/// Glob match on byte slices. Case-insensitive, supports `*` and `?`.
///
/// Verbatim from production `glob_match`.
pub fn glob_match(pattern: &[u8], value: &[u8]) -> bool {
    let mut pi = 0;
    let mut vi = 0;
    let mut star_pi = usize::MAX;
    let mut star_vi = 0;

    while vi < value.len() {
        if pi < pattern.len()
            && (pattern[pi] == b'?' || pattern[pi].eq_ignore_ascii_case(&value[vi]))
        {
            pi += 1;
            vi += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_vi = vi;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_vi += 1;
            vi = star_vi;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

/// Check if `child` pattern is a subset of `parent` pattern.
///
/// Verbatim from production `pattern_is_subset`.
pub fn pattern_is_subset(parent: &str, child: &str) -> bool {
    let parent_is_wildcard = parent == "*";
    let parent_equals_child_ignore_ascii_case = parent.eq_ignore_ascii_case(child);
    let child_has_metacharacters = has_glob_metacharacters(child);

    if !pattern_subset_guard(
        parent_is_wildcard,
        parent_equals_child_ignore_ascii_case,
        child_has_metacharacters,
    ) {
        return false;
    }

    if parent_is_wildcard || parent_equals_child_ignore_ascii_case {
        return true;
    }

    literal_child_pattern_subset(child_has_metacharacters, pattern_matches(parent, child))
}

/// Pattern matching helper (delegates to glob_match for glob patterns,
/// otherwise case-insensitive equality).
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let pattern_has_metacharacters = has_glob_metacharacters(pattern);
    if literal_pattern_matches(pattern_has_metacharacters, pattern.eq_ignore_ascii_case(value)) {
        return true;
    }
    if !pattern_has_metacharacters {
        return false;
    }
    glob_match(pattern.as_bytes(), value.as_bytes())
}

/// Normalize a path for grant comparison. Returns None on malformed input
/// (null bytes, above-root traversal).
///
/// Verbatim from production `normalize_path_for_grant`.
pub fn normalize_path_for_grant(path: &str) -> Option<String> {
    if path.contains('\0') {
        return None; // Null byte injection — fail-closed
    }
    let mut components: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => continue,
            ".." => {
                if components.is_empty() {
                    return None; // Traversal above root — fail-closed
                }
                components.pop();
            }
            c => components.push(c),
        }
    }
    let normalized = if path.starts_with('/') {
        format!("/{}", components.join("/"))
    } else {
        components.join("/")
    };
    Some(normalized)
}

/// A capability grant for verification.
pub struct CapabilityGrant {
    pub tool_pattern: String,
    pub function_pattern: String,
    pub allowed_paths: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub max_invocations: u32,
}

/// Check if `new_grant` is a subset of `parent_grant`.
///
/// Verbatim from production `grant_is_subset`.
pub fn grant_is_subset(new_grant: &CapabilityGrant, parent_grant: &CapabilityGrant) -> bool {
    if !pattern_is_subset(&parent_grant.tool_pattern, &new_grant.tool_pattern) {
        return false;
    }
    if !pattern_is_subset(&parent_grant.function_pattern, &new_grant.function_pattern) {
        return false;
    }
    if !grant_restrictions_attenuated(
        !parent_grant.allowed_paths.is_empty(),
        !new_grant.allowed_paths.is_empty(),
        !parent_grant.allowed_domains.is_empty(),
        !new_grant.allowed_domains.is_empty(),
        parent_grant.max_invocations,
        new_grant.max_invocations,
    ) {
        return false;
    }

    // If parent has path restrictions, child MUST also have non-empty path restrictions.
    if !parent_grant.allowed_paths.is_empty() {
        for path in &new_grant.allowed_paths {
            let normalized = match normalize_path_for_grant(path) {
                Some(n) => n,
                None => return false,
            };
            let covered = parent_grant.allowed_paths.iter().any(|pp| {
                let parent_normalized = match normalize_path_for_grant(pp) {
                    Some(n) => n,
                    None => return false,
                };
                if parent_normalized.is_empty() {
                    return false;
                }
                pattern_matches(&parent_normalized, &normalized)
            });
            if !covered {
                return false;
            }
        }
    }
    // Same check for domains.
    if !parent_grant.allowed_domains.is_empty() {
        for domain in &new_grant.allowed_domains {
            let covered = parent_grant
                .allowed_domains
                .iter()
                .any(|pd| pattern_matches(pd, domain));
            if !covered {
                return false;
            }
        }
    }
    true
}

/// Simplified action for capability coverage checking.
pub struct ActionRef<'a> {
    pub tool: &'a str,
    pub function: &'a str,
    pub target_paths: &'a [String],
    pub target_domains: &'a [String],
}

/// Check if a grant covers a specific action.
///
/// Verbatim from production `grant_covers_action` in
/// `vellaveto-mcp/src/capability_token.rs:485-537`.
///
/// Fail-closed: if grant has path/domain restrictions and action has none,
/// the grant does NOT cover the action.
pub fn grant_covers_action(grant: &CapabilityGrant, action: &ActionRef<'_>) -> bool {
    // Check tool pattern
    if !pattern_matches(&grant.tool_pattern, action.tool) {
        return false;
    }
    // Check function pattern
    if !pattern_matches(&grant.function_pattern, action.function) {
        return false;
    }
    // Check path constraints (if any)
    // SECURITY (FIND-R57-CAP-001): Fail-closed when grant requires path restrictions
    // but the action provides no target_paths.
    if !grant.allowed_paths.is_empty() {
        if action.target_paths.is_empty() {
            return false;
        }
        let all_covered = action.target_paths.iter().all(|path| {
            // Fail-closed: if normalization fails, deny the grant
            let normalized = match normalize_path_for_grant(path) {
                Some(n) => n,
                None => return false,
            };
            grant
                .allowed_paths
                .iter()
                .any(|pattern| pattern_matches(pattern, &normalized))
        });
        if !all_covered {
            return false;
        }
    }
    // Check domain constraints (if any)
    // SECURITY (FIND-R57-CAP-001): Fail-closed when grant requires domain restrictions
    // but the action provides no target_domains.
    if !grant.allowed_domains.is_empty() {
        if action.target_domains.is_empty() {
            return false;
        }
        let all_covered = action.target_domains.iter().all(|domain| {
            grant
                .allowed_domains
                .iter()
                .any(|pattern| pattern_matches(pattern, domain))
        });
        if !all_covered {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match(b"*", b"anything"));
        assert!(glob_match(b"*", b""));
        assert!(glob_match(b"fi*", b"file.txt"));
        assert!(!glob_match(b"fi*", b"Foo"));
    }

    #[test]
    fn test_glob_match_question() {
        assert!(glob_match(b"f?le", b"file"));
        assert!(!glob_match(b"f?le", b"fiile"));
    }

    #[test]
    fn test_pattern_is_subset() {
        assert!(pattern_is_subset("*", "anything"));
        assert!(pattern_is_subset("fi*", "file"));
        assert!(!pattern_is_subset("fi*", "f*")); // child is glob, rejected
        assert!(pattern_is_subset("file", "file"));
    }

    #[test]
    fn test_literal_pattern_fast_path() {
        assert!(literal_pattern_matches(false, true));
        assert!(!literal_pattern_matches(false, false));
        assert!(!literal_pattern_matches(true, true));
    }

    #[test]
    fn test_pattern_subset_guard() {
        assert!(pattern_subset_guard(true, false, true));
        assert!(pattern_subset_guard(false, true, true));
        assert!(pattern_subset_guard(false, false, false));
        assert!(!pattern_subset_guard(false, false, true));
    }

    #[test]
    fn test_literal_child_pattern_subset() {
        assert!(literal_child_pattern_subset(false, true));
        assert!(!literal_child_pattern_subset(false, false));
        assert!(!literal_child_pattern_subset(true, true));
    }

    #[test]
    fn test_normalize_path_no_traversal() {
        assert_eq!(normalize_path_for_grant("/a/b/c"), Some("/a/b/c".to_string()));
        assert_eq!(normalize_path_for_grant("/a/../b"), Some("/b".to_string()));
        assert_eq!(normalize_path_for_grant("/../etc/passwd"), None); // above root
        assert_eq!(normalize_path_for_grant("/a/\0/b"), None); // null byte
    }

    #[test]
    fn test_grant_is_subset_reflexive() {
        let g = CapabilityGrant {
            tool_pattern: "read*".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec!["/home/*".to_string()],
            allowed_domains: vec!["*.example.com".to_string()],
            max_invocations: 10,
        };
        assert!(grant_is_subset(&g, &g));
    }

    #[test]
    fn test_grant_covers_matching_action() {
        let g = CapabilityGrant {
            tool_pattern: "read*".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec!["/home/*".to_string()],
            allowed_domains: vec![],
            max_invocations: 10,
        };
        let action = ActionRef {
            tool: "read_file",
            function: "execute",
            target_paths: &["/home/user/file.txt".to_string()],
            target_domains: &[],
        };
        assert!(grant_covers_action(&g, &action));
    }

    #[test]
    fn test_grant_rejects_wrong_tool() {
        let g = CapabilityGrant {
            tool_pattern: "read*".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        };
        let action = ActionRef {
            tool: "write_file",
            function: "execute",
            target_paths: &[],
            target_domains: &[],
        };
        assert!(!grant_covers_action(&g, &action));
    }

    #[test]
    fn test_grant_fail_closed_empty_paths() {
        // Grant requires paths but action provides none → fail-closed
        let g = CapabilityGrant {
            tool_pattern: "*".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec!["/safe/*".to_string()],
            allowed_domains: vec![],
            max_invocations: 0,
        };
        let action = ActionRef {
            tool: "read",
            function: "exec",
            target_paths: &[],
            target_domains: &[],
        };
        assert!(!grant_covers_action(&g, &action));
    }

    #[test]
    fn test_grant_fail_closed_empty_domains() {
        // Grant requires domains but action provides none → fail-closed
        let g = CapabilityGrant {
            tool_pattern: "*".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec!["*.example.com".to_string()],
            max_invocations: 0,
        };
        let action = ActionRef {
            tool: "fetch",
            function: "get",
            target_paths: &[],
            target_domains: &[],
        };
        assert!(!grant_covers_action(&g, &action));
    }

    #[test]
    fn test_grant_escalation_blocked() {
        let parent = CapabilityGrant {
            tool_pattern: "read*".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec!["/home/*".to_string()],
            allowed_domains: vec![],
            max_invocations: 10,
        };
        // Child tries to add broader tool pattern — should fail
        let child = CapabilityGrant {
            tool_pattern: "*".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec!["/home/user".to_string()],
            allowed_domains: vec![],
            max_invocations: 5,
        };
        assert!(!grant_is_subset(&child, &parent));
    }
}
