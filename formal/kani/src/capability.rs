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
    if parent == "*" {
        return true;
    }
    if parent.eq_ignore_ascii_case(child) {
        return true;
    }
    // Glob-to-glob comparisons rejected for safety (could be broader).
    if child.contains('*') || child.contains('?') {
        return false;
    }
    // Child is literal — safe to check against parent glob.
    pattern_matches(parent, child)
}

/// Pattern matching helper (delegates to glob_match for glob patterns,
/// otherwise case-insensitive equality).
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern.contains('*') || pattern.contains('?') {
        glob_match(pattern.as_bytes(), value.as_bytes())
    } else {
        pattern.eq_ignore_ascii_case(value)
    }
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
    // If parent has path restrictions, child MUST also have non-empty path restrictions.
    if !parent_grant.allowed_paths.is_empty() {
        if new_grant.allowed_paths.is_empty() {
            return false;
        }
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
        if new_grant.allowed_domains.is_empty() {
            return false;
        }
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
    // max_invocations must be monotonically attenuated.
    if parent_grant.max_invocations > 0
        && (new_grant.max_invocations == 0
            || new_grant.max_invocations > parent_grant.max_invocations)
    {
        return false;
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
