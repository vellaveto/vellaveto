//! Shared utility functions for the vellaveto-mcp crate.
//!
//! Contains common helpers used across multiple modules, extracted here
//! to avoid code duplication.

/// Simple glob matching supporting `*` (any characters) and `?` (single character).
///
/// Uses an iterative algorithm with backtracking (no recursion, no DP allocation).
/// Operates on byte slices for performance; callers with `&str` should use
/// `glob_match_str` or pass `.as_bytes()`.
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    glob_match_bytes(pattern.as_bytes(), text.as_bytes())
}

/// Byte-level glob matching supporting `*` and `?`.
///
/// Used by `capability_token` where case-insensitive byte matching is needed.
pub(crate) fn glob_match_bytes(pattern: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len()
            && (pattern[pi] == b'?' || pattern[pi] == text[ti])
        {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("he*", "hello"));
        assert!(glob_match("*lo", "hello"));
        assert!(glob_match("h*o", "hello"));
        assert!(glob_match("x-*", "x-foo"));
        assert!(glob_match("x-*", "x-"));
        assert!(!glob_match("x-*", "y-foo"));
    }

    #[test]
    fn test_glob_match_question() {
        assert!(glob_match("x-fo?", "x-foo"));
        assert!(!glob_match("x-fo?", "x-fooo"));
    }

    #[test]
    fn test_glob_match_bytes_case_sensitive() {
        assert!(glob_match_bytes(b"Hello", b"Hello"));
        assert!(!glob_match_bytes(b"Hello", b"hello"));
    }

    #[test]
    fn test_glob_match_bytes_star() {
        assert!(glob_match_bytes(b"*", b"anything"));
        assert!(glob_match_bytes(b"he*", b"hello"));
    }
}
