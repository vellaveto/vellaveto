use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NormalizationError {
    #[error("path contains null bytes or control characters: {0}")]
    InvalidPath(String),
    #[error("path traversal beyond root")]
    PathTraversal,
    #[error("invalid domain: {0}")]
    InvalidDomain(String),
    #[error("IP addresses must use allow_private_ip, not domain field")]
    IpNotAllowed,
}

/// Normalized absolute filesystem path.
///
/// Guarantees:
/// - No null bytes or control characters
/// - Absolute (starts with /)
/// - No `.` or `..` components
/// - No trailing slash (except root)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NormalizedPath(String);

impl NormalizedPath {
    pub fn new(raw: &str) -> Result<Self, NormalizationError> {
        if raw.bytes().any(|b| b == 0 || (b < 32 && b != b'\t')) {
            return Err(NormalizationError::InvalidPath(raw.to_string()));
        }

        let path = if raw.starts_with('/') {
            PathBuf::from(raw)
        } else {
            // Relative paths anchored to root for normalization.
            // The caller should resolve against a working directory
            // before constructing NormalizedPath if context is available.
            PathBuf::from("/").join(raw)
        };

        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::RootDir => normalized.push("/"),
                std::path::Component::Normal(c) => normalized.push(c),
                std::path::Component::CurDir => {} // skip .
                std::path::Component::ParentDir => {
                    if !normalized.pop() {
                        return Err(NormalizationError::PathTraversal);
                    }
                }
                std::path::Component::Prefix(_) => {
                    return Err(NormalizationError::InvalidPath(
                        "Windows prefixes not supported".to_string(),
                    ));
                }
            }
        }

        let s = normalized.to_string_lossy().to_string();
        let s = if s.len() > 1 && s.ends_with('/') {
            s[..s.len() - 1].to_string()
        } else {
            s
        };

        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn matches(&self, pattern: &PathGlob) -> bool {
        pattern.matches(&self.0)
    }
}

/// Normalized domain name.
///
/// Guarantees:
/// - Lowercase
/// - No port
/// - No trailing dot
/// - Valid label lengths
/// - Not an IP address (use allow_private_ip for that)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NormalizedDomain(String);

impl NormalizedDomain {
    pub fn new(raw: &str) -> Result<Self, NormalizationError> {
        let mut s = raw.to_lowercase();

        // Strip port
        if let Some(idx) = s.rfind(':') {
            if s[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
                s = s[..idx].to_string();
            }
        }

        // Strip trailing dot
        if s.ends_with('.') {
            s.pop();
        }

        if s.is_empty() || s.len() > 253 {
            return Err(NormalizationError::InvalidDomain(raw.to_string()));
        }

        // Reject bare IP addresses
        if s.parse::<std::net::IpAddr>().is_ok() {
            return Err(NormalizationError::IpNotAllowed);
        }

        for label in s.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(NormalizationError::InvalidDomain(raw.to_string()));
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(NormalizationError::InvalidDomain(raw.to_string()));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(NormalizationError::InvalidDomain(raw.to_string()));
            }
        }

        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn matches(&self, pattern: &DomainPattern) -> bool {
        pattern.matches(&self.0)
    }
}

/// Path glob pattern. Wraps the `glob` crate's Pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathGlob {
    pattern: String,
}

impl PathGlob {
    pub fn new(pattern: &str) -> Result<Self, glob::PatternError> {
        // Validate the pattern compiles
        let _ = glob::Pattern::new(pattern)?;
        Ok(Self {
            pattern: pattern.to_string(),
        })
    }

    pub fn matches(&self, path: &str) -> bool {
        // Re-compile on each match. This is fine for policy evaluation
        // which happens infrequently relative to the cost of a tool call.
        // If profiling shows this matters, cache the compiled Pattern.
        glob::Pattern::new(&self.pattern)
            .map(|m| m.matches(path))
            .unwrap_or(false)
    }

    pub fn as_str(&self) -> &str {
        &self.pattern
    }
}

/// Domain match pattern. Supports exact match and wildcard (*.example.com).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPattern {
    pattern: String,
    is_wildcard: bool,
    suffix: String,
}

impl DomainPattern {
    pub fn new(pattern: &str) -> Self {
        let lower = pattern.to_lowercase();
        let is_wildcard = lower.starts_with("*.");
        let suffix = if is_wildcard {
            lower[1..].to_string() // ".example.com"
        } else {
            String::new()
        };

        Self {
            pattern: lower,
            is_wildcard,
            suffix,
        }
    }

    pub fn matches(&self, domain: &str) -> bool {
        if self.is_wildcard {
            // *.example.com matches sub.example.com AND example.com
            // but NOT evil-example.com (requires dot boundary before suffix)
            if domain == &self.suffix[1..] {
                return true; // exact match without wildcard prefix
            }
            if domain.len() > self.suffix.len()
                && domain.ends_with(&self.suffix)
                && domain.as_bytes()[domain.len() - self.suffix.len() - 1] == b'.'
            {
                return true; // dot-boundary verified subdomain match
            }
            false
        } else {
            domain == self.pattern
        }
    }

    pub fn as_str(&self) -> &str {
        &self.pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── NormalizedPath ──

    #[test]
    fn path_absolute() {
        let p = NormalizedPath::new("/home/user/file.txt").unwrap();
        assert_eq!(p.as_str(), "/home/user/file.txt");
    }

    #[test]
    fn path_resolves_dotdot() {
        let p = NormalizedPath::new("/home/user/../other/file.txt").unwrap();
        assert_eq!(p.as_str(), "/home/other/file.txt");
    }

    #[test]
    fn path_rejects_traversal_beyond_root() {
        assert!(NormalizedPath::new("/../../etc/passwd").is_err());
    }

    #[test]
    fn path_rejects_null_bytes() {
        assert!(NormalizedPath::new("/home/user/\0evil").is_err());
    }

    #[test]
    fn path_strips_trailing_slash() {
        let p = NormalizedPath::new("/home/user/").unwrap();
        assert_eq!(p.as_str(), "/home/user");
    }

    #[test]
    fn path_root_stays_root() {
        let p = NormalizedPath::new("/").unwrap();
        assert_eq!(p.as_str(), "/");
    }

    #[test]
    fn path_relative_gets_rooted() {
        let p = NormalizedPath::new("relative/path").unwrap();
        assert_eq!(p.as_str(), "/relative/path");
    }

    // ── NormalizedDomain ──

    #[test]
    fn domain_lowercased() {
        let d = NormalizedDomain::new("Example.COM").unwrap();
        assert_eq!(d.as_str(), "example.com");
    }

    #[test]
    fn domain_strips_port() {
        let d = NormalizedDomain::new("example.com:8080").unwrap();
        assert_eq!(d.as_str(), "example.com");
    }

    #[test]
    fn domain_strips_trailing_dot() {
        let d = NormalizedDomain::new("example.com.").unwrap();
        assert_eq!(d.as_str(), "example.com");
    }

    #[test]
    fn domain_rejects_ip() {
        assert!(NormalizedDomain::new("192.168.1.1").is_err());
    }

    #[test]
    fn domain_rejects_empty() {
        assert!(NormalizedDomain::new("").is_err());
    }

    #[test]
    fn domain_rejects_leading_hyphen() {
        assert!(NormalizedDomain::new("-example.com").is_err());
    }

    // ─ PathGlob ──

    #[test]
    fn glob_matches_star() {
        let g = PathGlob::new("/home/*/project/**").unwrap();
        assert!(g.matches("/home/user/project/src/main.rs"));
        assert!(!g.matches("/etc/passwd"));
    }

    // ── DomainPattern ──

    #[test]
    fn domain_pattern_exact() {
        let p = DomainPattern::new("example.com");
        assert!(p.matches("example.com"));
        assert!(!p.matches("sub.example.com"));
    }

    #[test]
    fn domain_pattern_wildcard() {
        let p = DomainPattern::new("*.example.com");
        assert!(p.matches("sub.example.com"));
        assert!(p.matches("example.com")); // wildcard also matches bare
        assert!(!p.matches("evil.com"));
    }

    #[test]
    fn domain_pattern_wildcard_requires_dot_boundary() {
        // *.example.com must NOT match evil-example.com (no dot boundary)
        let p = DomainPattern::new("*.example.com");
        assert!(!p.matches("evil-example.com"));
        assert!(!p.matches("notexample.com"));
        // But must match proper subdomains
        assert!(p.matches("sub.example.com"));
        assert!(p.matches("deep.sub.example.com"));
    }
}