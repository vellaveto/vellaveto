//! Domain extraction, matching, and validation utilities.
//!
//! This module provides functions for working with domains in URLs and patterns:
//! - Extracting domains from URLs (with security hardening against bypass attacks)
//! - Matching domains against patterns (including wildcard patterns)
//! - Validating domain patterns for policy configuration
//! - IDNA normalization for internationalized domain names

use std::borrow::Cow;

/// Validate a domain pattern for policy configuration.
///
/// Checks RFC 1035 compliance:
/// - Domain labels must be 1-63 characters
/// - Total domain length must be <= 253 characters
/// - Labels can only contain alphanumeric characters and hyphens
/// - Labels cannot start or end with a hyphen
/// - Wildcards are only allowed as a prefix (`*.domain.com`)
pub fn validate_domain_pattern(pattern: &str) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("Domain pattern cannot be empty".to_string());
    }

    // Strip wildcard prefix if present
    let domain = if let Some(rest) = pattern.strip_prefix("*.") {
        if rest.is_empty() {
            return Err("Domain pattern '*.' has no domain after wildcard".to_string());
        }
        rest
    } else if pattern.contains('*') {
        return Err(format!(
            "Wildcard '*' is only allowed as a prefix '*.domain', found in '{pattern}'"
        ));
    } else {
        pattern
    };

    // Check total length (max 253 for a fully qualified domain name)
    if domain.len() > 253 {
        // SECURITY (R33-003): Use safe truncation to avoid panics on UTF-8 boundaries.
        // Even though domains should be ASCII, malformed inputs could contain multi-byte chars.
        let truncated: String = domain.chars().take(40).collect();
        return Err(format!(
            "Domain '{}' exceeds maximum length of 253 characters ({} chars)",
            truncated,
            domain.len()
        ));
    }

    // Validate each label
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(format!(
                "Domain '{}' contains an empty label (consecutive dots or trailing dot)",
                pattern
            ));
        }
        if label.len() > 63 {
            // SECURITY (R33-003): Use safe truncation to avoid panics on UTF-8 boundaries.
            let truncated: String = label.chars().take(20).collect();
            return Err(format!(
                "Label '{}...' in domain '{}' exceeds maximum length of 63 characters",
                truncated, pattern
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "Label '{}' in domain '{}' has leading or trailing hyphen",
                label, pattern
            ));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!(
                "Label '{}' in domain '{}' contains invalid characters (only alphanumeric and hyphen allowed)",
                label, pattern
            ));
        }
    }

    Ok(())
}

/// Extract the domain from a URL string.
///
/// Strips scheme, port, path, query, and fragment.
///
/// # Security
///
/// This function is hardened against various bypass attacks:
/// - Backslash normalization (WHATWG URL Standard)
/// - Percent-encoded `@` symbols in authority
/// - Fragment delimiters misused in authority
/// - IPv6 bracket handling
/// - Trailing dot normalization
pub fn extract_domain(url: &str) -> String {
    let without_scheme = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        url
    };

    // SECURITY (R22-ENG-5): Normalize backslashes to forward slashes BEFORE
    // splitting on path separator. Per the WHATWG URL Standard, `\` is treated
    // as a path separator in "special" schemes (http, https, ftp, etc.).
    // Without this, "http://evil.com\@legit.com/path" splits on '/' but the
    // `\@legit.com/path` remains in the authority portion, and after rfind('@')
    // we extract "legit.com/path" — completely wrong domain.
    let normalized = without_scheme.replace('\\', "/");
    let without_scheme = normalized.as_str();

    // Fix #8: Extract the authority portion FIRST (before the first '/', '?', or '#'),
    // then search for '@' only within the authority. This prevents
    // ?email=user@safe.com in query params from being mistaken for userinfo.
    // SECURITY (R27-ENG-1): Per RFC 3986 §3.2 and WHATWG URL Standard, the authority
    // is terminated by '/', '?', or '#' — whichever comes first. Previously only '/'
    // was checked, so URLs like "http://evil.com#@legit.com" extracted "legit.com"
    // instead of "evil.com" (the fragment '#' was not treated as an authority delimiter,
    // causing rfind('@') to find the '@' after '#' and return the wrong domain).
    let authority_raw = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);

    // Fix #30: Percent-decode the authority BEFORE searching for '@'.
    // Without this, "http://evil.com%40blocked.com/path" extracts authority
    // "evil.com%40blocked.com" — rfind('@') misses the encoded %40, and the
    // domain becomes "evil.com@blocked.com" instead of "blocked.com".
    // A standards-compliant parser decoding first would see userinfo="evil.com",
    // host="blocked.com", so we must decode before splitting on '@'.
    let decoded_authority = percent_encoding::percent_decode_str(authority_raw).decode_utf8_lossy();
    // SECURITY (R37-ENG-1): Strip userinfo FIRST on the decoded authority,
    // BEFORE backslash normalization. A %2F in userinfo (e.g., "evil.com%2F@legit.com")
    // decodes to '/' which would cause a wrong split if we split on '/' first.
    // Per RFC 3986, only unencoded '/' terminates the authority; the '@' delimiter
    // takes precedence for separating userinfo from host.
    let without_userinfo = if let Some(at_pos) = decoded_authority.rfind('@') {
        &decoded_authority[at_pos + 1..]
    } else {
        &*decoded_authority
    };
    // SECURITY (R26-ENG-4): Apply backslash normalization on the host portion only.
    // Input like "http://evil.com%5C@legit.com" has the host portion as "legit.com"
    // (after userinfo stripping). For host-only cases like "http://host%5Cpath",
    // the decoded backslash becomes '/' per WHATWG, splitting host from path.
    let host_normalized = without_userinfo.replace('\\', "/");
    let without_userinfo = host_normalized
        .split('/')
        .next()
        .unwrap_or(&host_normalized);

    // Strip query and fragment (shouldn't normally be in authority, but defensive)
    let host_port = without_userinfo;
    let host_port = host_port.split('?').next().unwrap_or(host_port);
    let host_port = host_port.split('#').next().unwrap_or(host_port);

    // Strip port
    let host = if let Some(bracket_end) = host_port.find(']') {
        // SECURITY (R31-ENG-5): Strip IPv6 brackets for consistent domain matching.
        // Without this, extract_domain("http://[::1]:8080/path") returns "[::1]",
        // which doesn't match a blocked domain pattern "::1".
        let start = if host_port.starts_with('[') { 1 } else { 0 };
        &host_port[start..bracket_end]
    } else if let Some(pos) = host_port.rfind(':') {
        // Only strip if what follows looks like a port number
        if host_port[pos + 1..].chars().all(|c| c.is_ascii_digit()) {
            &host_port[..pos]
        } else {
            host_port
        }
    } else {
        host_port
    };

    // SECURITY (R38-ENG-2): The host is already a substring of decoded_authority
    // (which was percent-decoded at line 3866-3867). A second percent-decode here
    // would cause double-decode: %2525 → %25 → %, enabling domain mismatch bypass.
    // Fix #33: Strip trailing dot (DNS FQDN notation) to prevent bypass.
    // "evil.com." and "evil.com" must resolve to the same domain.
    // Single allocation: lowercase first, then strip trailing dots in-place.
    let mut result = host.to_lowercase();
    while result.ends_with('.') {
        result.pop();
    }
    result
}

/// Match a domain against a pattern like `*.example.com` or `example.com`.
///
/// Both domain and pattern are normalized (lowercase, IDNA, strip trailing dots).
/// Returns `false` (fail-closed) if either domain or pattern fails IDNA normalization.
pub fn match_domain_pattern(domain: &str, pattern: &str) -> bool {
    // Normalize domain and pattern with IDNA.
    // Fail-closed: if normalization fails, treat as non-matching.
    let dom = match normalize_domain_for_match(domain) {
        Some(d) => d,
        None => return false,
    };
    let pat = match normalize_domain_for_match(pattern) {
        Some(p) => p,
        None => return false,
    };

    if let Some(suffix) = pat.strip_prefix("*.") {
        // Wildcard: domain must end with .suffix or be exactly suffix.
        // Use byte-level check to avoid format!() allocation.
        dom == suffix
            || (dom.len() > suffix.len()
                && dom.ends_with(suffix)
                && dom.as_bytes()[dom.len() - suffix.len() - 1] == b'.')
    } else {
        dom == pat
    }
}

/// Normalize a domain for matching: lowercase, strip trailing dots, apply IDNA.
///
/// SECURITY (R18-DOMAIN-1): Applies IDNA (Internationalized Domain Names in
/// Applications) normalization to convert Unicode domains to ASCII Punycode.
/// This prevents bypass attacks using internationalized domain names that
/// visually resemble blocked domains but differ in encoding.
///
/// Returns `None` if IDNA conversion fails (invalid domain) — callers should
/// treat this as fail-closed (non-matching).
pub(crate) fn normalize_domain_for_match(s: &str) -> Option<Cow<'_, str>> {
    // Strip trailing dots first
    let stripped = s.trim_end_matches('.');

    // Check if the domain is already pure ASCII lowercase
    let is_ascii_lower = stripped.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'*'
    });

    if is_ascii_lower && stripped == s {
        // Already normalized, no IDNA needed
        return Some(Cow::Borrowed(s));
    }

    if is_ascii_lower {
        // Just needed trailing dot removal
        return Some(Cow::Owned(stripped.to_string()));
    }

    // SECURITY (R25-ENG-5): Strip wildcard prefix before IDNA normalization.
    // IDNA rejects "*" as an invalid label, so "*.münchen.de" would fail
    // normalization and the pattern would never match — effectively allowing
    // the internationalized domain to bypass wildcard blocking.
    let (wildcard_prefix, idna_input) = if let Some(rest) = stripped.strip_prefix("*.") {
        ("*.", rest)
    } else {
        ("", stripped)
    };

    // SECURITY (R39-ENG-3): Reject ASCII inputs with non-domain characters BEFORE
    // IDNA processing. Some IDNA implementations accept whitespace, colons, slashes,
    // null bytes, etc. without error, creating a fail-open path where malformed domains
    // bypass blocklists. Valid domain characters: alphanumeric, hyphen, dot, underscore
    // (underscore for SRV records), and non-ASCII (handled by IDNA normalization).
    if idna_input.is_ascii()
        && !idna_input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        tracing::debug!(domain = s, "Domain contains invalid ASCII characters");
        return None;
    }

    // Apply IDNA normalization for internationalized domains
    // This converts Unicode to Punycode (e.g., "münchen.de" -> "xn--mnchen-3ya.de")
    match idna::domain_to_ascii(idna_input) {
        Ok(ascii) => {
            if wildcard_prefix.is_empty() {
                Some(Cow::Owned(ascii))
            } else {
                Some(Cow::Owned(format!("{}{}", wildcard_prefix, ascii)))
            }
        }
        Err(_) => {
            // SECURITY (R27-ENG-2): When IDNA normalization fails for a pure-ASCII
            // domain (e.g., underscores in SRV records like "_sip._tcp.evil.com"),
            // fall back to ASCII lowercase. Without this fallback, IDNA failure
            // returns None → match_domain_pattern returns false → blocked patterns
            // don't match → the domain passes through (fail-OPEN for blocking).
            if idna_input.is_ascii() {
                // SECURITY (R39-ENG-3): Only fall back for legitimate IDNA edge cases
                // (e.g., underscores in SRV records). Reject ASCII strings containing
                // whitespace, colons, or other non-domain characters to prevent
                // malformed domains from bypassing blocklists.
                if idna_input
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
                {
                    let lowered = format!("{}{}", wildcard_prefix, idna_input.to_ascii_lowercase());
                    tracing::debug!(
                        domain = s,
                        "IDNA normalization failed but domain is ASCII — using lowercase fallback"
                    );
                    Some(Cow::Owned(lowered))
                } else {
                    tracing::debug!(
                        domain = s,
                        "IDNA normalization failed: non-domain ASCII characters"
                    );
                    None
                }
            } else {
                // Non-ASCII domain that fails IDNA — truly invalid
                tracing::debug!(domain = s, "IDNA normalization failed for non-ASCII domain");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_domain_pattern_valid() {
        assert!(validate_domain_pattern("example.com").is_ok());
        assert!(validate_domain_pattern("sub.example.com").is_ok());
        assert!(validate_domain_pattern("*.example.com").is_ok());
        assert!(validate_domain_pattern("a-b.example.com").is_ok());
    }

    #[test]
    fn test_validate_domain_pattern_empty() {
        assert!(validate_domain_pattern("").is_err());
    }

    #[test]
    fn test_validate_domain_pattern_invalid_wildcard() {
        assert!(validate_domain_pattern("example.*.com").is_err());
        assert!(validate_domain_pattern("*example.com").is_err());
        assert!(validate_domain_pattern("*.").is_err());
    }

    #[test]
    fn test_validate_domain_pattern_invalid_label() {
        assert!(validate_domain_pattern("-example.com").is_err());
        assert!(validate_domain_pattern("example-.com").is_err());
        assert!(validate_domain_pattern("exam ple.com").is_err());
    }

    #[test]
    fn test_extract_domain_simple() {
        assert_eq!(extract_domain("https://example.com/path"), "example.com");
        assert_eq!(
            extract_domain("http://example.com:8080/path"),
            "example.com"
        );
        assert_eq!(extract_domain("example.com"), "example.com");
    }

    #[test]
    fn test_extract_domain_userinfo() {
        assert_eq!(
            extract_domain("https://user@example.com/path"),
            "example.com"
        );
        assert_eq!(
            extract_domain("https://user:pass@example.com/path"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_domain_ipv6() {
        assert_eq!(extract_domain("http://[::1]:8080/path"), "::1");
        assert_eq!(extract_domain("http://[2001:db8::1]/path"), "2001:db8::1");
    }

    #[test]
    fn test_extract_domain_trailing_dot() {
        assert_eq!(extract_domain("https://example.com./path"), "example.com");
    }

    #[test]
    fn test_match_domain_pattern_exact() {
        assert!(match_domain_pattern("example.com", "example.com"));
        assert!(!match_domain_pattern("example.com", "other.com"));
    }

    #[test]
    fn test_match_domain_pattern_wildcard() {
        assert!(match_domain_pattern("sub.example.com", "*.example.com"));
        assert!(match_domain_pattern("example.com", "*.example.com"));
        assert!(!match_domain_pattern(
            "example.com.evil.com",
            "*.example.com"
        ));
    }

    #[test]
    fn test_match_domain_pattern_case_insensitive() {
        assert!(match_domain_pattern("EXAMPLE.COM", "example.com"));
        assert!(match_domain_pattern("example.com", "EXAMPLE.COM"));
    }

    #[test]
    fn test_normalize_domain_for_match_idna() {
        // German domain with umlaut
        let norm = normalize_domain_for_match("münchen.de");
        assert!(norm.is_some());
        assert_eq!(norm.unwrap().as_ref(), "xn--mnchen-3ya.de");
    }

    #[test]
    fn test_normalize_domain_for_match_trailing_dot() {
        let norm = normalize_domain_for_match("example.com.");
        assert!(norm.is_some());
        assert_eq!(norm.unwrap().as_ref(), "example.com");
    }

    #[test]
    fn test_extract_domain_encoded_at() {
        // Percent-encoded @ in authority should be decoded
        assert_eq!(
            extract_domain("http://evil.com%40blocked.com/path"),
            "blocked.com"
        );
    }

    #[test]
    fn test_extract_domain_backslash_normalization() {
        // Backslash should be treated as path separator per WHATWG
        assert_eq!(
            extract_domain("http://evil.com\\@legit.com/path"),
            "evil.com"
        );
    }

    // ════════════════════════════════════════════════════════
    // FIND-046: Domain homoglyph / confusable tests
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_match_domain_cyrillic_homoglyph_does_not_match_latin() {
        // Cyrillic "о" (U+043E) looks like Latin "o" but is different
        // "gооgle.com" with Cyrillic "о" should NOT match "google.com"
        let cyrillic_o = "g\u{043E}\u{043E}gle.com";
        assert!(
            !match_domain_pattern(cyrillic_o, "google.com"),
            "Cyrillic homoglyph domain should not match Latin domain (normalized to different punycode)"
        );
    }

    #[test]
    fn test_match_domain_cyrillic_homoglyph_normalizes_consistently() {
        // Both sides with Cyrillic should match each other
        let cyrillic_o = "g\u{043E}\u{043E}gle.com";
        assert!(
            match_domain_pattern(cyrillic_o, cyrillic_o),
            "Identical Cyrillic domains should match"
        );
    }

    #[test]
    fn test_match_domain_zero_width_characters_in_domain() {
        // Zero-width space (U+200B) in a domain should be handled by IDNA
        // IDNA should either strip it or reject it (fail-closed)
        let zwsp = "evil\u{200B}.com";
        let result = normalize_domain_for_match(zwsp);
        // Acceptable: either normalizes to "evil.com" or fails (None)
        // What's NOT acceptable: it normalizes to something that bypasses blocklists
        if let Some(normalized) = &result {
            // If it normalizes, it should match evil.com
            assert!(
                match_domain_pattern(zwsp, "evil.com") || normalized.contains("xn--"),
                "Zero-width domain should either match evil.com or become punycode, got: {}",
                normalized
            );
        }
        // If result is None, that's also fine (fail-closed)
    }

    #[test]
    fn test_match_domain_fullwidth_latin_characters() {
        // Fullwidth Latin 'e' (U+FF45) should be handled by IDNA normalization
        let fullwidth_e = "\u{FF45}xample.com";
        let result = normalize_domain_for_match(fullwidth_e);
        // IDNA may normalize to "example.com" or reject it
        if let Some(normalized) = &result {
            // If normalized, verify it maps to punycode or the ASCII equivalent
            assert!(
                normalized.as_ref() == "example.com" || normalized.contains("xn--"),
                "Fullwidth should normalize to example.com or punycode, got: {}",
                normalized
            );
        }
        // None is also acceptable (fail-closed)
    }

    #[test]
    fn test_match_domain_mixed_script_fails_closed() {
        // Mixed Latin + Cyrillic in same label — IDNA should reject or normalize to punycode
        let mixed = "g\u{043E}ogle.com"; // Cyrillic "о" + Latin "o"
        let result = normalize_domain_for_match(mixed);
        // Must NOT match "google.com" — that would be a security bypass
        assert!(
            !match_domain_pattern(mixed, "google.com"),
            "Mixed-script domain must not match pure ASCII equivalent"
        );
        // Either normalize to punycode (different from google.com) or reject
        if let Some(normalized) = &result {
            assert_ne!(
                normalized.as_ref(),
                "google.com",
                "Mixed-script must not silently normalize to ASCII lookalike"
            );
        }
    }

    #[test]
    fn test_match_domain_combining_character_diacritics() {
        // "a" + combining acute accent (U+0301) = "á"
        let combining = "ex\u{0301}mple.com";
        let result = normalize_domain_for_match(combining);
        // Should NOT match "example.com" — the diacritic changes the domain
        assert!(
            !match_domain_pattern(combining, "example.com"),
            "Domain with combining diacritics should not match plain ASCII"
        );
        // If normalized, should be punycode
        if let Some(normalized) = &result {
            assert!(
                normalized.contains("xn--") || normalized.as_ref() != "example.com",
                "Combining diacritics should produce different normalized form"
            );
        }
    }

    #[test]
    fn test_normalize_domain_for_match_rejects_invalid_ascii() {
        // Domains with spaces, colons, etc. should be rejected
        assert!(normalize_domain_for_match("evil .com").is_none());
        assert!(normalize_domain_for_match("evil:com").is_none());
        assert!(normalize_domain_for_match("evil\ncom").is_none());
    }
}
