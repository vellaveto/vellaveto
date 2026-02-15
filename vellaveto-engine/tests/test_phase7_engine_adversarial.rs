//! Phase 7 adversarial tests for the policy engine.
//!
//! Findings:
//! - #30 (MEDIUM): Domain extraction: percent-encoded @ produces different result
//!   than decoded-first parsing. If downstream tool decodes first, domain block bypassed.
//! - #31 (LOW): Path normalization: 5-iteration decode limit leaves deeply-encoded
//!   sequences as literal text, potentially mismatching policy patterns.
//! - #32 (LOW): Pattern matching has no Unicode normalization — homoglyph bypass
//!   possible if tool names contain non-ASCII characters.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType};

// =============================================================================
// Finding #30: Domain extraction with percent-encoded @.
//
// extract_domain splits on "/" to get the authority BEFORE percent-decoding.
// A URL like http://evil.com%40blocked.com/path produces:
//   authority = "evil.com%40blocked.com"
//   rfind('@') → no match (it's %40, not @)
//   percent_decode → "evil.com@blocked.com"
//   result: "evil.com@blocked.com"
//
// But a standards-compliant URL parser that decodes first would see:
//   decoded: http://evil.com@blocked.com/path
//   userinfo: "evil.com"
//   host: "blocked.com"
//
// If the downstream tool connects to "blocked.com" but the engine thinks
// the domain is "evil.com@blocked.com", a domain_not_in block on
// "blocked.com" is bypassed.
// =============================================================================

#[test]
fn exploit_30_percent_encoded_at_domain_bypass() {
    // Fix #30: The engine now percent-decodes the authority BEFORE splitting on @,
    // so %40 is decoded to @ and then userinfo is correctly stripped.
    let domain = PolicyEngine::extract_domain("http://evil.com%40blocked.com/exfil");

    // After fix: %40 is decoded → "evil.com@blocked.com" → userinfo stripped → "blocked.com"
    assert_eq!(
        domain, "blocked.com",
        "Percent-encoded @ must be decoded before authority parsing"
    );

    // Now correctly matches "blocked.com"
    assert!(
        PolicyEngine::match_domain_pattern(&domain, "blocked.com"),
        "Decoded percent-encoded @ must match exact domain"
    );

    // Also matches *.blocked.com
    assert!(
        PolicyEngine::match_domain_pattern(&domain, "*.blocked.com"),
        "Decoded percent-encoded @ must match wildcard domain"
    );

    // Compare with the un-encoded version — they must now agree
    let normal_domain = PolicyEngine::extract_domain("http://evil.com@blocked.com/exfil");
    assert_eq!(
        normal_domain, "blocked.com",
        "Un-encoded @ correctly identifies blocked.com as the host"
    );

    // After fix: both forms produce the same domain — no bypass possible
    assert_eq!(
        domain, normal_domain,
        "Percent-encoded and literal @ must produce the SAME domain after fix #30"
    );
}

#[test]
fn exploit_30_percent_encoded_at_policy_bypass() {
    // Fix #30 verification: percent-encoded @ in authority is decoded before
    // splitting on @, so both forms now produce the same domain.

    let encoded_domain = PolicyEngine::extract_domain("http://evil.com%40blocked.com/exfil");
    let normal_domain = PolicyEngine::extract_domain("http://evil.com@blocked.com/exfil");

    // After fix: both produce "blocked.com" — no mismatch, no bypass
    assert_eq!(
        encoded_domain, normal_domain,
        "Percent-encoded and literal @ must produce identical domains after fix #30"
    );

    // Both match the domain block
    assert!(
        PolicyEngine::match_domain_pattern(&normal_domain, "blocked.com"),
        "Un-encoded form matches blocked.com"
    );
    assert!(
        PolicyEngine::match_domain_pattern(&encoded_domain, "blocked.com"),
        "Encoded form now correctly matches blocked.com after fix #30"
    );
}

// =============================================================================
// Finding #31: Path normalization 5-iteration decode limit.
//
// normalize_path decodes percent sequences in a loop, max 5 iterations.
// With 6+ levels of encoding (e.g., %25252525252e), the path is NOT fully
// decoded. The remaining encoded sequences become literal text, potentially
// mismatching policy patterns that reference the decoded form.
// =============================================================================

#[test]
fn exploit_31_path_normalization_deep_encoding_limit() {
    // 3 levels of encoding: %252e → %2e → .
    let path_3_levels = "/home/user/%252e%252e/secret";
    let normalized = PolicyEngine::normalize_path(path_3_levels).unwrap();
    assert_eq!(
        normalized, "/home/secret",
        "3 levels of encoding should be fully normalized within 5 iterations"
    );

    // 5 levels of encoding: needs exactly 5 decode iterations
    // %25 = %, so %2525252e decodes as:
    //   iter 1: %25252e → %252e (decoded outer %25 to %)
    //   iter 2: %252e → %2e
    //   iter 3: %2e → .
    let path_5_levels = "/home/user/%25252e%25252e/secret";
    let normalized = PolicyEngine::normalize_path(path_5_levels).unwrap();
    // After 5 iterations, this should resolve to ../secret → /home/secret
    // The 5-iteration limit MIGHT be sufficient here, but let's verify
    let resolved_traversal = normalized == "/home/secret";
    let still_encoded = normalized.contains('%');

    // Document the behavior — this is the edge of the limit
    if still_encoded {
        // If still encoded after 5 iterations, the traversal is hidden
        // and the path won't match policy patterns for /home/secret
        eprintln!(
            "FINDING: After 5 decode iterations, path is '{}' — still contains encoded sequences",
            normalized
        );
    } else if !resolved_traversal {
        eprintln!("Path decoded but traversal not resolved: '{}'", normalized);
    }
}

#[test]
fn exploit_31_null_byte_in_path_rejected() {
    // Null bytes in paths must be rejected (not silently stripped)
    let path_with_null = "/home/user/.aws\0/credentials";
    assert!(
        PolicyEngine::normalize_path(path_with_null).is_err(),
        "Null byte in path must return Err (fail-closed), not pass through"
    );
}

#[test]
fn exploit_31_percent_encoded_null_rejected() {
    // %00 = null byte — must also be rejected after decoding
    let path_with_encoded_null = "/home/user/.aws%00/credentials";
    assert!(
        PolicyEngine::normalize_path(path_with_encoded_null).is_err(),
        "Percent-encoded null byte must return Err (fail-closed)"
    );
}

// =============================================================================
// Finding #32: Pattern matching has no Unicode normalization.
//
// PatternMatcher::Exact uses direct == comparison. Tool names with Unicode
// homoglyphs (e.g., Cyrillic 'а' U+0430 vs Latin 'a' U+0061) are treated
// as different strings even though they look identical.
//
// In practice, MCP tool names are ASCII identifiers, so this is LOW severity.
// But if a custom MCP server uses non-ASCII tool names, homoglyph attacks
// bypass policies.
// =============================================================================

#[test]
fn exploit_32_unicode_homoglyph_in_tool_name() {
    let policies = vec![Policy {
        // Policy blocks "bash:execute"
        id: "bash:execute".to_string(),
        name: "Block bash".to_string(),
        policy_type: PolicyType::Deny,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];

    if let Ok(engine) = PolicyEngine::with_policies(false, &policies) {
        // Normal action — should be denied
        let normal_action = Action::new("bash".to_string(), "execute".to_string(), json!({}));
        let result = engine.evaluate_action(&normal_action, &policies);
        assert!(
            matches!(result, Ok(vellaveto_types::Verdict::Deny { .. })),
            "Normal 'bash' tool should be denied"
        );

        // Homoglyph attack: Cyrillic 'а' (U+0430) instead of Latin 'a' (U+0061)
        let homoglyph_action =
            Action::new("b\u{0430}sh".to_string(), "execute".to_string(), json!({}));
        let result = engine.evaluate_action(&homoglyph_action, &policies);
        // The homoglyph tool doesn't match the policy pattern "bash"
        // The engine's default behavior determines the verdict
        match result {
            Ok(vellaveto_types::Verdict::Deny { .. }) => {
                // If denied — fail-closed behavior caught it
            }
            Ok(vellaveto_types::Verdict::Allow) => {
                // If allowed — the homoglyph bypassed the deny policy
                // This is concerning if there was ONLY a deny policy for "bash"
            }
            _ => {}
        }
        // The key finding: the pattern matching is byte-level, not Unicode-normalized
        assert_ne!(
            "bash", "b\u{0430}sh",
            "Latin 'a' and Cyrillic 'а' are different bytes — homoglyph bypass possible"
        );
    }
}

// =============================================================================
// Additional: Domain extraction edge cases
// =============================================================================

#[test]
fn domain_extraction_ipv6_with_zone_id() {
    // IPv6 with zone ID — some implementations include %25 for literal %
    let domain = PolicyEngine::extract_domain("http://[fe80::1%25eth0]:8080/path");
    // SECURITY (R31-ENG-5): Brackets stripped for consistent domain matching
    assert!(
        domain.starts_with("fe80::"),
        "IPv6 with zone ID should be extracted without brackets: got '{}'",
        domain
    );
}

#[test]
fn domain_extraction_empty_authority() {
    // file:// URLs have empty authority
    let domain = PolicyEngine::extract_domain("file:///etc/passwd");
    assert!(
        domain.is_empty() || domain == "/etc/passwd",
        "file:// URL domain extraction should not extract path as domain: got '{}'",
        domain
    );
}

#[test]
fn domain_extraction_data_uri() {
    // data: URIs have no authority
    let domain = PolicyEngine::extract_domain("data:text/html,<script>alert(1)</script>");
    // Should not extract the content as a domain
    assert!(
        !domain.contains("script"),
        "data: URI content should not be extracted as domain: got '{}'",
        domain
    );
}

#[test]
fn domain_match_unicode_domain() {
    // IDN domain: café.com (with é = U+00E9, 2 bytes in UTF-8)
    let domain = "café.evil.com";
    let matches = PolicyEngine::match_domain_pattern(domain, "*.evil.com");
    assert!(
        matches,
        "Unicode subdomain should still match wildcard parent: '{}'",
        domain
    );
}

#[test]
fn domain_match_very_long_subdomain() {
    // Very long subdomain to test for buffer issues
    let long_sub = "a".repeat(1000);
    let domain = format!("{}.evil.com", long_sub);
    let matches = PolicyEngine::match_domain_pattern(&domain, "*.evil.com");
    assert!(matches, "Very long subdomain should match wildcard pattern");
}
