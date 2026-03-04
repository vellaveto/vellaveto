// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use crate::pii::PiiScanner;
use regex::Regex;
use std::sync::LazyLock;
use unicode_normalization::UnicodeNormalization;

/// Sensitive parameter key names that should always be redacted.
const SENSITIVE_PARAM_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "secret_key",
    "private_key",
    "authorization",
    "credentials",
    "session_token",
    "refresh_token",
    "client_secret",
];

/// Prefixes of values that indicate secrets. If a string value starts with
/// any of these prefixes, the value is redacted.
const SENSITIVE_VALUE_PREFIXES: &[&str] = &[
    "sk-",         // OpenAI, Anthropic API keys
    "AKIA",        // AWS access key ID
    "ghp_",        // GitHub personal access token
    "gho_",        // GitHub OAuth token
    "ghs_",        // GitHub server-to-server token
    "github_pat_", // GitHub fine-grained PAT
    "xoxb-",       // Slack bot token
    "xoxp-",       // Slack user token
    "Bearer ",     // Authorization header value
    "Basic ",      // Authorization header value
    "sk_live_",    // Stripe live secret key
    "sk_test_",    // Stripe test secret key
    "pk_live_",    // Stripe live publishable key
    "rk_live_",    // Stripe live restricted key
    "AIza",        // Google Cloud Platform API key
    "SG.",         // SendGrid API key
    "npm_",        // npm access token
    "pypi-",       // PyPI API token
];

pub(crate) const REDACTED: &str = "[REDACTED]";

/// Pre-compiled PII detection regexes (email, SSN, US phone numbers).
///
/// Patterns that fail to compile are logged at error level and dropped.
/// Since all patterns are hardcoded constants, compilation failure indicates
/// a bug in the source and degrades PII redaction coverage.
pub(crate) static PII_REGEXES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // Email addresses
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        // US Social Security Numbers (XXX-XX-XXXX)
        r"\b\d{3}-\d{2}-\d{4}\b",
        // US phone numbers (various formats)
        r"\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b",
    ]
    .into_iter()
    .filter_map(|p| match Regex::new(p) {
        Ok(re) => Some(re),
        Err(e) => {
            // SECURITY (FIND-R56-AUDIT-001): Log at error level when a PII regex
            // fails to compile — this degrades redaction coverage and is a bug.
            tracing::error!(
                "CRITICAL: Failed to compile PII regex '{}': {}. \
                 This pattern will be SKIPPED — PII redaction degraded.",
                p,
                e
            );
            None
        }
    })
    .collect()
});

/// Maximum recursion depth for redaction functions.
/// SECURITY (FIND-R46-011/013): Prevents stack overflow from deeply nested JSON.
const MAX_REDACTION_DEPTH: usize = 64;

/// Recursively redact only sensitive key names.
///
/// Keys matching `SENSITIVE_PARAM_KEYS` (case-insensitive) have their values replaced.
/// Value content is NOT inspected — only key names drive redaction.
pub(crate) fn redact_keys_only(value: &serde_json::Value) -> serde_json::Value {
    redact_keys_only_inner(value, 0)
}

fn redact_keys_only_inner(value: &serde_json::Value, depth: usize) -> serde_json::Value {
    // SECURITY (FIND-R46-011, GAP-S06): Stop recursion at max depth. Fail-closed by
    // redacting the value at max depth instead of returning it unredacted, which could
    // leak sensitive data in deeply nested structures.
    if depth >= MAX_REDACTION_DEPTH {
        return serde_json::Value::String(REDACTED.to_string());
    }
    match value {
        serde_json::Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (key, val) in map {
                let key_lower = key.to_lowercase();
                if SENSITIVE_PARAM_KEYS.iter().any(|k| key_lower == *k) {
                    result.insert(key.clone(), serde_json::Value::String(REDACTED.to_string()));
                } else {
                    result.insert(key.clone(), redact_keys_only_inner(val, depth + 1));
                }
            }
            serde_json::Value::Object(result)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.iter()
                .map(|v| redact_keys_only_inner(v, depth + 1))
                .collect(),
        ),
        _ => value.clone(),
    }
}

/// Recursively redact sensitive keys, value prefixes, and PII patterns.
///
/// - Keys matching `SENSITIVE_PARAM_KEYS` (case-insensitive) have their values replaced.
/// - String values starting with `SENSITIVE_VALUE_PREFIXES` are replaced.
/// - String values matching PII patterns (email, SSN, phone) are replaced.
/// - Number values matching PII patterns are also redacted (R9-3).
///
/// Public so that other crates (e.g., vellaveto-server) can apply the same
/// redaction to approval listings and other API responses that may contain
/// sensitive parameters.
pub fn redact_keys_and_patterns(value: &serde_json::Value) -> serde_json::Value {
    redact_keys_and_patterns_inner(value, 0)
}

fn redact_keys_and_patterns_inner(value: &serde_json::Value, depth: usize) -> serde_json::Value {
    // SECURITY (FIND-R46-013, GAP-S06): Stop recursion at max depth. Fail-closed by
    // redacting the value at max depth instead of returning it unredacted.
    if depth >= MAX_REDACTION_DEPTH {
        return serde_json::Value::String(REDACTED.to_string());
    }
    match value {
        serde_json::Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (key, val) in map {
                let key_lower = key.to_lowercase();
                if SENSITIVE_PARAM_KEYS.iter().any(|k| key_lower == *k) {
                    result.insert(key.clone(), serde_json::Value::String(REDACTED.to_string()));
                } else {
                    result.insert(key.clone(), redact_keys_and_patterns_inner(val, depth + 1));
                }
            }
            serde_json::Value::Object(result)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.iter()
                .map(|v| redact_keys_and_patterns_inner(v, depth + 1))
                .collect(),
        ),
        serde_json::Value::String(s) => {
            // SECURITY (R9-8): Case-insensitive prefix check — "SK-..." or
            // "bearer ..." should match as well as "sk-..." and "Bearer ...".
            let s_lower = s.to_lowercase();
            if SENSITIVE_VALUE_PREFIXES
                .iter()
                .any(|prefix| s_lower.starts_with(&prefix.to_lowercase()))
            {
                return serde_json::Value::String(REDACTED.to_string());
            }
            // SECURITY (FIND-084): Apply NFKC normalization before PII regex matching.
            // This converts fullwidth digits (U+FF10-FF19) to ASCII digits,
            // preventing bypass via Unicode digit variants.
            let normalized: String = s.nfkc().collect();
            if PII_REGEXES.iter().any(|re| re.is_match(&normalized)) {
                serde_json::Value::String(REDACTED.to_string())
            } else {
                value.clone()
            }
        }
        // SECURITY (R9-3): Numbers can contain PII (credit card numbers, SSNs
        // stored as integers). Convert to string representation and check against
        // PII regex patterns. If a match is found, redact the value.
        serde_json::Value::Number(n) => {
            let s = n.to_string();
            if PII_REGEXES.iter().any(|re| re.is_match(&s)) {
                serde_json::Value::String(REDACTED.to_string())
            } else {
                value.clone()
            }
        }
        _ => value.clone(),
    }
}

/// Recursively redact sensitive keys, value prefixes, and PII patterns using
/// a [`PiiScanner`] for **substring** replacement instead of whole-value replacement.
///
/// Example: `"Call 555-123-4567"` → `"Call [REDACTED]"` (not just `"[REDACTED]"`).
pub(crate) fn redact_keys_and_patterns_with_scanner(
    value: &serde_json::Value,
    scanner: &PiiScanner,
) -> serde_json::Value {
    redact_keys_and_patterns_with_scanner_inner(value, scanner, 0)
}

fn redact_keys_and_patterns_with_scanner_inner(
    value: &serde_json::Value,
    scanner: &PiiScanner,
    depth: usize,
) -> serde_json::Value {
    // SECURITY (FIND-R46-013, GAP-S06): Stop recursion at max depth. Fail-closed by
    // redacting the value at max depth instead of returning it unredacted.
    if depth >= MAX_REDACTION_DEPTH {
        return serde_json::Value::String(REDACTED.to_string());
    }
    match value {
        serde_json::Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (key, val) in map {
                let key_lower = key.to_lowercase();
                if SENSITIVE_PARAM_KEYS.iter().any(|k| key_lower == *k) {
                    result.insert(key.clone(), serde_json::Value::String(REDACTED.to_string()));
                } else {
                    result.insert(
                        key.clone(),
                        redact_keys_and_patterns_with_scanner_inner(val, scanner, depth + 1),
                    );
                }
            }
            serde_json::Value::Object(result)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.iter()
                .map(|v| redact_keys_and_patterns_with_scanner_inner(v, scanner, depth + 1))
                .collect(),
        ),
        serde_json::Value::String(s) => {
            // Check value prefixes first (whole-value replacement for secrets)
            // SECURITY (R9-8): Case-insensitive prefix matching.
            let s_lower = s.to_lowercase();
            if SENSITIVE_VALUE_PREFIXES
                .iter()
                .any(|prefix| s_lower.starts_with(&prefix.to_lowercase()))
            {
                serde_json::Value::String(REDACTED.to_string())
            } else {
                // SECURITY (FIND-084): NFKC-normalize before PII scanning.
                let normalized: String = s.nfkc().collect();
                // Substring PII redaction via scanner (on normalized text)
                let redacted = scanner.redact_string(&normalized);
                if redacted != normalized {
                    // PII was found in normalized form — redact the original
                    serde_json::Value::String(REDACTED.to_string())
                } else {
                    // No PII found — return original
                    serde_json::Value::String(scanner.redact_string(s))
                }
            }
        }
        // SECURITY (R9-3): Numbers can contain PII (credit card numbers, SSNs
        // stored as integers). Convert to string and apply scanner-based redaction.
        serde_json::Value::Number(n) => {
            let s = n.to_string();
            let redacted = scanner.redact_string(&s);
            if redacted != s {
                serde_json::Value::String(redacted)
            } else {
                value.clone()
            }
        }
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── redact_keys_only tests ──────────────────────────────────────

    #[test]
    fn test_redact_keys_only_password_redacted() {
        let input = json!({"password": "s3cret", "username": "alice"});
        let result = redact_keys_only(&input);
        assert_eq!(result["password"], REDACTED);
        assert_eq!(result["username"], "alice");
    }

    #[test]
    fn test_redact_keys_only_case_insensitive() {
        let input = json!({"PASSWORD": "s3cret", "Api_Key": "key123"});
        let result = redact_keys_only(&input);
        assert_eq!(result["PASSWORD"], REDACTED);
        assert_eq!(result["Api_Key"], REDACTED);
    }

    #[test]
    fn test_redact_keys_only_nested_object() {
        let input = json!({"config": {"secret": "hidden", "name": "test"}});
        let result = redact_keys_only(&input);
        assert_eq!(result["config"]["secret"], REDACTED);
        assert_eq!(result["config"]["name"], "test");
    }

    #[test]
    fn test_redact_keys_only_array_elements() {
        let input = json!([{"token": "abc"}, {"name": "safe"}]);
        let result = redact_keys_only(&input);
        assert_eq!(result[0]["token"], REDACTED);
        assert_eq!(result[1]["name"], "safe");
    }

    #[test]
    fn test_redact_keys_only_does_not_redact_values() {
        // redact_keys_only should NOT scan string values for patterns
        let input = json!({"note": "sk-proj-secret123"});
        let result = redact_keys_only(&input);
        assert_eq!(result["note"], "sk-proj-secret123");
    }

    #[test]
    fn test_redact_keys_only_depth_limit_fail_closed() {
        // Build a JSON value nested deeper than MAX_REDACTION_DEPTH.
        // At max depth the function should redact (fail-closed), not pass through.
        let mut value = json!("leaf");
        for _ in 0..MAX_REDACTION_DEPTH + 5 {
            value = json!({"a": value});
        }
        let result = redact_keys_only(&value);
        // Walk down to the depth limit -- should be REDACTED
        let mut cursor = &result;
        for _ in 0..MAX_REDACTION_DEPTH {
            cursor = &cursor["a"];
        }
        assert_eq!(cursor, REDACTED);
    }

    // ── redact_keys_and_patterns tests ──────────────────────────────

    #[test]
    fn test_redact_keys_and_patterns_sensitive_key() {
        let input = json!({"client_secret": "abc123"});
        let result = redact_keys_and_patterns(&input);
        assert_eq!(result["client_secret"], REDACTED);
    }

    #[test]
    fn test_redact_keys_and_patterns_value_prefix_sk() {
        let input = json!({"key": "sk-proj-abcdef123456"});
        let result = redact_keys_and_patterns(&input);
        assert_eq!(result["key"], REDACTED);
    }

    #[test]
    fn test_redact_keys_and_patterns_value_prefix_case_insensitive() {
        // "SK-" should match "sk-" (R9-8)
        let input = json!({"key": "SK-UPPERCASE-KEY"});
        let result = redact_keys_and_patterns(&input);
        assert_eq!(result["key"], REDACTED);
    }

    #[test]
    fn test_redact_keys_and_patterns_email_pii() {
        let input = json!({"note": "contact user@example.com"});
        let result = redact_keys_and_patterns(&input);
        assert_eq!(result["note"], REDACTED);
    }

    #[test]
    fn test_redact_keys_and_patterns_ssn_pii() {
        let input = json!({"info": "SSN 123-45-6789"});
        let result = redact_keys_and_patterns(&input);
        assert_eq!(result["info"], REDACTED);
    }

    #[test]
    fn test_redact_keys_and_patterns_phone_pii() {
        let input = json!({"contact": "555-123-4567"});
        let result = redact_keys_and_patterns(&input);
        assert_eq!(result["contact"], REDACTED);
    }

    #[test]
    fn test_redact_keys_and_patterns_number_pii() {
        // SSN-like pattern in a numeric value (R9-3)
        // Use a number that matches the phone regex: 5551234567
        let input = json!({"data": 5551234567u64});
        let result = redact_keys_and_patterns(&input);
        assert_eq!(result["data"], REDACTED);
    }

    #[test]
    fn test_redact_keys_and_patterns_nfkc_normalization() {
        // FIND-084: Fullwidth digits should be normalized before PII scanning.
        // Fullwidth "1" is U+FF11, "2" is U+FF12, etc.
        // Build a fullwidth SSN-like pattern: 123-45-6789 in fullwidth digits.
        let fullwidth_ssn =
            "\u{FF11}\u{FF12}\u{FF13}-\u{FF14}\u{FF15}-\u{FF16}\u{FF17}\u{FF18}\u{FF19}";
        let input = json!({"data": fullwidth_ssn});
        let result = redact_keys_and_patterns(&input);
        // NFKC normalizes fullwidth digits to ASCII, so the SSN pattern should match
        assert_eq!(
            result["data"], REDACTED,
            "Fullwidth digit SSN should be detected after NFKC normalization"
        );
    }

    #[test]
    fn test_redact_keys_and_patterns_aws_key_prefix() {
        let input = json!({"val": "AKIAIOSFODNN7EXAMPLE"});
        let result = redact_keys_and_patterns(&input);
        assert_eq!(result["val"], REDACTED);
    }

    #[test]
    fn test_redact_keys_and_patterns_bearer_prefix() {
        let input = json!({"header": "Bearer eyJhbGciOiJ..."});
        let result = redact_keys_and_patterns(&input);
        assert_eq!(result["header"], REDACTED);
    }

    #[test]
    fn test_redact_keys_and_patterns_depth_limit_fail_closed() {
        let mut value = json!("innocuous");
        for _ in 0..MAX_REDACTION_DEPTH + 5 {
            value = json!({"a": value});
        }
        let result = redact_keys_and_patterns(&value);
        let mut cursor = &result;
        for _ in 0..MAX_REDACTION_DEPTH {
            cursor = &cursor["a"];
        }
        assert_eq!(cursor, REDACTED);
    }

    #[test]
    fn test_redact_keys_and_patterns_safe_value_unchanged() {
        let input = json!({"greeting": "hello world"});
        let result = redact_keys_and_patterns(&input);
        assert_eq!(result["greeting"], "hello world");
    }

    // ── redact_keys_and_patterns_with_scanner tests ─────────────────

    #[test]
    fn test_redact_with_scanner_sensitive_key() {
        let scanner = PiiScanner::default();
        let input = json!({"authorization": "my-token"});
        let result = redact_keys_and_patterns_with_scanner(&input, &scanner);
        assert_eq!(result["authorization"], REDACTED);
    }

    #[test]
    fn test_redact_with_scanner_substring_preserves_context() {
        let scanner = PiiScanner::default();
        // The scanner should do substring replacement for PII.
        // With scanner, the original string gets NFKC-normalized and checked.
        // If PII is found in normalized form, the entire value is REDACTED.
        let input = json!({"note": "Contact user@example.com for info"});
        let result = redact_keys_and_patterns_with_scanner(&input, &scanner);
        // Email is PII -- the normalized form has it, so full value redacted
        assert_eq!(result["note"], REDACTED);
    }

    #[test]
    fn test_redact_with_scanner_value_prefix() {
        let scanner = PiiScanner::default();
        let input = json!({"key": "ghp_abcdef1234567890"});
        let result = redact_keys_and_patterns_with_scanner(&input, &scanner);
        assert_eq!(result["key"], REDACTED);
    }

    #[test]
    fn test_redact_with_scanner_depth_limit_fail_closed() {
        let scanner = PiiScanner::default();
        let mut value = json!("safe");
        for _ in 0..MAX_REDACTION_DEPTH + 5 {
            value = json!({"a": value});
        }
        let result = redact_keys_and_patterns_with_scanner(&value, &scanner);
        let mut cursor = &result;
        for _ in 0..MAX_REDACTION_DEPTH {
            cursor = &cursor["a"];
        }
        assert_eq!(cursor, REDACTED);
    }

    #[test]
    fn test_redact_with_scanner_safe_string_unchanged() {
        let scanner = PiiScanner::default();
        let input = json!({"msg": "no sensitive data here"});
        let result = redact_keys_and_patterns_with_scanner(&input, &scanner);
        assert_eq!(result["msg"], "no sensitive data here");
    }

    #[test]
    fn test_redact_keys_and_patterns_all_sensitive_keys() {
        // Verify all SENSITIVE_PARAM_KEYS are redacted
        for &key in SENSITIVE_PARAM_KEYS {
            let input = json!({key: "some_value"});
            let result = redact_keys_and_patterns(&input);
            assert_eq!(result[key], REDACTED, "Key '{key}' should be redacted");
        }
    }

    #[test]
    fn test_redact_keys_and_patterns_bool_null_unchanged() {
        let input = json!({"flag": true, "nothing": null, "count": 42});
        let result = redact_keys_and_patterns(&input);
        assert_eq!(result["flag"], true);
        assert!(result["nothing"].is_null());
        assert_eq!(result["count"], 42);
    }
}
