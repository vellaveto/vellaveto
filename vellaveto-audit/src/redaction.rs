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
/// Patterns that fail to compile are silently dropped. Since all patterns are
/// hardcoded constants, compilation failure indicates a bug in the source.
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
    .filter_map(|p| Regex::new(p).ok())
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
    // SECURITY (FIND-R46-011): Stop recursion at max depth — return value as-is.
    if depth >= MAX_REDACTION_DEPTH {
        return value.clone();
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
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(|v| redact_keys_only_inner(v, depth + 1)).collect())
        }
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
    // SECURITY (FIND-R46-013): Stop recursion at max depth — return value as-is.
    if depth >= MAX_REDACTION_DEPTH {
        return value.clone();
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
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(|v| redact_keys_and_patterns_inner(v, depth + 1)).collect())
        }
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
    // SECURITY (FIND-R46-013): Stop recursion at max depth — return value as-is.
    if depth >= MAX_REDACTION_DEPTH {
        return value.clone();
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
