//! Shared utilities for inspection modules.
//!
//! This module contains common decoding and transformation functions
//! used by DLP scanning, injection detection, and other inspection modules.

/// Attempt to decode a base64-encoded string.
///
/// Returns `Some(decoded_string)` if the input is valid base64 and decodes to valid UTF-8,
/// `None` otherwise.
///
/// # Security Note (R40-MCP-1)
///
/// Each base64 variant is tried independently with its own UTF-8 check.
/// Previously an `or_else` chain meant a STANDARD decode that succeeded but produced
/// non-UTF-8 bytes would prevent URL_SAFE from being attempted, allowing attackers to
/// evade DLP by encoding secrets with base64url (RFC 4648 §5).
///
/// # Arguments
///
/// * `s` - The input string to decode
///
/// # Returns
///
/// `Some(decoded)` if successfully decoded, `None` otherwise.
///
/// # Example
///
/// ```ignore
/// use sentinel_mcp::inspection::util::try_base64_decode;
///
/// // Standard base64
/// assert_eq!(try_base64_decode("SGVsbG8gV29ybGQh"), Some("Hello World!".to_string()));
///
/// // Too short (less than 16 chars)
/// assert_eq!(try_base64_decode("SGVsbG8="), None);
///
/// // Contains spaces
/// assert_eq!(try_base64_decode("SGVs bG8gV29ybGQ="), None);
/// ```
pub fn try_base64_decode(s: &str) -> Option<String> {
    // Skip short strings and strings with spaces (unlikely to be base64)
    if s.len() <= 16 || s.contains(' ') {
        return None;
    }

    use base64::Engine;

    // Try all standard base64 variants
    let engines = [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];

    for engine in engines {
        if let Ok(bytes) = engine.decode(s) {
            if let Ok(decoded) = std::str::from_utf8(&bytes) {
                return Some(decoded.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_base64_decode_standard() {
        // "Hello World from Sentinel!" in standard base64
        let encoded = "SGVsbG8gV29ybGQgZnJvbSBTZW50aW5lbCE=";
        let decoded = try_base64_decode(encoded);
        assert_eq!(decoded, Some("Hello World from Sentinel!".to_string()));
    }

    #[test]
    fn test_try_base64_decode_url_safe() {
        // URL-safe base64 uses - and _ instead of + and /
        let encoded = "SGVsbG8gV29ybGQgZnJvbSBTZW50aW5lbCE";
        let decoded = try_base64_decode(encoded);
        assert_eq!(decoded, Some("Hello World from Sentinel!".to_string()));
    }

    #[test]
    fn test_try_base64_decode_too_short() {
        // 16 chars or less should return None
        let encoded = "SGVsbG8="; // "Hello"
        assert_eq!(try_base64_decode(encoded), None);
    }

    #[test]
    fn test_try_base64_decode_with_spaces() {
        // Strings with spaces should return None
        let encoded = "SGVs bG8gV29ybGQ=";
        assert_eq!(try_base64_decode(encoded), None);
    }

    #[test]
    fn test_try_base64_decode_invalid() {
        // Invalid base64 should return None
        let invalid = "This is not!!! base64 at all@@@@";
        assert_eq!(try_base64_decode(invalid), None);
    }

    #[test]
    fn test_try_base64_decode_non_utf8() {
        // Valid base64 that decodes to non-UTF8 bytes should return None
        // This is 4 bytes that form an invalid UTF-8 sequence
        let encoded = "/P7+/f39/fw="; // Invalid UTF-8 when decoded
        assert_eq!(try_base64_decode(encoded), None);
    }
}
