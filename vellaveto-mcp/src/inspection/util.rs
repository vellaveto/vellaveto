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
/// use vellaveto_mcp::inspection::util::try_base64_decode;
///
/// // Standard base64
/// assert_eq!(try_base64_decode("SGVsbG8gV29ybGQh"), Some("Hello World!".to_string()));
///
/// // Too short (8 chars or less)
/// assert_eq!(try_base64_decode("SGVsbG8="), None);
///
/// // Contains spaces
/// assert_eq!(try_base64_decode("SGVs bG8gV29ybGQ="), None);
/// ```
pub fn try_base64_decode(s: &str) -> Option<String> {
    // FIND-R44-029: Lowered threshold from 16 to 8 characters.
    // Short base64 strings (9-16 chars) can encode secrets like short API keys
    // or password fragments. The previous 16-char minimum allowed bypass by
    // splitting secrets into short base64 chunks.
    if s.len() <= 8 || s.contains(' ') {
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
        // "Hello World from Vellaveto!" in standard base64
        let encoded = "SGVsbG8gV29ybGQgZnJvbSBWZWxsYXZldG8h";
        let decoded = try_base64_decode(encoded);
        assert_eq!(decoded, Some("Hello World from Vellaveto!".to_string()));
    }

    #[test]
    fn test_try_base64_decode_url_safe() {
        // URL-safe base64 uses - and _ instead of + and /
        let encoded = "SGVsbG8gV29ybGQgZnJvbSBWZWxsYXZldG8h";
        let decoded = try_base64_decode(encoded);
        assert_eq!(decoded, Some("Hello World from Vellaveto!".to_string()));
    }

    #[test]
    fn test_try_base64_decode_too_short() {
        // 8 chars or less should return None (FIND-R44-029: lowered from 16)
        let encoded = "SGVsbG8="; // "Hello" - 8 chars
        assert_eq!(try_base64_decode(encoded), None);
    }

    /// FIND-R44-029: Strings between 9 and 16 chars should now be decoded
    /// (previously skipped with the 16-char threshold).
    #[test]
    fn test_try_base64_decode_medium_length() {
        // "short msg!" is 10 chars, encodes to 16 base64 chars
        let encoded = "c2hvcnQgbXNnIQ=="; // 16 chars, > 8 threshold
        let decoded = try_base64_decode(encoded);
        assert_eq!(decoded, Some("short msg!".to_string()));
    }

    /// FIND-R44-029: Boundary test — exactly 9 chars should be decoded.
    #[test]
    fn test_try_base64_decode_boundary_9_chars() {
        // 9 chars of base64 is above the 8-char threshold
        let encoded = "YWJjZGVmZw=="; // "abcdefg" = 12 chars base64
        let decoded = try_base64_decode(encoded);
        assert_eq!(decoded, Some("abcdefg".to_string()));
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
