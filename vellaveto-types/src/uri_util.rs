// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! URI normalization utilities per RFC 3986.
//!
//! Shared between `vellaveto-http-proxy::oauth` and `vellaveto-mcp::nhi` to
//! ensure identical DPoP `htu` normalization across both DPoP validation paths.

/// Decode unreserved percent-encoded characters per RFC 3986 §2.3.
///
/// Unreserved chars (`A-Z a-z 0-9 - . _ ~`) are decoded from `%XX` form.
/// Reserved/other characters stay percent-encoded with uppercase hex digits
/// per §6.2.2.1.
///
/// # Panics
///
/// Does not panic. Non-ASCII raw bytes are passed through (callers should
/// validate ASCII-only input before calling).
pub fn decode_unreserved_percent(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                let ch = (hi << 4) | lo;
                if ch.is_ascii_alphanumeric()
                    || ch == b'-'
                    || ch == b'.'
                    || ch == b'_'
                    || ch == b'~'
                {
                    out.push(ch as char);
                    i += 3;
                    continue;
                }
                // Reserved/other: keep as uppercase percent-encoding (§6.2.2.1)
                out.push('%');
                out.push((bytes[i + 1] as char).to_ascii_uppercase());
                out.push((bytes[i + 2] as char).to_ascii_uppercase());
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Parse a single hex digit to its numeric value (0–15).
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

/// Normalize a DPoP `htu` claim per RFC 3986 §6.2.
///
/// Steps:
/// 1. Strip trailing `/`
/// 2. Decode unreserved percent-encoded characters (§2.3)
/// 3. Lowercase scheme and authority (§6.2.2.1)
/// 4. Preserve path case (paths are case-sensitive)
pub fn normalize_dpop_htu(u: &str) -> String {
    let trimmed = u.trim_end_matches('/');
    let decoded = decode_unreserved_percent(trimmed);
    if let Some(idx) = decoded.find("://") {
        if let Some(path_start) = decoded[idx + 3..].find('/') {
            let authority_end = idx + 3 + path_start;
            let mut normalized = decoded[..authority_end].to_ascii_lowercase();
            normalized.push_str(&decoded[authority_end..]);
            normalized
        } else {
            decoded.to_ascii_lowercase()
        }
    } else {
        decoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- decode_unreserved_percent tests ---

    #[test]
    fn test_decode_unreserved_decodes_alphanumeric() {
        assert_eq!(decode_unreserved_percent("%41"), "A");
        assert_eq!(decode_unreserved_percent("%61"), "a");
        assert_eq!(decode_unreserved_percent("%30"), "0");
        assert_eq!(decode_unreserved_percent("%39"), "9");
    }

    #[test]
    fn test_decode_unreserved_decodes_special_unreserved() {
        assert_eq!(decode_unreserved_percent("%2D"), "-");
        assert_eq!(decode_unreserved_percent("%2E"), ".");
        assert_eq!(decode_unreserved_percent("%5F"), "_");
        assert_eq!(decode_unreserved_percent("%7E"), "~");
    }

    #[test]
    fn test_decode_unreserved_keeps_reserved_encoded() {
        assert_eq!(decode_unreserved_percent("%2F"), "%2F"); // /
        assert_eq!(decode_unreserved_percent("%40"), "%40"); // @
        assert_eq!(decode_unreserved_percent("%3A"), "%3A"); // :
        assert_eq!(decode_unreserved_percent("%20"), "%20"); // space
        assert_eq!(decode_unreserved_percent("%00"), "%00"); // NUL
    }

    #[test]
    fn test_decode_unreserved_normalizes_hex_case() {
        assert_eq!(decode_unreserved_percent("%2d"), "-"); // lowercase → decoded
        assert_eq!(decode_unreserved_percent("%7e"), "~");
        assert_eq!(decode_unreserved_percent("%2f"), "%2F"); // lowercase reserved → uppercase
    }

    #[test]
    fn test_decode_unreserved_incomplete_sequences() {
        assert_eq!(decode_unreserved_percent("foo%"), "foo%");
        assert_eq!(decode_unreserved_percent("foo%2"), "foo%2");
        assert_eq!(decode_unreserved_percent("%"), "%");
    }

    #[test]
    fn test_decode_unreserved_mixed() {
        assert_eq!(
            decode_unreserved_percent("foo%2Dbar%2Fbaz"),
            "foo-bar%2Fbaz"
        );
        assert_eq!(decode_unreserved_percent(""), "");
        assert_eq!(decode_unreserved_percent("no-encoding"), "no-encoding");
    }

    // --- normalize_dpop_htu tests ---

    #[test]
    fn test_normalize_htu_lowercase_scheme_authority() {
        assert_eq!(
            normalize_dpop_htu("HTTP://API.EXAMPLE.COM/path"),
            "http://api.example.com/path"
        );
    }

    #[test]
    fn test_normalize_htu_preserves_path_case() {
        assert_eq!(
            normalize_dpop_htu("https://example.com/CaseSensitive/Path"),
            "https://example.com/CaseSensitive/Path"
        );
    }

    #[test]
    fn test_normalize_htu_strips_trailing_slash() {
        assert_eq!(
            normalize_dpop_htu("https://example.com/path/"),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_normalize_htu_decodes_unreserved_in_path() {
        assert_eq!(
            normalize_dpop_htu("https://example.com/foo%2Dbar"),
            "https://example.com/foo-bar"
        );
    }

    #[test]
    fn test_normalize_htu_keeps_reserved_in_path() {
        assert_eq!(
            normalize_dpop_htu("https://example.com/path%2Fslash"),
            "https://example.com/path%2Fslash"
        );
    }

    #[test]
    fn test_normalize_htu_no_path() {
        assert_eq!(
            normalize_dpop_htu("https://EXAMPLE.COM"),
            "https://example.com"
        );
    }
}
