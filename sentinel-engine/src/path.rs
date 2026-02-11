//! Path normalization utilities.
//!
//! This module provides path normalization functions that:
//! - Resolve `..` and `.` components
//! - Reject null bytes (fail-closed)
//! - Iteratively decode percent-encoding until stable
//! - Normalize backslashes to forward slashes
//! - Ensure deterministic, absolute path output

use crate::error::EngineError;
use std::borrow::Cow;
use std::path::{Component, PathBuf};

/// Default maximum percent-decoding iterations for path normalization.
/// Paths requiring more iterations fail-closed with an error.
pub const DEFAULT_MAX_PATH_DECODE_ITERATIONS: u32 = 20;

/// Normalize a file path: resolve `..`, `.`, reject null bytes, ensure deterministic form.
///
/// Uses the default decode iteration limit ([`DEFAULT_MAX_PATH_DECODE_ITERATIONS`]).
/// For a configurable limit, use [`normalize_path_bounded`].
///
/// # Security
///
/// This function is hardened against path traversal attacks:
/// - Rejects paths containing null bytes
/// - Iteratively percent-decodes until stable (prevents double-encoding bypass)
/// - Resolves `..` and `.` components
/// - Normalizes backslashes to forward slashes
/// - Ensures output is an absolute path (prepends `/` if needed)
///
/// # Errors
///
/// Returns `EngineError::PathNormalization` if:
/// - Input contains null bytes
/// - Decoded path contains null bytes
/// - Decode iteration limit is exceeded
/// - Normalization produces an empty path
pub fn normalize_path(raw: &str) -> Result<String, EngineError> {
    normalize_path_bounded(raw, DEFAULT_MAX_PATH_DECODE_ITERATIONS)
}

/// Normalize a file path with a configurable percent-decoding iteration limit.
///
/// Iteratively decodes percent-encoding until stable. If `max_iterations` is
/// reached before stabilization, returns an error (fail-closed) and emits a
/// warning via `tracing`.
///
/// # Arguments
///
/// * `raw` - The raw path string to normalize
/// * `max_iterations` - Maximum number of decode iterations before fail-closed
///
/// # Security
///
/// See [`normalize_path`] for security details. The iteration limit prevents
/// DoS attacks via deeply-nested percent-encoding (e.g., `%25252525...`).
pub fn normalize_path_bounded(raw: &str, max_iterations: u32) -> Result<String, EngineError> {
    // Reject null bytes — return root instead of empty/raw to prevent bypass
    if raw.contains('\0') {
        return Err(EngineError::PathNormalization {
            reason: "input contains null byte".to_string(),
        });
    }

    // Phase 4.2: Percent-decode the path before normalization.
    // Decode in a loop until stable to guarantee idempotency:
    //   normalize_path(normalize_path(x)) == normalize_path(x)
    // Without loop decode, inputs like "%2570" produce "%70" on first call,
    // which decodes to "p" on the next call — breaking idempotency.
    // Safety cap prevents DoS from deeply-nested encodings.
    // If the cap is reached, return "/" (fail-closed).
    //
    // Uses Cow to avoid allocation when no percent sequences are present.
    let mut current = Cow::Borrowed(raw);
    let mut iterations = 0u32;
    loop {
        let decoded = percent_encoding::percent_decode_str(&current).decode_utf8_lossy();
        if decoded.contains('\0') {
            return Err(EngineError::PathNormalization {
                reason: "decoded path contains null byte".to_string(),
            });
        }
        // SECURITY (R35-ENG-1): Normalize backslashes INSIDE the decode loop
        // to prevent multi-stage encoded backslash traversals (%255C → %5C → \ → /).
        // Previously (R34-ENG-1) this was done after the loop, which meant
        // backslashes produced by intermediate decode steps were not converted
        // before the stability check, allowing %255C-based traversal.
        let decoded = if decoded.contains('\\') {
            Cow::Owned(decoded.replace('\\', "/"))
        } else {
            decoded
        };
        if decoded.as_ref() == current.as_ref() {
            break; // Stable — no more percent sequences to decode
        }
        iterations += 1;
        if iterations >= max_iterations {
            tracing::warn!(
                path = raw,
                iterations,
                max_iterations,
                "path normalization hit decode iteration limit — returning \"/\" (possible adversarial input)"
            );
            return Err(EngineError::PathNormalization {
                reason: format!("decode iteration limit ({}) exceeded", max_iterations),
            });
        }
        current = Cow::Owned(decoded.into_owned());
    }

    let path = PathBuf::from(current.as_ref());
    let mut components = Vec::new();

    for component in path.components() {
        match component {
            Component::ParentDir => {
                match components.last() {
                    Some(Component::RootDir) | None => {
                        // At root or empty — absorb the .., can't go above root
                        continue;
                    }
                    _ => {
                        components.pop();
                        continue;
                    }
                }
            }
            Component::CurDir => continue,
            _ => {}
        }
        components.push(component);
    }

    let result: PathBuf = components.iter().collect();
    let s = result.to_string_lossy();
    if s.is_empty() {
        // Fix #9: Return "/" (root) instead of the raw input when normalization
        // produces an empty string. The raw input contains the traversal sequences
        // that normalization was supposed to remove.
        return Err(EngineError::PathNormalization {
            reason: "normalization produced empty path".to_string(),
        });
    }

    // SECURITY (R11-PATH-6): Enforce absolute path output.
    // If the input was a relative path (e.g., "etc/passwd"), the result
    // will not start with '/', causing it to miss absolute-path glob
    // patterns like "/etc/**". Prepend '/' to make it matchable.
    let s = s.into_owned();
    if !s.starts_with('/') {
        return Ok(format!("/{}", s));
    }

    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path_simple() {
        assert_eq!(normalize_path("/etc/passwd").unwrap(), "/etc/passwd");
        assert_eq!(
            normalize_path("/home/user/file.txt").unwrap(),
            "/home/user/file.txt"
        );
    }

    #[test]
    fn test_normalize_path_traversal() {
        assert_eq!(normalize_path("/etc/../etc/passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("/etc/./passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("/etc/foo/../passwd").unwrap(), "/etc/passwd");
    }

    #[test]
    fn test_normalize_path_above_root() {
        // Can't traverse above root
        assert_eq!(normalize_path("/etc/../../../passwd").unwrap(), "/passwd");
        assert_eq!(normalize_path("/../../../etc").unwrap(), "/etc");
    }

    #[test]
    fn test_normalize_path_relative() {
        // Relative paths get '/' prepended
        assert_eq!(normalize_path("etc/passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("file.txt").unwrap(), "/file.txt");
    }

    #[test]
    fn test_normalize_path_percent_encoded() {
        // %2e = '.', %2f = '/'
        assert_eq!(normalize_path("/etc/%2e%2e/passwd").unwrap(), "/passwd");
    }

    #[test]
    fn test_normalize_path_double_encoded() {
        // %252e = '%2e' -> '.'
        assert_eq!(normalize_path("/etc/%252e%252e/passwd").unwrap(), "/passwd");
    }

    #[test]
    fn test_normalize_path_null_byte_rejected() {
        assert!(normalize_path("/etc/passwd\0").is_err());
    }

    #[test]
    fn test_normalize_path_encoded_null_rejected() {
        // %00 = null byte
        assert!(normalize_path("/etc/passwd%00").is_err());
    }

    #[test]
    fn test_normalize_path_backslash_normalized() {
        assert_eq!(normalize_path("/etc\\passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("\\etc\\passwd").unwrap(), "/etc/passwd");
    }

    #[test]
    fn test_normalize_path_iteration_limit() {
        // Deeply nested encoding should hit iteration limit
        let result = normalize_path_bounded("%25252525252525252525", 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_path_empty_result() {
        // Path that resolves to empty should error
        assert!(normalize_path("..").is_err());
    }
}
