// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Path normalization — verbatim extraction from `vellaveto-engine/src/path.rs`.
//!
//! The only differences from the production code:
//! - `EngineError::PathNormalization` → `PathError`
//! - `tracing::warn!()` → no-op (Kani cannot model tracing)
//!
//! The algorithm is identical. This correspondence is verified by CI.

use crate::PathError;
use std::borrow::Cow;
use std::path::{Component, PathBuf};

/// Default maximum percent-decoding iterations for path normalization.
pub const DEFAULT_MAX_PATH_DECODE_ITERATIONS: u32 = 20;

/// Normalize a file path: resolve `..`, `.`, reject null bytes, ensure deterministic form.
pub fn normalize_path(raw: &str) -> Result<String, PathError> {
    normalize_path_bounded(raw, DEFAULT_MAX_PATH_DECODE_ITERATIONS)
}

/// Normalize a file path with a configurable percent-decoding iteration limit.
///
/// Verbatim from `vellaveto-engine/src/path.rs:65-174` with error type substitution.
pub fn normalize_path_bounded(raw: &str, max_iterations: u32) -> Result<String, PathError> {
    // Reject null bytes
    if raw.contains('\0') {
        return Err(PathError {
            reason: "input contains null byte".to_string(),
        });
    }

    // Iterative percent-decode until stable
    let mut current = Cow::Borrowed(raw);
    let mut iterations = 0u32;
    loop {
        let decoded = match percent_encoding::percent_decode_str(&current).decode_utf8() {
            Ok(d) => d,
            Err(_) => {
                return Err(PathError {
                    reason: "decoded path contains invalid UTF-8".to_string(),
                });
            }
        };
        if decoded.contains('\0') {
            return Err(PathError {
                reason: "decoded path contains null byte".to_string(),
            });
        }
        // Normalize backslashes inside the decode loop (R35-ENG-1)
        let decoded = if decoded.contains('\\') {
            Cow::Owned(decoded.replace('\\', "/"))
        } else {
            decoded
        };
        if decoded.as_ref() == current.as_ref() {
            break; // Stable
        }
        iterations += 1;
        if iterations >= max_iterations {
            // Production code: tracing::warn!(...) — omitted for Kani
            return Err(PathError {
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
                        continue; // At root or empty — absorb
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
        return Err(PathError {
            reason: "normalization produced empty path".to_string(),
        });
    }

    let s = s.into_owned();
    if !s.starts_with('/') {
        return Ok(format!("/{}", s));
    }

    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the extracted algorithm matches production behavior
    /// on the same test vectors from `vellaveto-engine/src/path.rs`.
    #[test]
    fn test_production_parity() {
        assert_eq!(normalize_path("/etc/passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("/etc/../etc/passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("/etc/./passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("/etc/../../../passwd").unwrap(), "/passwd");
        assert_eq!(normalize_path("etc/passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("/etc/%2e%2e/passwd").unwrap(), "/passwd");
        assert_eq!(normalize_path("/etc/%252e%252e/passwd").unwrap(), "/passwd");
        assert!(normalize_path("/etc/passwd\0").is_err());
        assert!(normalize_path("/etc/passwd%00").is_err());
        assert_eq!(normalize_path("/etc\\passwd").unwrap(), "/etc/passwd");
        assert!(normalize_path_bounded("%25252525252525252525", 3).is_err());
        assert!(normalize_path("..").is_err());
    }
}
