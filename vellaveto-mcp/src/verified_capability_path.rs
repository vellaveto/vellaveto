// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability grant path-normalization kernel.
//!
//! This module extracts the security-critical fail-closed traversal logic from
//! `capability_token.rs::normalize_path_for_grant()` so it can be mirrored in
//! Verus without pulling the full capability matcher into the proof boundary.

use core::cmp::Ordering;

/// Return the next normalized depth after consuming one path component.
///
/// `None` means the component would traverse above the root or overflow the
/// component depth, and the caller must deny fail-closed.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn path_component_next_depth(
    current_depth: usize,
    component_is_empty_or_dot: bool,
    component_is_dotdot: bool,
) -> Option<usize> {
    if component_is_empty_or_dot {
        Some(current_depth)
    } else if component_is_dotdot {
        if current_depth == 0 {
            None
        } else {
            Some(current_depth - 1)
        }
    } else {
        current_depth.checked_add(1)
    }
}

/// Normalize a grant/action path for capability comparison.
///
/// Returns `None` on null bytes, above-root traversal, or impossible component
/// depth overflow.
#[must_use = "security decisions must not be discarded"]
pub(crate) fn normalize_path_for_grant(path: &str) -> Option<String> {
    if path.contains('\0') {
        return None;
    }

    let mut components: Vec<&str> = Vec::new();
    for component in path.split('/') {
        let next_depth = path_component_next_depth(
            components.len(),
            component.is_empty() || component == ".",
            component == "..",
        )?;

        match next_depth.cmp(&components.len()) {
            Ordering::Less => {
                components.pop();
            }
            Ordering::Equal => {}
            Ordering::Greater => components.push(component),
        }
    }

    let normalized = if path.starts_with('/') {
        format!("/{}", components.join("/"))
    } else {
        components.join("/")
    };
    Some(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_component_next_depth_skips_empty_or_dot() {
        assert_eq!(path_component_next_depth(2, true, false), Some(2));
        assert_eq!(path_component_next_depth(2, true, true), Some(2));
    }

    #[test]
    fn test_path_component_next_depth_fails_closed_above_root() {
        assert_eq!(path_component_next_depth(0, false, true), None);
    }

    #[test]
    fn test_path_component_next_depth_pops_or_pushes() {
        assert_eq!(path_component_next_depth(2, false, true), Some(1));
        assert_eq!(path_component_next_depth(2, false, false), Some(3));
    }

    #[test]
    fn test_normalize_path_for_grant_normalizes_components() {
        assert_eq!(normalize_path_for_grant("/a/./b"), Some("/a/b".to_string()));
        assert_eq!(normalize_path_for_grant("a/b/.."), Some("a".to_string()));
    }

    #[test]
    fn test_normalize_path_for_grant_fails_closed() {
        assert_eq!(normalize_path_for_grant("/../etc/passwd"), None);
        assert_eq!(normalize_path_for_grant("/a/\0/b"), None);
    }
}
