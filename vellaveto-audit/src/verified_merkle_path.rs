// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified Merkle proof-path kernel.
//!
//! This module extracts the pure structural rules shared by
//! `merkle.rs::compute_siblings()` and `merkle.rs::verify_proof()`: which
//! levels emit a sibling step, which sibling index is chosen, how the left/right
//! direction bit is encoded, and how the leaf index advances to the parent.

/// Return the sibling index paired with `node_index` at the current tree level.
#[inline]
#[must_use = "Merkle proof-path decisions must not be discarded"]
pub(crate) const fn proof_sibling_index(node_index: usize) -> usize {
    if node_index % 2 == 0 {
        node_index + 1
    } else {
        node_index - 1
    }
}

/// Return true when the encoded proof step places the sibling hash on the left
/// side of the verifier's concatenation order.
#[inline]
#[must_use = "Merkle proof-path decisions must not be discarded"]
pub(crate) const fn proof_step_is_left(node_index: usize) -> bool {
    node_index % 2 == 1
}

/// Return true when the current node has a sibling at this level and therefore
/// emits a proof step instead of being promoted unchanged.
#[inline]
#[must_use = "Merkle proof-path decisions must not be discarded"]
pub(crate) const fn proof_level_has_sibling(node_index: usize, level_len: usize) -> bool {
    proof_sibling_index(node_index) < level_len
}

/// Return the parent index reached after ascending one Merkle level.
#[inline]
#[must_use = "Merkle proof-path decisions must not be discarded"]
pub(crate) const fn proof_parent_index(node_index: usize) -> usize {
    node_index / 2
}

/// Return true when the verifier must hash `sibling || current` for this proof
/// step instead of `current || sibling`.
#[inline]
#[must_use = "Merkle proof-path decisions must not be discarded"]
pub(crate) const fn proof_step_places_sibling_left(step_is_left: bool) -> bool {
    step_is_left
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_sibling_index_even_uses_right_neighbor() {
        assert_eq!(proof_sibling_index(0), 1);
        assert_eq!(proof_sibling_index(2), 3);
    }

    #[test]
    fn test_proof_sibling_index_odd_uses_left_neighbor() {
        assert_eq!(proof_sibling_index(1), 0);
        assert_eq!(proof_sibling_index(3), 2);
    }

    #[test]
    fn test_proof_step_is_left_matches_odd_indices() {
        assert!(!proof_step_is_left(0));
        assert!(proof_step_is_left(1));
        assert!(!proof_step_is_left(2));
        assert!(proof_step_is_left(3));
    }

    #[test]
    fn test_proof_level_has_sibling_rejects_promoted_tail() {
        assert!(!proof_level_has_sibling(2, 3));
    }

    #[test]
    fn test_proof_level_has_sibling_accepts_paired_nodes() {
        assert!(proof_level_has_sibling(0, 2));
        assert!(proof_level_has_sibling(1, 2));
        assert!(proof_level_has_sibling(2, 4));
    }

    #[test]
    fn test_proof_parent_index_halves_node_index() {
        assert_eq!(proof_parent_index(0), 0);
        assert_eq!(proof_parent_index(1), 0);
        assert_eq!(proof_parent_index(5), 2);
    }

    #[test]
    fn test_proof_step_places_sibling_left_is_identity() {
        assert!(!proof_step_places_sibling_left(false));
        assert!(proof_step_places_sibling_left(true));
    }
}
