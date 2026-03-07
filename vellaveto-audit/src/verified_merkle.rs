// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified Merkle fail-closed guard kernel.
//!
//! This module extracts the pure capacity and proof-shape guards from
//! `merkle.rs`. It does not verify cryptographic collision resistance or the
//! hash-computation internals; it formalizes the control-flow boundary that
//! decides when Merkle append / initialization / proof verification must reject
//! inputs.

/// Maximum allowed proof depth.
///
/// A Merkle tree with more than `2^64` leaves is physically unrealistic, so a
/// proof with more siblings than this is treated as malformed.
pub(crate) const MAX_PROOF_SIBLINGS: usize = 64;

/// Return true when a new leaf may be appended without exceeding the maximum
/// leaf count.
#[inline]
#[must_use = "Merkle capacity decisions must not be discarded"]
pub(crate) const fn append_allowed(leaf_count: u64, max_leaf_count: u64) -> bool {
    leaf_count < max_leaf_count
}

/// Return true when a persisted leaf file / replayed state contains at most the
/// configured maximum number of leaves.
#[inline]
#[must_use = "Merkle initialization decisions must not be discarded"]
pub(crate) const fn stored_leaf_count_valid(leaf_count: u64, max_leaf_count: u64) -> bool {
    leaf_count <= max_leaf_count
}

/// Return true when the proof tree size is non-zero.
#[inline]
#[must_use = "Merkle proof validation decisions must not be discarded"]
pub(crate) const fn proof_tree_size_valid(tree_size: u64) -> bool {
    tree_size > 0
}

/// Return true when the proof leaf index lies within the claimed tree size.
#[inline]
#[must_use = "Merkle proof validation decisions must not be discarded"]
pub(crate) const fn proof_leaf_index_valid(leaf_index: u64, tree_size: u64) -> bool {
    leaf_index < tree_size
}

/// Return true when the proof sibling count stays within the configured bound.
#[inline]
#[must_use = "Merkle proof validation decisions must not be discarded"]
pub(crate) const fn proof_sibling_count_valid(sibling_count: usize) -> bool {
    sibling_count <= MAX_PROOF_SIBLINGS
}

/// Return true when a decoded sibling hash has the expected SHA-256 byte length.
#[inline]
#[must_use = "Merkle proof validation decisions must not be discarded"]
pub(crate) const fn sibling_hash_len_valid(sibling_len: usize) -> bool {
    sibling_len == 32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_allowed_rejects_at_limit() {
        assert!(!append_allowed(2, 2));
    }

    #[test]
    fn test_append_allowed_accepts_below_limit() {
        assert!(append_allowed(1, 2));
    }

    #[test]
    fn test_stored_leaf_count_valid_accepts_equal_limit() {
        assert!(stored_leaf_count_valid(2, 2));
    }

    #[test]
    fn test_stored_leaf_count_valid_rejects_over_limit() {
        assert!(!stored_leaf_count_valid(3, 2));
    }

    #[test]
    fn test_proof_tree_size_valid_rejects_zero() {
        assert!(!proof_tree_size_valid(0));
    }

    #[test]
    fn test_proof_leaf_index_valid_rejects_out_of_range() {
        assert!(!proof_leaf_index_valid(5, 3));
    }

    #[test]
    fn test_proof_sibling_count_valid_rejects_too_many_siblings() {
        assert!(!proof_sibling_count_valid(MAX_PROOF_SIBLINGS + 1));
    }

    #[test]
    fn test_sibling_hash_len_valid_requires_32_bytes() {
        assert!(sibling_hash_len_valid(32));
        assert!(!sibling_hash_len_valid(31));
        assert!(!sibling_hash_len_valid(33));
    }
}
