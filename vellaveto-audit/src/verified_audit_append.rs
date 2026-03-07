// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified audit append/recovery counter kernel.
//!
//! This module extracts the pure counter transitions that govern audit append
//! state across normal writes, rotation resets, and restart recovery.

/// Return the per-file entry count immediately after a rotation reset.
#[inline]
#[must_use = "audit append state updates must not be discarded"]
pub(crate) const fn entry_count_after_rotation() -> u64 {
    0
}

/// Return the sequence value assigned to the entry being written.
#[inline]
#[must_use = "audit append state updates must not be discarded"]
pub(crate) const fn assigned_sequence(global_sequence: u64) -> u64 {
    global_sequence
}

/// Return the per-file entry count after one successful append.
#[inline]
#[must_use = "audit append state updates must not be discarded"]
pub(crate) const fn next_entry_count(current_entry_count: u64) -> u64 {
    current_entry_count.saturating_add(1)
}

/// Return the global sequence counter after one successful append.
#[inline]
#[must_use = "audit append state updates must not be discarded"]
pub(crate) const fn next_global_sequence(current_global_sequence: u64) -> u64 {
    current_global_sequence.saturating_add(1)
}

/// Return the next global sequence value after recovering the highest observed
/// sequence from disk.
#[inline]
#[must_use = "audit append state updates must not be discarded"]
pub(crate) const fn next_sequence_after_recovery(max_observed_sequence: u64) -> u64 {
    max_observed_sequence.saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_count_after_rotation_resets_to_zero() {
        assert_eq!(entry_count_after_rotation(), 0);
    }

    #[test]
    fn test_assigned_sequence_is_identity() {
        assert_eq!(assigned_sequence(7), 7);
    }

    #[test]
    fn test_next_entry_count_increments_when_not_saturated() {
        assert_eq!(next_entry_count(7), 8);
    }

    #[test]
    fn test_next_entry_count_saturates_at_u64_max() {
        assert_eq!(next_entry_count(u64::MAX), u64::MAX);
    }

    #[test]
    fn test_next_global_sequence_increments_when_not_saturated() {
        assert_eq!(next_global_sequence(7), 8);
    }

    #[test]
    fn test_next_global_sequence_saturates_at_u64_max() {
        assert_eq!(next_global_sequence(u64::MAX), u64::MAX);
    }

    #[test]
    fn test_next_sequence_after_recovery_increments_when_not_saturated() {
        assert_eq!(next_sequence_after_recovery(7), 8);
    }

    #[test]
    fn test_next_sequence_after_recovery_saturates_at_u64_max() {
        assert_eq!(next_sequence_after_recovery(u64::MAX), u64::MAX);
    }
}
