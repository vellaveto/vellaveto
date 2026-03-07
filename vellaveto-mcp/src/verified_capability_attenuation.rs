// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability attenuation arithmetic kernel.
//!
//! This module extracts the delegation depth decrement and expiry clamp from
//! `capability_token.rs` so they can be proved in Verus without pulling chrono,
//! UUID generation, signing, or string normalization into the proof boundary.

/// Return the child token's remaining delegation depth, or `None` if the
/// parent can no longer delegate.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn attenuated_remaining_depth(parent_remaining_depth: u8) -> Option<u8> {
    if parent_remaining_depth == 0 {
        None
    } else {
        Some(parent_remaining_depth - 1)
    }
}

/// Return the child token's expiry time in Unix seconds.
///
/// The child expiry is the earlier of the parent's expiry and the requested
/// `now + ttl_secs` window. Returns `None` if the parent is already expired,
/// the requested TTL exceeds policy, or the requested expiry overflows `u64`.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) fn attenuated_expiry_epoch(
    parent_expires_at_epoch: u64,
    now_epoch: u64,
    ttl_secs: u64,
    max_ttl_secs: u64,
) -> Option<u64> {
    if ttl_secs > max_ttl_secs || now_epoch >= parent_expires_at_epoch {
        return None;
    }

    let requested_expires = now_epoch.checked_add(ttl_secs)?;
    Some(requested_expires.min(parent_expires_at_epoch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attenuated_remaining_depth_decrements() {
        assert_eq!(attenuated_remaining_depth(0), None);
        assert_eq!(attenuated_remaining_depth(1), Some(0));
        assert_eq!(attenuated_remaining_depth(5), Some(4));
    }

    #[test]
    fn test_attenuated_expiry_epoch_clamps_to_parent() {
        assert_eq!(
            attenuated_expiry_epoch(1_000, 100, 950, 10_000),
            Some(1_000)
        );
    }

    #[test]
    fn test_attenuated_expiry_epoch_uses_requested_window() {
        assert_eq!(attenuated_expiry_epoch(1_000, 100, 200, 10_000), Some(300));
    }

    #[test]
    fn test_attenuated_expiry_epoch_rejects_expired_parent() {
        assert_eq!(attenuated_expiry_epoch(100, 100, 1, 10_000), None);
        assert_eq!(attenuated_expiry_epoch(100, 101, 1, 10_000), None);
    }

    #[test]
    fn test_attenuated_expiry_epoch_rejects_excessive_ttl() {
        assert_eq!(attenuated_expiry_epoch(1_000, 100, 401, 400), None);
    }

    #[test]
    fn test_attenuated_expiry_epoch_rejects_overflow() {
        assert_eq!(
            attenuated_expiry_epoch(u64::MAX, u64::MAX - 5, 10, 20),
            None
        );
    }
}
