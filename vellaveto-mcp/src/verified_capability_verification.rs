// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability-token verification precheck boundary.
//!
//! This module extracts the pure fail-closed guards from
//! `capability_token.rs::verify_capability_token()` so they can be mirrored in
//! Verus without pulling Ed25519 or hashing into the proof boundary.

/// Exact decoded Ed25519 public-key length in bytes.
pub(crate) const CAPABILITY_PUBLIC_KEY_LEN: usize = 32;

/// Exact decoded Ed25519 signature length in bytes.
pub(crate) const CAPABILITY_SIGNATURE_LEN: usize = 64;

/// Return true when the current time remains strictly before expiry.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_not_expired(now_before_expires: bool) -> bool {
    now_before_expires
}

/// Return true when `issued_at` does not exceed the allowed future skew.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_issued_at_within_skew(
    issued_at_skew_secs: i64,
    max_issued_at_skew_secs: i64,
) -> bool {
    issued_at_skew_secs <= max_issued_at_skew_secs
}

/// Return true when an expected issuer public key matches the token key.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_expected_public_key_matches(
    expected_key_equals_token_key: bool,
) -> bool {
    expected_key_equals_token_key
}

/// Return true when the decoded issuer public key has the required length.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_public_key_length_valid(public_key_len: usize) -> bool {
    public_key_len == CAPABILITY_PUBLIC_KEY_LEN
}

/// Return true when the decoded signature has the required length.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_signature_length_valid(signature_len: usize) -> bool {
    signature_len == CAPABILITY_SIGNATURE_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_not_expired_rejects_elapsed_window() {
        assert!(capability_not_expired(true));
        assert!(!capability_not_expired(false));
    }

    #[test]
    fn test_capability_issued_at_within_skew_rejects_future_drift() {
        assert!(capability_issued_at_within_skew(30, 60));
        assert!(capability_issued_at_within_skew(60, 60));
        assert!(!capability_issued_at_within_skew(61, 60));
    }

    #[test]
    fn test_capability_expected_public_key_matches_is_identity() {
        assert!(capability_expected_public_key_matches(true));
        assert!(!capability_expected_public_key_matches(false));
    }

    #[test]
    fn test_capability_public_key_length_valid_requires_exact_length() {
        assert!(capability_public_key_length_valid(
            CAPABILITY_PUBLIC_KEY_LEN
        ));
        assert!(!capability_public_key_length_valid(
            CAPABILITY_PUBLIC_KEY_LEN - 1
        ));
        assert!(!capability_public_key_length_valid(
            CAPABILITY_PUBLIC_KEY_LEN + 1
        ));
    }

    #[test]
    fn test_capability_signature_length_valid_requires_exact_length() {
        assert!(capability_signature_length_valid(CAPABILITY_SIGNATURE_LEN));
        assert!(!capability_signature_length_valid(
            CAPABILITY_SIGNATURE_LEN - 1
        ));
        assert!(!capability_signature_length_valid(
            CAPABILITY_SIGNATURE_LEN + 1
        ));
    }
}
