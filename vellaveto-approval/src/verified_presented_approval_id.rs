// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified presented-approval-id validation guards.
//!
//! JSON-RPC transport surfaces may present an approval identifier through
//! `_meta.approval_id`. The value is only accepted when it fits within the
//! transport-specific length cap and contains no dangerous characters.

/// Maximum length accepted for a presented approval ID in transport `_meta`.
pub const MAX_PRESENTED_APPROVAL_ID_LEN: usize = 256;

/// Return true when the presented approval ID length fits within the cap.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn presented_approval_id_length_valid(len: usize) -> bool {
    len <= MAX_PRESENTED_APPROVAL_ID_LEN
}

/// Return true when a presented approval ID should be accepted.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn presented_approval_id_value_accepted(
    length_valid: bool,
    contains_dangerous_chars: bool,
) -> bool {
    length_valid && !contains_dangerous_chars
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_presented_approval_id_length_valid_accepts_within_cap() {
        assert!(presented_approval_id_length_valid(0));
        assert!(presented_approval_id_length_valid(1));
        assert!(presented_approval_id_length_valid(
            MAX_PRESENTED_APPROVAL_ID_LEN
        ));
    }

    #[test]
    fn test_presented_approval_id_length_valid_rejects_above_cap() {
        assert!(!presented_approval_id_length_valid(
            MAX_PRESENTED_APPROVAL_ID_LEN + 1
        ));
    }

    #[test]
    fn test_presented_approval_id_value_accepted_requires_safe_bounded_value() {
        assert!(presented_approval_id_value_accepted(true, false));
        assert!(!presented_approval_id_value_accepted(false, false));
        assert!(!presented_approval_id_value_accepted(true, true));
        assert!(!presented_approval_id_value_accepted(false, true));
    }
}
