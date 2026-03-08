// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Verified server approval-id validation guards.
//!
//! The HTTP API accepts approval IDs through URL path parameters and the
//! `x-vellaveto-approval-id` header. These values are only accepted when they
//! are non-empty, fit within the server's public contract length cap, and
//! contain no unsafe characters.

/// Maximum length for approval IDs accepted by the HTTP API.
pub const MAX_SERVER_APPROVAL_ID_LEN: usize = 128;

/// Return true when the server-visible approval ID length is valid.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn server_approval_id_length_valid(len: usize) -> bool {
    len > 0 && len <= MAX_SERVER_APPROVAL_ID_LEN
}

/// Return true when the server should accept this approval ID value.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn server_approval_id_value_accepted(
    length_valid: bool,
    contains_unsafe_chars: bool,
) -> bool {
    length_valid && !contains_unsafe_chars
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_approval_id_length_valid_accepts_non_empty_within_cap() {
        assert!(server_approval_id_length_valid(1));
        assert!(server_approval_id_length_valid(MAX_SERVER_APPROVAL_ID_LEN));
    }

    #[test]
    fn test_server_approval_id_length_valid_rejects_empty_or_too_long() {
        assert!(!server_approval_id_length_valid(0));
        assert!(!server_approval_id_length_valid(
            MAX_SERVER_APPROVAL_ID_LEN + 1
        ));
    }

    #[test]
    fn test_server_approval_id_value_accepted_requires_safe_bounded_value() {
        assert!(server_approval_id_value_accepted(true, false));
        assert!(!server_approval_id_value_accepted(false, false));
        assert!(!server_approval_id_value_accepted(true, true));
        assert!(!server_approval_id_value_accepted(false, true));
    }
}
