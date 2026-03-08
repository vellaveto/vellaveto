// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified approval-scope binding guards.
//!
//! Approvals may optionally be bound to a `session_id` and an
//! `action_fingerprint`. When a binding is present, any future use of that
//! approval must present the same bound value. Missing or mismatched bound
//! values fail closed.

/// Return true when a request satisfies the approval's session binding.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn approval_session_binding_satisfied(
    approval_has_session_binding: bool,
    request_has_session: bool,
    request_matches_bound_session: bool,
) -> bool {
    !approval_has_session_binding || (request_has_session && request_matches_bound_session)
}

/// Return true when a request satisfies the approval's action-fingerprint binding.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn approval_fingerprint_binding_satisfied(
    approval_has_action_fingerprint_binding: bool,
    request_has_action_fingerprint: bool,
    request_matches_bound_fingerprint: bool,
) -> bool {
    !approval_has_action_fingerprint_binding
        || (request_has_action_fingerprint && request_matches_bound_fingerprint)
}

/// Return true when a request satisfies all approval scope bindings.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn approval_scope_binding_satisfied(
    approval_has_session_binding: bool,
    request_has_session: bool,
    request_matches_bound_session: bool,
    approval_has_action_fingerprint_binding: bool,
    request_has_action_fingerprint: bool,
    request_matches_bound_fingerprint: bool,
) -> bool {
    approval_session_binding_satisfied(
        approval_has_session_binding,
        request_has_session,
        request_matches_bound_session,
    ) && approval_fingerprint_binding_satisfied(
        approval_has_action_fingerprint_binding,
        request_has_action_fingerprint,
        request_matches_bound_fingerprint,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unbound_session_binding_always_succeeds() {
        assert!(approval_session_binding_satisfied(false, false, false));
        assert!(approval_session_binding_satisfied(false, true, false));
        assert!(approval_session_binding_satisfied(false, true, true));
    }

    #[test]
    fn test_bound_session_binding_requires_present_match() {
        assert!(!approval_session_binding_satisfied(true, false, false));
        assert!(!approval_session_binding_satisfied(true, true, false));
        assert!(approval_session_binding_satisfied(true, true, true));
    }

    #[test]
    fn test_unbound_fingerprint_binding_always_succeeds() {
        assert!(approval_fingerprint_binding_satisfied(false, false, false));
        assert!(approval_fingerprint_binding_satisfied(false, true, false));
        assert!(approval_fingerprint_binding_satisfied(false, true, true));
    }

    #[test]
    fn test_bound_fingerprint_binding_requires_present_match() {
        assert!(!approval_fingerprint_binding_satisfied(true, false, false));
        assert!(!approval_fingerprint_binding_satisfied(true, true, false));
        assert!(approval_fingerprint_binding_satisfied(true, true, true));
    }

    #[test]
    fn test_combined_scope_binding_requires_all_bound_dimensions() {
        assert!(approval_scope_binding_satisfied(
            false, false, false, false, false, false
        ));
        assert!(approval_scope_binding_satisfied(
            true, true, true, true, true, true
        ));
        assert!(!approval_scope_binding_satisfied(
            true, false, false, false, false, false
        ));
        assert!(!approval_scope_binding_satisfied(
            false, false, false, true, false, false
        ));
        assert!(!approval_scope_binding_satisfied(
            true, true, true, true, true, false
        ));
    }
}
