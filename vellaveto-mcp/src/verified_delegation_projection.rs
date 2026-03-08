// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified projection of deputy delegation state into engine evaluation
//! context.
//!
//! The relay currently only has deputy-validated delegation depth, not the
//! full multi-hop path. It therefore projects active delegation into a
//! synthetic fail-closed call-chain shape whose only trusted semantic is its
//! length.

/// Return the synthetic call-chain length that should be exposed to the engine.
///
/// Active delegation preserves the deputy-reported depth. Direct requests or
/// sessions without an active delegation context project to an empty chain.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn projected_call_chain_len(
    has_active_delegation: bool,
    delegation_depth: u8,
) -> usize {
    if has_active_delegation {
        delegation_depth as usize
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_projected_call_chain_len_is_zero_without_active_delegation() {
        assert_eq!(projected_call_chain_len(false, 0), 0);
        assert_eq!(projected_call_chain_len(false, 3), 0);
    }

    #[test]
    fn test_projected_call_chain_len_preserves_active_depth() {
        assert_eq!(projected_call_chain_len(true, 0), 0);
        assert_eq!(projected_call_chain_len(true, 1), 1);
        assert_eq!(projected_call_chain_len(true, 3), 3);
        assert_eq!(
            projected_call_chain_len(true, u8::MAX),
            usize::from(u8::MAX)
        );
    }
}
