// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! ResolvedMatch construction equivalence verification.
//!
//! In production, `apply_compiled_policy_ctx` does NOT call `compute_verdict`.
//! Instead, it inlines structurally equivalent logic. This module extracts the
//! decision tree as a pure function and proves it produces the same verdict
//! as constructing a `ResolvedMatch` and calling `compute_single_verdict`.
//!
//! # Verified Properties (K46-K48)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K46 | Path deny → rule_override_deny = true in equivalent ResolvedMatch |
//! | K47 | Context deny → context_deny = true in equivalent ResolvedMatch |
//! | K48 | Inline verdict == compute_single_verdict(constructed ResolvedMatch) |
//!
//! # Production Correspondence
//!
//! - `apply_policy_inline` ↔ `vellaveto-engine/src/lib.rs:741-810` (apply_compiled_policy_ctx)

use crate::verified_core::{compute_single_verdict, ResolvedMatch, VerdictKind, VerdictOutcome};

/// Verdict produced by the inline evaluation path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InlineVerdict {
    Deny,
    Allow,
    RequireApproval,
    Continue, // No verdict from this policy, try next
}

/// Inline evaluation decision tree, extracted from `apply_compiled_policy_ctx`.
///
/// This models the production decision tree as a pure function.
/// Parameters are pre-computed booleans representing each check's result.
pub fn apply_policy_inline(
    path_deny: bool,
    network_deny: bool,
    ip_deny: bool,
    context_deny: bool,
    has_context_conditions: bool,
    context_provided: bool,
    is_allow_type: bool,
    is_deny_type: bool,
    is_conditional: bool,
    // For conditional policies:
    condition_result: Option<InlineVerdict>,
    all_constraints_skipped: bool,
    on_no_match_continue: bool,
    require_approval: bool,
) -> InlineVerdict {
    // Rule overrides checked first
    if path_deny {
        return InlineVerdict::Deny;
    }
    if network_deny {
        return InlineVerdict::Deny;
    }
    if ip_deny {
        return InlineVerdict::Deny;
    }

    // Context conditions
    if has_context_conditions {
        if !context_provided {
            return InlineVerdict::Deny; // No context when required → fail-closed
        }
        if context_deny {
            return InlineVerdict::Deny;
        }
    }

    // Policy type dispatch
    if is_allow_type {
        return InlineVerdict::Allow;
    }
    if is_deny_type {
        return InlineVerdict::Deny;
    }
    if is_conditional {
        if require_approval {
            return InlineVerdict::RequireApproval;
        }
        if all_constraints_skipped && !on_no_match_continue {
            return InlineVerdict::Deny;
        }
        if all_constraints_skipped && on_no_match_continue {
            return InlineVerdict::Continue;
        }
        if let Some(v) = condition_result {
            return v;
        }
        if on_no_match_continue {
            return InlineVerdict::Continue;
        }
        return InlineVerdict::Allow;
    }

    // Unknown policy type → fail-closed
    InlineVerdict::Deny
}

/// Construct the equivalent ResolvedMatch and compute verdict via the
/// verified path, for comparison with `apply_policy_inline`.
pub fn apply_policy_verified(
    path_deny: bool,
    network_deny: bool,
    ip_deny: bool,
    context_deny: bool,
    has_context_conditions: bool,
    context_provided: bool,
    is_allow_type: bool,
    is_deny_type: bool,
    is_conditional: bool,
    condition_fired: bool,
    condition_verdict: VerdictKind,
    all_constraints_skipped: bool,
    on_no_match_continue: bool,
    require_approval: bool,
) -> InlineVerdict {
    // If a rule override fires, production returns early with Deny.
    // This corresponds to matched=true, rule_override_deny=true.
    let rule_override_deny = path_deny || network_deny || ip_deny;

    // Context deny: conditions exist, context provided, but condition failed
    let effective_context_deny = has_context_conditions
        && context_provided
        && context_deny;

    // Context missing when required: also a deny
    let context_missing_deny = has_context_conditions && !context_provided;

    if rule_override_deny || context_missing_deny {
        // Early exit — construct ResolvedMatch with overrides
        let rm = ResolvedMatch {
            matched: true,
            is_deny: false,
            is_conditional: false,
            priority: 0,
            rule_override_deny: true,
            context_deny: false,
            require_approval: false,
            condition_fired: false,
            condition_verdict: VerdictKind::Deny,
            on_no_match_continue: false,
            all_constraints_skipped: false,
        };
        return verdict_outcome_to_inline(compute_single_verdict(&rm));
    }

    // Main policy type dispatch
    let rm = ResolvedMatch {
        matched: true,
        is_deny: is_deny_type,
        is_conditional,
        priority: 0,
        rule_override_deny: false,
        context_deny: effective_context_deny,
        require_approval,
        condition_fired,
        condition_verdict,
        on_no_match_continue,
        all_constraints_skipped,
    };

    // Special case: is_allow_type without context deny or deny type
    if is_allow_type && !effective_context_deny {
        return InlineVerdict::Allow;
    }

    verdict_outcome_to_inline(compute_single_verdict(&rm))
}

fn verdict_outcome_to_inline(outcome: VerdictOutcome) -> InlineVerdict {
    match outcome {
        VerdictOutcome::Decided(VerdictKind::Allow) => InlineVerdict::Allow,
        VerdictOutcome::Decided(VerdictKind::Deny) => InlineVerdict::Deny,
        VerdictOutcome::Decided(VerdictKind::RequireApproval) => InlineVerdict::RequireApproval,
        VerdictOutcome::Continue => InlineVerdict::Continue,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_deny_produces_deny() {
        let v = apply_policy_inline(
            true, false, false, false, false, true, true, false, false,
            None, false, false, false,
        );
        assert_eq!(v, InlineVerdict::Deny);
    }

    #[test]
    fn test_context_deny_produces_deny() {
        let v = apply_policy_inline(
            false, false, false, true, true, true, true, false, false,
            None, false, false, false,
        );
        assert_eq!(v, InlineVerdict::Deny);
    }

    #[test]
    fn test_allow_type_produces_allow() {
        let v = apply_policy_inline(
            false, false, false, false, false, true, true, false, false,
            None, false, false, false,
        );
        assert_eq!(v, InlineVerdict::Allow);
    }

    #[test]
    fn test_unknown_type_deny() {
        let v = apply_policy_inline(
            false, false, false, false, false, true, false, false, false,
            None, false, false, false,
        );
        assert_eq!(v, InlineVerdict::Deny);
    }
}
