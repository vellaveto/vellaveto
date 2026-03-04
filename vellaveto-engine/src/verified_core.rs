// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified core verdict computation.
//!
//! This module contains the pure verdict computation logic that is verified
//! by Verus (deductive, all inputs) and tested by Kani (bounded model checking).
//!
//! The key abstraction is [`ResolvedMatch`]: the unverified wrapper code resolves
//! whether each policy matches the action (String operations, glob matching,
//! Unicode normalization, HashMap lookups) and produces a `Vec<ResolvedMatch>`.
//! This module computes the verdict from that Vec using pure logic — no String,
//! no HashMap, no serde, no glob.
//!
//! # Verification Properties (V1-V8)
//!
//! | ID | Property | Meaning |
//! |----|----------|---------|
//! | V1 | Fail-closed empty | Empty input → Deny |
//! | V2 | Fail-closed no match | All `!matched` → Deny |
//! | V3 | Allow requires match | Allow → ∃ matching Allow policy with no override |
//! | V4 | Rule override forces Deny | Path/network/IP override on first match → Deny |
//! | V5 | Totality | Function always terminates |
//! | V6 | Priority ordering | Higher-priority match wins (requires sorted input) |
//! | V7 | Deny-dominance at equal priority | Deny beats Allow at same priority (sorted) |
//! | V8 | Conditional pass-through | Unfired condition → evaluation continues |
//!
//! # Trust Boundary
//!
//! The wrapper (unverified) builds `Vec<ResolvedMatch>` from the action and policies.
//! The core (verified) computes the verdict from that Vec. The trust boundary is:
//! "the wrapper correctly resolves matches; the core correctly computes verdicts."
//!
//! See `docs/TRUSTED_COMPUTING_BASE.md` for the full trust model.
//! See `formal/verus/verified_core.rs` for the Verus-annotated version with specs.

/// The result of the core verdict computation.
///
/// This enum mirrors `Verdict` but without String payloads — the verified core
/// determines the verdict *kind*, and the caller attaches the reason string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictKind {
    /// Action is allowed.
    Allow,
    /// Action is denied.
    Deny,
    /// Action requires human approval.
    RequireApproval,
}

impl VerdictKind {
    /// Returns true if this verdict is Deny.
    #[inline]
    pub fn is_deny(self) -> bool {
        matches!(self, VerdictKind::Deny)
    }

    /// Returns true if this verdict is Allow.
    #[inline]
    pub fn is_allow(self) -> bool {
        matches!(self, VerdictKind::Allow)
    }
}

/// A pre-resolved policy match with all verdict-relevant information.
///
/// The unverified wrapper produces this struct from the action and a compiled
/// policy. The verified core consumes it. No String, HashMap, glob, or serde
/// operations are needed to compute the verdict from this struct.
///
/// # Fields
///
/// - `matched`: Whether the policy's tool/function pattern matched the action.
/// - `is_deny`: Whether the policy type is `Deny`.
/// - `is_conditional`: Whether the policy type is `Conditional`.
/// - `priority`: The policy's priority (higher = evaluated first).
/// - `rule_override_deny`: Whether path/network/IP rules forced a Deny.
/// - `context_deny`: Whether context conditions produced a Deny.
/// - `require_approval`: Whether the policy requires human approval.
/// - `condition_fired`: For Conditional policies, whether any constraint matched.
/// - `condition_verdict`: The verdict from the fired constraint (if any).
/// - `on_no_match_continue`: For Conditional policies, whether to skip to next
///   policy when no constraints fire (vs. implicit Allow).
/// - `all_constraints_skipped`: For Conditional policies, whether every constraint
///   was skipped due to missing parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMatch {
    /// Whether the policy's tool/function pattern matched the action.
    pub matched: bool,
    /// Whether the policy type is `Deny`.
    pub is_deny: bool,
    /// Whether the policy type is `Conditional`.
    pub is_conditional: bool,
    /// Policy priority (higher = evaluated first in sorted order).
    pub priority: u32,
    /// Whether path/network/IP rules forced a Deny on this policy.
    pub rule_override_deny: bool,
    /// Whether context conditions produced a Deny.
    pub context_deny: bool,
    /// Whether the policy requires human approval (Conditional with require_approval).
    pub require_approval: bool,
    /// For Conditional policies: whether any constraint fired.
    pub condition_fired: bool,
    /// For Conditional policies: the verdict from the fired constraint.
    pub condition_verdict: VerdictKind,
    /// For Conditional policies: skip to next policy when no constraint fires.
    pub on_no_match_continue: bool,
    /// For Conditional policies: all constraints were skipped (missing params).
    pub all_constraints_skipped: bool,
}

/// Outcome of verdict computation.
///
/// `Decided(VerdictKind)` means a final verdict was reached.
/// `Continue` means a Conditional policy with `on_no_match="continue"` had
/// no constraints fire, and the evaluation loop should try the next policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictOutcome {
    /// A final verdict was reached.
    Decided(VerdictKind),
    /// No verdict from this policy — continue to the next one.
    Continue,
}

/// Compute the verdict for a single resolved policy match.
///
/// This is the innermost verdict decision function. Given a fully-resolved
/// match, it determines whether the match produces a verdict or should be
/// skipped (Continue).
///
/// # Properties (per-policy)
///
/// - V4: `rule_override_deny == true` → `Decided(Deny)`
/// - V3: `Allow` only when `!is_deny && !rule_override_deny && !context_deny`
/// - V8: Conditional with unfired condition + `on_no_match_continue` → `Continue`
#[inline]
pub fn compute_single_verdict(rm: &ResolvedMatch) -> VerdictOutcome {
    if !rm.matched {
        return VerdictOutcome::Continue;
    }

    // V4: Rule override denials checked first (path/network/IP)
    if rm.rule_override_deny {
        return VerdictOutcome::Decided(VerdictKind::Deny);
    }

    // Context condition denials checked next
    if rm.context_deny {
        return VerdictOutcome::Decided(VerdictKind::Deny);
    }

    // Policy type dispatch
    if rm.is_deny {
        return VerdictOutcome::Decided(VerdictKind::Deny);
    }

    if rm.is_conditional {
        // Require approval takes precedence
        if rm.require_approval {
            return VerdictOutcome::Decided(VerdictKind::RequireApproval);
        }

        // All constraints skipped (missing params) → fail-closed
        if rm.all_constraints_skipped {
            if rm.on_no_match_continue {
                return VerdictOutcome::Continue;
            }
            return VerdictOutcome::Decided(VerdictKind::Deny);
        }

        if rm.condition_fired {
            return VerdictOutcome::Decided(rm.condition_verdict);
        }

        // V8: No constraint fired — continue or implicit Allow
        if rm.on_no_match_continue {
            return VerdictOutcome::Continue;
        }
        return VerdictOutcome::Decided(VerdictKind::Allow);
    }

    // Allow policy — V3
    VerdictOutcome::Decided(VerdictKind::Allow)
}

/// Compute the final verdict from a sequence of resolved policy matches.
///
/// The matches are expected to be in priority order (highest priority first,
/// deny-first at equal priority). This function implements first-match-wins:
/// it returns the first `Decided` verdict, or `Deny` if no policy produces one.
///
/// # Properties (V1-V8)
///
/// - **V1 (S1):** Empty `resolved` → Deny
/// - **V2 (S1):** All `!matched` → Deny
/// - **V3 (S5):** Allow → ∃ matching Allow policy with no override
/// - **V4 (S3/S4):** Rule override on first match → Deny
/// - **V5 (L1):** Always terminates (bounded by `resolved.len()`)
/// - **V6 (S2):** First matching policy in sorted order determines verdict
/// - **V7 (S3):** At equal priority, deny-sorted-first means Deny wins
/// - **V8:** Conditional with unfired condition → skipped to next policy
pub fn compute_verdict(resolved: &[ResolvedMatch]) -> VerdictKind {
    // V1: Empty → Deny
    // V5: Loop bounded by resolved.len()
    for rm in resolved {
        match compute_single_verdict(rm) {
            VerdictOutcome::Decided(kind) => return kind,
            VerdictOutcome::Continue => continue,
        }
    }
    // V2: No match produced a verdict → Deny (fail-closed)
    VerdictKind::Deny
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_policy(priority: u32) -> ResolvedMatch {
        ResolvedMatch {
            matched: true,
            is_deny: false,
            is_conditional: false,
            priority,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: false,
            condition_verdict: VerdictKind::Deny,
            on_no_match_continue: false,
            all_constraints_skipped: false,
        }
    }

    fn deny_policy(priority: u32) -> ResolvedMatch {
        ResolvedMatch {
            matched: true,
            is_deny: true,
            is_conditional: false,
            priority,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: false,
            condition_verdict: VerdictKind::Deny,
            on_no_match_continue: false,
            all_constraints_skipped: false,
        }
    }

    fn unmatched_policy(priority: u32) -> ResolvedMatch {
        ResolvedMatch {
            matched: false,
            is_deny: false,
            is_conditional: false,
            priority,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: false,
            condition_verdict: VerdictKind::Deny,
            on_no_match_continue: false,
            all_constraints_skipped: false,
        }
    }

    fn conditional_continue(priority: u32) -> ResolvedMatch {
        ResolvedMatch {
            matched: true,
            is_deny: false,
            is_conditional: true,
            priority,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: false,
            condition_verdict: VerdictKind::Deny,
            on_no_match_continue: true,
            all_constraints_skipped: false,
        }
    }

    fn conditional_fired_allow(priority: u32) -> ResolvedMatch {
        ResolvedMatch {
            matched: true,
            is_deny: false,
            is_conditional: true,
            priority,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: true,
            condition_verdict: VerdictKind::Allow,
            on_no_match_continue: false,
            all_constraints_skipped: false,
        }
    }

    fn conditional_fired_deny(priority: u32) -> ResolvedMatch {
        ResolvedMatch {
            matched: true,
            is_deny: false,
            is_conditional: true,
            priority,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: true,
            condition_verdict: VerdictKind::Deny,
            on_no_match_continue: false,
            all_constraints_skipped: false,
        }
    }

    // === V1: Empty → Deny ===

    #[test]
    fn test_v1_empty_produces_deny() {
        assert_eq!(compute_verdict(&[]), VerdictKind::Deny);
    }

    // === V2: All unmatched → Deny ===

    #[test]
    fn test_v2_all_unmatched_produces_deny() {
        let resolved = vec![unmatched_policy(100), unmatched_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    // === V3: Allow requires matching Allow policy ===

    #[test]
    fn test_v3_allow_from_allow_policy() {
        let resolved = vec![allow_policy(100)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    #[test]
    fn test_v3_allow_not_from_deny_policy() {
        let resolved = vec![deny_policy(100)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_v3_allow_not_from_rule_override() {
        let mut rm = allow_policy(100);
        rm.rule_override_deny = true;
        assert_eq!(compute_verdict(&[rm]), VerdictKind::Deny);
    }

    #[test]
    fn test_v3_allow_not_from_context_deny() {
        let mut rm = allow_policy(100);
        rm.context_deny = true;
        assert_eq!(compute_verdict(&[rm]), VerdictKind::Deny);
    }

    // === V4: Rule override → Deny ===

    #[test]
    fn test_v4_rule_override_forces_deny() {
        let mut rm = allow_policy(100);
        rm.rule_override_deny = true;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::Deny)
        );
    }

    #[test]
    fn test_v4_rule_override_on_deny_policy() {
        let mut rm = deny_policy(100);
        rm.rule_override_deny = true;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::Deny)
        );
    }

    #[test]
    fn test_v4_rule_override_on_conditional() {
        let mut rm = conditional_fired_allow(100);
        rm.rule_override_deny = true;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::Deny)
        );
    }

    // === V5: Totality (always terminates) ===
    // Implicitly tested by all tests completing.

    // === V6: Priority ordering (first-match-wins in sorted order) ===

    #[test]
    fn test_v6_higher_priority_deny_wins() {
        // Sorted: deny(100) before allow(50)
        let resolved = vec![deny_policy(100), allow_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_v6_higher_priority_allow_wins() {
        // Sorted: allow(100) before deny(50)
        let resolved = vec![allow_policy(100), deny_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    // === V7: Deny-dominance at equal priority ===

    #[test]
    fn test_v7_deny_before_allow_at_equal_priority() {
        // When sorted correctly: deny(100) before allow(100) at same priority
        let resolved = vec![deny_policy(100), allow_policy(100)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    // === V8: Conditional pass-through ===

    #[test]
    fn test_v8_conditional_continue_skips_to_next() {
        assert_eq!(
            compute_single_verdict(&conditional_continue(100)),
            VerdictOutcome::Continue,
        );
    }

    #[test]
    fn test_v8_conditional_continue_then_allow() {
        let resolved = vec![conditional_continue(100), allow_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    #[test]
    fn test_v8_conditional_continue_then_deny() {
        let resolved = vec![conditional_continue(100), deny_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_v8_all_conditional_continue_produces_deny() {
        let resolved = vec![conditional_continue(100), conditional_continue(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    // === Conditional constraint fired ===

    #[test]
    fn test_conditional_fired_allow() {
        let resolved = vec![conditional_fired_allow(100)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    #[test]
    fn test_conditional_fired_deny() {
        let resolved = vec![conditional_fired_deny(100)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    // === Conditional without on_no_match_continue: implicit Allow ===

    #[test]
    fn test_conditional_no_fire_no_continue_implicit_allow() {
        let mut rm = conditional_continue(100);
        rm.on_no_match_continue = false;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::Allow),
        );
    }

    // === Require approval ===

    #[test]
    fn test_require_approval_verdict() {
        let mut rm = conditional_continue(100);
        rm.require_approval = true;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::RequireApproval),
        );
    }

    // === All constraints skipped (fail-closed) ===

    #[test]
    fn test_all_constraints_skipped_continue() {
        let mut rm = conditional_continue(100);
        rm.all_constraints_skipped = true;
        assert_eq!(compute_single_verdict(&rm), VerdictOutcome::Continue,);
    }

    #[test]
    fn test_all_constraints_skipped_no_continue_deny() {
        let mut rm = conditional_continue(100);
        rm.all_constraints_skipped = true;
        rm.on_no_match_continue = false;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::Deny),
        );
    }

    // === Context deny ===

    #[test]
    fn test_context_deny_overrides_allow() {
        let mut rm = allow_policy(100);
        rm.context_deny = true;
        assert_eq!(compute_verdict(&[rm]), VerdictKind::Deny);
    }

    #[test]
    fn test_context_deny_on_conditional_overrides_fired_allow() {
        let mut rm = conditional_fired_allow(100);
        rm.context_deny = true;
        assert_eq!(compute_verdict(&[rm]), VerdictKind::Deny);
    }

    // === Mixed sequences ===

    #[test]
    fn test_mixed_unmatched_then_allow() {
        let resolved = vec![unmatched_policy(200), allow_policy(100)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    #[test]
    fn test_mixed_continue_then_continue_then_deny() {
        let resolved = vec![
            conditional_continue(100),
            conditional_continue(90),
            deny_policy(80),
        ];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_conditional_fired_require_approval() {
        let mut rm = conditional_continue(100);
        rm.condition_fired = true;
        rm.condition_verdict = VerdictKind::RequireApproval;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::RequireApproval),
        );
    }

    #[test]
    fn test_rule_override_before_context_deny() {
        let mut rm = allow_policy(100);
        rm.rule_override_deny = true;
        rm.context_deny = true;
        // Rule override checked first
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::Deny),
        );
    }

    // === Complex multi-policy scenarios ===

    #[test]
    fn test_many_unmatched_then_conditional_fired_allow() {
        let resolved = vec![
            unmatched_policy(200),
            unmatched_policy(150),
            unmatched_policy(100),
            conditional_fired_allow(50),
        ];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    #[test]
    fn test_conditional_chain_with_fired_deny_at_end() {
        let resolved = vec![
            conditional_continue(100),
            conditional_continue(90),
            conditional_continue(80),
            conditional_fired_deny(70),
        ];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_rule_override_on_first_match_skips_later_allow() {
        let mut overridden = allow_policy(100);
        overridden.rule_override_deny = true;
        let resolved = vec![overridden, allow_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_context_deny_on_first_match_skips_later_allow() {
        let mut ctx_deny = allow_policy(100);
        ctx_deny.context_deny = true;
        let resolved = vec![ctx_deny, allow_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_require_approval_in_conditional_chain() {
        let mut approval = conditional_continue(90);
        approval.require_approval = true;
        let resolved = vec![conditional_continue(100), approval];
        assert_eq!(compute_verdict(&resolved), VerdictKind::RequireApproval);
    }

    #[test]
    fn test_mixed_unmatched_continue_deny() {
        let resolved = vec![
            unmatched_policy(200),
            conditional_continue(150),
            unmatched_policy(100),
            deny_policy(50),
        ];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_all_constraints_skipped_in_chain_then_allow() {
        let mut skipped = conditional_continue(100);
        skipped.all_constraints_skipped = true;
        let resolved = vec![skipped, allow_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    #[test]
    fn test_all_constraints_skipped_no_continue_in_chain() {
        let mut skipped = conditional_continue(100);
        skipped.all_constraints_skipped = true;
        skipped.on_no_match_continue = false;
        let resolved = vec![skipped, allow_policy(50)];
        // Fail-closed: all_constraints_skipped + no continue = Deny
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_single_unmatched_produces_deny() {
        let resolved = vec![unmatched_policy(100)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_conditional_implicit_allow_when_no_continue() {
        let mut rm = conditional_continue(100);
        rm.on_no_match_continue = false;
        // No constraint fired, no continue → implicit Allow
        let resolved = vec![rm];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    #[test]
    fn test_large_policy_set_first_match_deny() {
        let mut resolved: Vec<ResolvedMatch> = (0..50).map(|i| unmatched_policy(200 - i)).collect();
        resolved.push(deny_policy(100));
        // Add some more unmatched after
        for i in 0..20 {
            resolved.push(unmatched_policy(50 - i));
        }
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_large_policy_set_all_unmatched() {
        let resolved: Vec<ResolvedMatch> = (0..100).map(|i| unmatched_policy(200 - i)).collect();
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_conditional_fired_deny_verdict_from_constraint() {
        let mut rm = conditional_continue(100);
        rm.condition_fired = true;
        rm.condition_verdict = VerdictKind::Deny;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::Deny),
        );
    }
}
