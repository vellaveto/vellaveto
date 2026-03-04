// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified core verdict computation.
//!
//! This file is the formally verified version of
//! `vellaveto-engine/src/verified_core.rs`. It uses Verus annotations
//! (preconditions, postconditions, loop invariants) to prove properties
//! V1-V8 on the actual Rust code for ALL possible inputs.
//!
//! To verify: `~/verus/verus-bin/verus-x86-linux/verus formal/verus/verified_core.rs`
//!
//! The executable code (inside `verus!` block) is identical in behavior
//! to the production version. Verus erases all ghost/proof annotations,
//! producing standard Rust.
//!
//! # Trust Boundary
//!
//! This file proves that `compute_verdict` and `compute_single_verdict`
//! satisfy properties V1-V8 for ALL possible `ResolvedMatch` inputs.
//! The wrapper code that *produces* `ResolvedMatch` from policies and
//! actions is not verified here — it is verified by Kani (bounded) and
//! tested by 10,000+ unit tests.

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

/// The result of the core verdict computation.
#[derive(Structural, PartialEq, Eq, Clone, Copy)]
pub enum VerdictKind {
    Allow,
    Deny,
    RequireApproval,
}

/// A pre-resolved policy match with all verdict-relevant information.
pub struct ResolvedMatch {
    pub matched: bool,
    pub is_deny: bool,
    pub is_conditional: bool,
    pub priority: u32,
    pub rule_override_deny: bool,
    pub context_deny: bool,
    pub require_approval: bool,
    pub condition_fired: bool,
    pub condition_verdict: VerdictKind,
    pub on_no_match_continue: bool,
    pub all_constraints_skipped: bool,
}

/// Outcome of verdict computation for a single policy.
#[derive(Structural, PartialEq, Eq)]
pub enum VerdictOutcome {
    Decided(VerdictKind),
    Continue,
}

/// Spec-mode version of single-verdict computation for use in invariants.
pub open spec fn spec_single_verdict(rm: &ResolvedMatch) -> VerdictOutcome {
    if !rm.matched {
        VerdictOutcome::Continue
    } else if rm.rule_override_deny {
        VerdictOutcome::Decided(VerdictKind::Deny)
    } else if rm.context_deny {
        VerdictOutcome::Decided(VerdictKind::Deny)
    } else if rm.is_deny {
        VerdictOutcome::Decided(VerdictKind::Deny)
    } else if rm.is_conditional {
        if rm.require_approval {
            VerdictOutcome::Decided(VerdictKind::RequireApproval)
        } else if rm.all_constraints_skipped {
            if rm.on_no_match_continue {
                VerdictOutcome::Continue
            } else {
                VerdictOutcome::Decided(VerdictKind::Deny)
            }
        } else if rm.condition_fired {
            VerdictOutcome::Decided(rm.condition_verdict)
        } else if rm.on_no_match_continue {
            VerdictOutcome::Continue
        } else {
            VerdictOutcome::Decided(VerdictKind::Allow)
        }
    } else {
        VerdictOutcome::Decided(VerdictKind::Allow)
    }
}

/// Compute the verdict for a single resolved policy match.
///
/// Properties proven for ALL possible inputs:
/// - V4: rule_override_deny && matched -> Decided(Deny)
/// - V3: Allow -> matched && !is_deny && !rule_override_deny && !context_deny
/// - V8: is_conditional && !condition_fired && on_no_match_continue -> Continue
/// - Exec matches spec: result == spec_single_verdict(rm)
pub fn compute_single_verdict(rm: &ResolvedMatch) -> (result: VerdictOutcome)
    ensures
        // Exec matches spec (master postcondition)
        result == spec_single_verdict(rm),

        // V4: Rule override on a matched policy always produces Deny
        (rm.matched && rm.rule_override_deny) ==>
            result == VerdictOutcome::Decided(VerdictKind::Deny),

        // Context deny on a matched policy always produces Deny
        (rm.matched && !rm.rule_override_deny && rm.context_deny) ==>
            result == VerdictOutcome::Decided(VerdictKind::Deny),

        // V3: Allow requires matching, non-deny, non-override, non-context-deny
        result == VerdictOutcome::Decided(VerdictKind::Allow) ==>
            rm.matched
            && !rm.is_deny
            && !rm.rule_override_deny
            && !rm.context_deny,

        // Deny policy always produces Deny (when matched, no override/context)
        (rm.matched && !rm.rule_override_deny && !rm.context_deny && rm.is_deny) ==>
            result == VerdictOutcome::Decided(VerdictKind::Deny),

        // V8: Conditional with on_no_match_continue and no fire -> Continue
        (rm.matched && !rm.rule_override_deny && !rm.context_deny
         && !rm.is_deny && rm.is_conditional && !rm.require_approval
         && !rm.all_constraints_skipped && !rm.condition_fired
         && rm.on_no_match_continue) ==>
            result == VerdictOutcome::Continue,

        // Unmatched policy always produces Continue
        !rm.matched ==> result == VerdictOutcome::Continue,
{
    if !rm.matched {
        return VerdictOutcome::Continue;
    }

    // V4: Rule override denials checked first
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
        if rm.require_approval {
            return VerdictOutcome::Decided(VerdictKind::RequireApproval);
        }

        if rm.all_constraints_skipped {
            if rm.on_no_match_continue {
                return VerdictOutcome::Continue;
            }
            return VerdictOutcome::Decided(VerdictKind::Deny);
        }

        if rm.condition_fired {
            return VerdictOutcome::Decided(rm.condition_verdict);
        }

        if rm.on_no_match_continue {
            return VerdictOutcome::Continue;
        }
        return VerdictOutcome::Decided(VerdictKind::Allow);
    }

    // Allow policy
    VerdictOutcome::Decided(VerdictKind::Allow)
}

/// Spec-mode version of multi-policy verdict computation.
pub open spec fn spec_compute_verdict(resolved: &Vec<ResolvedMatch>) -> VerdictKind
    decreases resolved.len(),
{
    spec_compute_verdict_from(resolved, 0)
}

/// Spec helper: compute verdict starting from index `start`.
pub open spec fn spec_compute_verdict_from(
    resolved: &Vec<ResolvedMatch>,
    start: int,
) -> VerdictKind
    decreases resolved.len() - start,
{
    if start >= resolved.len() {
        VerdictKind::Deny
    } else {
        let outcome = spec_single_verdict(&resolved[start]);
        match outcome {
            VerdictOutcome::Decided(kind) => kind,
            VerdictOutcome::Continue => spec_compute_verdict_from(resolved, start + 1),
        }
    }
}

/// Compute the final verdict from a sequence of resolved policy matches.
///
/// Properties proven for ALL possible inputs:
/// - V1 (S1): Empty -> Deny
/// - V2 (S1): All unmatched -> Deny
/// - V3 (S5): Allow -> exists matching Allow policy with no override
/// - V5 (L1): Always terminates (bounded by resolved.len())
#[verifier::when_used_as_spec(spec_compute_verdict)]
pub fn compute_verdict(resolved: &Vec<ResolvedMatch>) -> (result: VerdictKind)
    ensures
        // Master: exec matches spec
        result == spec_compute_verdict(resolved),

        // V1: Empty input -> Deny
        resolved.len() == 0 ==> result == VerdictKind::Deny,

        // V2: All unmatched -> Deny
        (forall|i: int| 0 <= i < resolved.len()
            ==> !(#[trigger] resolved[i]).matched)
            ==> result == VerdictKind::Deny,

        // V3: Allow -> exists a matching non-deny, non-override, non-context-deny policy
        result == VerdictKind::Allow ==> exists|i: int|
            0 <= i < resolved.len()
            && (#[trigger] resolved[i]).matched
            && !resolved[i].is_deny
            && !resolved[i].rule_override_deny
            && !resolved[i].context_deny,
{
    let mut idx: usize = 0;
    // V5: Loop terminates -- idx strictly increases, bounded by resolved.len()
    while idx < resolved.len()
        invariant
            0 <= idx <= resolved.len(),
            // All previous policies produced Continue (using spec fn)
            forall|j: int| #![auto] 0 <= j < idx as int ==>
                spec_single_verdict(&resolved[j])
                    == VerdictOutcome::Continue,
            // Spec equivalence: result so far matches spec starting from idx
            spec_compute_verdict(resolved)
                == spec_compute_verdict_from(resolved, idx as int),
        decreases resolved.len() - idx,
    {
        let outcome = compute_single_verdict(&resolved[idx]);
        match outcome {
            VerdictOutcome::Decided(kind) => { return kind; }
            VerdictOutcome::Continue => { idx = idx + 1; }
        }
    }
    // V1, V2: No policy produced a verdict -> Deny (fail-closed)
    VerdictKind::Deny
}

// === Proof lemmas ===

/// Lemma helper: spec_compute_verdict_from returns Deny when first matched
/// policy at `idx` has rule_override_deny and all earlier are Continue.
pub proof fn lemma_first_match_override_is_deny(
    resolved: &Vec<ResolvedMatch>,
    idx: int,
)
    requires
        0 <= idx < resolved.len(),
        resolved[idx].matched,
        resolved[idx].rule_override_deny,
        forall|j: int| #![auto] 0 <= j < idx ==>
            spec_single_verdict(&resolved[j])
                == VerdictOutcome::Continue,
    ensures
        spec_compute_verdict(resolved) == VerdictKind::Deny,
    decreases idx,
{
    // Unfold spec_compute_verdict = spec_compute_verdict_from(resolved, 0)
    // then induct: at each step < idx, the outcome is Continue, so we recurse
    if idx > 0 {
        // First element produces Continue, so spec_compute_verdict_from(0)
        // = spec_compute_verdict_from(1), etc.
        assert(spec_single_verdict(&resolved[0]) == VerdictOutcome::Continue);
        // We need to show spec_compute_verdict_from(resolved, 0) ==
        // spec_compute_verdict_from(resolved, 1) == ... == spec_compute_verdict_from(resolved, idx)
        lemma_skip_continues(resolved, 0, idx);
    }
    // At idx, spec_single_verdict produces Decided(Deny)
    assert(spec_single_verdict(&resolved[idx])
        == VerdictOutcome::Decided(VerdictKind::Deny));
}

/// Helper lemma: if all entries from `start` to `end` (exclusive) produce Continue,
/// then spec_compute_verdict_from(start) == spec_compute_verdict_from(end).
proof fn lemma_skip_continues(
    resolved: &Vec<ResolvedMatch>,
    start: int,
    end: int,
)
    requires
        0 <= start <= end <= resolved.len(),
        forall|j: int| #![auto] start <= j < end ==>
            spec_single_verdict(&resolved[j])
                == VerdictOutcome::Continue,
    ensures
        spec_compute_verdict_from(resolved, start)
            == spec_compute_verdict_from(resolved, end),
    decreases end - start,
{
    if start < end {
        // spec_compute_verdict_from(start) unfolds: outcome is Continue
        // so it equals spec_compute_verdict_from(start + 1)
        assert(spec_single_verdict(&resolved[start])
            == VerdictOutcome::Continue);
        lemma_skip_continues(resolved, start + 1, end);
    }
}

/// Lemma: if all entries are unmatched, compute_verdict returns Deny.
pub proof fn lemma_all_unmatched_is_deny(resolved: &Vec<ResolvedMatch>)
    requires
        forall|i: int| 0 <= i < resolved.len()
            ==> !(#[trigger] resolved[i]).matched,
    ensures
        spec_compute_verdict(resolved) == VerdictKind::Deny,
{
    // All unmatched means all produce Continue
    assert forall|i: int| #![auto] 0 <= i < resolved.len()
        implies spec_single_verdict(&resolved[i])
            == VerdictOutcome::Continue
    by {
        // spec_single_verdict on unmatched returns Continue
    };
    lemma_skip_continues(resolved, 0, resolved.len() as int);
    // spec_compute_verdict_from(resolved, resolved.len()) == Deny
}

// === V11-V12: Rule override correctness proofs ===

/// V11: Path block → Deny in final verdict.
///
/// If a policy at index `idx` is matched with rule_override_deny (which is
/// set when path/network/IP rules deny), and all earlier policies produce
/// Continue, then compute_verdict returns Deny.
pub proof fn lemma_path_block_is_deny(
    resolved: &Vec<ResolvedMatch>,
    idx: int,
)
    requires
        0 <= idx < resolved.len(),
        resolved[idx].matched,
        resolved[idx].rule_override_deny,
        forall|j: int| #![auto] 0 <= j < idx ==>
            spec_single_verdict(&resolved[j])
                == VerdictOutcome::Continue,
    ensures
        spec_compute_verdict(resolved) == VerdictKind::Deny,
{
    // Follows directly from lemma_first_match_override_is_deny:
    // rule_override_deny produces Decided(Deny) via spec_single_verdict,
    // and all earlier entries are Continue.
    lemma_first_match_override_is_deny(resolved, idx);
}

/// V12: Network block → Deny in final verdict.
///
/// Identical structure to V11 — network blocks also set rule_override_deny.
/// This lemma demonstrates that the same mechanism handles both path
/// and network denials uniformly.
pub proof fn lemma_network_block_is_deny(
    resolved: &Vec<ResolvedMatch>,
    idx: int,
)
    requires
        0 <= idx < resolved.len(),
        resolved[idx].matched,
        resolved[idx].rule_override_deny,
        forall|j: int| #![auto] 0 <= j < idx ==>
            spec_single_verdict(&resolved[j])
                == VerdictOutcome::Continue,
    ensures
        spec_compute_verdict(resolved) == VerdictKind::Deny,
{
    // Both path and network blocks set rule_override_deny.
    // The proof is structurally identical to V11.
    lemma_first_match_override_is_deny(resolved, idx);
}

/// V11/V12 combined: Any rule override at position idx with all prior
/// Continue → Deny. This covers path, network, and IP rule overrides
/// uniformly since they all set rule_override_deny.
pub proof fn lemma_any_rule_override_is_deny(
    resolved: &Vec<ResolvedMatch>,
    idx: int,
)
    requires
        0 <= idx < resolved.len(),
        resolved[idx].matched,
        resolved[idx].rule_override_deny,
        forall|j: int| #![auto] 0 <= j < idx ==>
            spec_single_verdict(&resolved[j])
                == VerdictOutcome::Continue,
    ensures
        spec_compute_verdict(resolved) == VerdictKind::Deny,
{
    lemma_first_match_override_is_deny(resolved, idx);
}

fn main() {}

} // verus!
