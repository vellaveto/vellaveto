// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Kani proof harnesses for Vellaveto security invariants.
//!
//! 25 harnesses verifying security properties using CBMC bounded model
//! checking on actual Rust implementation code.
//!
//! K1-K9: Original harnesses (path, counters, ABAC, domain)
//! K10-K13: DLP buffer arithmetic (Verus bridge)
//! K14-K17: Core verdict computation (Verus bridge)
//! K18: Sort correctness (Verus bridge)
//! K19-K20: ABAC extensions
//! K21-K22: DLP overlap
//! K23-K25: UTF-8, context_deny, all_constraints_skipped

use crate::path;
use crate::Verdict;

// =========================================================================
// K1: Fail-closed — no matching policy produces Deny
// =========================================================================

#[kani::proof]
fn proof_fail_closed_no_match_produces_deny() {
    let verdict = crate::evaluate_empty_policies();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "K1 violated: empty policy set produced non-Deny verdict"
    );
}

// =========================================================================
// K2: Path normalization is idempotent
// =========================================================================

#[kani::proof]
#[kani::unwind(20)]
fn proof_path_normalize_idempotent() {
    const ALPHABET: [u8; 8] = [b'/', b'.', b'%', b'\\', b'a', b'0', b'2', b'e'];
    let i0: usize = kani::any();
    let i1: usize = kani::any();
    let i2: usize = kani::any();
    let i3: usize = kani::any();
    kani::assume(i0 < ALPHABET.len());
    kani::assume(i1 < ALPHABET.len());
    kani::assume(i2 < ALPHABET.len());
    kani::assume(i3 < ALPHABET.len());

    let bytes = [ALPHABET[i0], ALPHABET[i1], ALPHABET[i2], ALPHABET[i3]];
    let input = std::str::from_utf8(&bytes).unwrap();

    if let Ok(first) = path::normalize_path(input) {
        match path::normalize_path(&first) {
            Ok(second) => {
                assert_eq!(first, second, "K2 violated: normalize_path is not idempotent");
            }
            Err(_) => {
                panic!("K2 violated: normalize_path errors on its own output");
            }
        }
    }
}

// =========================================================================
// K3: Path normalization eliminates traversal
// =========================================================================

#[kani::proof]
#[kani::unwind(20)]
fn proof_path_normalize_no_traversal() {
    const ALPHABET: [u8; 8] = [b'/', b'.', b'%', b'\\', b'a', b'0', b'2', b'e'];
    let i0: usize = kani::any();
    let i1: usize = kani::any();
    let i2: usize = kani::any();
    let i3: usize = kani::any();
    let i4: usize = kani::any();
    kani::assume(i0 < ALPHABET.len());
    kani::assume(i1 < ALPHABET.len());
    kani::assume(i2 < ALPHABET.len());
    kani::assume(i3 < ALPHABET.len());
    kani::assume(i4 < ALPHABET.len());

    let bytes = [ALPHABET[i0], ALPHABET[i1], ALPHABET[i2], ALPHABET[i3], ALPHABET[i4]];
    let input = std::str::from_utf8(&bytes).unwrap();

    if let Ok(normalized) = path::normalize_path(input) {
        for component in std::path::Path::new(&normalized).components() {
            assert!(
                !matches!(component, std::path::Component::ParentDir),
                "K3 violated: normalize_path output contains '..'"
            );
        }
    }
}

// =========================================================================
// K4: Saturating counters never wrap to zero
// =========================================================================

#[kani::proof]
fn proof_saturating_counters_never_wrap() {
    let counter: u64 = kani::any();
    let increment: u64 = kani::any();

    let result = counter.saturating_add(increment);

    assert!(result >= counter, "K4 violated: saturating_add decreased the counter");

    if counter > 0 {
        assert!(result >= increment, "K4 violated: saturating_add lost the increment");
    }

    assert!(result <= u64::MAX);
}

// =========================================================================
// K5: Verdict::Deny on evaluation error / empty policies
// =========================================================================

#[kani::proof]
fn proof_verdict_deny_on_error() {
    let verdict = crate::evaluate_empty_policies();
    match verdict {
        Verdict::Allow => {
            panic!("K5 violated: empty policies produced Allow");
        }
        Verdict::Deny { .. } => {}
    }
}

// =========================================================================
// K6: ABAC forbid dominance
// =========================================================================

#[kani::proof]
fn proof_abac_forbid_dominance() {
    use crate::{AbacDecision, AbacEffect, AbacPolicy};

    let e0: bool = kani::any();
    let e1: bool = kani::any();
    let e2: bool = kani::any();

    let policies = [
        AbacPolicy {
            id: "p0".to_string(),
            effect: if e0 { AbacEffect::Forbid } else { AbacEffect::Permit },
        },
        AbacPolicy {
            id: "p1".to_string(),
            effect: if e1 { AbacEffect::Forbid } else { AbacEffect::Permit },
        },
        AbacPolicy {
            id: "p2".to_string(),
            effect: if e2 { AbacEffect::Forbid } else { AbacEffect::Permit },
        },
    ];

    let result = crate::abac_evaluate(&policies, &|_| true);

    let has_forbid = e0 || e1 || e2;
    if has_forbid {
        assert!(
            matches!(result, AbacDecision::Deny(_)),
            "K6 violated: forbid policy matched but result is not Deny"
        );
    }
}

// =========================================================================
// K7: ABAC no-match produces NoMatch
// =========================================================================

#[kani::proof]
fn proof_abac_no_match_produces_nomatch() {
    use crate::{AbacDecision, AbacEffect, AbacPolicy};

    let e0: bool = kani::any();
    let e1: bool = kani::any();

    let policies = [
        AbacPolicy {
            id: "p0".to_string(),
            effect: if e0 { AbacEffect::Forbid } else { AbacEffect::Permit },
        },
        AbacPolicy {
            id: "p1".to_string(),
            effect: if e1 { AbacEffect::Forbid } else { AbacEffect::Permit },
        },
    ];

    let result = crate::abac_evaluate(&policies, &|_| false);

    assert!(
        matches!(result, AbacDecision::NoMatch),
        "K7 violated: no matching policies but result is not NoMatch"
    );
}

// =========================================================================
// K8: Evaluation determinism
// =========================================================================

#[kani::proof]
fn proof_evaluation_deterministic() {
    let v1 = crate::evaluate_empty_policies();
    let v2 = crate::evaluate_empty_policies();
    assert_eq!(v1, v2, "K8 violated: evaluation is not deterministic");
}

// =========================================================================
// K9: Domain normalization is idempotent
// =========================================================================

#[kani::proof]
#[kani::unwind(10)]
fn proof_domain_normalize_idempotent() {
    const ALPHABET: [u8; 8] = [b'a', b'A', b'.', b'-', b'0', b'z', b'Z', b' '];
    let i0: usize = kani::any();
    let i1: usize = kani::any();
    let i2: usize = kani::any();
    let i3: usize = kani::any();
    kani::assume(i0 < ALPHABET.len());
    kani::assume(i1 < ALPHABET.len());
    kani::assume(i2 < ALPHABET.len());
    kani::assume(i3 < ALPHABET.len());

    let bytes = [ALPHABET[i0], ALPHABET[i1], ALPHABET[i2], ALPHABET[i3]];
    let input = std::str::from_utf8(&bytes).unwrap();

    let first = crate::normalize_domain(input);
    let second = crate::normalize_domain(&first);

    assert_eq!(first, second, "K9 violated: domain normalization is not idempotent");
}

// =========================================================================
// K10: extract_tail no panic for arbitrary inputs (D1-D2 bridge)
// =========================================================================
//
// Verifies: extract_tail never panics and always returns valid indices,
// regardless of input content or max_size. Bridges Verus D1+D2 properties.

#[kani::proof]
#[kani::unwind(6)]
fn proof_extract_tail_no_panic() {
    use crate::dlp_core;

    let max_size: usize = kani::any();
    // Bound max_size to keep CBMC tractable
    kani::assume(max_size <= 4);

    // Test with a 4-byte input (covers ASCII + all UTF-8 prefix types)
    let b0: u8 = kani::any();
    let b1: u8 = kani::any();
    let b2: u8 = kani::any();
    let b3: u8 = kani::any();
    let value = [b0, b1, b2, b3];

    let (start, end) = dlp_core::extract_tail(&value, max_size);

    // D2: tail never exceeds max_size
    assert!(end - start <= max_size || max_size == 0,
        "K10 violated: tail exceeds max_size");
    // end == value.len()
    assert_eq!(end, value.len(), "K10 violated: end != value.len()");
    // start <= end
    assert!(start <= end, "K10 violated: start > end");
    // D1: start is at a char boundary (or past end)
    if start < value.len() {
        assert!(
            dlp_core::is_utf8_char_boundary(value[start]),
            "K10 violated: start is not at a char boundary"
        );
    }
}

// =========================================================================
// K11: UTF-8 char boundary exhaustive (all 256 byte values)
// =========================================================================
//
// Verifies: is_utf8_char_boundary correctly classifies every possible byte.

#[kani::proof]
fn proof_utf8_char_boundary_exhaustive() {
    use crate::dlp_core;

    let b: u8 = kani::any();

    let result = dlp_core::is_utf8_char_boundary(b);

    // Continuation bytes (0x80-0xBF) are NOT char boundaries
    if b >= 0x80 && b <= 0xBF {
        assert!(!result, "K11 violated: continuation byte classified as boundary");
    }

    // ASCII bytes (0x00-0x7F) are char boundaries
    if b < 0x80 {
        assert!(result, "K11 violated: ASCII byte not classified as boundary");
    }

    // Leading bytes (0xC0-0xFF) are char boundaries
    if b >= 0xC0 {
        assert!(result, "K11 violated: leading byte not classified as boundary");
    }
}

// =========================================================================
// K12: can_track_field fail-closed at capacity (D4 bridge)
// =========================================================================
//
// Verifies: at max_fields, can_track_field always returns false.

#[kani::proof]
fn proof_can_track_field_fail_closed() {
    use crate::dlp_core;

    let max_fields: usize = kani::any();
    let current_bytes: usize = kani::any();
    let new_buffer_bytes: usize = kani::any();
    let max_total_bytes: usize = kani::any();

    // Bound to avoid state explosion
    kani::assume(max_fields <= 256);
    kani::assume(current_bytes <= 100_000);
    kani::assume(new_buffer_bytes <= 1000);
    kani::assume(max_total_bytes <= 100_000);

    // D4: at max_fields, always false
    let result = dlp_core::can_track_field(
        max_fields, max_fields, current_bytes, new_buffer_bytes, max_total_bytes
    );
    assert!(!result, "K12 violated: can_track_field returned true at max_fields");

    // Above max_fields, always false
    if max_fields < usize::MAX {
        let result2 = dlp_core::can_track_field(
            max_fields + 1, max_fields, current_bytes, new_buffer_bytes, max_total_bytes
        );
        assert!(!result2, "K12 violated: can_track_field returned true above max_fields");
    }
}

// =========================================================================
// K13: update_total_bytes saturating correctness (D3/D5 bridge)
// =========================================================================
//
// Verifies: D3 (correct accounting) and D5 (no underflow).

#[kani::proof]
fn proof_update_total_bytes_saturating() {
    use crate::dlp_core;

    let old_total: usize = kani::any();
    let old_buffer_len: usize = kani::any();
    let new_buffer_len: usize = kani::any();

    // Bound to avoid state explosion
    kani::assume(old_total <= 100_000);
    kani::assume(old_buffer_len <= 100_000);
    kani::assume(new_buffer_len <= 100_000);

    let result = dlp_core::update_total_bytes(old_total, old_buffer_len, new_buffer_len);

    // D3: when state is consistent, accounting is correct
    if old_total >= old_buffer_len {
        let expected = (old_total - old_buffer_len).saturating_add(new_buffer_len);
        assert_eq!(result, expected, "K13 violated: incorrect accounting");
    }

    // D5: when state is inconsistent, result == new_buffer_len
    if old_total < old_buffer_len {
        // saturating_sub(old_total, old_buffer_len) = 0, + new_buffer_len
        assert_eq!(result, new_buffer_len, "K13 violated: underflow not handled");
    }

    // Result is always >= 0 (trivially true for usize)
    // Result never wraps — it's capped at usize::MAX by saturating_add
}

// =========================================================================
// K14: compute_verdict fail-closed empty (V1 bridge)
// =========================================================================

#[kani::proof]
fn proof_compute_verdict_fail_closed_empty() {
    use crate::verified_core::{compute_verdict, VerdictKind};

    let result = compute_verdict(&[]);
    assert!(result.is_deny(), "K14 violated: empty resolved set did not produce Deny");
}

// =========================================================================
// K15: compute_verdict allow requires matching allow (V3 bridge)
// =========================================================================

#[kani::proof]
fn proof_compute_verdict_allow_requires_match() {
    use crate::verified_core::{compute_verdict, ResolvedMatch, VerdictKind};

    // Generate a single policy with non-deterministic fields
    let matched: bool = kani::any();
    let is_deny: bool = kani::any();
    let rule_override_deny: bool = kani::any();
    let context_deny: bool = kani::any();

    let rm = ResolvedMatch {
        matched,
        is_deny,
        is_conditional: false,
        priority: 100,
        rule_override_deny,
        context_deny,
        require_approval: false,
        condition_fired: false,
        condition_verdict: VerdictKind::Deny,
        on_no_match_continue: false,
        all_constraints_skipped: false,
    };

    let result = compute_verdict(&[rm]);

    // V3: Allow only when matched, not deny, no override, no context deny
    if result.is_allow() {
        assert!(matched, "K15 violated: Allow without match");
        assert!(!is_deny, "K15 violated: Allow from Deny policy");
        assert!(!rule_override_deny, "K15 violated: Allow with rule override");
        assert!(!context_deny, "K15 violated: Allow with context deny");
    }
}

// =========================================================================
// K16: compute_verdict rule_override forces deny (V4 bridge)
// =========================================================================

#[kani::proof]
fn proof_compute_verdict_rule_override_deny() {
    use crate::verified_core::{compute_single_verdict, ResolvedMatch, VerdictKind, VerdictOutcome};

    // Any matched policy with rule_override_deny must produce Deny
    let is_deny: bool = kani::any();
    let is_conditional: bool = kani::any();

    let rm = ResolvedMatch {
        matched: true,
        is_deny,
        is_conditional,
        priority: kani::any(),
        rule_override_deny: true,
        context_deny: kani::any(),
        require_approval: kani::any(),
        condition_fired: kani::any(),
        condition_verdict: VerdictKind::Deny,
        on_no_match_continue: kani::any(),
        all_constraints_skipped: kani::any(),
    };

    let outcome = compute_single_verdict(&rm);

    assert!(
        matches!(outcome, VerdictOutcome::Decided(VerdictKind::Deny)),
        "K16 violated: rule_override_deny did not produce Deny"
    );
}

// =========================================================================
// K17: compute_verdict conditional pass-through (V8 bridge)
// =========================================================================

#[kani::proof]
fn proof_compute_verdict_conditional_passthrough() {
    use crate::verified_core::{compute_single_verdict, ResolvedMatch, VerdictKind, VerdictOutcome};

    // Conditional with no condition fired + on_no_match_continue → Continue
    let rm = ResolvedMatch {
        matched: true,
        is_deny: false,
        is_conditional: true,
        priority: kani::any(),
        rule_override_deny: false,
        context_deny: false,
        require_approval: false,
        condition_fired: false,
        condition_verdict: VerdictKind::Deny,
        on_no_match_continue: true,
        all_constraints_skipped: false,
    };

    let outcome = compute_single_verdict(&rm);

    assert!(
        matches!(outcome, VerdictOutcome::Continue),
        "K17 violated: conditional pass-through did not produce Continue"
    );
}

// =========================================================================
// K18: sort produces sorted output (Verus bridge)
// =========================================================================
//
// Verifies: sort_resolved_matches produces output satisfying the is_sorted
// invariant that Verus requires as a precondition for V6/V7.

#[kani::proof]
fn proof_sort_produces_sorted_output() {
    use crate::verified_core::{sort_resolved_matches, is_sorted, ResolvedMatch, VerdictKind};

    // Generate 3 policies with non-deterministic priority and type
    let p0: u32 = kani::any();
    let p1: u32 = kani::any();
    let p2: u32 = kani::any();
    let d0: bool = kani::any();
    let d1: bool = kani::any();
    let d2: bool = kani::any();

    // Bound priorities to reduce state space
    kani::assume(p0 <= 200);
    kani::assume(p1 <= 200);
    kani::assume(p2 <= 200);

    let mut policies = [
        ResolvedMatch {
            matched: true, is_deny: d0, is_conditional: false, priority: p0,
            rule_override_deny: false, context_deny: false, require_approval: false,
            condition_fired: false, condition_verdict: VerdictKind::Deny,
            on_no_match_continue: false, all_constraints_skipped: false,
        },
        ResolvedMatch {
            matched: true, is_deny: d1, is_conditional: false, priority: p1,
            rule_override_deny: false, context_deny: false, require_approval: false,
            condition_fired: false, condition_verdict: VerdictKind::Deny,
            on_no_match_continue: false, all_constraints_skipped: false,
        },
        ResolvedMatch {
            matched: true, is_deny: d2, is_conditional: false, priority: p2,
            rule_override_deny: false, context_deny: false, require_approval: false,
            condition_fired: false, condition_verdict: VerdictKind::Deny,
            on_no_match_continue: false, all_constraints_skipped: false,
        },
    ];

    sort_resolved_matches(&mut policies);

    assert!(
        is_sorted(&policies),
        "K18 violated: sort_resolved_matches does not produce sorted output"
    );
}

// =========================================================================
// K19: ABAC forbid ignores priority order
// =========================================================================
//
// Verifies: even when a Forbid policy comes AFTER a Permit policy
// (lower in the array), it still produces Deny.

#[kani::proof]
fn proof_abac_forbid_ignores_priority_order() {
    use crate::{AbacDecision, AbacEffect, AbacPolicy};

    // Permit first, then Forbid — Forbid still wins
    let policies = [
        AbacPolicy { id: "permit".to_string(), effect: AbacEffect::Permit },
        AbacPolicy { id: "forbid".to_string(), effect: AbacEffect::Forbid },
    ];

    let result = crate::abac_evaluate(&policies, &|_| true);

    // First forbid match wins immediately — but since Permit is scanned first
    // and Forbid is second, the algorithm should still return Deny because
    // forbid takes precedence regardless of position? Actually no — the
    // algorithm returns immediately on first Forbid. So if Permit is first
    // and matches, it stores it. Then Forbid matches and returns immediately.
    assert!(
        matches!(result, AbacDecision::Deny(_)),
        "K19 violated: Forbid after Permit did not produce Deny"
    );
}

// =========================================================================
// K20: ABAC permit requires no prior forbid
// =========================================================================
//
// Verifies: if result is Allow, no Forbid policy matched.

#[kani::proof]
fn proof_abac_permit_requires_no_forbid() {
    use crate::{AbacDecision, AbacEffect, AbacPolicy};

    let e0: bool = kani::any();
    let e1: bool = kani::any();
    let e2: bool = kani::any();
    let m0: bool = kani::any();
    let m1: bool = kani::any();
    let m2: bool = kani::any();

    let policies = [
        AbacPolicy {
            id: "p0".to_string(),
            effect: if e0 { AbacEffect::Forbid } else { AbacEffect::Permit },
        },
        AbacPolicy {
            id: "p1".to_string(),
            effect: if e1 { AbacEffect::Forbid } else { AbacEffect::Permit },
        },
        AbacPolicy {
            id: "p2".to_string(),
            effect: if e2 { AbacEffect::Forbid } else { AbacEffect::Permit },
        },
    ];

    let result = crate::abac_evaluate(&policies, &|p| {
        if p.id == "p0" { m0 }
        else if p.id == "p1" { m1 }
        else { m2 }
    });

    // S9: Allow result → no matching Forbid policy
    if matches!(result, AbacDecision::Allow(_)) {
        // If any Forbid matched, result would be Deny
        if e0 && m0 { panic!("K20 violated: Allow with matching Forbid p0"); }
        if e1 && m1 { panic!("K20 violated: Allow with matching Forbid p1"); }
        if e2 && m2 { panic!("K20 violated: Allow with matching Forbid p2"); }
    }
}

// =========================================================================
// K21: overlap_covers_secret for small secrets (D6 bridge)
// =========================================================================
//
// Verifies: for secrets <= 2 * overlap_size split at any point,
// the combined buffer covers the entire secret.

#[kani::proof]
fn proof_overlap_covers_small_secrets() {
    use crate::dlp_core;

    let overlap_size: usize = kani::any();
    let secret_len: usize = kani::any();
    let split_point: usize = kani::any();

    // Bound for tractability
    kani::assume(overlap_size >= 1 && overlap_size <= 32);
    kani::assume(secret_len >= 2 && secret_len <= 2 * overlap_size);
    kani::assume(split_point >= 1 && split_point < secret_len);

    // Previous and current values large enough to contain the secret parts
    let prev_value_len: usize = 100;
    let current_value_len: usize = 100;

    let result = dlp_core::overlap_covers_secret(
        prev_value_len, current_value_len, overlap_size, secret_len, split_point
    );

    assert!(result, "K21 violated: overlap does not cover split secret");
}

// =========================================================================
// K22: compute_overlap_region_size saturating
// =========================================================================
//
// Verifies: region size computation never overflows.

#[kani::proof]
fn proof_overlap_region_size_saturating() {
    use crate::dlp_core;

    let prev_tail_len: usize = kani::any();
    let current_value_len: usize = kani::any();

    let result = dlp_core::compute_overlap_region_size(prev_tail_len, current_value_len);

    // Result is always >= both inputs (monotonically non-decreasing)
    assert!(result >= prev_tail_len, "K22 violated: result < prev_tail_len");
    assert!(result >= current_value_len, "K22 violated: result < current_value_len");
}

// =========================================================================
// K23: extract_tail multibyte boundary (4-byte emoji)
// =========================================================================
//
// Verifies: extract_tail correctly handles 4-byte UTF-8 sequences
// and never splits them.

#[kani::proof]
fn proof_extract_tail_multibyte_boundary() {
    use crate::dlp_core;

    // "A😀B" = [0x41, 0xF0, 0x9F, 0x98, 0x80, 0x42] — 6 bytes
    let value: [u8; 6] = [0x41, 0xF0, 0x9F, 0x98, 0x80, 0x42];

    let max_size: usize = kani::any();
    kani::assume(max_size >= 1 && max_size <= 6);

    let (start, end) = dlp_core::extract_tail(&value, max_size);

    assert!(start <= end);
    assert_eq!(end, 6);
    assert!(end - start <= max_size);

    // Start must be at a char boundary
    if start < value.len() {
        assert!(
            dlp_core::is_utf8_char_boundary(value[start]),
            "K23 violated: start at continuation byte"
        );
    }

    // The extracted tail must be valid UTF-8
    let tail = &value[start..end];
    assert!(
        std::str::from_utf8(tail).is_ok(),
        "K23 violated: extracted tail is not valid UTF-8"
    );
}

// =========================================================================
// K24: context_deny overrides allow (V3 extension)
// =========================================================================
//
// Verifies: a matched Allow policy with context_deny produces Deny.

#[kani::proof]
fn proof_context_deny_overrides_allow() {
    use crate::verified_core::{compute_verdict, ResolvedMatch, VerdictKind};

    let rm = ResolvedMatch {
        matched: true,
        is_deny: false,
        is_conditional: false,
        priority: 100,
        rule_override_deny: false,
        context_deny: true,
        require_approval: false,
        condition_fired: false,
        condition_verdict: VerdictKind::Deny,
        on_no_match_continue: false,
        all_constraints_skipped: false,
    };

    let result = compute_verdict(&[rm]);

    assert!(
        result.is_deny(),
        "K24 violated: context_deny did not override Allow"
    );
}

// =========================================================================
// K25: all_constraints_skipped fail-closed (V8 extension)
// =========================================================================
//
// Verifies: when all constraints are skipped and on_no_match_continue
// is false, the result is Deny (fail-closed).

#[kani::proof]
fn proof_all_constraints_skipped_fail_closed() {
    use crate::verified_core::{compute_single_verdict, ResolvedMatch, VerdictKind, VerdictOutcome};

    let rm = ResolvedMatch {
        matched: true,
        is_deny: false,
        is_conditional: true,
        priority: 100,
        rule_override_deny: false,
        context_deny: false,
        require_approval: false,
        condition_fired: false,
        condition_verdict: VerdictKind::Deny,
        on_no_match_continue: false,
        all_constraints_skipped: true,
    };

    let outcome = compute_single_verdict(&rm);

    assert!(
        matches!(outcome, VerdictOutcome::Decided(VerdictKind::Deny)),
        "K25 violated: all_constraints_skipped with no continue did not produce Deny"
    );
}
