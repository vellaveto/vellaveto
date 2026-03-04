# Kani Proof Harnesses — Vellaveto

Bounded model checking proofs using [Kani](https://github.com/model-checking/kani)
for critical security invariants. 25 harnesses verifying security properties
using CBMC on actual Rust implementation code.

## What's Verified

### K1-K9: Core Properties

| ID | Harness | Property | Source |
|----|---------|----------|--------|
| K1 | `proof_fail_closed_no_match_produces_deny` | Fail-closed: empty policies → Deny | `vellaveto-engine/src/lib.rs` |
| K2 | `proof_path_normalize_idempotent` | Path normalization idempotent | `vellaveto-engine/src/path.rs` |
| K3 | `proof_path_normalize_no_traversal` | No `..` in normalized output | `vellaveto-engine/src/path.rs` |
| K4 | `proof_saturating_counters_never_wrap` | Saturating arithmetic never wraps | All counter operations |
| K5 | `proof_verdict_deny_on_error` | Errors produce Deny | `vellaveto-engine/src/lib.rs` |
| K6 | `proof_abac_forbid_dominance` | ABAC forbid → Deny | `vellaveto-engine/src/abac.rs` |
| K7 | `proof_abac_no_match_produces_nomatch` | ABAC no-match → NoMatch | `vellaveto-engine/src/abac.rs` |
| K8 | `proof_evaluation_deterministic` | Same input → same output | `vellaveto-engine/src/lib.rs` |
| K9 | `proof_domain_normalize_idempotent` | Domain normalization idempotent | Domain handling |

### K10-K13: DLP Buffer Arithmetic (Verus D1-D6 Bridge)

| ID | Harness | Property | Verus Bridge |
|----|---------|----------|-------------|
| K10 | `proof_extract_tail_no_panic` | extract_tail safe for arbitrary bytes | D1, D2 |
| K11 | `proof_utf8_char_boundary_exhaustive` | All 256 byte values classified correctly | D1 |
| K12 | `proof_can_track_field_fail_closed` | At max_fields, always rejects | D4 |
| K13 | `proof_update_total_bytes_saturating` | Saturating accounting correct | D3, D5 |

### K14-K18: Core Verdict Computation (Verus V1-V8 Bridge)

| ID | Harness | Property | Verus Bridge |
|----|---------|----------|-------------|
| K14 | `proof_compute_verdict_fail_closed_empty` | Empty → Deny | V1 |
| K15 | `proof_compute_verdict_allow_requires_match` | Allow requires matching Allow policy | V3 |
| K16 | `proof_compute_verdict_rule_override_deny` | rule_override_deny → Deny | V4 |
| K17 | `proof_compute_verdict_conditional_passthrough` | Unfired condition + continue → Continue | V8 |
| K18 | `proof_sort_produces_sorted_output` | Sort satisfies is_sorted precondition | V6, V7 |

### K19-K22: ABAC and DLP Extensions

| ID | Harness | Property | Bridge |
|----|---------|----------|--------|
| K19 | `proof_abac_forbid_ignores_priority_order` | Forbid after Permit still Deny | S8 |
| K20 | `proof_abac_permit_requires_no_forbid` | Allow → no matching Forbid | S9 |
| K21 | `proof_overlap_covers_small_secrets` | Split secrets covered by overlap buffer | D6 |
| K22 | `proof_overlap_region_size_saturating` | Region size never overflows | D6 |

### K23-K25: Edge Cases

| ID | Harness | Property | Bridge |
|----|---------|----------|--------|
| K23 | `proof_extract_tail_multibyte_boundary` | 4-byte emoji never split mid-char | D1 |
| K24 | `proof_context_deny_overrides_allow` | context_deny forces Deny | V3 |
| K25 | `proof_all_constraints_skipped_fail_closed` | All skipped + no continue → Deny | V8 |

## Source Correspondence

| Kani File | Production File | Verus File |
|-----------|----------------|------------|
| `src/path.rs` | `vellaveto-engine/src/path.rs` | — |
| `src/verified_core.rs` | `vellaveto-engine/src/verified_core.rs` | `formal/verus/verified_core.rs` |
| `src/dlp_core.rs` | `vellaveto-mcp/src/inspection/verified_dlp_core.rs` | `formal/verus/verified_dlp_core.rs` |

## Running

```bash
# Install Kani (requires Rust nightly)
cargo install --locked kani-verifier
cargo kani setup

# Run all proofs from the kani crate
cd formal/kani
cargo kani --harness proof_fail_closed_no_match_produces_deny
cargo kani --harness proof_path_normalize_idempotent
cargo kani --harness proof_path_normalize_no_traversal
# ... etc for all 25 harnesses

# Run a specific harness
cargo kani --harness proof_compute_verdict_fail_closed_empty
```

## Verification Chain

The Kani harnesses bridge the gap between Verus deductive proofs (all inputs)
and the production Rust code:

```
Verus (ALL inputs, core logic)     Kani (bounded, actual Rust)
        V1-V8  ←──────────────────── K14-K18 (verdict bridge)
        D1-D6  ←──────────────────── K10-K13, K21-K23 (DLP bridge)
                                     K18 proves sort → is_sorted
                                       (Verus V6/V7 precondition)
```

- **K18 + Verus:** Kani proves sorting correct (bounded) → Verus proves verdict
  correct given sorted input (unbounded)
- **K14-K17 + Verus:** Kani verifies compute_verdict on bounded inputs; Verus
  proves it for ALL inputs

## Design Decisions

- Separate crate (excluded from workspace) to avoid Kani's ICE on `icu_normalizer`
- Harnesses use `kani::any()` to generate arbitrary inputs
- `kani::assume()` constrains inputs to valid ranges (tractability)
- Properties verified via `assert!()` macros
- Bounded verification: Kani unrolls loops up to configured depth
- Production parity unit tests ensure extracted code matches production
