# Kani Proof Harnesses — Vellaveto

Bounded model checking proofs using [Kani](https://github.com/model-checking/kani)
for critical security invariants. 82 harnesses verify security properties
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

### K26-K32: IP Address Verification

| ID | Harness | Property |
|----|---------|----------|
| K26 | `proof_is_private_ip_loopback_v4` | 127.x.x.x always classified as private (loopback) |
| K27 | `proof_is_private_ip_rfc1918` | RFC 1918 ranges (10/8, 172.16/12, 192.168/16) always private |
| K28 | `proof_is_private_ip_cgnat` | CGNAT 100.64.0.0/10 always classified as private |
| K29 | `proof_is_embedded_ipv4_reserved_parity` | Embedded IPv4 reserved check has parity with is_private_ipv4 |
| K30 | `proof_extract_embedded_ipv4_mapped` | IPv4-mapped `::ffff:x.x.x.x` extracts correct IPv4 address |
| K31 | `proof_extract_embedded_ipv4_teredo_xor` | Teredo XOR inversion round-trip is lossless |
| K32 | `proof_is_private_ip_public_not_blocked` | Known public IPs are NOT classified as private |

### K33-K35: Cache Safety

| ID | Harness | Property |
|----|---------|----------|
| K33 | `proof_is_cacheable_context_no_session_state` | is_cacheable_context==true → all session fields empty/None |
| K34 | `proof_cache_key_case_insensitive` | Cache key computation is case-insensitive |
| K35 | `proof_cache_staleness_monotonic` | Entry invalid after TTL expiry or generation bump |

### K36-K40: Capability Delegation

| ID | Harness | Property |
|----|---------|----------|
| K36 | `proof_grant_is_subset_reflexive` | grant_is_subset is reflexive (A ⊆ A) |
| K37 | `proof_grant_is_subset_no_escalation` | No escalation: child grants ⊆ parent grants |
| K38 | `proof_pattern_is_subset_correctness` | pattern_is_subset correctness for glob patterns |
| K39 | `proof_glob_match_wildcard_universal` | glob_match("*", any) == true (universal match) |
| K40 | `proof_normalize_path_for_grant_no_traversal` | normalize_path_for_grant: no `..` in output |

### K41-K45: Rule Checking Fail-Closed

| ID | Harness | Property |
|----|---------|----------|
| K41 | `proof_path_rules_empty_paths_with_allowlist_deny` | No target_paths + allowlist configured → Deny |
| K42 | `proof_path_rules_blocked_before_allowed` | Blocked pattern match → Deny (even if also in allowed) |
| K43 | `proof_network_rules_idna_fail_deny` | IDNA normalization failure → Deny (fail-closed) |
| K44 | `proof_ip_rules_no_resolved_ips_deny` | IP rules configured + no resolved IPs → Deny |
| K45 | `proof_ip_rules_private_blocked` | block_private + private IP → Deny |

### K46-K48: ResolvedMatch Construction

| ID | Harness | Property |
|----|---------|----------|
| K46 | `proof_apply_policy_path_deny_is_rule_override` | Path deny → rule_override_deny in ResolvedMatch |
| K47 | `proof_apply_policy_context_deny_is_context_deny` | Context deny → context_deny in ResolvedMatch |
| K48 | `proof_apply_policy_equivalence` | Inline verdict == compute_single_verdict for key cases |

### K49-K52: Cascading Failure Circuit Breaker

| ID | Harness | Property |
|----|---------|----------|
| K49 | `proof_cascading_config_validate_rejects_nan` | NaN/Infinity in cascading config → rejected |
| K50 | `proof_chain_depth_saturating` | Chain depth increment never wraps |
| K51 | `proof_capacity_fail_closed` | At MAX capacity → Deny (fail-closed) |
| K52 | `proof_error_rate_bounded` | Error rate ∈ [0.0, 1.0] |

### K53-K55: Constraint Evaluation

| ID | Harness | Property |
|----|---------|----------|
| K53 | `proof_all_skipped_detected` | All constraints skipped → all_constraints_skipped==true |
| K54 | `proof_forbidden_params_deny` | Forbidden parameter match → Deny |
| K55 | `proof_require_approval_propagated` | require_approval → RequireApproval verdict |

### K56-K58: Task Lifecycle

| ID | Harness | Property |
|----|---------|----------|
| K56 | `proof_terminal_state_immutable` | Terminal state → no further transitions allowed |
| K57 | `proof_capacity_check_fail_closed` | At max tasks → reject new registration |
| K58 | `proof_cancel_authorization` | Self-cancel required + different requester → reject |

### K59-K60: Entropy and Grant Coverage

| ID | Harness | Property |
|----|---------|----------|
| K59 | `proof_compute_entropy_partition_1_1_1_1_bounded` | [1,1,1,1] partition entropy within [0, 8] |
| K60 | `proof_grant_covers_action_fail_closed` | grant_covers_action fail-closed on empty paths/domains |

### K61-K65: IDNA and Unicode Normalization

| ID | Harness | Property |
|----|---------|----------|
| K61 | `proof_idna_failure_non_ascii_fail_closed` | IDNA failure on non-ASCII → None (fail-closed) |
| K62 | `proof_idna_failure_ascii_fallback` | IDNA failure on ASCII → lowercase fallback |
| K63 | `proof_wildcard_prefix_preserved` | Wildcard prefix preserved through IDNA normalization |
| K64 | `proof_normalize_homoglyphs_idempotent` | normalize_homoglyphs is idempotent |
| K65 | `proof_confusables_collapse_to_ascii` | All mapped confusables collapse to ASCII |

### K66-K68: RwLock Poisoning Fail-Closed

| ID | Harness | Property |
|----|---------|----------|
| K66 | `proof_cache_lock_poison_safe` | Cache lock poison → cache miss (never stale Allow) |
| K67 | `proof_deputy_lock_poison_deny` | Deputy lock poison → InternalError (Deny) |
| K68 | `proof_all_lock_poison_handlers_safe` | ALL lock poison handlers produce safe outcome |

### K69-K70: PII Sanitizer

| ID | Harness | Property |
|----|---------|----------|
| K69 | `proof_sanitizer_roundtrip_inversion` | PII token insertion + replacement round-trip (inversion) |
| K70 | `proof_sanitizer_token_uniqueness` | PII token uniqueness from monotonic sequence counter |

### K71-K72: Temporal Window

| ID | Harness | Property |
|----|---------|----------|
| K71 | `proof_temporal_window_expiry` | Events outside window are expired |
| K72 | `proof_temporal_window_boundary` | Boundary precision at window edges |

### K73-K75: Cascading FSM Transitions

| ID | Harness | Property |
|----|---------|----------|
| K73 | `proof_cascading_fsm_break_guard` | Closed→Open requires threshold AND min_events |
| K74 | `proof_cascading_fsm_probe_timing` | Half-open probe only after break_duration |
| K75 | `proof_cascading_fsm_recovery_guard` | Recovery requires error_rate < threshold |

### K76-K77: Injection Pipeline

| ID | Harness | Property |
|----|---------|----------|
| K76 | `proof_injection_pipeline_completeness` | Injection decode pipeline covers all decode layers |
| K77 | `proof_injection_known_patterns_detected` | Known injection patterns detected after decode chain |

## Source Correspondence

| Kani Module | Production File | Verus Bridge | Harnesses |
|-------------|----------------|-------------|-----------|
| `src/verified_core.rs` | `vellaveto-engine/src/verified_core.rs` | `formal/verus/verified_core.rs` | K1, K4-K8, K14-K20, K24-K25 |
| `src/dlp_core.rs` | `vellaveto-mcp/src/inspection/verified_dlp_core.rs` | `formal/verus/verified_dlp_core.rs` | K10-K13, K21-K23 |
| `src/path.rs` | `vellaveto-engine/src/path.rs` | — | K2-K3, K40 |
| `src/domain.rs` | Domain handling | — | K9, K61-K65 |
| `src/ip.rs` | `vellaveto-engine/src/ip.rs` | — | K26-K32 |
| `src/cache.rs` | `vellaveto-engine/src/cache.rs` | — | K33-K35 |
| `src/capability.rs` | `vellaveto-mcp/src/capability_token.rs` | — | K36-K39, K60 |
| `src/rule_check.rs` | `vellaveto-engine/src/lib.rs` (rule checking) | — | K41-K45 |
| `src/resolve.rs` | `vellaveto-engine/src/lib.rs` (ResolvedMatch) | — | K46-K48 |
| `src/cascading.rs` | `vellaveto-engine/src/cascading.rs` | — | K49-K52 |
| `src/constraint.rs` | `vellaveto-engine/src/lib.rs` (constraints) | — | K53-K55 |
| `src/task.rs` | `vellaveto-mcp/src/task_state.rs` | — | K56-K58 |
| `src/entropy.rs` | `vellaveto-engine/src/collusion.rs` | — | K59 |
| `src/lock_safety.rs` | Various (RwLock sites) | — | K66-K68 |
| `src/sanitizer.rs` | `vellaveto-mcp-shield/src/sanitizer.rs` | — | K69-K70 |
| `src/temporal_window.rs` | `vellaveto-engine/src/collusion.rs` | — | K71-K72 |
| `src/cascading_fsm.rs` | `vellaveto-engine/src/cascading.rs` | — | K73-K75 |
| `src/injection_pipeline.rs` | `vellaveto-mcp/src/inspection/mod.rs` | — | K76-K77 |

## Running

```bash
# Install Kani (requires Rust nightly)
cargo install --locked kani-verifier --version 0.67.0
cargo kani setup

# Run all proofs from the kani crate
cd formal/kani
cargo kani --harness proof_fail_closed_no_match_produces_deny
cargo kani --harness proof_path_normalize_idempotent
cargo kani --harness proof_path_normalize_no_traversal
# ... etc for all 82 harnesses

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
