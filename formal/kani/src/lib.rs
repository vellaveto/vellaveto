// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Kani bounded model checking proofs for Vellaveto security invariants.
//!
//! This crate extracts security-critical algorithms from the production
//! codebase and verifies them using Kani's CBMC backend.
//!
//! # Why a separate crate?
//!
//! Kani 0.67 hits an internal compiler error on the `icu_normalizer` crate
//! (transitive dependency: `idna` → `icu_normalizer` → `zerovec`). Since
//! the verified algorithms — path normalization, verdict computation, DLP
//! buffer arithmetic — do not use IDNA functionality, we extract them here
//! with minimal dependencies to make verification tractable.
//!
//! # Verified Properties
//!
//! | ID | Property | Corresponds To |
//! |----|----------|----------------|
//! | K1 | Empty policies → Deny (fail-closed) | S1, MCPPolicyEngine.tla |
//! | K2 | normalize(normalize(x)) == normalize(x) | PathNormalization.lean/v |
//! | K3 | normalize(x) has no ".." component | PathNormalization.lean/v |
//! | K4 | saturating_add never wraps | Trap #9, counter monotonicity |
//! | K5 | No policies + any input → never Allow | S5, MCPPolicyEngine.tla |
//! | K6 | ABAC forbid dominance | S7, AbacForbidOverride.lean/v |
//! | K7 | ABAC no-match → NoMatch | S10, AbacForbidOverride.lean/v |
//! | K8 | Evaluation determinism | Determinism.lean/v |
//! | K9 | Simplified domain normalization idempotent | Lowercase + trim (NOT full IDNA) |
//! | K10 | extract_tail no panic for arbitrary input | D1-D2, Verus bridge |
//! | K11 | UTF-8 char boundary exhaustive (all 256 bytes) | D1, Verus bridge |
//! | K12 | can_track_field fail-closed at capacity | D4, Verus bridge |
//! | K13 | update_total_bytes saturating correctness | D3/D5, Verus bridge |
//! | K14 | compute_verdict fail-closed empty | V1, Verus bridge |
//! | K15 | compute_verdict allow requires matching allow | V3, Verus bridge |
//! | K16 | compute_verdict rule_override forces deny | V4, Verus bridge |
//! | K17 | compute_verdict conditional pass-through | V8, Verus bridge |
//! | K18 | sort produces sorted output (Verus bridge) | V6/V7, is_sorted |
//! | K19 | ABAC forbid ignores priority order | S8, AbacForbidOverride |
//! | K20 | ABAC permit requires no prior forbid | S9, AbacForbidOverride |
//! | K21 | overlap_covers_secret for small secrets within retained overlap | D6, Verus bridge |
//! | K22 | compute_overlap_region_size saturating | D6, region arithmetic |
//! | K23 | extract_tail multibyte boundary (4-byte emoji) | D1, UTF-8 safety |
//! | K24 | context_deny overrides allow | V3, context conditions |
//! | K25 | all_constraints_skipped fail-closed | V8, conditional handling |
//! | K26 | 127.x.x.x always private (loopback) | IP verification |
//! | K27 | RFC 1918 ranges always private | IP verification |
//! | K28 | CGNAT 100.64.0.0/10 always private | IP verification |
//! | K29 | is_embedded_ipv4_reserved parity with is_private_ipv4 | IP verification |
//! | K30 | IPv4-mapped ::ffff:x.x.x.x extraction correct | IP verification |
//! | K31 | Teredo XOR inversion round-trip correct | IP verification |
//! | K32 | Known public IPs (8.8.8.8, 1.1.1.1) NOT private | IP verification |
//! | K33 | is_cacheable == true → all session fields empty/None | Cache safety |
//! | K34 | Cache key case-insensitive | Cache safety |
//! | K35 | Entry invalid after TTL or generation bump | Cache safety |
//! | K36 | grant_is_subset reflexive | Capability delegation, S11 |
//! | K37 | No escalation (child ⊆ parent) | Capability delegation, S11 |
//! | K38 | pattern_is_subset correctness | Capability delegation, S11 |
//! | K39 | glob_match("*", any) == true | Capability delegation |
//! | K40 | normalize_path_for_grant: no ".." in output | Capability delegation, S11 |
//! | K41 | No target_paths + allowlist → Deny | Rule checking |
//! | K42 | Blocked pattern → Deny even if also allowed | Rule checking |
//! | K43 | IDNA normalization failure → Deny | Rule checking |
//! | K44 | IP rules + no resolved IPs → Deny | Rule checking |
//! | K45 | block_private + private IP → Deny | Rule checking |
//! | K46 | Path deny → rule_override_deny in ResolvedMatch | ResolvedMatch equivalence |
//! | K47 | Context deny → context_deny in ResolvedMatch | ResolvedMatch equivalence |
//! | K48 | Inline verdict == compute_single_verdict(ResolvedMatch) | ResolvedMatch equivalence |
//! | K49 | NaN/Infinity in cascading config → rejected | Cascading failure |
//! | K50 | Chain depth increment never wraps | Cascading failure |
//! | K51 | At MAX capacity → Deny | Cascading failure |
//! | K52 | Error rate ∈ [0.0, 1.0] | Cascading failure |
//! | K53 | All constraints skipped → detected | Constraint evaluation |
//! | K54 | Forbidden parameter match → Deny | Constraint evaluation |
//! | K55 | require_approval → RequireApproval verdict | Constraint evaluation |
//! | K56 | Terminal state → no further transitions | Task lifecycle |
//! | K57 | At max tasks → reject new registration | Task lifecycle |
//! | K58 | Self-cancel + different requester → reject | Task lifecycle |
//! | K59 | Entropy finite, non-negative, ≤ 8.0, empty → 0.0 | Collusion detection |
//! | K60 | grant_covers_action fail-closed (paths/domains) | Capability delegation |
//! | K61 | IDNA failure on non-ASCII → None (fail-closed) | Domain normalization |
//! | K62 | IDNA failure on ASCII → lowercase fallback | Domain normalization |
//! | K63 | Wildcard prefix preserved through IDNA | Domain normalization |
//! | K64 | normalize_homoglyphs idempotent | Unicode security |
//! | K65 | Confusable chars collapse to ASCII | Unicode security |
//! | K66 | Cache lock poison → cache miss (never stale Allow) | Lock safety |
//! | K67 | Deputy lock poison → InternalError (Deny) | Lock safety |
//! | K68 | All lock poison handlers produce safe outcome | Lock safety |
//! | K69 | PII token insertion + replacement round-trip (inversion) | Sanitizer bidirectional |
//! | K70 | PII token uniqueness from monotonic sequence counter | Sanitizer bidirectional |
//! | K71 | Temporal window: events outside window expired (no stale) | Collusion temporal |
//! | K72 | Temporal window: boundary precision (>= cutoff included) | Collusion temporal |
//! | K73 | Cascading FSM: Closed→Open requires threshold AND min_events | Cascading FSM |
//! | K74 | Cascading FSM: half-open probe after break_duration | Cascading FSM |
//! | K75 | Cascading FSM: recovery requires error_rate < threshold | Cascading FSM |
//! | K76 | Injection decode pipeline completeness (7 stages ordered) | Injection completeness |
//! | K77 | Injection: known patterns detected after decode chain | Injection completeness |
//!
//! # Source Correspondence
//!
//! - `path.rs`: Verbatim from `vellaveto-engine/src/path.rs`
//! - `verified_core.rs`: Verbatim from `vellaveto-engine/src/verified_core.rs`
//! - `dlp_core.rs`: Verbatim from `vellaveto-mcp/src/inspection/verified_dlp_core.rs`
//! - `ip.rs`: Extracted from `vellaveto-engine/src/ip.rs`
//! - `cache.rs`: Extracted from `vellaveto-engine/src/cache.rs`
//! - `capability.rs`: Extracted from `vellaveto-mcp/src/capability_token.rs`
//! - `rule_check.rs`: Extracted from `vellaveto-engine/src/rule_check.rs`
//! - `resolve.rs`: Extracted from `vellaveto-engine/src/lib.rs` (ResolvedMatch construction)
//! - `cascading.rs`: Extracted from `vellaveto-engine/src/cascading.rs`
//! - `constraint.rs`: Extracted from `vellaveto-engine/src/constraint_eval.rs`
//! - `task.rs`: Extracted from `vellaveto-mcp/src/task_state.rs`
//! - `entropy.rs`: Extracted from `vellaveto-engine/src/collusion.rs`
//! - `domain.rs`: Extracted from `vellaveto-engine/src/domain.rs` (IDNA wrapper)
//! - `unicode.rs`: Extracted from `vellaveto-types/src/unicode.rs` (homoglyph mapping)
//! - `lock_safety.rs`: Models RwLock poisoning handlers across engine/MCP
//! - `sanitizer.rs`: Extracted from `vellaveto-mcp-shield/src/sanitizer.rs` (PII inversion)
//! - `temporal_window.rs`: Extracted from `vellaveto-engine/src/collusion.rs` (sliding window)
//! - `cascading_fsm.rs`: Extracted from `vellaveto-engine/src/cascading.rs` (circuit breaker FSM)
//! - `injection_pipeline.rs`: Extracted from `vellaveto-mcp/src/inspection/injection.rs` (decode chain)

pub mod path;
pub mod verified_core;
pub mod dlp_core;
pub mod ip;
pub mod cache;
pub mod capability;
pub mod rule_check;
pub mod resolve;
pub mod cascading;
pub mod constraint;
pub mod task;
pub mod entropy;
pub mod domain;
pub mod unicode;
pub mod lock_safety;
pub mod sanitizer;
pub mod temporal_window;
pub mod cascading_fsm;
pub mod injection_pipeline;

#[cfg(kani)]
mod proofs;

/// Error type for path normalization (mirrors `EngineError::PathNormalization`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathError {
    pub reason: String,
}

/// Verdict type (mirrors `vellaveto_types::Verdict`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny { reason: String },
}

/// Evaluate an action against an empty policy set.
///
/// This is the fail-closed default path extracted from
/// `PolicyEngine::evaluate_action` (vellaveto-engine/src/lib.rs:367-371).
///
/// With no policies defined, the engine MUST return Deny.
pub fn evaluate_empty_policies() -> Verdict {
    Verdict::Deny {
        reason: "No policies defined".to_string(),
    }
}

// =========================================================================
// ABAC forbid-override combining (extracted from abac.rs:322-364)
// =========================================================================

/// ABAC policy effect — Permit or Forbid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbacEffect {
    Permit,
    Forbid,
}

/// ABAC policy entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbacPolicy {
    pub id: String,
    pub effect: AbacEffect,
}

/// ABAC combining result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbacDecision {
    Deny(String),
    Allow(String),
    NoMatch,
}

/// ABAC forbid-override combining algorithm.
///
/// Extracted from `vellaveto-engine/src/abac.rs:322-364`.
/// The core rule: scan all policies; first forbid match wins immediately.
pub fn abac_evaluate(policies: &[AbacPolicy], matches: &dyn Fn(&AbacPolicy) -> bool) -> AbacDecision {
    let mut best_permit: Option<&str> = None;
    for policy in policies {
        if matches(policy) {
            match policy.effect {
                AbacEffect::Forbid => {
                    return AbacDecision::Deny(policy.id.clone());
                }
                AbacEffect::Permit => {
                    if best_permit.is_none() {
                        best_permit = Some(&policy.id);
                    }
                }
            }
        }
    }
    match best_permit {
        Some(pid) => AbacDecision::Allow(pid.to_string()),
        None => AbacDecision::NoMatch,
    }
}

// =========================================================================
// Domain normalization (extracted from engine domain handling)
// =========================================================================

/// Normalize a domain name: ASCII lowercase, strip trailing dots.
///
/// **Simplified extraction** from domain handling in `vellaveto-engine/src/lib.rs`.
/// Production uses full IDNA normalization (74 lines: punycode, homoglyph mapping,
/// Unicode confusable resolution). This function verifies only the post-IDNA
/// ASCII lowercase + trim subset. This is a pure function — calling it twice
/// yields the same result.
pub fn normalize_domain(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == b'.' {
        end -= 1;
    }
    raw[..end].to_ascii_lowercase()
}
