// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Kani bounded model checking proofs for Vellaveto security invariants.
//!
//! This crate extracts security-critical algorithms from the production
//! `vellaveto-engine` crate and verifies them using Kani's CBMC backend.
//!
//! # Why a separate crate?
//!
//! Kani 0.67 hits an internal compiler error on the `icu_normalizer` crate
//! (transitive dependency: `idna` → `icu_normalizer` → `zerovec`). Since
//! the verified algorithms — path normalization and fail-closed policy
//! evaluation — do not use IDNA functionality, we extract them here with
//! minimal dependencies to make verification tractable.
//!
//! # Verified Properties
//!
//! | ID | Property | Corresponds To |
//! |----|----------|----------------|
//! | K1 | Empty policies → Deny (fail-closed) | S1, MCPPolicyEngine.tla, FailClosed.lean/v |
//! | K2 | normalize(normalize(x)) == normalize(x) | PathNormalization.lean/v |
//! | K3 | normalize(x) has no ".." component | PathNormalization.lean/v |
//! | K4 | saturating_add never wraps | Trap #9, counter monotonicity |
//! | K5 | No policies + any input → never Allow | S5, MCPPolicyEngine.tla |
//! | K6 | ABAC forbid dominance | S7, AbacForbidOverride.lean/v |
//! | K7 | ABAC no-match → NoMatch | S10, AbacForbidOverride.lean/v |
//! | K8 | Evaluation determinism | Determinism.lean/v |
//! | K9 | Domain normalization idempotent | Domain handling in engine |
//!
//! # Source Correspondence
//!
//! - `normalize_path_bounded`: Verbatim from `vellaveto-engine/src/path.rs`
//!   (with `tracing::warn!` replaced by a no-op, and `EngineError` replaced
//!   by a local error type — the algorithm is identical).
//! - `evaluate_empty_policies`: Extracted from `vellaveto-engine/src/lib.rs`
//!   `evaluate_action` method, empty-policies branch (line 367-371).

mod path;

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

/// Normalize a domain name: lowercase, strip trailing dot.
///
/// Extracted from domain handling in `vellaveto-engine/src/lib.rs`.
/// This is a pure function — calling it twice yields the same result.
pub fn normalize_domain(raw: &str) -> String {
    let lower = raw.to_lowercase();
    let trimmed = lower.trim_end_matches('.');
    trimmed.to_string()
}
