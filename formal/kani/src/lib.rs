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
