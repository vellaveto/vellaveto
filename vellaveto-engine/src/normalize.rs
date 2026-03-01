// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Shared normalization utilities for policy compilation and evaluation.
//!
//! SECURITY (FIND-R218-001): This module provides the canonical normalization
//! pipeline used by both compile-time (policy_compile) and eval-time
//! (context_check) paths. Both MUST use the same function to prevent
//! compile/eval normalization mismatches that bypass policy enforcement.

use unicode_normalization::UnicodeNormalization;
use vellaveto_types::unicode::normalize_homoglyphs;

/// Apply full normalization pipeline: NFKC → lowercase → homoglyph mapping.
///
/// SECURITY (FIND-R218-001, FIND-R220-001–003): NFKC normalization catches
/// NFKC-only confusables (circled letters Ⓐ-ⓩ, mathematical script 𝐀-𝐳,
/// parenthesized ⒜-⒵) that `normalize_homoglyphs` alone does not map.
///
/// This function MUST be used for all string comparisons between compiled
/// policy values and runtime values. Using `normalize_homoglyphs` without
/// NFKC, or using `to_ascii_lowercase` instead of `to_lowercase`, creates
/// a normalization mismatch exploitable by attackers.
pub(crate) fn normalize_full(s: &str) -> String {
    let nfkc: String = s.nfkc().collect();
    normalize_homoglyphs(&nfkc.to_lowercase())
}
