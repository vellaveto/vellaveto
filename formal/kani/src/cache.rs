// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Cache safety verification extracted from `vellaveto-engine/src/cache.rs`.
//!
//! Pure predicates for cache key safety, cacheability, and staleness checking.
//!
//! # Verified Properties (K33-K35)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K33 | is_cacheable == true → all session fields empty/None |
//! | K34 | build_key is case-insensitive |
//! | K35 | Entry invalid after TTL or generation bump |
//!
//! # Production Correspondence
//!
//! - `is_cacheable_context` ↔ `vellaveto-engine/src/cache.rs:297-323`
//! - `is_stale` ↔ `vellaveto-engine/src/cache.rs:192-207` (inline in `get`)

/// Abstract representation of session-dependent fields in EvaluationContext.
///
/// Each boolean indicates whether the corresponding field has a value
/// (Some/non-empty). We abstract over the field contents because cacheability
/// depends only on presence, not on values.
pub struct CacheabilityFields {
    pub has_timestamp: bool,
    pub has_call_counts: bool,       // !call_counts.is_empty()
    pub has_previous_actions: bool,  // !previous_actions.is_empty()
    pub has_call_chain: bool,        // !call_chain.is_empty()
    pub has_capability_token: bool,  // capability_token.is_some()
    pub has_session_state: bool,     // session_state.is_some()
    pub has_verification_tier: bool, // verification_tier.is_some()
    pub context_present: bool,       // context.is_some()
}

/// Determine if a context is safe to cache.
///
/// Verbatim logic from production `is_cacheable_context`.
/// Returns true only if NO session-dependent fields are populated.
pub fn is_cacheable_context(fields: &CacheabilityFields) -> bool {
    if !fields.context_present {
        return true;
    }
    !fields.has_timestamp
        && !fields.has_call_counts
        && !fields.has_previous_actions
        && !fields.has_call_chain
        && !fields.has_capability_token
        && !fields.has_session_state
        && !fields.has_verification_tier
}

/// Check if a cache entry is stale.
///
/// Extracted from the inline check in `DecisionCache::get`.
/// Entry is valid only when both generation matches AND TTL has not elapsed.
pub fn is_stale(
    entry_generation: u64,
    current_generation: u64,
    elapsed_ms: u64,
    ttl_ms: u64,
) -> bool {
    entry_generation != current_generation || elapsed_ms >= ttl_ms
}

/// Abstract cache key computation.
///
/// We model only the case-normalization property: the key must be the same
/// regardless of the case of the tool/function input.
pub fn normalize_for_key(s: &str) -> String {
    s.to_lowercase()
}

/// ASCII-only case normalization for Kani proofs.
/// Avoids std to_lowercase() which encodes the full Unicode case mapping table
/// and creates SAT formulas too large for bounded model checking.
/// Production uses to_lowercase(); this proves the same property for ASCII.
#[cfg(kani)]
pub fn normalize_for_key_ascii(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b >= b'A' && b <= b'Z' {
            out.push(b + 32);
        } else {
            out.push(b);
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_context_is_cacheable() {
        let fields = CacheabilityFields {
            has_timestamp: false,
            has_call_counts: false,
            has_previous_actions: false,
            has_call_chain: false,
            has_capability_token: false,
            has_session_state: false,
            has_verification_tier: false,
            context_present: false,
        };
        assert!(is_cacheable_context(&fields));
    }

    #[test]
    fn test_empty_context_is_cacheable() {
        let fields = CacheabilityFields {
            has_timestamp: false,
            has_call_counts: false,
            has_previous_actions: false,
            has_call_chain: false,
            has_capability_token: false,
            has_session_state: false,
            has_verification_tier: false,
            context_present: true,
        };
        assert!(is_cacheable_context(&fields));
    }

    #[test]
    fn test_session_state_not_cacheable() {
        let fields = CacheabilityFields {
            has_timestamp: false,
            has_call_counts: false,
            has_previous_actions: false,
            has_call_chain: false,
            has_capability_token: false,
            has_session_state: true,
            has_verification_tier: false,
            context_present: true,
        };
        assert!(!is_cacheable_context(&fields));
    }

    #[test]
    fn test_stale_on_generation_mismatch() {
        assert!(is_stale(1, 2, 0, 1000));
    }

    #[test]
    fn test_stale_on_ttl_expired() {
        assert!(is_stale(1, 1, 1001, 1000));
    }

    #[test]
    fn test_fresh_entry() {
        assert!(!is_stale(1, 1, 500, 1000));
    }

    #[test]
    fn test_normalize_case() {
        assert_eq!(normalize_for_key("ReadFile"), normalize_for_key("readfile"));
    }
}
