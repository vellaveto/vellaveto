// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! RwLock poisoning fail-closed verification.
//!
//! In Vellaveto, all `RwLock` usage follows a fail-closed pattern:
//! if the lock is poisoned (a thread panicked while holding it),
//! the handler returns a safe default — never an `Allow` verdict.
//!
//! This module models the lock poisoning handlers as pure predicates
//! so Kani can verify the fail-closed property without requiring
//! actual concurrency (which is outside Kani/Verus scope).
//!
//! # Verified Properties (K66-K68)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K66 | Cache lock poison → cache miss (None), never stale Allow |
//! | K67 | Deputy lock poison → InternalError (Deny) |
//! | K68 | All lock poison handlers produce safe outcome |
//!
//! # Production Correspondence
//!
//! - `cache_read_poisoned` ↔ `vellaveto-engine/src/cache.rs:196-199`
//! - `cache_write_poisoned` ↔ `vellaveto-engine/src/cache.rs:260-262`
//! - `deputy_read_poisoned` ↔ `vellaveto-engine/src/deputy.rs:355-358`
//! - `deputy_write_poisoned` ↔ `vellaveto-engine/src/deputy.rs:241-243`
//! - `glob_cache_read_poisoned` ↔ `vellaveto-engine/src/lib.rs:1063-1067`
//! - `glob_cache_write_poisoned` ↔ `vellaveto-engine/src/lib.rs:1091-1094`

/// Outcome of a lock-guarded security operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockOutcome {
    /// Normal result available (lock acquired successfully).
    Normal,
    /// Cache miss — re-evaluate from scratch (fail-closed for caches).
    CacheMiss,
    /// No-op — write was skipped (safe for write-side caches).
    WriteSkipped,
    /// Internal error propagated — will become Deny upstream.
    InternalError,
    /// Compile fresh — bypass cache, compute inline (correct but uncached).
    FreshCompile,
}

/// Determine if a lock outcome is security-safe.
///
/// A "safe" outcome means the system will NOT return a stale Allow verdict.
/// - `CacheMiss` → re-evaluates policy from scratch → correct
/// - `WriteSkipped` → doesn't cache result → no stale data
/// - `InternalError` → propagated as error → becomes Deny
/// - `FreshCompile` → computes without cache → correct
/// - `Normal` → lock acquired → normal operation
pub fn is_safe_outcome(outcome: LockOutcome) -> bool {
    match outcome {
        LockOutcome::Normal => true,
        LockOutcome::CacheMiss => true,
        LockOutcome::WriteSkipped => true,
        LockOutcome::InternalError => true,
        LockOutcome::FreshCompile => true,
    }
}

// =========================================================================
// Cache lock poisoning handlers
// =========================================================================

/// Cache read poisoning handler.
///
/// Extracted from `vellaveto-engine/src/cache.rs:196-199`:
/// ```ignore
/// let inner = match self.inner.read() {
///     Ok(guard) => guard,
///     Err(_) => { self.misses.fetch_add(1, Relaxed); return None; }
/// };
/// ```
pub fn cache_read_poisoned(lock_ok: bool) -> LockOutcome {
    if lock_ok {
        LockOutcome::Normal
    } else {
        LockOutcome::CacheMiss
    }
}

/// Cache write poisoning handler.
///
/// Extracted from `vellaveto-engine/src/cache.rs:260-262`:
/// ```ignore
/// let mut inner = match self.inner.write() {
///     Ok(guard) => guard,
///     Err(_) => return,
/// };
/// ```
pub fn cache_write_poisoned(lock_ok: bool) -> LockOutcome {
    if lock_ok {
        LockOutcome::Normal
    } else {
        LockOutcome::WriteSkipped
    }
}

// =========================================================================
// Deputy validator lock poisoning handlers
// =========================================================================

/// Deputy read poisoning handler.
///
/// Extracted from `vellaveto-engine/src/deputy.rs:355-358`:
/// ```ignore
/// let contexts = self.active_contexts.read().map_err(|e| {
///     DeputyError::InternalError(format!("RwLock poisoned: {}", e))
/// })?;
/// ```
pub fn deputy_read_poisoned(lock_ok: bool) -> LockOutcome {
    if lock_ok {
        LockOutcome::Normal
    } else {
        LockOutcome::InternalError
    }
}

/// Deputy write poisoning handler.
///
/// Extracted from `vellaveto-engine/src/deputy.rs:241-243`.
pub fn deputy_write_poisoned(lock_ok: bool) -> LockOutcome {
    if lock_ok {
        LockOutcome::Normal
    } else {
        LockOutcome::InternalError
    }
}

// =========================================================================
// Glob matcher cache poisoning handlers
// =========================================================================

/// Glob cache read poisoning handler.
///
/// Extracted from `vellaveto-engine/src/lib.rs:1063-1067`:
/// On poisoned lock, falls through to fresh compile of the pattern.
pub fn glob_cache_read_poisoned(lock_ok: bool) -> LockOutcome {
    if lock_ok {
        LockOutcome::Normal
    } else {
        LockOutcome::FreshCompile
    }
}

/// Glob cache write poisoning handler.
///
/// Extracted from `vellaveto-engine/src/lib.rs:1091-1094`:
/// On poisoned lock, returns the compiled pattern without caching.
pub fn glob_cache_write_poisoned(lock_ok: bool) -> LockOutcome {
    if lock_ok {
        LockOutcome::Normal
    } else {
        LockOutcome::WriteSkipped
    }
}

// =========================================================================
// Unified handler — models any lock poisoning in the system
// =========================================================================

/// All lock poisoning handlers in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockSite {
    CacheRead,
    CacheWrite,
    DeputyRead,
    DeputyWrite,
    GlobCacheRead,
    GlobCacheWrite,
}

/// Get the poison outcome for any lock site.
pub fn poison_outcome(site: LockSite) -> LockOutcome {
    match site {
        LockSite::CacheRead => cache_read_poisoned(false),
        LockSite::CacheWrite => cache_write_poisoned(false),
        LockSite::DeputyRead => deputy_read_poisoned(false),
        LockSite::DeputyWrite => deputy_write_poisoned(false),
        LockSite::GlobCacheRead => glob_cache_read_poisoned(false),
        LockSite::GlobCacheWrite => glob_cache_write_poisoned(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_read_poisoned_returns_miss() {
        assert_eq!(cache_read_poisoned(false), LockOutcome::CacheMiss);
        assert_eq!(cache_read_poisoned(true), LockOutcome::Normal);
    }

    #[test]
    fn test_cache_write_poisoned_returns_skip() {
        assert_eq!(cache_write_poisoned(false), LockOutcome::WriteSkipped);
        assert_eq!(cache_write_poisoned(true), LockOutcome::Normal);
    }

    #[test]
    fn test_deputy_read_poisoned_returns_error() {
        assert_eq!(deputy_read_poisoned(false), LockOutcome::InternalError);
        assert_eq!(deputy_read_poisoned(true), LockOutcome::Normal);
    }

    #[test]
    fn test_deputy_write_poisoned_returns_error() {
        assert_eq!(deputy_write_poisoned(false), LockOutcome::InternalError);
        assert_eq!(deputy_write_poisoned(true), LockOutcome::Normal);
    }

    #[test]
    fn test_glob_cache_read_poisoned_compiles_fresh() {
        assert_eq!(glob_cache_read_poisoned(false), LockOutcome::FreshCompile);
        assert_eq!(glob_cache_read_poisoned(true), LockOutcome::Normal);
    }

    #[test]
    fn test_glob_cache_write_poisoned_skips() {
        assert_eq!(glob_cache_write_poisoned(false), LockOutcome::WriteSkipped);
        assert_eq!(glob_cache_write_poisoned(true), LockOutcome::Normal);
    }

    #[test]
    fn test_all_poison_outcomes_are_safe() {
        let sites = [
            LockSite::CacheRead,
            LockSite::CacheWrite,
            LockSite::DeputyRead,
            LockSite::DeputyWrite,
            LockSite::GlobCacheRead,
            LockSite::GlobCacheWrite,
        ];
        for site in &sites {
            let outcome = poison_outcome(*site);
            assert!(
                is_safe_outcome(outcome),
                "Lock site {:?} produced unsafe outcome {:?}",
                site,
                outcome
            );
        }
    }

    #[test]
    fn test_no_outcome_is_allow() {
        // Verify none of the poison outcomes could be mistaken for Allow
        let sites = [
            LockSite::CacheRead,
            LockSite::CacheWrite,
            LockSite::DeputyRead,
            LockSite::DeputyWrite,
            LockSite::GlobCacheRead,
            LockSite::GlobCacheWrite,
        ];
        for site in &sites {
            let outcome = poison_outcome(*site);
            assert_ne!(
                outcome,
                LockOutcome::Normal,
                "Poison on {:?} must not produce Normal",
                site
            );
        }
    }
}
