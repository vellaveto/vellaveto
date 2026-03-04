// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Cascading failure circuit breaker verification extracted from
//! `vellaveto-engine/src/cascading.rs`.
//!
//! Pure predicates for config validation, capacity enforcement,
//! error rate computation, and depth tracking.
//!
//! # Verified Properties (K49-K52)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K49 | NaN/Infinity in config → rejected |
//! | K50 | Chain depth increment never wraps |
//! | K51 | At MAX capacity → Deny |
//! | K52 | Error rate always in [0.0, 1.0] |
//!
//! # Production Correspondence
//!
//! - `validate_config` ↔ `vellaveto-engine/src/cascading.rs:178-216`
//! - `compute_error_rate` ↔ `vellaveto-engine/src/cascading.rs:638-665`

/// Maximum tracked chains and pipelines (mirrors production constants).
pub const MAX_TRACKED_CHAINS: usize = 10_000;
pub const MAX_TRACKED_PIPELINES: usize = 50_000;
pub const ABSOLUTE_MAX_CHAIN_DEPTH: u32 = 64;
pub const MAX_MIN_WINDOW_EVENTS: u32 = 100_000;

/// Validate cascading config fields.
///
/// Verbatim from production `CascadingConfig::validate`.
pub fn validate_config(
    max_chain_depth: u32,
    error_rate_threshold: f64,
    window_secs: u64,
    break_duration_secs: u64,
    min_window_events: u32,
) -> bool {
    if max_chain_depth == 0 || max_chain_depth > ABSOLUTE_MAX_CHAIN_DEPTH {
        return false;
    }
    if !error_rate_threshold.is_finite()
        || error_rate_threshold < 0.0
        || error_rate_threshold > 1.0
    {
        return false;
    }
    if window_secs == 0 {
        return false;
    }
    if break_duration_secs == 0 {
        return false;
    }
    if min_window_events > MAX_MIN_WINDOW_EVENTS {
        return false;
    }
    true
}

/// Check capacity for new chain entry (fail-closed).
///
/// Verbatim from production `enter_chain` capacity check.
pub fn check_chain_capacity(current_chains: usize) -> bool {
    current_chains < MAX_TRACKED_CHAINS
}

/// Check capacity for new pipeline entry (fail-closed).
///
/// Verbatim from production `record_pipeline_event` capacity check.
pub fn check_pipeline_capacity(current_pipelines: usize, pipeline_exists: bool) -> bool {
    pipeline_exists || current_pipelines < MAX_TRACKED_PIPELINES
}

/// Compute error rate from event counts.
///
/// Verbatim from production `compute_error_rate_inner`.
pub fn compute_error_rate(total_events: u64, error_events: u64) -> f64 {
    if total_events == 0 {
        return 0.0;
    }
    let rate = error_events as f64 / total_events as f64;
    if !rate.is_finite() {
        return 1.0; // Fail-closed
    }
    rate
}

/// Saturating chain depth increment.
pub fn increment_depth(current: u32) -> u32 {
    current.saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_rejects_nan() {
        assert!(!validate_config(1, f64::NAN, 60, 30, 10));
    }

    #[test]
    fn test_validate_rejects_infinity() {
        assert!(!validate_config(1, f64::INFINITY, 60, 30, 10));
    }

    #[test]
    fn test_validate_rejects_negative_rate() {
        assert!(!validate_config(1, -0.1, 60, 30, 10));
    }

    #[test]
    fn test_validate_rejects_zero_depth() {
        assert!(!validate_config(0, 0.5, 60, 30, 10));
    }

    #[test]
    fn test_validate_accepts_valid() {
        assert!(validate_config(10, 0.5, 60, 30, 10));
    }

    #[test]
    fn test_capacity_at_max_denied() {
        assert!(!check_chain_capacity(MAX_TRACKED_CHAINS));
    }

    #[test]
    fn test_error_rate_zero_events() {
        assert_eq!(compute_error_rate(0, 0), 0.0);
    }

    #[test]
    fn test_error_rate_bounded() {
        let rate = compute_error_rate(100, 50);
        assert!(rate >= 0.0 && rate <= 1.0);
    }

    #[test]
    fn test_depth_saturating() {
        assert_eq!(increment_depth(u32::MAX), u32::MAX);
    }
}
