// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Cascading failure FSM implementation-level state transition verification.
//!
//! Extracts the circuit breaker state machine from
//! `vellaveto-engine/src/cascading.rs` at the implementation level:
//! actual state fields (`is_broken`, `broken_at`), transition guards,
//! and timing conditions.
//!
//! The TLA+ CascadingFailure.tla models this abstractly; these Kani
//! harnesses verify the Rust implementation matches.
//!
//! # Verified Properties (K73-K75)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K73 | Valid transitions only: Closed→Open requires error_rate ≥ threshold AND min_events |
//! | K74 | Half-open probe: broken pipeline allows probe after break_duration elapsed |
//! | K75 | Recovery: Open→Closed requires error_rate < threshold after break_duration |
//!
//! # Production Correspondence
//!
//! - `transition_to_open` ↔ cascading.rs:526-551 (record_pipeline_error break check)
//! - `should_allow_probe` ↔ cascading.rs:484-488 (check_pipeline half-open logic)
//! - `try_recover` ↔ cascading.rs:609-631 (record_pipeline_event recovery)

/// Circuit breaker pipeline state (mirrors production PipelineState).
#[derive(Debug, Clone)]
pub struct PipelineState {
    pub is_broken: bool,
    pub broken_at: Option<u64>,
    pub break_count: u32,
    pub error_count_in_window: u64,
    pub total_count_in_window: u64,
}

impl PipelineState {
    pub fn new() -> Self {
        Self {
            is_broken: false,
            broken_at: None,
            break_count: 0,
            error_count_in_window: 0,
            total_count_in_window: 0,
        }
    }
}

/// Configuration for the circuit breaker.
pub struct BreakerConfig {
    pub error_rate_threshold: f64,
    pub min_window_events: u32,
    pub break_duration_secs: u64,
}

/// Compute error rate (extracted from cascading.rs:638-665).
fn compute_error_rate(total: u64, errors: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let rate = errors as f64 / total as f64;
    if !rate.is_finite() {
        return 1.0; // Fail-closed
    }
    rate
}

/// K73: Check if a transition to "open" (broken) should occur.
///
/// Mirrors cascading.rs:526-551.
/// Transition guard: !is_broken AND total_events >= min_window_events
///                   AND error_rate >= error_rate_threshold.
pub fn should_break(state: &PipelineState, config: &BreakerConfig) -> bool {
    if state.is_broken {
        return false; // Already broken — no re-break
    }

    let error_rate = compute_error_rate(state.total_count_in_window, state.error_count_in_window);

    state.total_count_in_window >= config.min_window_events as u64
        && error_rate >= config.error_rate_threshold
}

/// Transition to broken (open) state.
pub fn transition_to_open(state: &mut PipelineState, now: u64) {
    state.is_broken = true;
    state.broken_at = Some(now);
    state.break_count = state.break_count.saturating_add(1);
}

/// K74: Check if a probe should be allowed (half-open).
///
/// Mirrors cascading.rs:484-488.
/// A broken pipeline allows probes after break_duration has elapsed.
pub fn should_allow_probe(state: &PipelineState, now: u64, config: &BreakerConfig) -> bool {
    if !state.is_broken {
        return true; // Not broken — always allow
    }
    match state.broken_at {
        Some(broken_at) => now >= broken_at.saturating_add(config.break_duration_secs),
        None => false, // Broken but no timestamp — don't allow (defensive)
    }
}

/// K75: Try to recover from broken state.
///
/// Mirrors cascading.rs:609-631.
/// Recovery guard: is_broken AND break_duration elapsed AND error_rate < threshold.
pub fn try_recover(state: &mut PipelineState, now: u64, config: &BreakerConfig) -> bool {
    if !state.is_broken {
        return false; // Not broken — nothing to recover
    }
    let duration_elapsed = match state.broken_at {
        Some(broken_at) => now >= broken_at.saturating_add(config.break_duration_secs),
        None => false,
    };
    if !duration_elapsed {
        return false; // Break duration not yet elapsed
    }
    let error_rate = compute_error_rate(state.total_count_in_window, state.error_count_in_window);
    if error_rate < config.error_rate_threshold {
        state.is_broken = false;
        state.broken_at = None;
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> BreakerConfig {
        BreakerConfig {
            error_rate_threshold: 0.5,
            min_window_events: 10,
            break_duration_secs: 30,
        }
    }

    #[test]
    fn test_closed_to_open_requires_threshold() {
        let config = default_config();
        let state = PipelineState {
            is_broken: false,
            broken_at: None,
            break_count: 0,
            error_count_in_window: 4,
            total_count_in_window: 10,
        };
        // 4/10 = 0.4 < 0.5 threshold → should NOT break
        assert!(!should_break(&state, &config));
    }

    #[test]
    fn test_closed_to_open_at_threshold() {
        let config = default_config();
        let state = PipelineState {
            is_broken: false,
            broken_at: None,
            break_count: 0,
            error_count_in_window: 5,
            total_count_in_window: 10,
        };
        // 5/10 = 0.5 >= 0.5 threshold → should break
        assert!(should_break(&state, &config));
    }

    #[test]
    fn test_closed_to_open_requires_min_events() {
        let config = default_config();
        let state = PipelineState {
            is_broken: false,
            broken_at: None,
            break_count: 0,
            error_count_in_window: 9,
            total_count_in_window: 9,
        };
        // 100% error rate but only 9 events < 10 min → should NOT break
        assert!(!should_break(&state, &config));
    }

    #[test]
    fn test_already_broken_no_rebreak() {
        let config = default_config();
        let state = PipelineState {
            is_broken: true,
            broken_at: Some(100),
            break_count: 1,
            error_count_in_window: 10,
            total_count_in_window: 10,
        };
        assert!(!should_break(&state, &config));
    }

    #[test]
    fn test_probe_before_duration() {
        let config = default_config();
        let state = PipelineState {
            is_broken: true,
            broken_at: Some(100),
            break_count: 1,
            error_count_in_window: 0,
            total_count_in_window: 0,
        };
        // now=120, broken_at=100, duration=30 → 120 < 130, no probe
        assert!(!should_allow_probe(&state, 120, &config));
    }

    #[test]
    fn test_probe_after_duration() {
        let config = default_config();
        let state = PipelineState {
            is_broken: true,
            broken_at: Some(100),
            break_count: 1,
            error_count_in_window: 0,
            total_count_in_window: 0,
        };
        // now=130, broken_at=100, duration=30 → 130 >= 130, allow probe
        assert!(should_allow_probe(&state, 130, &config));
    }

    #[test]
    fn test_recovery_requires_low_error_rate() {
        let config = default_config();
        let mut state = PipelineState {
            is_broken: true,
            broken_at: Some(100),
            break_count: 1,
            error_count_in_window: 1,
            total_count_in_window: 10,
        };
        // error_rate = 0.1 < 0.5, duration elapsed (now=200 >= 130)
        assert!(try_recover(&mut state, 200, &config));
        assert!(!state.is_broken);
    }

    #[test]
    fn test_no_recovery_high_error_rate() {
        let config = default_config();
        let mut state = PipelineState {
            is_broken: true,
            broken_at: Some(100),
            break_count: 1,
            error_count_in_window: 8,
            total_count_in_window: 10,
        };
        // error_rate = 0.8 >= 0.5, even though duration elapsed
        assert!(!try_recover(&mut state, 200, &config));
        assert!(state.is_broken);
    }

    #[test]
    fn test_break_count_saturating() {
        let mut state = PipelineState {
            is_broken: false,
            broken_at: None,
            break_count: u32::MAX,
            error_count_in_window: 0,
            total_count_in_window: 0,
        };
        transition_to_open(&mut state, 100);
        assert_eq!(state.break_count, u32::MAX, "break_count must not wrap");
    }

    #[test]
    fn test_fsm_no_impossible_transitions() {
        // Closed state: should_allow_probe always true (not broken)
        let config = default_config();
        let state = PipelineState::new();
        assert!(should_allow_probe(&state, 0, &config));

        // Closed state: try_recover returns false (nothing to recover)
        let mut state2 = PipelineState::new();
        assert!(!try_recover(&mut state2, 0, &config));
    }
}
