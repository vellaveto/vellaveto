// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Temporal window correctness verification for collusion detection.
//!
//! Extracts the sliding-window event expiry logic from
//! `vellaveto-engine/src/collusion.rs` and the cascading failure
//! pipeline event tracking.
//!
//! # Verified Properties (K71-K72)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K71 | Events outside window are correctly expired (no stale events) |
//! | K72 | Window boundary precision: events at exactly cutoff are included |
//!
//! # Production Correspondence
//!
//! - `expire_events` ↔ cascading.rs:588-596 (event eviction loop)
//! - `count_in_window` ↔ collusion.rs compute_error_rate_inner pattern

use std::collections::VecDeque;

/// Maximum events retained per resource/pipeline.
pub const MAX_EVENTS: usize = 1_000;

/// A timestamped event in a sliding window.
#[derive(Debug, Clone)]
pub struct WindowEvent {
    pub timestamp: u64,
    pub is_error: bool,
}

/// Count the expired prefix of an ordered event slice.
///
/// Events with `timestamp < cutoff` are expired. The returned count is the
/// number of consecutive expired events from the front of the slice.
pub fn expired_prefix_len(events: &[WindowEvent], now: u64, window_secs: u64) -> usize {
    let cutoff = now.saturating_sub(window_secs);
    let mut idx = 0usize;
    while idx < events.len() {
        if events[idx].timestamp < cutoff {
            idx += 1;
        } else {
            break;
        }
    }
    idx
}

/// Count events within the window using a plain slice walk.
pub fn count_in_window_slice(events: &[WindowEvent], now: u64, window_secs: u64) -> (u64, u64) {
    let cutoff = now.saturating_sub(window_secs);
    let mut total = 0u64;
    let mut errors = 0u64;
    let mut idx = 0usize;

    while idx < events.len() {
        let event = &events[idx];
        if event.timestamp >= cutoff {
            total = total.saturating_add(1);
            if event.is_error {
                errors = errors.saturating_add(1);
            }
        }
        idx += 1;
    }

    (total, errors)
}

/// Expire events outside the window.
///
/// Extracted from cascading.rs:588-596.
/// Events with `timestamp < cutoff` are removed from the front of the deque.
pub fn expire_events(events: &mut VecDeque<WindowEvent>, now: u64, window_secs: u64) {
    let (front, back) = events.as_slices();
    let front_expired = expired_prefix_len(front, now, window_secs);
    let expired = if front_expired < front.len() {
        front_expired
    } else {
        front.len() + expired_prefix_len(back, now, window_secs)
    };

    let mut removed = 0usize;
    while removed < expired {
        events.pop_front();
        removed += 1;
    }
}

/// Count events within the window.
///
/// Extracted from collusion.rs and cascading.rs error rate computation.
/// Events with `timestamp >= cutoff` are counted.
pub fn count_in_window(events: &VecDeque<WindowEvent>, now: u64, window_secs: u64) -> (u64, u64) {
    let (front, back) = events.as_slices();
    let (front_total, front_errors) = count_in_window_slice(front, now, window_secs);
    let (back_total, back_errors) = count_in_window_slice(back, now, window_secs);
    (
        front_total.saturating_add(back_total),
        front_errors.saturating_add(back_errors),
    )
}

/// Add an event with bounded capacity.
///
/// Extracted from cascading.rs:598-606.
pub fn add_event(events: &mut VecDeque<WindowEvent>, now: u64, window_secs: u64, is_error: bool) {
    // First expire old events
    expire_events(events, now, window_secs);

    // Then bound capacity
    if events.len() >= MAX_EVENTS {
        events.pop_front();
    }

    events.push_back(WindowEvent {
        timestamp: now,
        is_error,
    });
}

/// Compute error rate from window counts.
///
/// Extracted from cascading.rs:638-665.
pub fn compute_error_rate(total: u64, errors: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let rate = errors as f64 / total as f64;
    if !rate.is_finite() {
        return 1.0; // Fail-closed
    }
    rate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expire_removes_old_events() {
        let mut events = VecDeque::new();
        events.push_back(WindowEvent {
            timestamp: 10,
            is_error: false,
        });
        events.push_back(WindowEvent {
            timestamp: 50,
            is_error: false,
        });
        events.push_back(WindowEvent {
            timestamp: 100,
            is_error: false,
        });

        expire_events(&mut events, 120, 60);
        // cutoff = 60. Events at 10 and 50 are < 60, so removed.
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp, 100);
    }

    #[test]
    fn test_boundary_event_included() {
        let mut events = VecDeque::new();
        events.push_back(WindowEvent {
            timestamp: 60,
            is_error: false,
        });

        // cutoff = 120 - 60 = 60. Event at exactly 60 has timestamp >= cutoff.
        let (total, _) = count_in_window(&events, 120, 60);
        assert_eq!(
            total, 1,
            "Event at exactly cutoff boundary should be included"
        );
    }

    #[test]
    fn test_boundary_event_excluded() {
        let mut events = VecDeque::new();
        events.push_back(WindowEvent {
            timestamp: 59,
            is_error: false,
        });

        // cutoff = 120 - 60 = 60. Event at 59 < 60, so excluded.
        let (total, _) = count_in_window(&events, 120, 60);
        assert_eq!(total, 0, "Event before cutoff should be excluded");
    }

    #[test]
    fn test_error_rate_bounded() {
        for total in 0..=100u64 {
            for errors in 0..=total {
                let rate = compute_error_rate(total, errors);
                assert!(
                    rate >= 0.0 && rate <= 1.0,
                    "Error rate {rate} out of [0,1] for total={total}, errors={errors}"
                );
            }
        }
    }

    #[test]
    fn test_add_event_bounded() {
        let mut events = VecDeque::new();
        for i in 0..MAX_EVENTS + 10 {
            add_event(&mut events, i as u64, u64::MAX, false);
        }
        assert!(events.len() <= MAX_EVENTS, "Events should be bounded");
    }

    #[test]
    fn test_saturating_sub_at_zero() {
        let mut events = VecDeque::new();
        events.push_back(WindowEvent {
            timestamp: 0,
            is_error: false,
        });
        // now=5, window=100 → cutoff = 5.saturating_sub(100) = 0
        // Event at 0 >= 0, so included
        let (total, _) = count_in_window(&events, 5, 100);
        assert_eq!(
            total, 1,
            "Event at 0 with saturating_sub cutoff=0 should be included"
        );
    }
}
