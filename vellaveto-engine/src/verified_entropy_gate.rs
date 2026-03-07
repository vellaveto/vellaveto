// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified fixed-point entropy alert kernel.
//!
//! This module contains the integer-only decision logic used after the
//! float-to-fixed conversion in `entropy_gate.rs`. It is the intended Verus
//! proof boundary for the steganographic alert gate in `collusion.rs`.

/// Severity tier for repeated high-entropy observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntropyAlertLevel {
    Medium,
    High,
}

/// Return true when a fixed-point entropy observation is at or above the
/// configured fixed-point threshold.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn is_high_entropy_millibits(
    observation_millibits: u16,
    threshold_millibits: u16,
) -> bool {
    observation_millibits >= threshold_millibits
}

/// Return true when the high-entropy sample count reaches the configured alert
/// threshold.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn should_alert_on_high_entropy_count(
    high_entropy_count: u32,
    min_entropy_observations: u32,
) -> bool {
    high_entropy_count >= min_entropy_observations
}

/// Saturating double of the minimum alert threshold used for high severity.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn high_severity_entropy_threshold(min_entropy_observations: u32) -> u32 {
    if min_entropy_observations > u32::MAX / 2 {
        u32::MAX
    } else {
        min_entropy_observations * 2
    }
}

/// Compute the severity tier once the alert threshold has been reached.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn entropy_alert_level(
    high_entropy_count: u32,
    min_entropy_observations: u32,
) -> EntropyAlertLevel {
    if high_entropy_count >= high_severity_entropy_threshold(min_entropy_observations) {
        EntropyAlertLevel::High
    } else {
        EntropyAlertLevel::Medium
    }
}

/// Return the alert severity for the current high-entropy count, or `None`
/// when the alert threshold has not been reached.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn entropy_alert_severity(
    high_entropy_count: u32,
    min_entropy_observations: u32,
) -> Option<EntropyAlertLevel> {
    if should_alert_on_high_entropy_count(high_entropy_count, min_entropy_observations) {
        Some(entropy_alert_level(
            high_entropy_count,
            min_entropy_observations,
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_high_entropy_millibits() {
        assert!(is_high_entropy_millibits(6500, 6500));
        assert!(!is_high_entropy_millibits(6499, 6500));
    }

    #[test]
    fn test_should_alert_on_high_entropy_count() {
        assert!(!should_alert_on_high_entropy_count(2, 3));
        assert!(should_alert_on_high_entropy_count(3, 3));
    }

    #[test]
    fn test_high_severity_entropy_threshold() {
        assert_eq!(high_severity_entropy_threshold(3), 6);
        assert_eq!(high_severity_entropy_threshold(u32::MAX), u32::MAX);
    }

    #[test]
    fn test_entropy_alert_level() {
        assert_eq!(entropy_alert_level(3, 3), EntropyAlertLevel::Medium);
        assert_eq!(entropy_alert_level(6, 3), EntropyAlertLevel::High);
    }

    #[test]
    fn test_entropy_alert_severity() {
        assert_eq!(entropy_alert_severity(2, 3), None);
        assert_eq!(
            entropy_alert_severity(3, 3),
            Some(EntropyAlertLevel::Medium)
        );
        assert_eq!(entropy_alert_severity(6, 3), Some(EntropyAlertLevel::High));
    }
}
