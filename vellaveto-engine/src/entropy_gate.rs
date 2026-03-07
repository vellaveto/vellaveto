// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Fixed-point entropy decision helpers.
//!
//! These helpers are the security decision boundary for collusion entropy
//! alerts. Raw `f64` entropy values remain available for telemetry and
//! evidence, but alert gating uses millibit scores to keep the comparison
//! semantics centralized and deterministic.

pub(crate) use crate::verified_entropy_gate::{
    entropy_alert_severity, is_high_entropy_millibits, EntropyAlertLevel,
};

/// Fixed-point scale for entropy alert decisions (1/1000 bit precision).
pub(crate) const ENTROPY_DECISION_SCALE: u16 = 1000;
/// Maximum Shannon entropy for byte data, scaled to millibits.
pub(crate) const MAX_ENTROPY_DECISION_MILLIBITS: u16 = 8 * ENTROPY_DECISION_SCALE;

pub(crate) fn entropy_fixed_point(bits_per_byte: f64, round_up: bool) -> u16 {
    if !bits_per_byte.is_finite() {
        return 0;
    }

    let clamped = bits_per_byte.clamp(0.0, 8.0);
    let scaled = clamped * f64::from(ENTROPY_DECISION_SCALE);
    let rounded = if round_up {
        scaled.ceil()
    } else {
        scaled.floor()
    };

    if rounded <= 0.0 {
        0
    } else if rounded >= f64::from(MAX_ENTROPY_DECISION_MILLIBITS) {
        MAX_ENTROPY_DECISION_MILLIBITS
    } else {
        rounded as u16
    }
}

/// Convert a configured entropy threshold into the conservative decision score.
pub(crate) fn entropy_threshold_millibits(threshold_bits: f64) -> u16 {
    entropy_fixed_point(threshold_bits, false)
}

/// Convert an observed entropy value into the conservative decision score.
pub(crate) fn entropy_observation_millibits(bits_per_byte: f64) -> u16 {
    entropy_fixed_point(bits_per_byte, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verified_entropy_gate::{entropy_alert_level, high_severity_entropy_threshold};

    #[test]
    fn test_entropy_threshold_millibits_rounds_down() {
        assert_eq!(entropy_threshold_millibits(6.5), 6500);
        assert_eq!(entropy_threshold_millibits(6.9999), 6999);
    }

    #[test]
    fn test_entropy_observation_millibits_rounds_up() {
        assert_eq!(entropy_observation_millibits(6.5), 6500);
        assert_eq!(entropy_observation_millibits(6.4991), 6500);
    }

    #[test]
    fn test_is_high_entropy_millibits_uses_fixed_point_boundary() {
        let threshold = entropy_threshold_millibits(6.5);
        assert!(is_high_entropy_millibits(
            entropy_observation_millibits(6.5),
            threshold,
        ));
        assert!(!is_high_entropy_millibits(
            entropy_observation_millibits(6.498),
            threshold,
        ));
    }

    #[test]
    fn test_entropy_alert_helpers_delegate_to_verified_kernel() {
        assert_eq!(high_severity_entropy_threshold(3), 6);
        assert_eq!(
            entropy_alert_severity(3, 3),
            Some(EntropyAlertLevel::Medium)
        );
        assert_eq!(entropy_alert_level(6, 3), EntropyAlertLevel::High);
    }
}
