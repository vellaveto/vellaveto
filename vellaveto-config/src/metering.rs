// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

// ═══════════════════════════════════════════════════════════════════════════════
// METERING — Usage metering configuration for per-tenant billing
// ═══════════════════════════════════════════════════════════════════════════════
//
// Phase 50: Usage Metering & Billing Foundation.
// Controls per-tenant usage tracking, billing period boundaries, quota warning
// thresholds, and per-tier evaluation limits.

use serde::{Deserialize, Serialize};

fn default_period_start_day() -> u8 {
    1
}

fn default_warning_threshold() -> f32 {
    0.8
}

fn default_community_evaluations() -> u64 {
    10_000
}

fn default_pro_evaluations() -> u64 {
    100_000
}

fn default_business_evaluations() -> u64 {
    1_000_000
}

fn default_enterprise_evaluations() -> u64 {
    // Use i64::MAX to stay within TOML's integer range (signed 64-bit).
    // i64::MAX as u64 would fail TOML serialization which uses i64 internally.
    i64::MAX as u64
}

/// Usage metering configuration.
///
/// When enabled, tracks per-tenant usage counters (evaluations, policies,
/// approvals, audit entries) per billing period and enforces hard evaluation
/// quotas. Disabled by default for backward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeteringConfig {
    /// Whether usage metering is enabled (default: false).
    #[serde(default)]
    pub enabled: bool,

    /// Day of month for billing period start (1-28, default: 1).
    /// Capped at 28 to avoid month-length ambiguity.
    #[serde(default = "default_period_start_day")]
    pub period_start_day: u8,

    /// Percentage threshold for quota warning (0.0-1.0, default: 0.8).
    /// When a tenant reaches this fraction of their evaluation limit,
    /// a warning is logged.
    #[serde(default = "default_warning_threshold")]
    pub quota_warning_threshold: f32,

    /// Per-tier evaluation limits per billing period.
    #[serde(default)]
    pub tier_limits: TierUsageLimits,
}

impl Default for MeteringConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            period_start_day: default_period_start_day(),
            quota_warning_threshold: default_warning_threshold(),
            tier_limits: TierUsageLimits::default(),
        }
    }
}

impl MeteringConfig {
    /// Validate metering configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.period_start_day == 0 || self.period_start_day > 28 {
            return Err(format!(
                "metering.period_start_day must be in [1, 28], got {}",
                self.period_start_day
            ));
        }
        if !self.quota_warning_threshold.is_finite()
            || self.quota_warning_threshold < 0.0
            || self.quota_warning_threshold > 1.0
        {
            return Err(format!(
                "metering.quota_warning_threshold must be in [0.0, 1.0], got {}",
                self.quota_warning_threshold
            ));
        }
        self.tier_limits.validate()?;
        Ok(())
    }
}

/// Per-tier evaluation limits per billing period.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierUsageLimits {
    /// Maximum evaluations per period for Community tier (default: 10,000).
    #[serde(default = "default_community_evaluations")]
    pub community_evaluations_per_month: u64,

    /// Maximum evaluations per period for Pro tier (default: 100,000).
    #[serde(default = "default_pro_evaluations")]
    pub pro_evaluations_per_month: u64,

    /// Maximum evaluations per period for Business tier (default: 1,000,000).
    #[serde(default = "default_business_evaluations")]
    pub business_evaluations_per_month: u64,

    /// Maximum evaluations per period for Enterprise tier (default: unlimited).
    #[serde(default = "default_enterprise_evaluations")]
    pub enterprise_evaluations_per_month: u64,
}

impl Default for TierUsageLimits {
    fn default() -> Self {
        Self {
            community_evaluations_per_month: default_community_evaluations(),
            pro_evaluations_per_month: default_pro_evaluations(),
            business_evaluations_per_month: default_business_evaluations(),
            enterprise_evaluations_per_month: default_enterprise_evaluations(),
        }
    }
}

impl TierUsageLimits {
    /// Validate tier usage limits.
    pub fn validate(&self) -> Result<(), String> {
        // All limits must be > 0 (0 would block all evaluations unconditionally).
        if self.community_evaluations_per_month == 0 {
            return Err(
                "metering.tier_limits.community_evaluations_per_month must be > 0".to_string(),
            );
        }
        if self.pro_evaluations_per_month == 0 {
            return Err("metering.tier_limits.pro_evaluations_per_month must be > 0".to_string());
        }
        if self.business_evaluations_per_month == 0 {
            return Err(
                "metering.tier_limits.business_evaluations_per_month must be > 0".to_string(),
            );
        }
        if self.enterprise_evaluations_per_month == 0 {
            return Err(
                "metering.tier_limits.enterprise_evaluations_per_month must be > 0".to_string(),
            );
        }
        Ok(())
    }

    /// Return the evaluation limit for the given license tier.
    pub fn limit_for_tier(&self, tier: &crate::LicenseTier) -> u64 {
        match tier {
            crate::LicenseTier::Community => self.community_evaluations_per_month,
            crate::LicenseTier::Pro => self.pro_evaluations_per_month,
            crate::LicenseTier::Business => self.business_evaluations_per_month,
            crate::LicenseTier::Enterprise => self.enterprise_evaluations_per_month,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metering_config_defaults() {
        let config = MeteringConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.period_start_day, 1);
        assert!((config.quota_warning_threshold - 0.8).abs() < f32::EPSILON);
        assert_eq!(config.tier_limits.community_evaluations_per_month, 10_000);
        assert_eq!(config.tier_limits.pro_evaluations_per_month, 100_000);
        assert_eq!(config.tier_limits.business_evaluations_per_month, 1_000_000);
        assert_eq!(
            config.tier_limits.enterprise_evaluations_per_month,
            i64::MAX as u64
        );
    }

    #[test]
    fn test_metering_config_validate_ok() {
        let config = MeteringConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_metering_config_validate_period_start_day_zero() {
        let config = MeteringConfig {
            period_start_day: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("period_start_day"));
    }

    #[test]
    fn test_metering_config_validate_period_start_day_29() {
        let config = MeteringConfig {
            period_start_day: 29,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("period_start_day"));
    }

    #[test]
    fn test_metering_config_validate_warning_threshold_nan() {
        let config = MeteringConfig {
            quota_warning_threshold: f32::NAN,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("quota_warning_threshold"));
    }

    #[test]
    fn test_metering_config_validate_warning_threshold_negative() {
        let config = MeteringConfig {
            quota_warning_threshold: -0.1,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_metering_config_validate_warning_threshold_over_one() {
        let config = MeteringConfig {
            quota_warning_threshold: 1.1,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_tier_limits_validate_zero_community() {
        let limits = TierUsageLimits {
            community_evaluations_per_month: 0,
            ..Default::default()
        };
        assert!(limits.validate().is_err());
    }

    #[test]
    fn test_tier_limits_limit_for_tier() {
        let limits = TierUsageLimits::default();
        assert_eq!(
            limits.limit_for_tier(&crate::LicenseTier::Community),
            10_000
        );
        assert_eq!(limits.limit_for_tier(&crate::LicenseTier::Pro), 100_000);
        assert_eq!(
            limits.limit_for_tier(&crate::LicenseTier::Enterprise),
            i64::MAX as u64
        );
    }

    #[test]
    fn test_metering_config_serde_roundtrip() {
        let config = MeteringConfig {
            enabled: true,
            period_start_day: 15,
            quota_warning_threshold: 0.9,
            tier_limits: TierUsageLimits::default(),
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let parsed: MeteringConfig = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.enabled);
        assert_eq!(parsed.period_start_day, 15);
    }

    #[test]
    fn test_metering_config_deny_unknown_fields() {
        let json = r#"{"enabled": true, "unknown_field": "bad"}"#;
        let result: Result<MeteringConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_tier_limits_deny_unknown_fields() {
        let json = r#"{"community_evaluations_per_month": 100, "extra": true}"#;
        let result: Result<TierUsageLimits, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
