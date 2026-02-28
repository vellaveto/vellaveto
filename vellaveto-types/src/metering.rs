// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

// ═══════════════════════════════════════════════════════════════════════════════
// METERING — Per-tenant usage tracking types for billing periods
// ═══════════════════════════════════════════════════════════════════════════════
//
// Phase 50: Usage Metering & Billing Foundation.
// These types represent per-tenant usage counters, quota status, billing periods,
// and historical usage summaries. All types enforce bounds via validate() and
// reject control/format characters in string fields.

use serde::{Deserialize, Serialize};

/// Maximum number of historical periods returned in a usage summary.
pub const MAX_USAGE_PERIODS: usize = 120;

/// Maximum length for tenant_id in metering types (matches tenant validation).
pub const MAX_METERING_TENANT_ID_LEN: usize = 64;

/// Maximum length for ISO 8601 timestamp strings in metering types.
const MAX_TIMESTAMP_LEN: usize = 64;

/// Per-tenant usage counters for a billing period.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageMetrics {
    /// Tenant identifier.
    pub tenant_id: String,
    /// Period start (ISO 8601).
    pub period_start: String,
    /// Period end (ISO 8601).
    pub period_end: String,
    /// Total evaluations in this period.
    pub evaluations: u64,
    /// Evaluations that resulted in Allow.
    pub evaluations_allowed: u64,
    /// Evaluations that resulted in Deny.
    pub evaluations_denied: u64,
    /// Policies created in this period.
    pub policies_created: u64,
    /// Approvals processed (approve + deny) in this period.
    pub approvals_processed: u64,
    /// Audit entries recorded in this period.
    pub audit_entries: u64,
}

impl UsageMetrics {
    /// Validate usage metrics fields.
    pub fn validate(&self) -> Result<(), String> {
        validate_metering_tenant_id(&self.tenant_id)?;
        validate_metering_timestamp(&self.period_start, "period_start")?;
        validate_metering_timestamp(&self.period_end, "period_end")?;
        // evaluations_allowed + evaluations_denied should not exceed total
        // (but we don't enforce this strictly — counters may be updated independently)
        Ok(())
    }
}

/// Quota status for a tenant — usage vs limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaStatus {
    /// Tenant identifier.
    pub tenant_id: String,
    /// Evaluations used in current period.
    pub evaluations_used: u64,
    /// Evaluation limit for current period.
    pub evaluations_limit: u64,
    /// Evaluations remaining (saturating subtraction).
    pub evaluations_remaining: u64,
    /// Policies currently active for this tenant.
    pub policies_used: u64,
    /// Policy limit for this tenant.
    pub policies_limit: u64,
    /// Period start (ISO 8601).
    pub period_start: String,
    /// Period end (ISO 8601).
    pub period_end: String,
    /// Whether the evaluation quota has been exceeded.
    pub quota_exceeded: bool,
}

impl QuotaStatus {
    /// Validate quota status fields.
    pub fn validate(&self) -> Result<(), String> {
        validate_metering_tenant_id(&self.tenant_id)?;
        validate_metering_timestamp(&self.period_start, "period_start")?;
        validate_metering_timestamp(&self.period_end, "period_end")?;
        Ok(())
    }
}

/// Billing period boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingPeriod {
    /// Period start (ISO 8601).
    pub start: String,
    /// Period end (ISO 8601).
    pub end: String,
}

impl BillingPeriod {
    /// Validate billing period fields.
    pub fn validate(&self) -> Result<(), String> {
        validate_metering_timestamp(&self.start, "start")?;
        validate_metering_timestamp(&self.end, "end")?;
        Ok(())
    }
}

/// Usage summary across periods (for historical queries).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageSummary {
    /// Tenant identifier.
    pub tenant_id: String,
    /// Historical usage periods (bounded by MAX_USAGE_PERIODS).
    pub periods: Vec<UsageMetrics>,
    /// Lifetime total evaluations across all returned periods.
    pub total_evaluations: u64,
}

impl UsageSummary {
    /// Validate usage summary fields.
    pub fn validate(&self) -> Result<(), String> {
        validate_metering_tenant_id(&self.tenant_id)?;
        if self.periods.len() > MAX_USAGE_PERIODS {
            return Err(format!(
                "periods has {} entries, max is {}",
                self.periods.len(),
                MAX_USAGE_PERIODS
            ));
        }
        for (i, period) in self.periods.iter().enumerate() {
            period
                .validate()
                .map_err(|e| format!("periods[{}]: {}", i, e))?;
        }
        Ok(())
    }
}

/// Validate a tenant ID for metering types.
fn validate_metering_tenant_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("tenant_id must not be empty".to_string());
    }
    if id.len() > MAX_METERING_TENANT_ID_LEN {
        return Err(format!(
            "tenant_id length {} exceeds max {}",
            id.len(),
            MAX_METERING_TENANT_ID_LEN
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err("tenant_id contains invalid characters".to_string());
    }
    Ok(())
}

/// Validate a timestamp string for metering types.
fn validate_metering_timestamp(ts: &str, field: &str) -> Result<(), String> {
    if ts.is_empty() {
        return Err(format!("{} must not be empty", field));
    }
    if ts.len() > MAX_TIMESTAMP_LEN {
        return Err(format!(
            "{} length {} exceeds max {}",
            field,
            ts.len(),
            MAX_TIMESTAMP_LEN
        ));
    }
    if crate::has_dangerous_chars(ts) {
        return Err(format!("{} contains control or format characters", field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usage_metrics_validate_ok() {
        let m = UsageMetrics {
            tenant_id: "acme".to_string(),
            period_start: "2026-02-01T00:00:00Z".to_string(),
            period_end: "2026-03-01T00:00:00Z".to_string(),
            evaluations: 100,
            evaluations_allowed: 80,
            evaluations_denied: 20,
            policies_created: 5,
            approvals_processed: 3,
            audit_entries: 100,
        };
        assert!(m.validate().is_ok());
    }

    #[test]
    fn test_usage_metrics_validate_empty_tenant() {
        let m = UsageMetrics {
            tenant_id: String::new(),
            period_start: "2026-02-01T00:00:00Z".to_string(),
            period_end: "2026-03-01T00:00:00Z".to_string(),
            evaluations: 0,
            evaluations_allowed: 0,
            evaluations_denied: 0,
            policies_created: 0,
            approvals_processed: 0,
            audit_entries: 0,
        };
        let err = m.validate().unwrap_err();
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn test_usage_metrics_validate_tenant_too_long() {
        let m = UsageMetrics {
            tenant_id: "a".repeat(65),
            period_start: "2026-02-01T00:00:00Z".to_string(),
            period_end: "2026-03-01T00:00:00Z".to_string(),
            evaluations: 0,
            evaluations_allowed: 0,
            evaluations_denied: 0,
            policies_created: 0,
            approvals_processed: 0,
            audit_entries: 0,
        };
        let err = m.validate().unwrap_err();
        assert!(err.contains("exceeds max"));
    }

    #[test]
    fn test_usage_metrics_validate_tenant_invalid_chars() {
        let m = UsageMetrics {
            tenant_id: "acme/corp".to_string(),
            period_start: "2026-02-01T00:00:00Z".to_string(),
            period_end: "2026-03-01T00:00:00Z".to_string(),
            evaluations: 0,
            evaluations_allowed: 0,
            evaluations_denied: 0,
            policies_created: 0,
            approvals_processed: 0,
            audit_entries: 0,
        };
        let err = m.validate().unwrap_err();
        assert!(err.contains("invalid characters"));
    }

    #[test]
    fn test_usage_metrics_validate_empty_timestamp() {
        let m = UsageMetrics {
            tenant_id: "acme".to_string(),
            period_start: String::new(),
            period_end: "2026-03-01T00:00:00Z".to_string(),
            evaluations: 0,
            evaluations_allowed: 0,
            evaluations_denied: 0,
            policies_created: 0,
            approvals_processed: 0,
            audit_entries: 0,
        };
        let err = m.validate().unwrap_err();
        assert!(err.contains("period_start must not be empty"));
    }

    #[test]
    fn test_usage_metrics_validate_timestamp_control_chars() {
        let m = UsageMetrics {
            tenant_id: "acme".to_string(),
            period_start: "2026-02-01\x00T00:00:00Z".to_string(),
            period_end: "2026-03-01T00:00:00Z".to_string(),
            evaluations: 0,
            evaluations_allowed: 0,
            evaluations_denied: 0,
            policies_created: 0,
            approvals_processed: 0,
            audit_entries: 0,
        };
        let err = m.validate().unwrap_err();
        assert!(err.contains("control or format characters"));
    }

    #[test]
    fn test_quota_status_validate_ok() {
        let q = QuotaStatus {
            tenant_id: "acme".to_string(),
            evaluations_used: 50,
            evaluations_limit: 100,
            evaluations_remaining: 50,
            policies_used: 5,
            policies_limit: 100,
            period_start: "2026-02-01T00:00:00Z".to_string(),
            period_end: "2026-03-01T00:00:00Z".to_string(),
            quota_exceeded: false,
        };
        assert!(q.validate().is_ok());
    }

    #[test]
    fn test_billing_period_validate_ok() {
        let bp = BillingPeriod {
            start: "2026-02-01T00:00:00Z".to_string(),
            end: "2026-03-01T00:00:00Z".to_string(),
        };
        assert!(bp.validate().is_ok());
    }

    #[test]
    fn test_billing_period_validate_empty_start() {
        let bp = BillingPeriod {
            start: String::new(),
            end: "2026-03-01T00:00:00Z".to_string(),
        };
        assert!(bp.validate().is_err());
    }

    #[test]
    fn test_usage_summary_validate_ok() {
        let s = UsageSummary {
            tenant_id: "acme".to_string(),
            periods: vec![],
            total_evaluations: 0,
        };
        assert!(s.validate().is_ok());
    }

    #[test]
    fn test_usage_summary_validate_too_many_periods() {
        let periods: Vec<UsageMetrics> = (0..=MAX_USAGE_PERIODS)
            .map(|i| UsageMetrics {
                tenant_id: "acme".to_string(),
                period_start: format!("2026-{:02}-01T00:00:00Z", (i % 12) + 1),
                period_end: format!("2026-{:02}-01T00:00:00Z", (i % 12) + 1),
                evaluations: 0,
                evaluations_allowed: 0,
                evaluations_denied: 0,
                policies_created: 0,
                approvals_processed: 0,
                audit_entries: 0,
            })
            .collect();
        let s = UsageSummary {
            tenant_id: "acme".to_string(),
            periods,
            total_evaluations: 0,
        };
        let err = s.validate().unwrap_err();
        assert!(err.contains("max is"));
    }

    #[test]
    fn test_usage_metrics_serde_roundtrip() {
        let m = UsageMetrics {
            tenant_id: "acme".to_string(),
            period_start: "2026-02-01T00:00:00Z".to_string(),
            period_end: "2026-03-01T00:00:00Z".to_string(),
            evaluations: 42,
            evaluations_allowed: 30,
            evaluations_denied: 12,
            policies_created: 2,
            approvals_processed: 1,
            audit_entries: 42,
        };
        let json = serde_json::to_string(&m).expect("serialize");
        let parsed: UsageMetrics = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.tenant_id, "acme");
        assert_eq!(parsed.evaluations, 42);
    }

    #[test]
    fn test_usage_metrics_deny_unknown_fields() {
        let json = r#"{"tenant_id":"acme","period_start":"2026-02-01","period_end":"2026-03-01","evaluations":0,"evaluations_allowed":0,"evaluations_denied":0,"policies_created":0,"approvals_processed":0,"audit_entries":0,"unknown":"bad"}"#;
        let result: Result<UsageMetrics, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_quota_status_deny_unknown_fields() {
        let json = r#"{"tenant_id":"acme","evaluations_used":0,"evaluations_limit":0,"evaluations_remaining":0,"policies_used":0,"policies_limit":0,"period_start":"x","period_end":"x","quota_exceeded":false,"extra":"bad"}"#;
        let result: Result<QuotaStatus, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_metering_tenant_id_underscore_allowed() {
        // Underscores and hyphens are allowed in tenant IDs
        assert!(validate_metering_tenant_id("my_tenant-1").is_ok());
    }

    #[test]
    fn test_validate_metering_timestamp_too_long() {
        let long_ts = "x".repeat(MAX_TIMESTAMP_LEN + 1);
        let err = validate_metering_timestamp(&long_ts, "test").unwrap_err();
        assert!(err.contains("exceeds max"));
    }
}
