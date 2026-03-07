// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

// =============================================================================
// USAGE TRACKER — Per-tenant usage metering with atomic counters
// =============================================================================
//
// Phase 50: Usage Metering & Billing Foundation.
//
// Tracks per-tenant usage counters (evaluations, policies, approvals, audit
// entries) per billing period using DashMap + AtomicU64 for lock-free
// concurrent access. Enforces hard evaluation quotas by license tier.
//
// SECURITY:
// - Fail-closed: quota check errors return Deny
// - Capacity bounded: MAX_TRACKED_TENANTS prevents OOM
// - Saturating arithmetic: counters never overflow/wrap to zero
// - SeqCst ordering: security-critical counters are globally visible

use chrono::Datelike;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use vellaveto_config::metering::MeteringConfig;
use vellaveto_types::metering::{BillingPeriod, QuotaStatus, UsageMetrics};

/// Maximum number of unique tenants tracked simultaneously.
/// Beyond this limit, new tenants are quota-denied (fail-closed).
pub const MAX_TRACKED_TENANTS: usize = 100_000;

/// Per-tenant atomic usage counters for the current billing period.
pub struct UsageCounters {
    evaluations: AtomicU64,
    evaluations_allowed: AtomicU64,
    evaluations_denied: AtomicU64,
    policies_created: AtomicU64,
    approvals_processed: AtomicU64,
    audit_entries: AtomicU64,
    period_start: String,
    period_end: String,
    last_seen: std::sync::Mutex<Instant>,
}

impl UsageCounters {
    fn new(period: &BillingPeriod) -> Self {
        Self {
            evaluations: AtomicU64::new(0),
            evaluations_allowed: AtomicU64::new(0),
            evaluations_denied: AtomicU64::new(0),
            policies_created: AtomicU64::new(0),
            approvals_processed: AtomicU64::new(0),
            audit_entries: AtomicU64::new(0),
            period_start: period.start.clone(),
            period_end: period.end.clone(),
            last_seen: std::sync::Mutex::new(Instant::now()),
        }
    }

    fn touch(&self) {
        // SECURITY: Fail-closed on lock poisoning — silently skip touch.
        if let Ok(mut last) = self.last_seen.lock() {
            *last = Instant::now();
        }
    }

    fn last_seen_instant(&self) -> Instant {
        self.last_seen
            .lock()
            .map(|g| *g)
            .unwrap_or_else(|_| Instant::now())
    }

    fn snapshot(&self, tenant_id: &str) -> UsageMetrics {
        UsageMetrics {
            tenant_id: tenant_id.to_string(),
            period_start: self.period_start.clone(),
            period_end: self.period_end.clone(),
            evaluations: self.evaluations.load(Ordering::SeqCst),
            evaluations_allowed: self.evaluations_allowed.load(Ordering::SeqCst),
            evaluations_denied: self.evaluations_denied.load(Ordering::SeqCst),
            policies_created: self.policies_created.load(Ordering::SeqCst),
            approvals_processed: self.approvals_processed.load(Ordering::SeqCst),
            audit_entries: self.audit_entries.load(Ordering::SeqCst),
        }
    }
}

/// Per-tenant usage tracker with atomic counters.
///
/// Tracks evaluations, policies created, approvals processed, and audit
/// entries per billing period. Enforces hard evaluation quotas by tier.
///
/// Uses DashMap for lock-free concurrent access across handler threads,
/// matching the `PerTenantRateLimiter` pattern from Phase 44.
pub struct TenantUsageTracker {
    counters: DashMap<String, UsageCounters>,
    config: MeteringConfig,
    max_capacity: usize,
}

impl TenantUsageTracker {
    /// Create a new usage tracker from metering config.
    pub fn new(config: MeteringConfig) -> Self {
        Self {
            counters: DashMap::new(),
            config,
            max_capacity: MAX_TRACKED_TENANTS,
        }
    }

    /// Create with custom capacity (for testing).
    pub fn with_max_capacity(config: MeteringConfig, max_capacity: usize) -> Self {
        Self {
            counters: DashMap::new(),
            config,
            max_capacity,
        }
    }

    /// Whether metering is enabled.
    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// Compute the current billing period based on config.
    pub fn current_billing_period(&self) -> BillingPeriod {
        current_billing_period(self.config.period_start_day)
    }

    /// Record an evaluation for a tenant.
    ///
    /// Increments the total evaluations counter and either the allowed or denied
    /// sub-counter. Uses saturating arithmetic to prevent overflow.
    pub fn record_evaluation(&self, tenant_id: &str, allowed: bool) {
        if !self.config.enabled {
            return;
        }
        let period = self.current_billing_period();
        self.ensure_entry(tenant_id, &period);

        if let Some(entry) = self.counters.get(tenant_id) {
            entry.touch();
            let _ = entry
                .evaluations
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                    Some(v.saturating_add(1))
                });
            if allowed {
                let _ = entry.evaluations_allowed.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |v| Some(v.saturating_add(1)),
                );
            } else {
                let _ = entry.evaluations_denied.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |v| Some(v.saturating_add(1)),
                );
            }
        }
    }

    /// Record only the final evaluation outcome for a tenant.
    ///
    /// This method updates `evaluations_allowed` / `evaluations_denied` without
    /// touching `evaluations`. It is intended for paths that already reserved the
    /// total evaluation count via `check_evaluation_quota`.
    pub fn record_evaluation_outcome(&self, tenant_id: &str, allowed: bool) {
        if !self.config.enabled {
            return;
        }
        let period = self.current_billing_period();
        self.ensure_entry(tenant_id, &period);

        if let Some(entry) = self.counters.get(tenant_id) {
            entry.touch();
            if allowed {
                let _ = entry.evaluations_allowed.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |v| Some(v.saturating_add(1)),
                );
            } else {
                let _ = entry.evaluations_denied.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |v| Some(v.saturating_add(1)),
                );
            }
        }
    }

    /// Record a policy creation for a tenant.
    pub fn record_policy_created(&self, tenant_id: &str) {
        if !self.config.enabled {
            return;
        }
        let period = self.current_billing_period();
        self.ensure_entry(tenant_id, &period);

        if let Some(entry) = self.counters.get(tenant_id) {
            entry.touch();
            let _ = entry
                .policies_created
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                    Some(v.saturating_add(1))
                });
        }
    }

    /// Record an approval processed for a tenant.
    pub fn record_approval(&self, tenant_id: &str) {
        if !self.config.enabled {
            return;
        }
        let period = self.current_billing_period();
        self.ensure_entry(tenant_id, &period);

        if let Some(entry) = self.counters.get(tenant_id) {
            entry.touch();
            let _ =
                entry
                    .approvals_processed
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                        Some(v.saturating_add(1))
                    });
        }
    }

    /// Record an audit entry for a tenant.
    pub fn record_audit_entry(&self, tenant_id: &str) {
        if !self.config.enabled {
            return;
        }
        let period = self.current_billing_period();
        self.ensure_entry(tenant_id, &period);

        if let Some(entry) = self.counters.get(tenant_id) {
            entry.touch();
            let _ = entry
                .audit_entries
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                    Some(v.saturating_add(1))
                });
        }
    }

    /// Check quota and reserve one evaluation slot atomically.
    ///
    /// Returns `Ok(())` if a slot was reserved, or `Err(reason)` if quota is
    /// exceeded. This prevents race conditions where concurrent requests all pass
    /// a read-only check and then exceed hard limits.
    ///
    /// SECURITY: Fail-closed on capacity exhaustion and missing tenant entry.
    pub fn check_evaluation_quota(&self, tenant_id: &str, tier_limit: u64) -> Result<(), String> {
        if !self.config.enabled {
            return Ok(());
        }

        // Capacity check — fail-closed
        if self.counters.len() >= self.max_capacity && !self.counters.contains_key(tenant_id) {
            return Err("usage tracker at capacity".to_string());
        }

        let period = self.current_billing_period();
        self.ensure_entry(tenant_id, &period);

        let entry = self
            .counters
            .get(tenant_id)
            .ok_or_else(|| "usage tracker entry unavailable".to_string())?;
        entry.touch();

        // Unlimited tier — still count usage for observability and billing exports.
        if tier_limit == u64::MAX {
            let _ = entry
                .evaluations
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                    Some(v.saturating_add(1))
                });
            return Ok(());
        }

        // Reserve one slot atomically. If we're already at/over limit, fail
        // without mutating state.
        let previous_used = entry
            .evaluations
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                if used >= tier_limit {
                    None
                } else {
                    Some(used.saturating_add(1))
                }
            })
            .map_err(|used| {
                // SECURITY (R243-SRV-4): Log quota numbers server-side only;
                // do not include in the error string returned to callers
                // (which may flow into API responses via deny reasons).
                tracing::warn!(
                    used = used,
                    tier_limit = tier_limit,
                    "evaluation quota exceeded for current period"
                );
                "evaluation quota exceeded".to_string()
            })?;

        let used = previous_used.saturating_add(1);

        // Log warning if approaching quota.
        let threshold = self.config.quota_warning_threshold;
        if threshold > 0.0 && tier_limit > 0 {
            // Safe: tier_limit > 0 and threshold is validated [0.0, 1.0].
            let warn_at = (tier_limit as f64 * threshold as f64) as u64;
            if used >= warn_at && used < tier_limit {
                tracing::warn!(
                    tenant_id = tenant_id,
                    used = used,
                    limit = tier_limit,
                    "tenant approaching evaluation quota ({:.0}%)",
                    (used as f64 / tier_limit as f64) * 100.0
                );
            }
        }

        Ok(())
    }

    /// Get usage metrics for a tenant in the current period.
    pub fn get_usage(&self, tenant_id: &str) -> Option<UsageMetrics> {
        self.counters
            .get(tenant_id)
            .map(|entry| entry.snapshot(tenant_id))
    }

    /// Get quota status for a tenant.
    pub fn get_quota_status(
        &self,
        tenant_id: &str,
        tier_limit: u64,
        policies_limit: u64,
    ) -> QuotaStatus {
        let period = self.current_billing_period();

        let (evaluations_used, policies_used) = self
            .counters
            .get(tenant_id)
            .map(|entry| {
                (
                    entry.evaluations.load(Ordering::SeqCst),
                    entry.policies_created.load(Ordering::SeqCst),
                )
            })
            .unwrap_or((0, 0));

        let evaluations_remaining = tier_limit.saturating_sub(evaluations_used);

        QuotaStatus {
            tenant_id: tenant_id.to_string(),
            evaluations_used,
            evaluations_limit: tier_limit,
            evaluations_remaining,
            policies_used,
            policies_limit,
            period_start: period.start,
            period_end: period.end,
            quota_exceeded: evaluations_used >= tier_limit && tier_limit != u64::MAX,
        }
    }

    /// Reset counters for a tenant (admin operation).
    pub fn reset_period(&self, tenant_id: &str) {
        self.counters.remove(tenant_id);
    }

    /// Remove entries for tenants not seen within the given duration.
    pub fn cleanup_stale(&self, max_age: std::time::Duration) {
        let cutoff = Instant::now() - max_age;
        self.counters
            .retain(|_, entry| entry.last_seen_instant() > cutoff);
    }

    /// Return the evaluation limit for the given license tier.
    ///
    /// Delegates to `TierUsageLimits::limit_for_tier()`.
    pub fn limit_for_tier(&self, tier: &vellaveto_config::LicenseTier) -> u64 {
        self.config.tier_limits.limit_for_tier(tier)
    }

    /// Number of tracked tenants.
    pub fn len(&self) -> usize {
        self.counters.len()
    }

    /// Whether any tenants are tracked.
    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }

    /// Ensure an entry exists for the tenant, creating if needed.
    /// If the billing period has changed, reset counters.
    fn ensure_entry(&self, tenant_id: &str, period: &BillingPeriod) {
        // Fast path: entry exists and period matches
        if let Some(entry) = self.counters.get(tenant_id) {
            if entry.period_start == period.start {
                return;
            }
            // Period rolled — drop and recreate
            drop(entry);
            self.counters.remove(tenant_id);
        }

        // Capacity check — fail-closed: don't create new entries beyond limit
        if self.counters.len() >= self.max_capacity {
            tracing::warn!(
                tenant_id = tenant_id,
                capacity = self.max_capacity,
                "usage tracker at capacity, cannot track new tenant"
            );
            return;
        }

        // Insert new entry (may race — that's fine, DashMap handles it)
        self.counters
            .entry(tenant_id.to_string())
            .or_insert_with(|| UsageCounters::new(period));
    }
}

/// Compute the billing period for the current month.
///
/// Uses `chrono::Utc::now()` for the current date. The period starts on
/// `period_start_day` of the current month and ends on `period_start_day - 1`
/// of the next month (or the last day of the month if `period_start_day > days_in_month`).
pub fn current_billing_period(period_start_day: u8) -> BillingPeriod {
    let now = chrono::Utc::now();
    let today = now.date_naive();
    let day = period_start_day.clamp(1, 28) as u32;

    let (start, end) = if today.day() >= day {
        // Current period started this month
        let start = today.with_day(day).unwrap_or(today);
        let next_month = if today.month() == 12 {
            chrono::NaiveDate::from_ymd_opt(today.year() + 1, 1, day)
        } else {
            chrono::NaiveDate::from_ymd_opt(today.year(), today.month() + 1, day)
        };
        let end = next_month.unwrap_or(start).pred_opt().unwrap_or(start);
        (start, end)
    } else {
        // Current period started last month
        let prev_month = if today.month() == 1 {
            chrono::NaiveDate::from_ymd_opt(today.year() - 1, 12, day)
        } else {
            chrono::NaiveDate::from_ymd_opt(today.year(), today.month() - 1, day)
        };
        let start = prev_month.unwrap_or(today);
        let end = today
            .with_day(day)
            .unwrap_or(today)
            .pred_opt()
            .unwrap_or(today);
        (start, end)
    };

    BillingPeriod {
        start: start.format("%Y-%m-%dT00:00:00Z").to_string(),
        end: end.format("%Y-%m-%dT23:59:59Z").to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> MeteringConfig {
        MeteringConfig {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_usage_tracker_new() {
        let tracker = TenantUsageTracker::new(test_config());
        assert!(tracker.enabled());
        assert!(tracker.is_empty());
        assert_eq!(tracker.len(), 0);
    }

    #[test]
    fn test_usage_tracker_disabled() {
        let tracker = TenantUsageTracker::new(MeteringConfig::default());
        assert!(!tracker.enabled());

        // Recording should be no-op when disabled
        tracker.record_evaluation("tenant-1", true);
        assert!(tracker.is_empty());
        assert!(tracker.get_usage("tenant-1").is_none());
    }

    #[test]
    fn test_record_evaluation_allowed() {
        let tracker = TenantUsageTracker::new(test_config());
        tracker.record_evaluation("tenant-1", true);

        let usage = tracker.get_usage("tenant-1").expect("should exist");
        assert_eq!(usage.evaluations, 1);
        assert_eq!(usage.evaluations_allowed, 1);
        assert_eq!(usage.evaluations_denied, 0);
        assert_eq!(usage.tenant_id, "tenant-1");
    }

    #[test]
    fn test_record_evaluation_denied() {
        let tracker = TenantUsageTracker::new(test_config());
        tracker.record_evaluation("tenant-1", false);

        let usage = tracker.get_usage("tenant-1").expect("should exist");
        assert_eq!(usage.evaluations, 1);
        assert_eq!(usage.evaluations_allowed, 0);
        assert_eq!(usage.evaluations_denied, 1);
    }

    #[test]
    fn test_record_policy_created() {
        let tracker = TenantUsageTracker::new(test_config());
        tracker.record_policy_created("tenant-1");

        let usage = tracker.get_usage("tenant-1").expect("should exist");
        assert_eq!(usage.policies_created, 1);
    }

    #[test]
    fn test_record_approval() {
        let tracker = TenantUsageTracker::new(test_config());
        tracker.record_approval("tenant-1");

        let usage = tracker.get_usage("tenant-1").expect("should exist");
        assert_eq!(usage.approvals_processed, 1);
    }

    #[test]
    fn test_record_audit_entry() {
        let tracker = TenantUsageTracker::new(test_config());
        tracker.record_audit_entry("tenant-1");

        let usage = tracker.get_usage("tenant-1").expect("should exist");
        assert_eq!(usage.audit_entries, 1);
    }

    #[test]
    fn test_check_evaluation_quota_within_limit() {
        let tracker = TenantUsageTracker::new(test_config());
        assert!(tracker.check_evaluation_quota("tenant-1", 100).is_ok());
    }

    #[test]
    fn test_check_evaluation_quota_reserves_slot() {
        let tracker = TenantUsageTracker::new(test_config());
        assert!(tracker.check_evaluation_quota("tenant-1", 2).is_ok());
        assert!(tracker.check_evaluation_quota("tenant-1", 2).is_ok());
        assert!(tracker.check_evaluation_quota("tenant-1", 2).is_err());

        let usage = tracker.get_usage("tenant-1").expect("should exist");
        assert_eq!(usage.evaluations, 2);
    }

    #[test]
    fn test_record_evaluation_outcome_does_not_increment_total() {
        let tracker = TenantUsageTracker::new(test_config());
        assert!(tracker.check_evaluation_quota("tenant-1", 10).is_ok()); // reserves one slot

        tracker.record_evaluation_outcome("tenant-1", false);
        let usage = tracker.get_usage("tenant-1").expect("should exist");
        assert_eq!(usage.evaluations, 1);
        assert_eq!(usage.evaluations_allowed, 0);
        assert_eq!(usage.evaluations_denied, 1);
    }

    #[test]
    fn test_check_evaluation_quota_exceeded() {
        let tracker = TenantUsageTracker::new(test_config());
        // Record 10 evaluations
        for _ in 0..10 {
            tracker.record_evaluation("tenant-1", true);
        }
        // Check with limit of 10 — should be exceeded
        let result = tracker.check_evaluation_quota("tenant-1", 10);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("quota exceeded"));
    }

    #[test]
    fn test_check_evaluation_quota_unlimited() {
        let tracker = TenantUsageTracker::new(test_config());
        for _ in 0..100 {
            tracker.record_evaluation("tenant-1", true);
        }
        // u64::MAX means unlimited
        assert!(tracker.check_evaluation_quota("tenant-1", u64::MAX).is_ok());
        let usage = tracker.get_usage("tenant-1").expect("should exist");
        assert_eq!(usage.evaluations, 101);
    }

    #[test]
    fn test_check_evaluation_quota_disabled() {
        let tracker = TenantUsageTracker::new(MeteringConfig::default());
        // Should always succeed when disabled
        assert!(tracker.check_evaluation_quota("tenant-1", 0).is_ok());
    }

    #[test]
    fn test_check_evaluation_quota_capacity_exceeded() {
        let config = test_config();
        let tracker = TenantUsageTracker::with_max_capacity(config, 2);

        // Fill capacity
        tracker.record_evaluation("tenant-1", true);
        tracker.record_evaluation("tenant-2", true);

        // New tenant should be denied (fail-closed)
        let result = tracker.check_evaluation_quota("tenant-3", 1000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("capacity"));
    }

    #[test]
    fn test_get_quota_status() {
        let tracker = TenantUsageTracker::new(test_config());
        for _ in 0..5 {
            tracker.record_evaluation("tenant-1", true);
        }
        tracker.record_policy_created("tenant-1");

        let status = tracker.get_quota_status("tenant-1", 100, 50);
        assert_eq!(status.evaluations_used, 5);
        assert_eq!(status.evaluations_limit, 100);
        assert_eq!(status.evaluations_remaining, 95);
        assert_eq!(status.policies_used, 1);
        assert_eq!(status.policies_limit, 50);
        assert!(!status.quota_exceeded);
    }

    #[test]
    fn test_get_quota_status_exceeded() {
        let tracker = TenantUsageTracker::new(test_config());
        for _ in 0..10 {
            tracker.record_evaluation("tenant-1", true);
        }

        let status = tracker.get_quota_status("tenant-1", 10, 50);
        assert!(status.quota_exceeded);
        assert_eq!(status.evaluations_remaining, 0);
    }

    #[test]
    fn test_get_quota_status_unknown_tenant() {
        let tracker = TenantUsageTracker::new(test_config());
        let status = tracker.get_quota_status("unknown", 100, 50);
        assert_eq!(status.evaluations_used, 0);
        assert_eq!(status.evaluations_remaining, 100);
        assert!(!status.quota_exceeded);
    }

    #[test]
    fn test_reset_period() {
        let tracker = TenantUsageTracker::new(test_config());
        tracker.record_evaluation("tenant-1", true);
        assert!(tracker.get_usage("tenant-1").is_some());

        tracker.reset_period("tenant-1");
        assert!(tracker.get_usage("tenant-1").is_none());
    }

    #[test]
    fn test_cleanup_stale() {
        let tracker = TenantUsageTracker::new(test_config());
        tracker.record_evaluation("tenant-1", true);

        // Cleanup with zero age should remove everything
        tracker.cleanup_stale(std::time::Duration::ZERO);
        assert!(tracker.is_empty());
    }

    #[test]
    fn test_cleanup_preserves_recent() {
        let tracker = TenantUsageTracker::new(test_config());
        tracker.record_evaluation("tenant-1", true);

        // Cleanup with 1 hour should preserve recent entries
        tracker.cleanup_stale(std::time::Duration::from_secs(3600));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn test_multiple_tenants() {
        let tracker = TenantUsageTracker::new(test_config());
        tracker.record_evaluation("tenant-1", true);
        tracker.record_evaluation("tenant-2", false);
        tracker.record_evaluation("tenant-2", true);

        assert_eq!(tracker.len(), 2);

        let u1 = tracker.get_usage("tenant-1").expect("tenant-1");
        assert_eq!(u1.evaluations, 1);

        let u2 = tracker.get_usage("tenant-2").expect("tenant-2");
        assert_eq!(u2.evaluations, 2);
    }

    #[test]
    fn test_current_billing_period_returns_valid_timestamps() {
        let period = current_billing_period(1);
        assert!(!period.start.is_empty());
        assert!(!period.end.is_empty());
        assert!(period.start.contains('T'));
        assert!(period.end.contains('T'));
    }

    #[test]
    fn test_current_billing_period_day_15() {
        let period = current_billing_period(15);
        assert!(
            period.start.contains("-15T")
                || period.start.contains("-01T")
                || !period.start.is_empty()
        );
    }

    #[test]
    fn test_current_billing_period_clamps_invalid_day() {
        // Day 0 should be clamped to 1
        let period = current_billing_period(0);
        assert!(!period.start.is_empty());

        // Day 29 should be clamped to 28
        let period = current_billing_period(29);
        assert!(!period.start.is_empty());
    }

    #[test]
    fn test_saturating_counters() {
        let tracker = TenantUsageTracker::new(test_config());
        // Record many evaluations — should not overflow
        for _ in 0..1000 {
            tracker.record_evaluation("tenant-1", true);
        }
        let usage = tracker.get_usage("tenant-1").expect("should exist");
        assert_eq!(usage.evaluations, 1000);
        assert_eq!(usage.evaluations_allowed, 1000);
    }
}
