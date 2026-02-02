pub mod routes;

use arc_swap::ArcSwap;
use governor::{Quota, RateLimiter};
use sentinel_approval::ApprovalStore;
use sentinel_audit::AuditLogger;
use sentinel_engine::PolicyEngine;
use sentinel_types::Policy;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Per-category rate limiters using governor.
///
/// Each category can independently be enabled (Some) or disabled (None).
/// When enabled, the limiter enforces a global requests-per-second cap.
pub struct RateLimits {
    pub evaluate: Option<governor::DefaultDirectRateLimiter>,
    pub admin: Option<governor::DefaultDirectRateLimiter>,
    pub readonly: Option<governor::DefaultDirectRateLimiter>,
}

impl RateLimits {
    /// Create rate limiters from optional requests-per-second values.
    /// A value of None or 0 disables rate limiting for that category.
    pub fn new(
        evaluate_rps: Option<u32>,
        admin_rps: Option<u32>,
        readonly_rps: Option<u32>,
    ) -> Self {
        Self {
            evaluate: evaluate_rps
                .and_then(NonZeroU32::new)
                .map(|r| RateLimiter::direct(Quota::per_second(r))),
            admin: admin_rps
                .and_then(NonZeroU32::new)
                .map(|r| RateLimiter::direct(Quota::per_second(r))),
            readonly: readonly_rps
                .and_then(NonZeroU32::new)
                .map(|r| RateLimiter::direct(Quota::per_second(r))),
        }
    }

    /// Create rate limits with all categories disabled (no rate limiting).
    pub fn disabled() -> Self {
        Self {
            evaluate: None,
            admin: None,
            readonly: None,
        }
    }
}

/// Operational metrics with atomic counters for lock-free updates.
pub struct Metrics {
    pub start_time: Instant,
    pub evaluations_total: AtomicU64,
    pub evaluations_allow: AtomicU64,
    pub evaluations_deny: AtomicU64,
    pub evaluations_require_approval: AtomicU64,
    pub evaluations_error: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            evaluations_total: AtomicU64::new(0),
            evaluations_allow: AtomicU64::new(0),
            evaluations_deny: AtomicU64::new(0),
            evaluations_require_approval: AtomicU64::new(0),
            evaluations_error: AtomicU64::new(0),
        }
    }
}

impl Metrics {
    pub fn record_evaluation(&self, verdict: &sentinel_types::Verdict) {
        self.evaluations_total.fetch_add(1, Ordering::Relaxed);
        match verdict {
            sentinel_types::Verdict::Allow => {
                self.evaluations_allow.fetch_add(1, Ordering::Relaxed);
            }
            sentinel_types::Verdict::Deny { .. } => {
                self.evaluations_deny.fetch_add(1, Ordering::Relaxed);
            }
            sentinel_types::Verdict::RequireApproval { .. } => {
                self.evaluations_require_approval.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn record_error(&self) {
        self.evaluations_total.fetch_add(1, Ordering::Relaxed);
        self.evaluations_error.fetch_add(1, Ordering::Relaxed);
    }
}

/// Shared application state for axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<PolicyEngine>,
    pub policies: Arc<ArcSwap<Vec<Policy>>>,
    pub audit: Arc<AuditLogger>,
    pub config_path: Arc<String>,
    pub approvals: Arc<ApprovalStore>,
    /// API key for authenticating mutating requests. None disables auth.
    pub api_key: Option<Arc<String>>,
    /// Per-category rate limiters. Arc-wrapped for Clone.
    pub rate_limits: Arc<RateLimits>,
    /// Allowed CORS origins. Empty vec means localhost only (strict default).
    /// Use `vec!["*".to_string()]` to allow any origin.
    pub cors_origins: Vec<String>,
    /// Operational metrics counters.
    pub metrics: Arc<Metrics>,
}
