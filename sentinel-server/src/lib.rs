pub mod routes;

use arc_swap::ArcSwap;
use governor::clock::Clock;
use governor::{Quota, RateLimiter};
use sentinel_approval::ApprovalStore;
use sentinel_audit::AuditLogger;
use sentinel_config::PolicyConfig;
use sentinel_engine::PolicyEngine;
use sentinel_types::{Policy, Verdict};
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
    pub per_ip: Option<PerIpRateLimiter>,
}

/// Per-IP rate limiter using DashMap for lock-free concurrent access.
///
/// Each unique client IP gets its own governor bucket. Stale entries
/// (no requests for 1 hour) are periodically cleaned up.
///
/// A configurable max capacity prevents memory exhaustion from
/// attackers spoofing large numbers of unique source IPs.
pub struct PerIpRateLimiter {
    buckets: dashmap::DashMap<std::net::IpAddr, (governor::DefaultDirectRateLimiter, Instant)>,
    quota: Quota,
    max_capacity: usize,
}

/// Default maximum number of unique IPs tracked simultaneously (~15MB).
/// Beyond this limit, new IPs are rate-limited immediately (fail-closed)
/// until the periodic cleanup frees slots.
pub const DEFAULT_MAX_IP_CAPACITY: usize = 100_000;

impl PerIpRateLimiter {
    pub fn new(rps: NonZeroU32) -> Self {
        Self {
            buckets: dashmap::DashMap::new(),
            quota: Quota::per_second(rps),
            max_capacity: DEFAULT_MAX_IP_CAPACITY,
        }
    }

    /// Create with burst allowance.
    pub fn new_with_burst(rps: NonZeroU32, burst: Option<NonZeroU32>) -> Self {
        Self {
            buckets: dashmap::DashMap::new(),
            quota: build_quota(rps, burst),
            max_capacity: DEFAULT_MAX_IP_CAPACITY,
        }
    }

    /// Create with a custom max capacity (useful for testing).
    pub fn with_max_capacity(rps: NonZeroU32, max_capacity: usize) -> Self {
        Self {
            buckets: dashmap::DashMap::new(),
            quota: Quota::per_second(rps),
            max_capacity,
        }
    }

    /// Create with burst allowance and custom max capacity.
    pub fn with_max_capacity_and_burst(
        rps: NonZeroU32,
        burst: Option<NonZeroU32>,
        max_capacity: usize,
    ) -> Self {
        Self {
            buckets: dashmap::DashMap::new(),
            quota: build_quota(rps, burst),
            max_capacity,
        }
    }

    /// Check the rate limit for a given IP. Returns `None` if allowed,
    /// `Some(retry_after_secs)` if rate-limited.
    ///
    /// Uses a two-phase lookup to avoid TOCTOU races: first tries `get_mut`
    /// for existing entries, then checks capacity before inserting new ones.
    /// If the number of tracked IPs exceeds max capacity, unknown IPs are
    /// immediately rate-limited (fail-closed) to prevent memory DoS.
    pub fn check(&self, ip: std::net::IpAddr) -> Option<u64> {
        let now = Instant::now();

        // Fast path: existing IP — no capacity check needed
        if let Some(mut entry) = self.buckets.get_mut(&ip) {
            entry.value_mut().1 = now;
            return match entry.value().0.check() {
                Ok(()) => None,
                Err(not_until) => {
                    let wait =
                        not_until.wait_time_from(governor::clock::DefaultClock::default().now());
                    Some(wait.as_secs().max(1))
                }
            };
        }

        // New IP — check capacity before inserting (fail-closed)
        if self.buckets.len() >= self.max_capacity {
            return Some(60); // Ask client to retry in 60s (cleanup will free slots)
        }

        // Insert new bucket and consume the first token.
        // We must call .check() on the new limiter so it counts against the quota.
        let limiter = RateLimiter::direct(self.quota);
        let result = match limiter.check() {
            Ok(()) => None,
            Err(not_until) => {
                let wait = not_until.wait_time_from(governor::clock::DefaultClock::default().now());
                Some(wait.as_secs().max(1))
            }
        };
        self.buckets.insert(ip, (limiter, now));
        result
    }

    /// Remove entries that haven't been seen for the given duration.
    pub fn cleanup(&self, max_age: std::time::Duration) {
        let cutoff = Instant::now() - max_age;
        self.buckets.retain(|_, (_, last_seen)| *last_seen > cutoff);
    }

    /// Number of tracked IPs.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// Whether any IPs are tracked.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Maximum capacity for tracked IPs.
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }
}

/// Build a governor `Quota` from a sustained rate and optional burst size.
///
/// When `burst` is `Some`, `allow_burst(b)` sets the token bucket capacity
/// to `b`, meaning up to `b` requests can be served instantly before the
/// sustained `rps` rate kicks in.  When `None`, the default bucket size of 1
/// is used (no burst above the sustained rate).
fn build_quota(rps: NonZeroU32, burst: Option<NonZeroU32>) -> Quota {
    let q = Quota::per_second(rps);
    match burst {
        Some(b) => q.allow_burst(b),
        None => q,
    }
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
            per_ip: None,
        }
    }

    /// Create rate limiters with burst configuration.
    ///
    /// Each category takes an optional RPS and optional burst. A `None` or 0
    /// RPS disables rate limiting for that category. A `None` burst means
    /// no burst above the sustained rate (bucket size = 1).
    pub fn new_with_burst(
        evaluate_rps: Option<u32>,
        evaluate_burst: Option<u32>,
        admin_rps: Option<u32>,
        admin_burst: Option<u32>,
        readonly_rps: Option<u32>,
        readonly_burst: Option<u32>,
    ) -> Self {
        Self {
            evaluate: evaluate_rps.and_then(NonZeroU32::new).map(|r| {
                RateLimiter::direct(build_quota(r, evaluate_burst.and_then(NonZeroU32::new)))
            }),
            admin: admin_rps.and_then(NonZeroU32::new).map(|r| {
                RateLimiter::direct(build_quota(r, admin_burst.and_then(NonZeroU32::new)))
            }),
            readonly: readonly_rps.and_then(NonZeroU32::new).map(|r| {
                RateLimiter::direct(build_quota(r, readonly_burst.and_then(NonZeroU32::new)))
            }),
            per_ip: None,
        }
    }

    /// Set the per-IP rate limiter.
    pub fn with_per_ip(mut self, rps: NonZeroU32) -> Self {
        self.per_ip = Some(PerIpRateLimiter::new(rps));
        self
    }

    /// Set the per-IP rate limiter with optional burst and max capacity.
    pub fn with_per_ip_config(
        mut self,
        rps: NonZeroU32,
        burst: Option<NonZeroU32>,
        max_capacity: Option<usize>,
    ) -> Self {
        let capacity = max_capacity.unwrap_or(DEFAULT_MAX_IP_CAPACITY);
        self.per_ip = Some(PerIpRateLimiter::with_max_capacity_and_burst(
            rps, burst, capacity,
        ));
        self
    }

    /// Create rate limits with all categories disabled (no rate limiting).
    pub fn disabled() -> Self {
        Self {
            evaluate: None,
            admin: None,
            readonly: None,
            per_ip: None,
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
                self.evaluations_require_approval
                    .fetch_add(1, Ordering::Relaxed);
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
    pub engine: Arc<ArcSwap<PolicyEngine>>,
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
    /// Trusted reverse proxy IPs. When non-empty, `X-Forwarded-For` is only
    /// trusted if the connection originates from one of these IPs. The
    /// **rightmost untrusted** entry in the XFF chain is used as the client IP.
    /// When empty (default), proxy headers are ignored entirely and the
    /// connection IP is used directly.
    pub trusted_proxies: Arc<Vec<std::net::IpAddr>>,
}

/// Reload policies from the config file and recompile the engine.
///
/// This is the shared reload logic used by both the HTTP `/reload` endpoint
/// and the file watcher. Returns the number of policies loaded on success.
pub async fn reload_policies_from_file(state: &AppState, source: &str) -> Result<usize, String> {
    let config_path = state.config_path.as_str();

    let policy_config = PolicyConfig::load_file(config_path)
        .map_err(|e| format!("Failed to load config from {}: {}", config_path, e))?;

    let mut new_policies = policy_config.to_policies();
    PolicyEngine::sort_policies(&mut new_policies);
    let count = new_policies.len();

    // Update policies via ArcSwap (lock-free)
    state.policies.store(Arc::new(new_policies));

    // Recompile engine
    let policies = state.policies.load();
    match PolicyEngine::with_policies(false, &policies) {
        Ok(engine) => {
            state.engine.store(Arc::new(engine));
        }
        Err(errors) => {
            for e in &errors {
                tracing::warn!("Policy recompilation error: {}", e);
            }
            tracing::warn!("Keeping previous compiled engine due to errors");
        }
    }

    tracing::info!(
        "Reloaded {} policies from {} (source: {})",
        count,
        config_path,
        source
    );

    // Audit trail
    let action = sentinel_types::Action {
        tool: "sentinel".to_string(),
        function: "reload_policies".to_string(),
        parameters: serde_json::json!({
            "config_path": config_path,
            "policy_count": count,
            "source": source,
        }),
    };
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            serde_json::json!({"event": "policies_reloaded", "source": source}),
        )
        .await
    {
        tracing::warn!("Failed to audit policy reload: {}", e);
    }

    Ok(count)
}

/// Spawn a file watcher that reloads policies when the config file changes.
///
/// Uses the `notify` crate with debouncing (1 second) to avoid rapid reloads
/// from editors that write files in multiple steps (e.g., write temp + rename).
pub fn spawn_config_watcher(state: AppState) -> Result<(), String> {
    use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

    let config_path = std::path::PathBuf::from(state.config_path.as_str());
    let watch_dir = config_path
        .parent()
        .ok_or_else(|| "Cannot determine parent directory of config file".to_string())?
        .to_path_buf();
    let config_filename = config_path
        .file_name()
        .ok_or_else(|| "Cannot determine config filename".to_string())?
        .to_os_string();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);

    // Create the watcher on a std thread since notify's watcher
    // needs to live on a thread with an event loop
    let tx_clone = tx.clone();
    let config_filename_clone = config_filename.clone();
    std::thread::spawn(move || {
        let _rt = tokio::runtime::Handle::current();
        let tx = tx_clone;
        let config_filename = config_filename_clone;
        let config_filename_for_closure = config_filename.clone();

        let mut watcher = match RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    match event.kind {
                        EventKind::Modify(_) | EventKind::Create(_) => {
                            // Check if the event is for our config file
                            let is_config = event.paths.iter().any(|p| {
                                p.file_name() == Some(config_filename_for_closure.as_os_str())
                            });
                            if is_config {
                                let _ = tx.blocking_send(());
                            }
                        }
                        _ => {}
                    }
                }
            },
            Config::default(),
        ) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("Failed to create file watcher: {}", e);
                return;
            }
        };

        if let Err(e) = watcher.watch(&watch_dir, RecursiveMode::NonRecursive) {
            tracing::error!("Failed to watch directory {:?}: {}", watch_dir, e);
            return;
        }

        tracing::info!(
            "Watching {:?} for changes to {:?}",
            watch_dir,
            config_filename
        );

        // Park this thread forever to keep the watcher alive
        loop {
            std::thread::park();
        }
    });

    // Spawn async task to receive change events and debounce reloads
    tokio::spawn(async move {
        let debounce = tokio::time::Duration::from_secs(1);
        let mut last_reload = tokio::time::Instant::now() - debounce;

        while rx.recv().await.is_some() {
            // Debounce: skip if we reloaded within the last second
            let now = tokio::time::Instant::now();
            if now.duration_since(last_reload) < debounce {
                continue;
            }

            // Small delay to let editors finish writing
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

            // Drain any queued events
            while rx.try_recv().is_ok() {}

            match reload_policies_from_file(&state, "file_watcher").await {
                Ok(count) => {
                    tracing::info!("File watcher: reloaded {} policies", count);
                }
                Err(e) => {
                    tracing::warn!("File watcher: reload failed: {}", e);
                }
            }
            last_reload = tokio::time::Instant::now();
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_default_starts_at_zero() {
        let m = Metrics::default();
        assert_eq!(m.evaluations_total.load(Ordering::Relaxed), 0);
        assert_eq!(m.evaluations_allow.load(Ordering::Relaxed), 0);
        assert_eq!(m.evaluations_deny.load(Ordering::Relaxed), 0);
        assert_eq!(m.evaluations_require_approval.load(Ordering::Relaxed), 0);
        assert_eq!(m.evaluations_error.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn metrics_record_allow() {
        let m = Metrics::default();
        m.record_evaluation(&Verdict::Allow);
        assert_eq!(m.evaluations_total.load(Ordering::Relaxed), 1);
        assert_eq!(m.evaluations_allow.load(Ordering::Relaxed), 1);
        assert_eq!(m.evaluations_deny.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn metrics_record_deny() {
        let m = Metrics::default();
        m.record_evaluation(&Verdict::Deny {
            reason: "test".to_string(),
        });
        assert_eq!(m.evaluations_total.load(Ordering::Relaxed), 1);
        assert_eq!(m.evaluations_deny.load(Ordering::Relaxed), 1);
        assert_eq!(m.evaluations_allow.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn metrics_record_require_approval() {
        let m = Metrics::default();
        m.record_evaluation(&Verdict::RequireApproval {
            reason: "review".to_string(),
        });
        assert_eq!(m.evaluations_total.load(Ordering::Relaxed), 1);
        assert_eq!(m.evaluations_require_approval.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn metrics_record_error() {
        let m = Metrics::default();
        m.record_error();
        assert_eq!(m.evaluations_total.load(Ordering::Relaxed), 1);
        assert_eq!(m.evaluations_error.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn metrics_multiple_evaluations_accumulate() {
        let m = Metrics::default();
        for _ in 0..5 {
            m.record_evaluation(&Verdict::Allow);
        }
        for _ in 0..3 {
            m.record_evaluation(&Verdict::Deny {
                reason: "x".to_string(),
            });
        }
        m.record_error();
        m.record_error();
        assert_eq!(m.evaluations_total.load(Ordering::Relaxed), 10);
        assert_eq!(m.evaluations_allow.load(Ordering::Relaxed), 5);
        assert_eq!(m.evaluations_deny.load(Ordering::Relaxed), 3);
        assert_eq!(m.evaluations_error.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn rate_limits_disabled_has_all_none() {
        let rl = RateLimits::disabled();
        assert!(rl.evaluate.is_none());
        assert!(rl.admin.is_none());
        assert!(rl.readonly.is_none());
        assert!(rl.per_ip.is_none());
    }

    #[test]
    fn rate_limits_new_with_values() {
        let rl = RateLimits::new(Some(100), Some(50), Some(200));
        assert!(rl.evaluate.is_some());
        assert!(rl.admin.is_some());
        assert!(rl.readonly.is_some());
        assert!(rl.per_ip.is_none());
    }

    #[test]
    fn rate_limits_new_with_zero_disables() {
        let rl = RateLimits::new(Some(0), None, Some(10));
        assert!(rl.evaluate.is_none(), "0 should disable rate limiting");
        assert!(rl.admin.is_none(), "None should disable rate limiting");
        assert!(rl.readonly.is_some());
    }

    #[test]
    fn rate_limits_with_per_ip() {
        let rl = RateLimits::disabled().with_per_ip(NonZeroU32::new(10).unwrap());
        assert!(rl.per_ip.is_some());
    }

    #[test]
    fn per_ip_rate_limiter_allows_first_request() {
        let limiter = PerIpRateLimiter::new(NonZeroU32::new(10).unwrap());
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert!(limiter.is_empty());
        let result = limiter.check(ip);
        assert!(result.is_none(), "First request should be allowed");
        assert_eq!(limiter.len(), 1);
    }

    #[test]
    fn per_ip_rate_limiter_cleanup_removes_stale() {
        let limiter = PerIpRateLimiter::new(NonZeroU32::new(10).unwrap());
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        limiter.check(ip);
        assert_eq!(limiter.len(), 1);
        // Cleanup with zero duration removes everything
        limiter.cleanup(std::time::Duration::ZERO);
        assert_eq!(limiter.len(), 0);
    }

    #[test]
    fn per_ip_rate_limiter_with_max_capacity_sets_limit() {
        let limiter = PerIpRateLimiter::with_max_capacity(NonZeroU32::new(10).unwrap(), 50);
        assert_eq!(limiter.max_capacity(), 50);
        assert!(limiter.is_empty());

        // Fill to capacity
        for i in 0..50u32 {
            let ip: std::net::IpAddr = std::net::Ipv4Addr::from(i.wrapping_add(167772160)).into(); // 10.0.0.x
            let result = limiter.check(ip);
            assert!(result.is_none(), "IP {} should be allowed", ip);
        }
        assert_eq!(limiter.len(), 50);

        // New IP beyond capacity should be denied (fail-closed)
        let overflow_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let result = limiter.check(overflow_ip);
        assert!(
            result.is_some(),
            "New IP beyond max_capacity should be denied"
        );
        assert_eq!(limiter.len(), 50, "Should not grow beyond max_capacity");
    }

    #[test]
    fn per_ip_rate_limiter_default_capacity() {
        let limiter = PerIpRateLimiter::new(NonZeroU32::new(10).unwrap());
        assert_eq!(limiter.max_capacity(), DEFAULT_MAX_IP_CAPACITY);
    }

    #[test]
    fn rate_limits_new_with_burst_creates_limiters() {
        let rl =
            RateLimits::new_with_burst(Some(100), Some(50), Some(20), Some(5), Some(200), None);
        assert!(rl.evaluate.is_some());
        assert!(rl.admin.is_some());
        assert!(rl.readonly.is_some());
        assert!(rl.per_ip.is_none());

        // Zero RPS should still disable
        let rl2 = RateLimits::new_with_burst(Some(0), Some(10), None, None, None, None);
        assert!(rl2.evaluate.is_none());
        assert!(rl2.admin.is_none());
        assert!(rl2.readonly.is_none());
    }

    #[test]
    fn per_ip_rate_limiter_burst_allows_initial_burst() {
        // With burst=5 and rps=1, we should be able to make several requests quickly
        let limiter = PerIpRateLimiter::new_with_burst(
            NonZeroU32::new(1).unwrap(),
            Some(NonZeroU32::new(5).unwrap()),
        );
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

        // First several requests should all be allowed (burst window)
        for i in 0..5 {
            let result = limiter.check(ip);
            assert!(
                result.is_none(),
                "Request {} within burst should be allowed",
                i
            );
        }
        // After exhausting the burst, the next request should be rate-limited
        let result = limiter.check(ip);
        assert!(
            result.is_some(),
            "Request after burst exhaustion should be limited"
        );
    }

    #[test]
    fn rate_limits_with_per_ip_config_sets_capacity_and_burst() {
        let rl = RateLimits::disabled().with_per_ip_config(
            NonZeroU32::new(10).unwrap(),
            Some(NonZeroU32::new(20).unwrap()),
            Some(500),
        );
        assert!(rl.per_ip.is_some());
        let per_ip = rl.per_ip.as_ref().unwrap();
        assert_eq!(per_ip.max_capacity(), 500);

        // Default capacity when None
        let rl2 =
            RateLimits::disabled().with_per_ip_config(NonZeroU32::new(10).unwrap(), None, None);
        let per_ip2 = rl2.per_ip.as_ref().unwrap();
        assert_eq!(per_ip2.max_capacity(), DEFAULT_MAX_IP_CAPACITY);
    }
}
