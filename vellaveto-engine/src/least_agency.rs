//! Least-agency enforcement — tracks permission usage per agent session
//! and detects unused permissions for scope narrowing recommendations.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::time::Instant;
use vellaveto_types::{AgencyRecommendation, EnforcementMode, LeastAgencyReport, PermissionUsage};

/// Maximum tracked sessions to bound memory.
const MAX_TRACKED_SESSIONS: usize = 4096;

/// Maximum granted permissions per session to bound memory (FIND-R44-018).
const MAX_GRANTS_PER_SESSION: usize = 1_000;

/// Agency recommendation threshold: above this usage ratio, scope is optimal.
/// SECURITY (FIND-R56-ENGINE-005): Named constant for clarity and auditability.
const THRESHOLD_OPTIMAL: f64 = 0.8;
/// Agency recommendation threshold: above this, a review of grants is recommended.
const THRESHOLD_REVIEW: f64 = 0.5;
/// Agency recommendation threshold: above this, scope narrowing is recommended.
/// Below this, the recommendation is Critical.
const THRESHOLD_NARROW: f64 = 0.2;

/// Default auto-revocation period in seconds (1 hour).
/// SECURITY (FIND-R56-ENGINE-006): Named constant for clarity. Permissions
/// unused for this duration are candidates for automatic revocation.
const DEFAULT_AUTO_REVOKE_SECS: u64 = 3600;

/// Per-agent-session permission tracker.
///
/// Tracks the set of granted policy IDs and which of them have been exercised,
/// enabling unused-permission detection and auto-revocation of stale grants.
struct PermissionTracker {
    /// Set of policy IDs granted to this agent session (bounded by `MAX_GRANTS_PER_SESSION`).
    granted: HashSet<String>,
    /// Monotonic timestamp of the last usage (or grant time) for each granted permission.
    /// Used by [`LeastAgencyTracker::revoke_stale_permissions()`] to detect staleness.
    granted_last_used: HashMap<String, Instant>,
    /// Permissions that have been exercised, keyed by policy ID, with usage details.
    used: HashMap<String, PermissionUsage>,
    /// Monotonic timestamp when the session was first registered.
    session_start: Instant,
}

/// Tracks permission usage across agent sessions for least-agency enforcement.
pub struct LeastAgencyTracker {
    narrow_threshold: f64,
    enforcement_mode: EnforcementMode,
    auto_revoke_after_secs: u64,
    trackers: RwLock<HashMap<String, PermissionTracker>>,
}

impl LeastAgencyTracker {
    /// Sanitize narrow_threshold to [0.0, 1.0], clamping invalid values with a warning.
    ///
    /// SECURITY (FIND-R55-CORE-009): NaN/Infinity in narrow_threshold would cause
    /// `recommend_narrowing()` comparisons to always return false (NaN) or produce
    /// incorrect results (Infinity), effectively disabling scope narrowing enforcement.
    fn sanitize_threshold(raw: f64) -> f64 {
        if !raw.is_finite() {
            tracing::warn!(
                raw_value = %raw,
                "LeastAgencyTracker narrow_threshold is not finite, clamping to 0.0 (fail-closed)"
            );
            return 0.0;
        }
        if raw < 0.0 {
            tracing::warn!(
                raw_value = %raw,
                "LeastAgencyTracker narrow_threshold is negative, clamping to 0.0"
            );
            return 0.0;
        }
        if raw > 1.0 {
            tracing::warn!(
                raw_value = %raw,
                "LeastAgencyTracker narrow_threshold exceeds 1.0, clamping to 1.0"
            );
            return 1.0;
        }
        raw
    }

    /// Create a new tracker with the given narrowing threshold (monitor-only mode).
    pub fn new(narrow_threshold: f64) -> Self {
        Self {
            narrow_threshold: Self::sanitize_threshold(narrow_threshold),
            enforcement_mode: EnforcementMode::Monitor,
            auto_revoke_after_secs: DEFAULT_AUTO_REVOKE_SECS,
            trackers: RwLock::new(HashMap::new()),
        }
    }

    /// Create a tracker with enforcement configuration.
    pub fn new_with_config(
        narrow_threshold: f64,
        enforcement_mode: EnforcementMode,
        auto_revoke_after_secs: u64,
    ) -> Self {
        Self {
            narrow_threshold: Self::sanitize_threshold(narrow_threshold),
            enforcement_mode,
            auto_revoke_after_secs,
            trackers: RwLock::new(HashMap::new()),
        }
    }

    /// Return the current enforcement mode.
    pub fn enforcement_mode(&self) -> EnforcementMode {
        self.enforcement_mode
    }

    /// Build a collision-resistant session key using length-prefixed format
    /// (FIND-R44-021). This prevents collisions where `agent_id` contains `::`
    /// (e.g., `"a::b" + "c"` vs `"a" + "b::c"` would both produce `"a::b::c"`
    /// with the naive separator approach).
    fn session_key(agent_id: &str, session_id: &str) -> String {
        format!("{}:{agent_id}::{session_id}", agent_id.len())
    }

    /// Register granted policy IDs for an agent session.
    pub fn register_grants(&self, agent_id: &str, session_id: &str, policy_ids: &[String]) {
        let key = Self::session_key(agent_id, session_id);
        // SECURITY (FIND-P3-012, FIND-R58-ENG-005): Log poisoned lock recovery.
        // Unlike DeputyValidator (which fails closed on poison because it makes
        // allow/deny decisions), LeastAgencyTracker is observational — it tracks
        // permission usage for compliance reporting, not enforcement. Recovering
        // on poison preserves observability; failing closed would stop tracking.
        let mut trackers = match self.trackers.write() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!(
                    "LeastAgencyTracker::register_grants write lock poisoned: {}",
                    e
                );
                return;
            }
        };
        // Evict oldest if at capacity
        if trackers.len() >= MAX_TRACKED_SESSIONS && !trackers.contains_key(&key) {
            if let Some(oldest) = trackers
                .iter()
                .min_by_key(|(_, v)| v.session_start)
                .map(|(k, _)| k.clone())
            {
                trackers.remove(&oldest);
            }
        }
        let now = Instant::now();
        let tracker = trackers.entry(key).or_insert_with(|| PermissionTracker {
            granted: HashSet::new(),
            granted_last_used: HashMap::new(),
            used: HashMap::new(),
            session_start: now,
        });
        for id in policy_ids {
            // FIND-R44-018: Bound per-session grants to prevent memory exhaustion.
            if tracker.granted.len() >= MAX_GRANTS_PER_SESSION {
                tracing::warn!(
                    max = MAX_GRANTS_PER_SESSION,
                    "Per-session grant limit reached — ignoring remaining grants"
                );
                break;
            }
            tracker.granted.insert(id.clone());
            tracker.granted_last_used.entry(id.clone()).or_insert(now);
        }
    }

    /// Record that a permission was exercised by an agent in a session.
    ///
    /// Updates the `used_count` for the given `policy_id` and refreshes its
    /// `last_used` timestamp (both the wall-clock RFC 3339 value for audit
    /// and the monotonic `Instant` for auto-revocation staleness checks).
    ///
    /// If the session has not been registered via [`Self::register_grants()`],
    /// this is a no-op (the policy_id is silently ignored).
    pub fn record_usage(
        &self,
        agent_id: &str,
        session_id: &str,
        policy_id: &str,
        tool: &str,
        function: &str,
    ) {
        let key = Self::session_key(agent_id, session_id);
        // SECURITY (FIND-P3-012): Fail-closed on poisoned lock — skip usage recording.
        let mut trackers = match self.trackers.write() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!(
                    "LeastAgencyTracker::record_usage write lock poisoned: {}",
                    e
                );
                return;
            }
        };
        if let Some(tracker) = trackers.get_mut(&key) {
            // SECURITY (FIND-R139-L1): Only record usage for policy IDs that are
            // actually granted. Without this guard, tracker.used and
            // granted_last_used grow unboundedly for arbitrary policy_id values,
            // and generate_report produces corrupted Optimal recommendations
            // when used > granted. (FIND-R139-L2)
            if !tracker.granted.contains(policy_id) {
                tracing::debug!(
                    policy_id = %policy_id,
                    "record_usage: policy_id not in granted set, skipping"
                );
                return;
            }

            // Cap tracker.used at MAX_GRANTS_PER_SESSION to prevent unbounded growth
            if tracker.used.len() >= MAX_GRANTS_PER_SESSION
                && !tracker.used.contains_key(policy_id)
            {
                tracing::warn!(
                    max = MAX_GRANTS_PER_SESSION,
                    "record_usage: tracker.used at capacity"
                );
                return;
            }

            let usage = tracker
                .used
                .entry(policy_id.to_string())
                .or_insert_with(|| PermissionUsage {
                    tool_pattern: tool.to_string(),
                    function_pattern: function.to_string(),
                    used_count: 0,
                    last_used: None,
                });
            usage.used_count = usage.used_count.saturating_add(1);
            usage.last_used = Some(chrono::Utc::now().to_rfc3339());

            // Update last-used timestamp for auto-revocation tracking
            tracker
                .granted_last_used
                .insert(policy_id.to_string(), Instant::now());
        }
    }

    /// Return policy IDs that have been granted but never used.
    pub fn check_unused(&self, agent_id: &str, session_id: &str) -> Vec<String> {
        let key = Self::session_key(agent_id, session_id);
        // SECURITY (FIND-P3-012): Fail-closed on poisoned lock — return empty (no unused detected).
        let trackers = match self.trackers.read() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!("LeastAgencyTracker::check_unused read lock poisoned: {}", e);
                return Vec::new();
            }
        };
        if let Some(tracker) = trackers.get(&key) {
            tracker
                .granted
                .iter()
                .filter(|id| !tracker.used.contains_key(*id))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Generate a full least-agency compliance report.
    pub fn generate_report(&self, agent_id: &str, session_id: &str) -> Option<LeastAgencyReport> {
        let key = Self::session_key(agent_id, session_id);
        // SECURITY (FIND-P3-012): Fail-closed on poisoned lock — return None (no report).
        let trackers = match self.trackers.read() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!(
                    "LeastAgencyTracker::generate_report read lock poisoned: {}",
                    e
                );
                return None;
            }
        };
        let tracker = trackers.get(&key)?;

        let granted = tracker.granted.len();
        let used = tracker.used.len();
        let unused: Vec<String> = tracker
            .granted
            .iter()
            .filter(|id| !tracker.used.contains_key(*id))
            .cloned()
            .collect();
        // FIND-P3-013: When granted == 0, return 1.0 (not 0.0) to avoid division
        // by zero. An agent with zero grants has no unused permissions, so it is
        // trivially "optimal" from a least-agency perspective.
        let ratio = if granted > 0 {
            used as f64 / granted as f64
        } else {
            1.0
        };
        let recommendation = if ratio > THRESHOLD_OPTIMAL {
            AgencyRecommendation::Optimal
        } else if ratio >= THRESHOLD_REVIEW {
            AgencyRecommendation::ReviewGrants
        } else if ratio >= THRESHOLD_NARROW {
            AgencyRecommendation::NarrowScope
        } else {
            AgencyRecommendation::Critical
        };

        Some(LeastAgencyReport {
            agent_id: agent_id.to_string(),
            session_id: session_id.to_string(),
            granted_permissions: granted,
            used_permissions: used,
            unused_permissions: unused,
            usage_ratio: ratio,
            recommendation,
        })
    }

    /// Atomically identify and remove stale permissions (FIND-R44-019).
    ///
    /// Acquires a write lock, identifies permissions unused for longer than
    /// `auto_revoke_after_secs`, removes them from `granted` and `granted_last_used`,
    /// and returns the list of revoked permission IDs.
    ///
    /// In `Monitor` mode, returns candidates without revoking (read-only).
    /// In `Enforce` mode, atomically removes stale permissions.
    pub fn revoke_stale_permissions(&self, agent_id: &str, session_id: &str) -> Vec<String> {
        let key = Self::session_key(agent_id, session_id);
        let now = Instant::now();
        let threshold = std::time::Duration::from_secs(self.auto_revoke_after_secs);

        match self.enforcement_mode {
            EnforcementMode::Monitor => {
                // Read-only path: just identify candidates
                // SECURITY (FIND-P3-012): Fail-closed on poisoned lock — return empty.
                let trackers = match self.trackers.read() {
                    Ok(guard) => guard,
                    Err(e) => {
                        tracing::error!(
                            "LeastAgencyTracker::revoke_stale_permissions read lock poisoned: {}",
                            e
                        );
                        return Vec::new();
                    }
                };
                let Some(tracker) = trackers.get(&key) else {
                    return Vec::new();
                };
                tracker
                    .granted
                    .iter()
                    .filter(|id| {
                        let last_used = tracker
                            .granted_last_used
                            .get(*id)
                            .copied()
                            .unwrap_or(tracker.session_start);
                        now.duration_since(last_used) > threshold
                    })
                    .cloned()
                    .collect()
            }
            EnforcementMode::Enforce => {
                // FIND-R44-019: Atomic identify-and-remove under a single write lock
                // to prevent TOCTOU between checking staleness and revoking.
                // SECURITY (FIND-P3-012): Fail-closed on poisoned lock — return empty.
                let mut trackers = match self.trackers.write() {
                    Ok(guard) => guard,
                    Err(e) => {
                        tracing::error!(
                            "LeastAgencyTracker::revoke_stale_permissions write lock poisoned: {}",
                            e
                        );
                        return Vec::new();
                    }
                };
                let Some(tracker) = trackers.get_mut(&key) else {
                    return Vec::new();
                };
                let stale: Vec<String> = tracker
                    .granted
                    .iter()
                    .filter(|id| {
                        let last_used = tracker
                            .granted_last_used
                            .get(*id)
                            .copied()
                            .unwrap_or(tracker.session_start);
                        now.duration_since(last_used) > threshold
                    })
                    .cloned()
                    .collect();

                for id in &stale {
                    tracker.granted.remove(id);
                    tracker.granted_last_used.remove(id);
                }
                stale
            }
        }
    }

    /// Backward-compatible alias for [`LeastAgencyTracker::revoke_stale_permissions()`].
    ///
    /// Prefer `revoke_stale_permissions()` which has a clearer name reflecting
    /// its behavior in both `Monitor` and `Enforce` modes.
    #[deprecated(since = "4.0.1", note = "use revoke_stale_permissions() instead")]
    pub fn check_auto_revoke(&self, agent_id: &str, session_id: &str) -> Vec<String> {
        self.revoke_stale_permissions(agent_id, session_id)
    }

    /// Suggest policy IDs that could be revoked because the session's usage ratio
    /// is below `narrow_threshold`.
    ///
    /// Returns `Some(unused_policy_ids)` when the agent's `usage_ratio` (used/granted)
    /// is below the configured threshold, indicating over-provisioning.
    /// Returns `None` if the session is not tracked or usage is above the threshold
    /// (i.e., scope is appropriately sized).
    pub fn recommend_narrowing(&self, agent_id: &str, session_id: &str) -> Option<Vec<String>> {
        let report = self.generate_report(agent_id, session_id)?;
        if report.usage_ratio < self.narrow_threshold {
            Some(report.unused_permissions)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_record_usage() {
        let tracker = LeastAgencyTracker::new(0.5);
        tracker.register_grants("agent-1", "sess-1", &["p1".to_string(), "p2".to_string()]);
        tracker.record_usage("agent-1", "sess-1", "p1", "fs", "read");
        let unused = tracker.check_unused("agent-1", "sess-1");
        assert_eq!(unused, vec!["p2".to_string()]);
    }

    #[test]
    fn test_unused_detection() {
        let tracker = LeastAgencyTracker::new(0.5);
        tracker.register_grants(
            "agent-1",
            "sess-1",
            &["p1".to_string(), "p2".to_string(), "p3".to_string()],
        );
        let unused = tracker.check_unused("agent-1", "sess-1");
        assert_eq!(unused.len(), 3);
    }

    #[test]
    fn test_report_generation_optimal() {
        let tracker = LeastAgencyTracker::new(0.5);
        tracker.register_grants("agent-1", "sess-1", &["p1".to_string(), "p2".to_string()]);
        tracker.record_usage("agent-1", "sess-1", "p1", "fs", "read");
        tracker.record_usage("agent-1", "sess-1", "p2", "net", "fetch");
        let report = tracker.generate_report("agent-1", "sess-1").unwrap();
        assert_eq!(report.granted_permissions, 2);
        assert_eq!(report.used_permissions, 2);
        assert!(report.unused_permissions.is_empty());
        assert!((report.usage_ratio - 1.0).abs() < f64::EPSILON);
        assert_eq!(report.recommendation, AgencyRecommendation::Optimal);
    }

    #[test]
    fn test_report_generation_critical() {
        let tracker = LeastAgencyTracker::new(0.5);
        tracker.register_grants(
            "agent-1",
            "sess-1",
            &[
                "p1".to_string(),
                "p2".to_string(),
                "p3".to_string(),
                "p4".to_string(),
                "p5".to_string(),
                "p6".to_string(),
            ],
        );
        tracker.record_usage("agent-1", "sess-1", "p1", "fs", "read");
        let report = tracker.generate_report("agent-1", "sess-1").unwrap();
        assert_eq!(report.used_permissions, 1);
        assert_eq!(report.granted_permissions, 6);
        assert_eq!(report.recommendation, AgencyRecommendation::Critical);
    }

    #[test]
    fn test_narrowing_recommendations() {
        let tracker = LeastAgencyTracker::new(0.5);
        tracker.register_grants(
            "agent-1",
            "sess-1",
            &["p1".to_string(), "p2".to_string(), "p3".to_string()],
        );
        tracker.record_usage("agent-1", "sess-1", "p1", "fs", "read");

        // 1/3 = 0.33 < 0.5 threshold
        let narrowing = tracker.recommend_narrowing("agent-1", "sess-1");
        assert!(narrowing.is_some());
        let ids = narrowing.unwrap();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_multiple_agents_isolated() {
        let tracker = LeastAgencyTracker::new(0.5);
        tracker.register_grants("agent-1", "sess-1", &["p1".to_string()]);
        tracker.register_grants("agent-2", "sess-2", &["p2".to_string()]);

        tracker.record_usage("agent-1", "sess-1", "p1", "fs", "read");

        let report1 = tracker.generate_report("agent-1", "sess-1").unwrap();
        assert_eq!(report1.used_permissions, 1);

        let report2 = tracker.generate_report("agent-2", "sess-2").unwrap();
        assert_eq!(report2.used_permissions, 0);
    }

    #[test]
    fn test_bounded_tracker_count() {
        let tracker = LeastAgencyTracker::new(0.5);
        // Fill up to MAX
        for i in 0..MAX_TRACKED_SESSIONS {
            tracker.register_grants(&format!("a{}", i), "s", &["p".to_string()]);
        }
        // One more should evict
        tracker.register_grants("overflow-agent", "s", &["p".to_string()]);
        let trackers = tracker.trackers.read().unwrap();
        assert!(trackers.len() <= MAX_TRACKED_SESSIONS);
    }

    #[test]
    fn test_usage_ratio_calculation() {
        let tracker = LeastAgencyTracker::new(0.5);
        tracker.register_grants(
            "agent-1",
            "sess-1",
            &[
                "p1".to_string(),
                "p2".to_string(),
                "p3".to_string(),
                "p4".to_string(),
            ],
        );
        tracker.record_usage("agent-1", "sess-1", "p1", "fs", "read");
        tracker.record_usage("agent-1", "sess-1", "p2", "net", "fetch");
        let report = tracker.generate_report("agent-1", "sess-1").unwrap();
        assert!((report.usage_ratio - 0.5).abs() < f64::EPSILON);
        assert_eq!(report.recommendation, AgencyRecommendation::ReviewGrants);
    }

    #[test]
    fn test_new_with_config_enforcement_mode() {
        let tracker = LeastAgencyTracker::new_with_config(0.5, EnforcementMode::Enforce, 1800);
        assert_eq!(tracker.enforcement_mode(), EnforcementMode::Enforce);
    }

    #[test]
    fn test_new_with_config_monitor_mode() {
        let tracker = LeastAgencyTracker::new_with_config(0.5, EnforcementMode::Monitor, 3600);
        assert_eq!(tracker.enforcement_mode(), EnforcementMode::Monitor);
    }

    #[test]
    #[allow(deprecated)]
    fn test_check_auto_revoke_no_session() {
        let tracker = LeastAgencyTracker::new_with_config(0.5, EnforcementMode::Enforce, 1);
        // No session registered — should return empty
        let revokable = tracker.check_auto_revoke("agent-1", "sess-1");
        assert!(revokable.is_empty());
    }

    #[test]
    #[allow(deprecated)]
    fn test_check_auto_revoke_recently_granted() {
        let tracker = LeastAgencyTracker::new_with_config(0.5, EnforcementMode::Enforce, 3600);
        tracker.register_grants("agent-1", "sess-1", &["p1".to_string(), "p2".to_string()]);
        // Just granted — nothing should be revokable with 3600s threshold
        let revokable = tracker.check_auto_revoke("agent-1", "sess-1");
        assert!(revokable.is_empty());
    }

    #[test]
    #[allow(deprecated)]
    fn test_check_auto_revoke_with_zero_threshold() {
        // With auto_revoke_after_secs = 0, any elapsed time > 0 triggers revocation.
        // Config validation prevents 0 in production, but the tracker itself handles it.
        let tracker = LeastAgencyTracker::new_with_config(0.5, EnforcementMode::Enforce, 0);
        tracker.register_grants("agent-1", "sess-1", &["p1".to_string()]);
        // Even a microsecond of elapsed time is > Duration::from_secs(0),
        // so the permission should be revokable.
        let revokable = tracker.check_auto_revoke("agent-1", "sess-1");
        assert_eq!(revokable.len(), 1);
        assert_eq!(revokable[0], "p1");
    }

    // ════════════════════════════════════════════════════════
    // FIND-R44-021: Session key separator collision
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_session_key_no_collision_with_separator_in_id() {
        // "a::b" + "c" should not collide with "a" + "b::c"
        let key1 = LeastAgencyTracker::session_key("a::b", "c");
        let key2 = LeastAgencyTracker::session_key("a", "b::c");
        assert_ne!(
            key1, key2,
            "Session keys must not collide when agent_id contains separator"
        );
    }

    #[test]
    fn test_session_key_no_collision_different_lengths() {
        let key1 = LeastAgencyTracker::session_key("abc", "def");
        let key2 = LeastAgencyTracker::session_key("ab", "cdef");
        assert_ne!(
            key1, key2,
            "Session keys must not collide for different agent/session splits"
        );
    }

    #[test]
    fn test_session_key_collision_isolation_in_tracker() {
        let tracker = LeastAgencyTracker::new(0.5);
        // Register with agent_id containing the old separator
        tracker.register_grants("a::b", "c", &["p1".to_string()]);
        tracker.register_grants("a", "b::c", &["p2".to_string()]);

        // Each should have their own grants
        let unused1 = tracker.check_unused("a::b", "c");
        assert_eq!(unused1, vec!["p1".to_string()]);

        let unused2 = tracker.check_unused("a", "b::c");
        assert_eq!(unused2, vec!["p2".to_string()]);
    }

    // ════════════════════════════════════════════════════════
    // FIND-R44-018: Bounded per-session grants
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_grants_per_session_bounded() {
        let tracker = LeastAgencyTracker::new(0.5);
        // Generate more than MAX_GRANTS_PER_SESSION policy IDs
        let policy_ids: Vec<String> = (0..MAX_GRANTS_PER_SESSION + 500)
            .map(|i| format!("policy_{}", i))
            .collect();
        tracker.register_grants("agent-1", "sess-1", &policy_ids);

        let trackers = tracker.trackers.read().unwrap_or_else(|e| e.into_inner());
        let key = LeastAgencyTracker::session_key("agent-1", "sess-1");
        let pt = trackers.get(&key).expect("session should exist");
        assert!(
            pt.granted.len() <= MAX_GRANTS_PER_SESSION,
            "Grants should be bounded to {}, got {}",
            MAX_GRANTS_PER_SESSION,
            pt.granted.len()
        );
    }

    #[test]
    fn test_grants_within_limit_all_accepted() {
        let tracker = LeastAgencyTracker::new(0.5);
        let policy_ids: Vec<String> = (0..100).map(|i| format!("p_{}", i)).collect();
        tracker.register_grants("agent-1", "sess-1", &policy_ids);

        let trackers = tracker.trackers.read().unwrap_or_else(|e| e.into_inner());
        let key = LeastAgencyTracker::session_key("agent-1", "sess-1");
        let pt = trackers.get(&key).expect("session should exist");
        assert_eq!(pt.granted.len(), 100);
    }

    // ════════════════════════════════════════════════════════
    // FIND-R44-019: Atomic auto-revocation (TOCTOU fix)
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_revoke_stale_permissions_enforce_removes_stale() {
        let tracker = LeastAgencyTracker::new_with_config(0.5, EnforcementMode::Enforce, 0);
        tracker.register_grants("agent-1", "sess-1", &["p1".to_string(), "p2".to_string()]);

        // With 0-sec threshold, both should be stale immediately
        let revoked = tracker.revoke_stale_permissions("agent-1", "sess-1");
        assert_eq!(revoked.len(), 2, "Both permissions should be revoked");

        // After revocation, grants should be empty
        let trackers = tracker.trackers.read().unwrap_or_else(|e| e.into_inner());
        let key = LeastAgencyTracker::session_key("agent-1", "sess-1");
        let pt = trackers.get(&key).expect("session should exist");
        assert!(
            pt.granted.is_empty(),
            "Granted set should be empty after revocation"
        );
        assert!(
            pt.granted_last_used.is_empty(),
            "granted_last_used map should be empty after revocation"
        );
    }

    #[test]
    fn test_revoke_stale_permissions_monitor_does_not_remove() {
        let tracker = LeastAgencyTracker::new_with_config(0.5, EnforcementMode::Monitor, 0);
        tracker.register_grants("agent-1", "sess-1", &["p1".to_string(), "p2".to_string()]);

        // Monitor mode should identify but not remove
        let candidates = tracker.revoke_stale_permissions("agent-1", "sess-1");
        assert_eq!(candidates.len(), 2, "Both should be candidates");

        // Grants should still be present
        let trackers = tracker.trackers.read().unwrap_or_else(|e| e.into_inner());
        let key = LeastAgencyTracker::session_key("agent-1", "sess-1");
        let pt = trackers.get(&key).expect("session should exist");
        assert_eq!(pt.granted.len(), 2, "Monitor mode should not remove grants");
    }

    #[test]
    fn test_revoke_stale_permissions_used_recently_not_revoked() {
        let tracker = LeastAgencyTracker::new_with_config(0.5, EnforcementMode::Enforce, 3600);
        tracker.register_grants("agent-1", "sess-1", &["p1".to_string(), "p2".to_string()]);
        // Record usage to refresh last_used
        tracker.record_usage("agent-1", "sess-1", "p1", "fs", "read");

        // With 3600s threshold and just-registered grants, nothing should be stale
        let revoked = tracker.revoke_stale_permissions("agent-1", "sess-1");
        assert!(
            revoked.is_empty(),
            "Recently used/granted permissions should not be revoked"
        );
    }
}
