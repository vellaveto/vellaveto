//! Least-agency enforcement — tracks permission usage per agent session
//! and detects unused permissions for scope narrowing recommendations.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::time::Instant;
use vellaveto_types::{AgencyRecommendation, LeastAgencyReport, PermissionUsage};

/// Maximum tracked sessions to bound memory.
const MAX_TRACKED_SESSIONS: usize = 4096;

/// Per-agent-session permission tracker.
struct PermissionTracker {
    granted: HashSet<String>,
    used: HashMap<String, PermissionUsage>,
    session_start: Instant,
}

/// Tracks permission usage across agent sessions for least-agency enforcement.
pub struct LeastAgencyTracker {
    narrow_threshold: f64,
    trackers: RwLock<HashMap<String, PermissionTracker>>,
}

impl LeastAgencyTracker {
    /// Create a new tracker with the given narrowing threshold.
    pub fn new(narrow_threshold: f64) -> Self {
        Self {
            narrow_threshold,
            trackers: RwLock::new(HashMap::new()),
        }
    }

    fn session_key(agent_id: &str, session_id: &str) -> String {
        format!("{agent_id}::{session_id}")
    }

    /// Register granted policy IDs for an agent session.
    pub fn register_grants(&self, agent_id: &str, session_id: &str, policy_ids: &[String]) {
        let key = Self::session_key(agent_id, session_id);
        let Ok(mut trackers) = self.trackers.write() else {
            return;
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
        let tracker = trackers.entry(key).or_insert_with(|| PermissionTracker {
            granted: HashSet::new(),
            used: HashMap::new(),
            session_start: Instant::now(),
        });
        for id in policy_ids {
            tracker.granted.insert(id.clone());
        }
    }

    /// Record that a permission was exercised.
    pub fn record_usage(
        &self,
        agent_id: &str,
        session_id: &str,
        policy_id: &str,
        tool: &str,
        function: &str,
    ) {
        let key = Self::session_key(agent_id, session_id);
        let Ok(mut trackers) = self.trackers.write() else {
            return;
        };
        if let Some(tracker) = trackers.get_mut(&key) {
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
        }
    }

    /// Return policy IDs that have been granted but never used.
    pub fn check_unused(&self, agent_id: &str, session_id: &str) -> Vec<String> {
        let key = Self::session_key(agent_id, session_id);
        let Ok(trackers) = self.trackers.read() else {
            return Vec::new();
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
        let Ok(trackers) = self.trackers.read() else {
            return None;
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
        let ratio = if granted > 0 {
            used as f64 / granted as f64
        } else {
            1.0
        };
        let recommendation = if ratio > 0.8 {
            AgencyRecommendation::Optimal
        } else if ratio >= 0.5 {
            AgencyRecommendation::ReviewGrants
        } else if ratio >= 0.2 {
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

    /// Suggest policy IDs that could be revoked (unused permissions below threshold).
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
}
