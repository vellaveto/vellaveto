//! Context budget enforcement for RAG defense.
//!
//! Prevents context window flooding by enforcing token budgets
//! on retrieval results. This defends against attacks that attempt
//! to dilute legitimate information with irrelevant content.

use std::collections::HashMap;
use std::sync::RwLock;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use vellaveto_config::ContextBudgetConfig;

use super::error::RagDefenseError;

/// Maximum number of tracked sessions to prevent unbounded HashMap growth.
/// SECURITY (FIND-R104-006): Without a bound, an attacker generating unique
/// session IDs can cause OOM.
const MAX_BUDGET_SESSIONS: usize = 100_000;

/// Maximum retrieval records per session to prevent unbounded Vec growth.
const MAX_RETRIEVALS_PER_SESSION: usize = 10_000;

/// Tracks context budget usage per session.
pub struct ContextBudgetTracker {
    config: ContextBudgetConfig,
    /// Usage tracking per session ID.
    usage: RwLock<HashMap<String, BudgetUsage>>,
}

/// Budget usage for a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetUsage {
    /// Total tokens used in this session.
    pub total_tokens: u32,
    /// Individual retrieval usages.
    pub retrievals: Vec<RetrievalUsage>,
    /// When usage was last updated.
    pub last_updated: DateTime<Utc>,
}

impl Default for BudgetUsage {
    fn default() -> Self {
        Self {
            total_tokens: 0,
            retrievals: Vec::new(),
            last_updated: Utc::now(),
        }
    }
}

/// Usage record for a single retrieval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrievalUsage {
    /// Document ID that was retrieved.
    pub doc_id: String,
    /// Number of tokens used.
    pub tokens: u32,
    /// When this retrieval occurred.
    pub timestamp: DateTime<Utc>,
}

impl RetrievalUsage {
    /// Creates a new retrieval usage record.
    pub fn new(doc_id: impl Into<String>, tokens: u32) -> Self {
        Self {
            doc_id: doc_id.into(),
            tokens,
            timestamp: Utc::now(),
        }
    }
}

/// Result of budget enforcement check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BudgetEnforcement {
    /// Request is allowed within budget.
    Allowed,
    /// Request was truncated to fit budget.
    Truncated {
        /// Original token count.
        original: u32,
        /// Truncated token count.
        truncated_to: u32,
    },
    /// Request was rejected due to budget exhaustion.
    Rejected {
        /// Reason for rejection.
        reason: String,
    },
    /// Warning about budget usage (not blocking).
    Warning {
        /// Warning message.
        message: String,
    },
}

impl BudgetEnforcement {
    /// Returns true if the request is allowed (possibly with truncation).
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            BudgetEnforcement::Allowed
                | BudgetEnforcement::Truncated { .. }
                | BudgetEnforcement::Warning { .. }
        )
    }

    /// Returns true if this is a hard rejection.
    pub fn is_rejected(&self) -> bool {
        matches!(self, BudgetEnforcement::Rejected { .. })
    }
}

impl ContextBudgetTracker {
    /// Creates a new context budget tracker.
    pub fn new(config: ContextBudgetConfig) -> Self {
        Self {
            config,
            usage: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a disabled tracker that allows all requests.
    pub fn disabled() -> Self {
        Self::new(ContextBudgetConfig {
            enabled: false,
            ..Default::default()
        })
    }

    /// Returns whether budget tracking is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Checks if a token request fits within budget.
    pub fn check_budget(&self, session_id: &str, tokens: u32) -> BudgetEnforcement {
        if !self.config.enabled {
            return BudgetEnforcement::Allowed;
        }

        // Check per-retrieval limit
        if tokens > self.config.max_tokens_per_retrieval {
            return self.handle_over_retrieval_limit(tokens);
        }

        // Check total session budget
        let current_usage = self.get_current_usage(session_id);
        let new_total = current_usage + tokens;

        if new_total > self.config.max_total_context_tokens {
            return self.handle_over_session_limit(session_id, tokens, current_usage);
        }

        // Check alert threshold
        let usage_fraction = new_total as f64 / self.config.max_total_context_tokens as f64;
        if usage_fraction >= self.config.alert_threshold {
            return BudgetEnforcement::Warning {
                message: format!(
                    "Context budget at {:.0}% ({}/{} tokens)",
                    usage_fraction * 100.0,
                    new_total,
                    self.config.max_total_context_tokens
                ),
            };
        }

        BudgetEnforcement::Allowed
    }

    /// Enforces budget and returns Result for blocking mode.
    pub fn enforce_budget(
        &self,
        session_id: &str,
        tokens: u32,
    ) -> Result<BudgetEnforcement, RagDefenseError> {
        let enforcement = self.check_budget(session_id, tokens);

        if let BudgetEnforcement::Rejected { reason } = &enforcement {
            if self.config.enforcement == "reject" {
                return Err(RagDefenseError::ContextBudgetExceeded {
                    tokens,
                    budget: self.get_remaining_budget(session_id),
                });
            }
            // For non-reject modes, convert to warning
            return Ok(BudgetEnforcement::Warning {
                message: reason.clone(),
            });
        }

        Ok(enforcement)
    }

    /// Handles tokens exceeding per-retrieval limit.
    fn handle_over_retrieval_limit(&self, tokens: u32) -> BudgetEnforcement {
        match self.config.enforcement.as_str() {
            "truncate" => BudgetEnforcement::Truncated {
                original: tokens,
                truncated_to: self.config.max_tokens_per_retrieval,
            },
            "reject" => BudgetEnforcement::Rejected {
                reason: format!(
                    "Single retrieval {} tokens exceeds limit {}",
                    tokens, self.config.max_tokens_per_retrieval
                ),
            },
            _ => BudgetEnforcement::Warning {
                message: format!(
                    "Single retrieval {} tokens exceeds limit {}",
                    tokens, self.config.max_tokens_per_retrieval
                ),
            },
        }
    }

    /// Handles tokens exceeding session budget.
    fn handle_over_session_limit(
        &self,
        session_id: &str,
        tokens: u32,
        current_usage: u32,
    ) -> BudgetEnforcement {
        let remaining = self.get_remaining_budget(session_id);

        match self.config.enforcement.as_str() {
            "truncate" => {
                if remaining > 0 {
                    BudgetEnforcement::Truncated {
                        original: tokens,
                        truncated_to: remaining,
                    }
                } else {
                    BudgetEnforcement::Rejected {
                        reason: "Session context budget exhausted".to_string(),
                    }
                }
            }
            "reject" => BudgetEnforcement::Rejected {
                reason: format!(
                    "Request {} tokens would exceed budget (current: {}, max: {})",
                    tokens, current_usage, self.config.max_total_context_tokens
                ),
            },
            _ => BudgetEnforcement::Warning {
                message: format!(
                    "Request {} tokens would exceed budget (current: {}, max: {})",
                    tokens, current_usage, self.config.max_total_context_tokens
                ),
            },
        }
    }

    /// Records token usage for a session.
    ///
    /// SECURITY (FIND-R104-006): Enforces session count and per-session retrieval
    /// bounds. Uses saturating_add for total_tokens (FIND-R104-009).
    pub fn record_usage(&self, session_id: &str, doc_id: &str, tokens: u32) {
        if !self.config.enabled {
            return;
        }

        if let Ok(mut usage_map) = self.usage.write() {
            // SECURITY (FIND-R104-006): Reject new sessions if at capacity.
            if !usage_map.contains_key(session_id) && usage_map.len() >= MAX_BUDGET_SESSIONS {
                tracing::warn!(
                    max = MAX_BUDGET_SESSIONS,
                    "Context budget tracker at session capacity — dropping new session"
                );
                return;
            }

            let usage = usage_map.entry(session_id.to_string()).or_default();

            // SECURITY (FIND-R104-009): Use saturating_add to prevent wrapping to zero.
            usage.total_tokens = usage.total_tokens.saturating_add(tokens);
            // SECURITY (FIND-R104-006): Cap retrievals Vec to prevent unbounded growth.
            if usage.retrievals.len() < MAX_RETRIEVALS_PER_SESSION {
                usage.retrievals.push(RetrievalUsage::new(doc_id, tokens));
            }
            usage.last_updated = Utc::now();
        }
    }

    /// Returns the remaining budget for a session.
    pub fn get_remaining_budget(&self, session_id: &str) -> u32 {
        if !self.config.enabled {
            return u32::MAX;
        }

        let current = self.get_current_usage(session_id);
        self.config.max_total_context_tokens.saturating_sub(current)
    }

    /// Returns the current token usage for a session.
    ///
    /// SECURITY (FIND-R64-008): Returns `max_total_context_tokens` on lock poison
    /// (fail-closed — reports full budget used, so remaining_budget returns 0).
    pub fn get_current_usage(&self, session_id: &str) -> u32 {
        match self.usage.read() {
            Ok(u) => u.get(session_id).map(|bu| bu.total_tokens).unwrap_or(0),
            Err(_) => {
                tracing::error!("Context budget lock poisoned — fail-closed (max usage)");
                self.config.max_total_context_tokens
            }
        }
    }

    /// Returns the full budget usage for a session.
    pub fn get_usage(&self, session_id: &str) -> Option<BudgetUsage> {
        match self.usage.read() {
            Ok(u) => u.get(session_id).cloned(),
            Err(_) => {
                tracing::error!("Context budget lock poisoned in get_usage");
                None
            }
        }
    }

    /// Resets the budget for a session.
    pub fn reset_session(&self, session_id: &str) {
        if let Ok(mut usage_map) = self.usage.write() {
            usage_map.remove(session_id);
        } else {
            tracing::error!("Context budget write lock poisoned in reset_session");
        }
    }

    /// Returns the number of tracked sessions.
    pub fn session_count(&self) -> usize {
        self.usage.read().map(|u| u.len()).unwrap_or_else(|_| {
            tracing::error!("Context budget lock poisoned in session_count");
            0
        })
    }

    /// Returns budget statistics.
    pub fn stats(&self) -> BudgetStats {
        let usage_map = self.usage.read().ok();

        let (sessions, total_tokens, avg_tokens) = match usage_map {
            Some(map) => {
                let sessions = map.len();
                let total_tokens: u32 = map.values().map(|u| u.total_tokens).sum();
                let avg = if sessions > 0 {
                    total_tokens as f64 / sessions as f64
                } else {
                    0.0
                };
                (sessions, total_tokens, avg)
            }
            None => (0, 0, 0.0),
        };

        BudgetStats {
            tracked_sessions: sessions,
            total_tokens_used: total_tokens,
            avg_tokens_per_session: avg_tokens,
            max_per_retrieval: self.config.max_tokens_per_retrieval,
            max_per_session: self.config.max_total_context_tokens,
        }
    }
}

/// Budget tracking statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetStats {
    /// Number of tracked sessions.
    pub tracked_sessions: usize,
    /// Total tokens used across all sessions.
    pub total_tokens_used: u32,
    /// Average tokens per session.
    pub avg_tokens_per_session: f64,
    /// Maximum tokens per retrieval.
    pub max_per_retrieval: u32,
    /// Maximum tokens per session.
    pub max_per_session: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_enforcement_allowed() {
        let config = ContextBudgetConfig {
            enabled: true,
            max_tokens_per_retrieval: 1000,
            max_total_context_tokens: 5000,
            enforcement: "reject".to_string(),
            alert_threshold: 0.8,
        };
        let tracker = ContextBudgetTracker::new(config);

        let result = tracker.check_budget("session1", 500);
        assert_eq!(result, BudgetEnforcement::Allowed);
    }

    #[test]
    fn test_budget_enforcement_disabled() {
        let tracker = ContextBudgetTracker::disabled();

        // Even huge request should be allowed when disabled
        let result = tracker.check_budget("session1", 1_000_000);
        assert_eq!(result, BudgetEnforcement::Allowed);
    }

    #[test]
    fn test_budget_per_retrieval_truncate() {
        let config = ContextBudgetConfig {
            enabled: true,
            max_tokens_per_retrieval: 1000,
            max_total_context_tokens: 5000,
            enforcement: "truncate".to_string(),
            alert_threshold: 0.8,
        };
        let tracker = ContextBudgetTracker::new(config);

        let result = tracker.check_budget("session1", 1500);
        assert!(matches!(
            result,
            BudgetEnforcement::Truncated {
                original: 1500,
                truncated_to: 1000
            }
        ));
    }

    #[test]
    fn test_budget_per_retrieval_reject() {
        let config = ContextBudgetConfig {
            enabled: true,
            max_tokens_per_retrieval: 1000,
            max_total_context_tokens: 5000,
            enforcement: "reject".to_string(),
            alert_threshold: 0.8,
        };
        let tracker = ContextBudgetTracker::new(config);

        let result = tracker.check_budget("session1", 1500);
        assert!(matches!(result, BudgetEnforcement::Rejected { .. }));
    }

    #[test]
    fn test_budget_session_limit() {
        let config = ContextBudgetConfig {
            enabled: true,
            max_tokens_per_retrieval: 1000,
            max_total_context_tokens: 2000,
            enforcement: "reject".to_string(),
            alert_threshold: 0.8,
        };
        let tracker = ContextBudgetTracker::new(config);

        // Record some usage
        tracker.record_usage("session1", "doc1", 1500);

        // Check that remaining budget is correct
        assert_eq!(tracker.get_remaining_budget("session1"), 500);

        // Request that exceeds remaining budget should be rejected
        let result = tracker.check_budget("session1", 600);
        assert!(matches!(result, BudgetEnforcement::Rejected { .. }));
    }

    #[test]
    fn test_budget_session_limit_truncate() {
        let config = ContextBudgetConfig {
            enabled: true,
            max_tokens_per_retrieval: 1000,
            max_total_context_tokens: 2000,
            enforcement: "truncate".to_string(),
            alert_threshold: 0.8,
        };
        let tracker = ContextBudgetTracker::new(config);

        tracker.record_usage("session1", "doc1", 1500);

        let result = tracker.check_budget("session1", 600);
        assert!(matches!(
            result,
            BudgetEnforcement::Truncated {
                original: 600,
                truncated_to: 500
            }
        ));
    }

    #[test]
    fn test_budget_warning_threshold() {
        let config = ContextBudgetConfig {
            enabled: true,
            max_tokens_per_retrieval: 1000,
            max_total_context_tokens: 1000,
            enforcement: "warn".to_string(),
            alert_threshold: 0.8,
        };
        let tracker = ContextBudgetTracker::new(config);

        // 900/1000 = 90% > 80% threshold
        let result = tracker.check_budget("session1", 900);
        assert!(matches!(result, BudgetEnforcement::Warning { .. }));
    }

    #[test]
    fn test_record_usage() {
        let config = ContextBudgetConfig::default();
        let tracker = ContextBudgetTracker::new(config);

        tracker.record_usage("session1", "doc1", 100);
        tracker.record_usage("session1", "doc2", 200);

        let usage = tracker.get_usage("session1").unwrap();
        assert_eq!(usage.total_tokens, 300);
        assert_eq!(usage.retrievals.len(), 2);
    }

    #[test]
    fn test_reset_session() {
        let config = ContextBudgetConfig::default();
        let tracker = ContextBudgetTracker::new(config);

        tracker.record_usage("session1", "doc1", 100);
        assert_eq!(tracker.get_current_usage("session1"), 100);

        tracker.reset_session("session1");
        assert_eq!(tracker.get_current_usage("session1"), 0);
    }

    #[test]
    fn test_enforce_budget_error() {
        let config = ContextBudgetConfig {
            enabled: true,
            max_tokens_per_retrieval: 100,
            max_total_context_tokens: 100,
            enforcement: "reject".to_string(),
            alert_threshold: 0.8,
        };
        let tracker = ContextBudgetTracker::new(config);

        tracker.record_usage("session1", "doc1", 90);

        let result = tracker.enforce_budget("session1", 50);
        assert!(matches!(
            result,
            Err(RagDefenseError::ContextBudgetExceeded { .. })
        ));
    }

    #[test]
    fn test_stats() {
        let config = ContextBudgetConfig::default();
        let tracker = ContextBudgetTracker::new(config);

        tracker.record_usage("session1", "doc1", 100);
        tracker.record_usage("session2", "doc1", 200);

        let stats = tracker.stats();
        assert_eq!(stats.tracked_sessions, 2);
        assert_eq!(stats.total_tokens_used, 300);
        assert!((stats.avg_tokens_per_session - 150.0).abs() < 0.01);
    }

    #[test]
    fn test_is_allowed_variants() {
        assert!(BudgetEnforcement::Allowed.is_allowed());
        assert!(BudgetEnforcement::Truncated {
            original: 100,
            truncated_to: 50
        }
        .is_allowed());
        assert!(BudgetEnforcement::Warning {
            message: "test".to_string()
        }
        .is_allowed());
        assert!(!BudgetEnforcement::Rejected {
            reason: "test".to_string()
        }
        .is_allowed());
    }

    // =================================================================
    // ROUND 104: Bounds enforcement tests
    // =================================================================

    #[test]
    fn test_record_usage_session_bound() {
        let config = ContextBudgetConfig {
            enabled: true,
            max_tokens_per_retrieval: 1000,
            max_total_context_tokens: 10000,
            enforcement: "reject".to_string(),
            alert_threshold: 0.8,
        };
        let tracker = ContextBudgetTracker::new(config);

        // Fill up to MAX_BUDGET_SESSIONS
        for i in 0..MAX_BUDGET_SESSIONS {
            tracker.record_usage(&format!("session_{}", i), "doc1", 1);
        }

        // Next session should be silently dropped
        tracker.record_usage("overflow_session", "doc1", 1);
        assert_eq!(tracker.get_current_usage("overflow_session"), 0);
    }

    #[test]
    fn test_record_usage_retrievals_bound() {
        let config = ContextBudgetConfig {
            enabled: true,
            max_tokens_per_retrieval: 1,
            max_total_context_tokens: u32::MAX,
            enforcement: "truncate".to_string(),
            alert_threshold: 0.99,
        };
        let tracker = ContextBudgetTracker::new(config);

        // Record MAX_RETRIEVALS_PER_SESSION + 100 retrievals
        for i in 0..(MAX_RETRIEVALS_PER_SESSION + 100) {
            tracker.record_usage("session1", &format!("doc_{}", i), 1);
        }

        let usage = tracker.get_usage("session1").unwrap();
        assert_eq!(
            usage.retrievals.len(),
            MAX_RETRIEVALS_PER_SESSION,
            "Retrievals should be capped at MAX_RETRIEVALS_PER_SESSION"
        );
        // But total_tokens should still reflect all calls
        assert_eq!(
            usage.total_tokens,
            (MAX_RETRIEVALS_PER_SESSION + 100) as u32
        );
    }

    #[test]
    fn test_record_usage_saturating_add() {
        let config = ContextBudgetConfig {
            enabled: true,
            max_tokens_per_retrieval: u32::MAX,
            max_total_context_tokens: u32::MAX,
            enforcement: "truncate".to_string(),
            alert_threshold: 0.99,
        };
        let tracker = ContextBudgetTracker::new(config);

        // Push near u32::MAX
        tracker.record_usage("session1", "doc1", u32::MAX - 10);
        tracker.record_usage("session1", "doc2", 100);

        // Should saturate at u32::MAX, not wrap to 89
        let usage = tracker.get_current_usage("session1");
        assert_eq!(usage, u32::MAX, "total_tokens should saturate, not wrap");
    }
}
