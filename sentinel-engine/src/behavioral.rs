//! Behavioral anomaly detection for agent tool call patterns (P4.1 / OWASP ASI).
//!
//! Tracks per-agent tool call frequency using exponential moving average (EMA)
//! and flags deviations from established baselines. Deterministic and auditable —
//! no ML, no randomness.
//!
//! # Design
//!
//! - **EMA**: `new_ema = alpha * current + (1 - alpha) * old_ema`
//! - **Anomaly**: flagged when `current_count / baseline_ema >= threshold`
//! - **Cold start**: no alerts until `min_sessions` sessions are recorded
//! - **Bounded memory**: max agents and max tools per agent with LRU eviction
//! - **Decay**: tools unused in a session have their EMA decayed toward zero

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ═══════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════

/// Configuration for behavioral anomaly detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralConfig {
    /// EMA smoothing factor in (0.0, 1.0]. Higher values weight recent data more.
    /// Default: 0.2
    #[serde(default = "default_alpha")]
    pub alpha: f64,

    /// Deviation threshold multiplier. Anomaly flagged when
    /// `current_count / baseline_ema >= threshold`.
    /// Default: 10.0
    #[serde(default = "default_threshold")]
    pub threshold: f64,

    /// Minimum sessions before baselines are actionable (cold start protection).
    /// No anomalies are flagged until both the agent and the specific tool have
    /// at least this many recorded sessions.
    /// Default: 3
    #[serde(default = "default_min_sessions")]
    pub min_sessions: u32,

    /// Maximum tool entries tracked per agent. Oldest (by last active use) evicted first.
    /// Default: 500
    #[serde(default = "default_max_tools")]
    pub max_tools_per_agent: usize,

    /// Maximum agents tracked. Agent with fewest total sessions evicted first.
    /// Default: 10_000
    #[serde(default = "default_max_agents")]
    pub max_agents: usize,
}

fn default_alpha() -> f64 {
    0.2
}
fn default_threshold() -> f64 {
    10.0
}
fn default_min_sessions() -> u32 {
    3
}
fn default_max_tools() -> usize {
    500
}
fn default_max_agents() -> usize {
    10_000
}

impl Default for BehavioralConfig {
    fn default() -> Self {
        Self {
            alpha: default_alpha(),
            threshold: default_threshold(),
            min_sessions: default_min_sessions(),
            max_tools_per_agent: default_max_tools(),
            max_agents: default_max_agents(),
        }
    }
}

// ═══════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════

/// Errors from behavioral tracking operations.
#[derive(Debug, Clone, PartialEq)]
pub enum BehavioralError {
    /// Alpha must be in (0.0, 1.0].
    InvalidAlpha(f64),
    /// Threshold must be positive and finite.
    InvalidThreshold(f64),
    /// max_tools_per_agent must be > 0.
    InvalidMaxTools,
    /// max_agents must be > 0.
    InvalidMaxAgents,
    /// Snapshot contains invalid data.
    InvalidSnapshot(String),
}

impl std::fmt::Display for BehavioralError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BehavioralError::InvalidAlpha(a) => {
                write!(f, "alpha must be in (0.0, 1.0], got {}", a)
            }
            BehavioralError::InvalidThreshold(t) => {
                write!(f, "threshold must be positive and finite, got {}", t)
            }
            BehavioralError::InvalidMaxTools => write!(f, "max_tools_per_agent must be > 0"),
            BehavioralError::InvalidMaxAgents => write!(f, "max_agents must be > 0"),
            BehavioralError::InvalidSnapshot(msg) => write!(f, "invalid snapshot: {}", msg),
        }
    }
}

impl std::error::Error for BehavioralError {}

impl BehavioralConfig {
    /// Validate configuration values.
    pub fn validate(&self) -> Result<(), BehavioralError> {
        if self.alpha <= 0.0 || self.alpha > 1.0 || self.alpha.is_nan() {
            return Err(BehavioralError::InvalidAlpha(self.alpha));
        }
        if self.threshold <= 0.0 || self.threshold.is_nan() || self.threshold.is_infinite() {
            return Err(BehavioralError::InvalidThreshold(self.threshold));
        }
        if self.max_tools_per_agent == 0 {
            return Err(BehavioralError::InvalidMaxTools);
        }
        if self.max_agents == 0 {
            return Err(BehavioralError::InvalidMaxAgents);
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// BASELINE & ALERT TYPES
// ═══════════════════════════════════════════════════

/// Per-tool statistics tracked across sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolBaseline {
    /// Exponential moving average of call count.
    pub ema: f64,
    /// Number of sessions where this tool was observed or decayed.
    pub session_count: u32,
    /// Monotonic counter from last *active* use (non-zero call count).
    /// Used for eviction: tools only passively decaying have stale values.
    pub last_active: u64,
}

/// Severity of a detected anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalySeverity {
    /// Current count exceeds `threshold * baseline` (but below 2x threshold).
    Warning,
    /// Current count exceeds `2 * threshold * baseline`.
    Critical,
}

/// An anomaly detected in tool call behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyAlert {
    /// Agent that triggered the anomaly.
    pub agent_id: String,
    /// Tool name with anomalous frequency.
    pub tool: String,
    /// Current session's call count for this tool.
    pub current_count: u64,
    /// Historical EMA baseline.
    pub baseline_ema: f64,
    /// Deviation ratio (`current_count / baseline_ema`).
    pub deviation_ratio: f64,
    /// Severity level.
    pub severity: AnomalySeverity,
}

impl std::fmt::Display for AnomalyAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:?}] Agent '{}' tool '{}': {} calls (baseline {:.1}, ratio {:.1}x)",
            self.severity,
            self.agent_id,
            self.tool,
            self.current_count,
            self.baseline_ema,
            self.deviation_ratio,
        )
    }
}

// ═══════════════════════════════════════════════════
// SNAPSHOT (PERSISTENCE)
// ═══════════════════════════════════════════════════

/// Serializable snapshot of all behavioral tracking state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralSnapshot {
    /// Per-agent state.
    pub agents: HashMap<String, AgentSnapshotEntry>,
    /// Global update counter at time of snapshot.
    pub update_counter: u64,
}

/// Snapshot entry for a single agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSnapshotEntry {
    pub tools: HashMap<String, ToolBaseline>,
    pub total_sessions: u32,
}

// ═══════════════════════════════════════════════════
// INTERNAL STATE
// ═══════════════════════════════════════════════════

/// Per-agent tracking state.
#[derive(Debug, Clone)]
struct AgentState {
    tools: HashMap<String, ToolBaseline>,
    total_sessions: u32,
}

// ═══════════════════════════════════════════════════
// TRACKER
// ═══════════════════════════════════════════════════

/// Tracks per-agent tool call frequency patterns and detects anomalies.
///
/// Uses exponential moving average (EMA) — deterministic, auditable, no ML.
/// Designed to detect behavioral shifts like an agent suddenly making 500
/// `read_file` calls when the historical average is 5.
pub struct BehavioralTracker {
    config: BehavioralConfig,
    agents: HashMap<String, AgentState>,
    /// Monotonic counter incremented on each `record_session` call.
    update_counter: u64,
}

impl BehavioralTracker {
    /// Create a new tracker. Returns an error if the configuration is invalid.
    pub fn new(config: BehavioralConfig) -> Result<Self, BehavioralError> {
        config.validate()?;
        Ok(Self {
            config,
            agents: HashMap::new(),
            update_counter: 0,
        })
    }

    /// Check current session's call counts against historical baselines.
    ///
    /// Returns detected anomalies (may be empty). Does **not** modify state.
    /// Call [`record_session`](Self::record_session) after the session completes
    /// to update baselines.
    pub fn check_session(
        &self,
        agent_id: &str,
        call_counts: &HashMap<String, u64>,
    ) -> Vec<AnomalyAlert> {
        let mut alerts = Vec::new();

        let agent = match self.agents.get(agent_id) {
            Some(a) => a,
            None => return alerts, // No history for this agent
        };

        // Cold start: don't flag until the agent has enough sessions
        if agent.total_sessions < self.config.min_sessions {
            tracing::debug!(
                agent_id = %agent_id,
                sessions = %agent.total_sessions,
                min_required = %self.config.min_sessions,
                "Agent in cold-start phase, anomaly detection deferred"
            );
            return alerts;
        }

        for (tool, &count) in call_counts {
            if count == 0 {
                continue;
            }

            let baseline = match agent.tools.get(tool) {
                Some(b) => b,
                None => continue, // New tool — no baseline yet
            };

            // Per-tool cold start: need enough observations for this specific tool
            if baseline.session_count < self.config.min_sessions {
                tracing::trace!(
                    agent_id = %agent_id,
                    tool = %tool,
                    tool_sessions = %baseline.session_count,
                    min_required = %self.config.min_sessions,
                    "Tool in cold-start phase, skipping anomaly check"
                );
                continue;
            }

            // Compute deviation ratio. If baseline EMA is zero (edge case:
            // tool was recorded but EMA decayed to exactly 0.0), treat any
            // non-zero count as anomalous with a high synthetic ratio.
            let ratio = if baseline.ema <= f64::EPSILON {
                count as f64 // effectively infinite deviation
            } else {
                count as f64 / baseline.ema
            };

            if ratio >= self.config.threshold {
                let severity = if ratio >= self.config.threshold * 2.0 {
                    AnomalySeverity::Critical
                } else {
                    AnomalySeverity::Warning
                };

                let alert = AnomalyAlert {
                    agent_id: agent_id.to_string(),
                    tool: tool.clone(),
                    current_count: count,
                    baseline_ema: baseline.ema,
                    deviation_ratio: ratio,
                    severity,
                };

                // IMPROVEMENT_PLAN 1.2: Record anomaly detection metrics
                let severity_label = match severity {
                    AnomalySeverity::Critical => "critical",
                    AnomalySeverity::Warning => "warning",
                };
                metrics::counter!(
                    "sentinel_anomaly_detections_total",
                    "severity" => severity_label.to_string()
                )
                .increment(1);

                // Log anomaly detection for observability
                match severity {
                    AnomalySeverity::Critical => {
                        tracing::warn!(
                            agent_id = %agent_id,
                            tool = %tool,
                            current_count = %count,
                            baseline_ema = %baseline.ema,
                            deviation_ratio = %ratio,
                            "CRITICAL behavioral anomaly detected: tool call frequency {:.1}x above baseline",
                            ratio
                        );
                    }
                    AnomalySeverity::Warning => {
                        tracing::warn!(
                            agent_id = %agent_id,
                            tool = %tool,
                            current_count = %count,
                            baseline_ema = %baseline.ema,
                            deviation_ratio = %ratio,
                            "Behavioral anomaly detected: tool call frequency {:.1}x above baseline",
                            ratio
                        );
                    }
                }

                alerts.push(alert);
            }
        }

        alerts
    }

    /// Update baselines after a session completes.
    ///
    /// Call this with the final call counts when a session ends.
    /// Tools with zero counts are ignored for recording but existing baselines
    /// for tools **not present** in `call_counts` are decayed toward zero.
    pub fn record_session(&mut self, agent_id: &str, call_counts: &HashMap<String, u64>) {
        self.update_counter = self.update_counter.saturating_add(1);

        // Enforce agent limit via eviction before inserting a new agent
        if !self.agents.contains_key(agent_id) && self.agents.len() >= self.config.max_agents {
            self.evict_agent();
        }

        let agent = self
            .agents
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentState {
                tools: HashMap::new(),
                total_sessions: 0,
            });

        agent.total_sessions = agent.total_sessions.saturating_add(1);

        // Collect which tools were actively called (non-zero count)
        let called_tools: HashSet<&String> = call_counts
            .iter()
            .filter(|(_, &c)| c > 0)
            .map(|(k, _)| k)
            .collect();

        // Update baselines for actively called tools
        for (tool, &count) in call_counts {
            if count == 0 {
                continue;
            }

            // Enforce per-agent tool limit
            if !agent.tools.contains_key(tool)
                && agent.tools.len() >= self.config.max_tools_per_agent
            {
                Self::evict_tool(&mut agent.tools);
            }

            let baseline = agent
                .tools
                .entry(tool.clone())
                .or_insert_with(|| ToolBaseline {
                    ema: 0.0,
                    session_count: 0,
                    last_active: 0,
                });

            // EMA update
            if baseline.session_count == 0 {
                // First observation: initialize EMA directly
                baseline.ema = count as f64;
            } else {
                baseline.ema =
                    self.config.alpha * count as f64 + (1.0 - self.config.alpha) * baseline.ema;
            }

            baseline.session_count = baseline.session_count.saturating_add(1);
            baseline.last_active = self.update_counter;
        }

        // Decay baselines for tools that were NOT called this session.
        // Their effective count is 0 → EMA trends toward zero.
        // Note: we intentionally do NOT update `last_active` here so that
        // passively decaying tools are evicted before actively used ones.
        let existing_tools: Vec<String> = agent.tools.keys().cloned().collect();
        for tool_name in &existing_tools {
            if !called_tools.contains(tool_name) {
                if let Some(baseline) = agent.tools.get_mut(tool_name) {
                    baseline.ema *= 1.0 - self.config.alpha;
                    baseline.session_count = baseline.session_count.saturating_add(1);
                }
            }
        }
    }

    /// Get the baseline for a specific agent and tool.
    pub fn get_baseline(&self, agent_id: &str, tool: &str) -> Option<&ToolBaseline> {
        self.agents.get(agent_id)?.tools.get(tool)
    }

    /// Get the total sessions recorded for an agent.
    pub fn agent_sessions(&self, agent_id: &str) -> Option<u32> {
        self.agents.get(agent_id).map(|a| a.total_sessions)
    }

    /// Number of agents being tracked.
    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }

    /// Number of tools tracked for a specific agent.
    pub fn tool_count(&self, agent_id: &str) -> usize {
        self.agents.get(agent_id).map_or(0, |a| a.tools.len())
    }

    /// Access the current configuration.
    pub fn config(&self) -> &BehavioralConfig {
        &self.config
    }

    /// Create a serializable snapshot of all tracking state.
    pub fn snapshot(&self) -> BehavioralSnapshot {
        let agents = self
            .agents
            .iter()
            .map(|(id, state)| {
                (
                    id.clone(),
                    AgentSnapshotEntry {
                        tools: state.tools.clone(),
                        total_sessions: state.total_sessions,
                    },
                )
            })
            .collect();

        BehavioralSnapshot {
            agents,
            update_counter: self.update_counter,
        }
    }

    /// Restore from a persisted snapshot.
    ///
    /// Validates that all EMA values are finite and non-negative.
    pub fn from_snapshot(
        config: BehavioralConfig,
        snapshot: BehavioralSnapshot,
    ) -> Result<Self, BehavioralError> {
        config.validate()?;

        for (agent_id, entry) in &snapshot.agents {
            for (tool, baseline) in &entry.tools {
                if baseline.ema.is_nan() || baseline.ema.is_infinite() {
                    return Err(BehavioralError::InvalidSnapshot(format!(
                        "agent '{}' tool '{}' has invalid EMA: {}",
                        agent_id, tool, baseline.ema
                    )));
                }
                if baseline.ema < 0.0 {
                    return Err(BehavioralError::InvalidSnapshot(format!(
                        "agent '{}' tool '{}' has negative EMA: {}",
                        agent_id, tool, baseline.ema
                    )));
                }
            }
        }

        let agents = snapshot
            .agents
            .into_iter()
            .map(|(id, entry)| {
                (
                    id,
                    AgentState {
                        tools: entry.tools,
                        total_sessions: entry.total_sessions,
                    },
                )
            })
            .collect();

        Ok(Self {
            config,
            agents,
            update_counter: snapshot.update_counter,
        })
    }

    /// Evict the agent with the fewest total sessions.
    fn evict_agent(&mut self) {
        if let Some(victim) = self
            .agents
            .iter()
            .min_by_key(|(_, state)| state.total_sessions)
            .map(|(id, _)| id.clone())
        {
            self.agents.remove(&victim);
        }
    }

    /// Evict the tool with the oldest `last_active` timestamp.
    fn evict_tool(tools: &mut HashMap<String, ToolBaseline>) {
        if let Some(victim) = tools
            .iter()
            .min_by_key(|(_, baseline)| baseline.last_active)
            .map(|(name, _)| name.clone())
        {
            tools.remove(&victim);
        }
    }
}

// ═══════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build call count maps concisely.
    fn counts(data: &[(&str, u64)]) -> HashMap<String, u64> {
        data.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    // ── Config validation ─────────────────────────

    #[test]
    fn test_new_tracker_default_config() {
        let tracker = BehavioralTracker::new(BehavioralConfig::default());
        assert!(tracker.is_ok());
        assert_eq!(tracker.as_ref().map(|t| t.agent_count()).unwrap_or(0), 0);
    }

    #[test]
    fn test_config_validate_valid() {
        assert!(BehavioralConfig::default().validate().is_ok());
        let edge = BehavioralConfig {
            alpha: 1.0, // upper bound inclusive
            ..Default::default()
        };
        assert!(edge.validate().is_ok());
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_config_validate_invalid_alpha() {
        for bad in [0.0, -0.1, 1.1, f64::NAN] {
            let mut c = BehavioralConfig::default();
            c.alpha = bad;
            assert!(
                matches!(c.validate(), Err(BehavioralError::InvalidAlpha(_))),
                "alpha={} should fail",
                bad
            );
        }
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_config_validate_invalid_threshold() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut c = BehavioralConfig::default();
            c.threshold = bad;
            assert!(
                matches!(c.validate(), Err(BehavioralError::InvalidThreshold(_))),
                "threshold={} should fail",
                bad
            );
        }
    }

    #[test]
    fn test_config_validate_invalid_max_tools() {
        let c = BehavioralConfig {
            max_tools_per_agent: 0,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(),
            Err(BehavioralError::InvalidMaxTools)
        ));
    }

    #[test]
    fn test_config_validate_invalid_max_agents() {
        let c = BehavioralConfig {
            max_agents: 0,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(),
            Err(BehavioralError::InvalidMaxAgents)
        ));
    }

    // ── Cold start ────────────────────────────────

    #[test]
    fn test_no_anomaly_during_agent_cold_start() {
        let config = BehavioralConfig {
            min_sessions: 3,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let c = counts(&[("read_file", 5)]);
        tracker.record_session("agent-1", &c);
        tracker.record_session("agent-1", &c);
        // Only 2 sessions — below min_sessions of 3

        let high = counts(&[("read_file", 5000)]);
        let alerts = tracker.check_session("agent-1", &high);
        assert!(alerts.is_empty(), "Should not flag during cold start");
    }

    #[test]
    fn test_no_anomaly_during_tool_cold_start() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 2.0,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // 5 sessions with tool-a, establishing agent-level history
        for _ in 0..5 {
            tracker.record_session("agent-1", &counts(&[("tool-a", 10)]));
        }

        // Now introduce tool-b for only 1 session
        tracker.record_session("agent-1", &counts(&[("tool-b", 5)]));

        // tool-b has only 1 session of history — should not alert
        let check = counts(&[("tool-b", 500)]);
        let alerts = tracker.check_session("agent-1", &check);
        assert!(
            alerts.is_empty(),
            "Tool with insufficient history should not alert"
        );
    }

    // ── Anomaly detection ─────────────────────────

    #[test]
    fn test_anomaly_after_baseline_established() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 10.0,
            alpha: 0.2,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let normal = counts(&[("read_file", 5)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &normal);
        }

        let anomalous = counts(&[("read_file", 500)]);
        let alerts = tracker.check_session("agent-1", &anomalous);
        assert!(!alerts.is_empty(), "Should detect anomaly");
        assert_eq!(alerts[0].tool, "read_file");
        assert_eq!(alerts[0].current_count, 500);
        assert!(alerts[0].deviation_ratio >= 10.0);
    }

    #[test]
    fn test_no_anomaly_for_normal_usage() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 10.0,
            alpha: 0.2,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let normal = counts(&[("read_file", 5)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &normal);
        }

        // 7 is ~1.4x baseline — well below 10x threshold
        let still_normal = counts(&[("read_file", 7)]);
        let alerts = tracker.check_session("agent-1", &still_normal);
        assert!(
            alerts.is_empty(),
            "Normal variation should not trigger alert"
        );
    }

    #[test]
    fn test_new_tool_no_alert() {
        let config = BehavioralConfig {
            min_sessions: 3,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let normal = counts(&[("read_file", 5)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &normal);
        }

        // write_file never seen — no baseline, no alert
        let new_tool = counts(&[("write_file", 1000)]);
        let alerts = tracker.check_session("agent-1", &new_tool);
        assert!(
            alerts.is_empty(),
            "New tool with no baseline should not alert"
        );
    }

    // ── Severity ──────────────────────────────────

    #[test]
    fn test_critical_severity() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 5.0,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let normal = counts(&[("read_file", 10)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &normal);
        }

        // With alpha=0.5 over 5 sessions of count=10, EMA ≈ 10.0
        // 1000 / 10 = 100x → well above 2 * threshold(5) = 10x → Critical
        let critical = counts(&[("read_file", 1000)]);
        let alerts = tracker.check_session("agent-1", &critical);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].severity, AnomalySeverity::Critical);
    }

    #[test]
    fn test_warning_severity() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 5.0,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let normal = counts(&[("read_file", 10)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &normal);
        }

        // 60 / 10 = 6x → above threshold(5) but below 2*threshold(10) → Warning
        let warning = counts(&[("read_file", 60)]);
        let alerts = tracker.check_session("agent-1", &warning);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].severity, AnomalySeverity::Warning);
    }

    // ── EMA behavior ──────────────────────────────

    #[test]
    fn test_ema_first_observation_initializes() {
        let config = BehavioralConfig {
            min_sessions: 1,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        tracker.record_session("agent-1", &counts(&[("read_file", 42)]));

        let baseline = tracker
            .get_baseline("agent-1", "read_file")
            .expect("baseline should exist");
        assert!(
            (baseline.ema - 42.0).abs() < f64::EPSILON,
            "First observation should set EMA directly"
        );
        assert_eq!(baseline.session_count, 1);
    }

    #[test]
    fn test_ema_update_formula() {
        let config = BehavioralConfig {
            min_sessions: 1,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // Session 1: EMA = 100
        tracker.record_session("agent-1", &counts(&[("tool", 100)]));
        let ema1 = tracker.get_baseline("agent-1", "tool").expect("exists").ema;
        assert!((ema1 - 100.0).abs() < f64::EPSILON);

        // Session 2: EMA = 0.5 * 200 + 0.5 * 100 = 150
        tracker.record_session("agent-1", &counts(&[("tool", 200)]));
        let ema2 = tracker.get_baseline("agent-1", "tool").expect("exists").ema;
        assert!((ema2 - 150.0).abs() < f64::EPSILON);

        // Session 3: EMA = 0.5 * 100 + 0.5 * 150 = 125
        tracker.record_session("agent-1", &counts(&[("tool", 100)]));
        let ema3 = tracker.get_baseline("agent-1", "tool").expect("exists").ema;
        assert!((ema3 - 125.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_ema_decay_unused_tools() {
        let config = BehavioralConfig {
            min_sessions: 1,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // Establish baseline
        tracker.record_session("agent-1", &counts(&[("read_file", 100)]));
        assert!(
            (tracker
                .get_baseline("agent-1", "read_file")
                .expect("exists")
                .ema
                - 100.0)
                .abs()
                < f64::EPSILON
        );

        // Session without read_file — EMA should decay
        tracker.record_session("agent-1", &counts(&[("other_tool", 1)]));
        let ema = tracker
            .get_baseline("agent-1", "read_file")
            .expect("exists")
            .ema;
        // Decay: ema = (1 - 0.5) * 100 = 50
        assert!(
            (ema - 50.0).abs() < 0.01,
            "EMA should decay to 50.0, got {}",
            ema
        );
    }

    #[test]
    fn test_ema_decay_does_not_update_last_active() {
        let config = BehavioralConfig {
            min_sessions: 1,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        tracker.record_session("agent-1", &counts(&[("read_file", 100)]));
        let active_before = tracker
            .get_baseline("agent-1", "read_file")
            .expect("exists")
            .last_active;

        // Decay-only session
        tracker.record_session("agent-1", &counts(&[("other_tool", 1)]));
        let active_after = tracker
            .get_baseline("agent-1", "read_file")
            .expect("exists")
            .last_active;

        assert_eq!(
            active_before, active_after,
            "Passive decay should not update last_active"
        );
    }

    // ── Agent/tool isolation ──────────────────────

    #[test]
    fn test_multiple_agents_independent() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 10.0,
            alpha: 0.2,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // Agent-1: low baseline (~5)
        let low = counts(&[("read_file", 5)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &low);
        }

        // Agent-2: high baseline (~500)
        let high = counts(&[("read_file", 500)]);
        for _ in 0..5 {
            tracker.record_session("agent-2", &high);
        }

        // 50 calls: anomalous for agent-1, normal for agent-2
        let check = counts(&[("read_file", 50)]);
        let alerts_1 = tracker.check_session("agent-1", &check);
        assert!(!alerts_1.is_empty(), "50 should be anomalous for agent-1");

        let alerts_2 = tracker.check_session("agent-2", &check);
        assert!(alerts_2.is_empty(), "50 should be normal for agent-2");
    }

    #[test]
    fn test_unknown_agent_no_alerts() {
        let tracker = BehavioralTracker::new(BehavioralConfig::default()).expect("valid config");
        let alerts = tracker.check_session("unknown", &counts(&[("tool", 1000)]));
        assert!(alerts.is_empty());
    }

    // ── Eviction ──────────────────────────────────

    #[test]
    fn test_agent_eviction_by_session_count() {
        let config = BehavioralConfig {
            max_agents: 2,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let c = counts(&[("tool", 1)]);
        tracker.record_session("agent-1", &c);
        tracker.record_session("agent-2", &c);
        tracker.record_session("agent-2", &c); // agent-2 has more sessions

        // Adding agent-3 should evict agent-1 (fewest sessions)
        tracker.record_session("agent-3", &c);

        assert_eq!(tracker.agent_count(), 2);
        assert!(
            tracker.get_baseline("agent-1", "tool").is_none(),
            "agent-1 should be evicted"
        );
        assert!(tracker.get_baseline("agent-2", "tool").is_some());
        assert!(tracker.get_baseline("agent-3", "tool").is_some());
    }

    #[test]
    fn test_tool_eviction_by_last_active() {
        let config = BehavioralConfig {
            max_tools_per_agent: 2,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // Record tool-a first (update_counter=1)
        tracker.record_session("agent-1", &counts(&[("tool-a", 1)]));
        // Record tool-b second (update_counter=2)
        tracker.record_session("agent-1", &counts(&[("tool-b", 1)]));

        // Adding tool-c should evict tool-a (oldest last_active)
        tracker.record_session("agent-1", &counts(&[("tool-c", 1)]));

        assert_eq!(tracker.tool_count("agent-1"), 2);
        assert!(
            tracker.get_baseline("agent-1", "tool-a").is_none(),
            "tool-a should be evicted"
        );
    }

    // ── Zero/empty handling ───────────────────────

    #[test]
    fn test_zero_counts_not_recorded() {
        let config = BehavioralConfig {
            min_sessions: 1,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        tracker.record_session("agent-1", &counts(&[("read_file", 0)]));
        assert!(
            tracker.get_baseline("agent-1", "read_file").is_none(),
            "Zero-count tool should not create a baseline"
        );
    }

    #[test]
    fn test_empty_call_counts_no_panic() {
        let mut tracker =
            BehavioralTracker::new(BehavioralConfig::default()).expect("valid config");
        let empty = HashMap::new();
        tracker.record_session("agent-1", &empty);
        let alerts = tracker.check_session("agent-1", &empty);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_check_with_zero_count_skipped() {
        let config = BehavioralConfig {
            min_sessions: 1,
            threshold: 2.0,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let c = counts(&[("tool", 10)]);
        for _ in 0..3 {
            tracker.record_session("agent-1", &c);
        }

        // Zero-count entry should be skipped in check
        let zero = counts(&[("tool", 0)]);
        let alerts = tracker.check_session("agent-1", &zero);
        assert!(alerts.is_empty());
    }

    // ── Snapshot persistence ──────────────────────

    #[test]
    fn test_snapshot_roundtrip() {
        let config = BehavioralConfig {
            min_sessions: 2,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config.clone()).expect("valid config");

        let c = counts(&[("read_file", 10), ("write_file", 3)]);
        tracker.record_session("agent-1", &c);
        tracker.record_session("agent-1", &c);

        let snapshot = tracker.snapshot();

        // Serialize and deserialize (simulating persistence)
        let json = serde_json::to_string(&snapshot).expect("serialize");
        let restored_snap: BehavioralSnapshot = serde_json::from_str(&json).expect("deserialize");

        let restored =
            BehavioralTracker::from_snapshot(config, restored_snap).expect("valid snapshot");
        assert_eq!(restored.agent_count(), 1);
        assert_eq!(restored.agent_sessions("agent-1"), Some(2));
        assert!(restored.get_baseline("agent-1", "read_file").is_some());
        assert!(restored.get_baseline("agent-1", "write_file").is_some());
    }

    #[test]
    fn test_snapshot_rejects_nan_ema() {
        let config = BehavioralConfig::default();
        let mut tools = HashMap::new();
        tools.insert(
            "bad_tool".to_string(),
            ToolBaseline {
                ema: f64::NAN,
                session_count: 1,
                last_active: 0,
            },
        );
        let mut agents = HashMap::new();
        agents.insert(
            "agent-1".to_string(),
            AgentSnapshotEntry {
                tools,
                total_sessions: 1,
            },
        );
        let snapshot = BehavioralSnapshot {
            agents,
            update_counter: 0,
        };

        assert!(matches!(
            BehavioralTracker::from_snapshot(config, snapshot),
            Err(BehavioralError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn test_snapshot_rejects_negative_ema() {
        let config = BehavioralConfig::default();
        let mut tools = HashMap::new();
        tools.insert(
            "bad_tool".to_string(),
            ToolBaseline {
                ema: -1.0,
                session_count: 1,
                last_active: 0,
            },
        );
        let mut agents = HashMap::new();
        agents.insert(
            "agent-1".to_string(),
            AgentSnapshotEntry {
                tools,
                total_sessions: 1,
            },
        );
        let snapshot = BehavioralSnapshot {
            agents,
            update_counter: 0,
        };

        assert!(matches!(
            BehavioralTracker::from_snapshot(config, snapshot),
            Err(BehavioralError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn test_snapshot_rejects_infinite_ema() {
        let config = BehavioralConfig::default();
        let mut tools = HashMap::new();
        tools.insert(
            "bad_tool".to_string(),
            ToolBaseline {
                ema: f64::INFINITY,
                session_count: 1,
                last_active: 0,
            },
        );
        let mut agents = HashMap::new();
        agents.insert(
            "agent-1".to_string(),
            AgentSnapshotEntry {
                tools,
                total_sessions: 1,
            },
        );
        let snapshot = BehavioralSnapshot {
            agents,
            update_counter: 0,
        };

        assert!(matches!(
            BehavioralTracker::from_snapshot(config, snapshot),
            Err(BehavioralError::InvalidSnapshot(_))
        ));
    }

    // ── Accessors ─────────────────────────────────

    #[test]
    fn test_agent_sessions_none_for_unknown() {
        let tracker = BehavioralTracker::new(BehavioralConfig::default()).expect("valid config");
        assert_eq!(tracker.agent_sessions("nonexistent"), None);
    }

    #[test]
    fn test_tool_count_zero_for_unknown() {
        let tracker = BehavioralTracker::new(BehavioralConfig::default()).expect("valid config");
        assert_eq!(tracker.tool_count("nonexistent"), 0);
    }

    #[test]
    fn test_config_accessor() {
        let config = BehavioralConfig {
            alpha: 0.3,
            threshold: 8.0,
            ..Default::default()
        };
        let tracker = BehavioralTracker::new(config).expect("valid config");
        assert!((tracker.config().alpha - 0.3).abs() < f64::EPSILON);
        assert!((tracker.config().threshold - 8.0).abs() < f64::EPSILON);
    }

    // ── Display ───────────────────────────────────

    #[test]
    fn test_anomaly_alert_display() {
        let alert = AnomalyAlert {
            agent_id: "agent-1".to_string(),
            tool: "read_file".to_string(),
            current_count: 500,
            baseline_ema: 5.0,
            deviation_ratio: 100.0,
            severity: AnomalySeverity::Critical,
        };
        let display = format!("{}", alert);
        assert!(display.contains("Critical"));
        assert!(display.contains("agent-1"));
        assert!(display.contains("read_file"));
        assert!(display.contains("500"));
    }

    #[test]
    fn test_behavioral_error_display() {
        let e = BehavioralError::InvalidAlpha(0.0);
        assert!(format!("{}", e).contains("alpha"));
        let e = BehavioralError::InvalidThreshold(-1.0);
        assert!(format!("{}", e).contains("threshold"));
        let e = BehavioralError::InvalidMaxTools;
        assert!(format!("{}", e).contains("max_tools"));
        let e = BehavioralError::InvalidMaxAgents;
        assert!(format!("{}", e).contains("max_agents"));
        let e = BehavioralError::InvalidSnapshot("test".to_string());
        assert!(format!("{}", e).contains("test"));
    }

    // ── Saturating arithmetic ─────────────────────

    #[test]
    fn test_saturating_session_count() {
        let config = BehavioralConfig {
            min_sessions: 1,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let c = counts(&[("tool", 1)]);
        for _ in 0..100 {
            tracker.record_session("agent-1", &c);
        }
        assert_eq!(tracker.agent_sessions("agent-1"), Some(100));
    }

    // ── Multiple tools in one session ─────────────

    #[test]
    fn test_multiple_tools_single_session() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 10.0,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let normal = counts(&[("read_file", 5), ("write_file", 2), ("list_dir", 10)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &normal);
        }

        // read_file anomalous, write_file normal, list_dir normal
        let mixed = counts(&[("read_file", 500), ("write_file", 3), ("list_dir", 12)]);
        let alerts = tracker.check_session("agent-1", &mixed);
        assert_eq!(alerts.len(), 1, "Only read_file should trigger");
        assert_eq!(alerts[0].tool, "read_file");
    }

    // ── Gradual increase adapts baseline ──────────

    #[test]
    fn test_gradual_increase_adapts() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 5.0,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // Start with baseline of 10
        for _ in 0..3 {
            tracker.record_session("agent-1", &counts(&[("tool", 10)]));
        }

        // Gradually increase — EMA adapts, so 20 shouldn't alert after adaptation
        for _ in 0..10 {
            tracker.record_session("agent-1", &counts(&[("tool", 20)]));
        }

        // After many sessions at 20, EMA is close to 20. 20 should not alert.
        let alerts = tracker.check_session("agent-1", &counts(&[("tool", 20)]));
        assert!(
            alerts.is_empty(),
            "Gradual increase should adapt the baseline"
        );
    }
}
