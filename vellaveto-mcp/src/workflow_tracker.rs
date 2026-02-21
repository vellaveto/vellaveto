//! Workflow Intent Tracking
//!
//! Detects long-horizon attacks that span many steps. An attacker may
//! split a malicious workflow across multiple seemingly innocent actions
//! that only become dangerous in combination.
//!
//! Mitigates: ASI01 (Prompt Injection), ASI06 (Excessive Agency)
//!
//! Features:
//! - Track active workflows per session with step budgets
//! - Check cumulative effects of action sequences
//! - Detect suspicious workflow patterns
//! - Predict potential outcomes based on action history

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use vellaveto_types::Action;

/// SECURITY (FIND-R114-018): Maximum actions stored per workflow.
///
/// Without this cap, a long-running workflow could accumulate unlimited
/// actions in its VecDeque, causing OOM. When the limit is reached, the
/// oldest actions are evicted (FIFO) with a warning log.
const MAX_WORKFLOW_ACTIONS: usize = 10_000;

/// Result of recording a workflow step.
#[derive(Debug, Clone, PartialEq)]
pub enum StepResult {
    /// Step recorded successfully, workflow continues.
    Recorded {
        /// Current step count.
        step_count: usize,
        /// Remaining budget.
        remaining_budget: usize,
    },
    /// Step budget exceeded, requires re-authorization.
    BudgetExceeded {
        /// Current step count.
        step_count: usize,
        /// Configured budget.
        budget: usize,
    },
    /// Workflow completed or terminated.
    WorkflowEnded,
}

/// Alert for suspicious workflow patterns.
#[derive(Debug, Clone)]
pub struct WorkflowAlert {
    /// Session ID.
    pub session_id: String,
    /// Alert type.
    pub alert_type: WorkflowAlertType,
    /// Human-readable description.
    pub description: String,
    /// Actions involved in the alert.
    pub involved_actions: Vec<String>,
    /// Severity (1-5).
    pub severity: u8,
}

/// Types of workflow alerts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowAlertType {
    /// Budget exceeded for this workflow.
    BudgetExceeded,
    /// Suspicious pattern of actions detected.
    SuspiciousPattern,
    /// Potential data exfiltration chain.
    ExfiltrationChain,
    /// Privilege escalation sequence.
    PrivilegeEscalation,
    /// Resource exhaustion attempt.
    ResourceExhaustion,
    /// Internal error (e.g., lock poisoning) — fail-closed.
    InternalError,
}

/// Prediction of workflow outcome.
#[derive(Debug, Clone)]
pub struct OutcomePrediction {
    /// Predicted outcome category.
    pub category: OutcomeCategory,
    /// Confidence in the prediction (0.0-1.0).
    pub confidence: f32,
    /// Reasoning for the prediction.
    pub reasoning: String,
    /// Suggested action.
    pub suggested_action: SuggestedAction,
}

impl OutcomePrediction {
    /// Validate that the confidence score is finite and in [0.0, 1.0].
    ///
    /// SECURITY (FIND-R112-007): Prevents NaN/Infinity confidence values from
    /// bypassing threshold comparisons in workflow decision logic.
    pub fn validate(&self) -> Result<(), String> {
        if !self.confidence.is_finite() || self.confidence < 0.0 || self.confidence > 1.0 {
            return Err(format!(
                "OutcomePrediction confidence must be in [0.0, 1.0], got {}",
                self.confidence
            ));
        }
        Ok(())
    }
}

/// Categories of predicted outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutcomeCategory {
    /// Workflow appears benign.
    Benign,
    /// Workflow needs monitoring.
    NeedsMonitoring,
    /// Workflow may be harmful.
    PotentiallyHarmful,
    /// Workflow is likely malicious.
    LikelyMalicious,
}

/// Suggested actions based on prediction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuggestedAction {
    /// Allow workflow to continue.
    Continue,
    /// Continue but increase monitoring.
    Monitor,
    /// Request human review.
    RequestReview,
    /// Terminate the workflow.
    Terminate,
}

/// Configuration for workflow tracking.
#[derive(Debug, Clone)]
pub struct WorkflowTrackerConfig {
    /// Maximum steps before mandatory re-authorization.
    pub step_budget: usize,
    /// Maximum concurrent workflows per session.
    pub max_workflows_per_session: usize,
    /// Maximum sessions to track.
    pub max_sessions: usize,
    /// Session TTL.
    pub session_ttl: Duration,
    /// Enable pattern detection.
    pub detect_patterns: bool,
    /// Patterns that indicate suspicious workflows.
    pub suspicious_patterns: Vec<SuspiciousPattern>,
}

impl WorkflowTrackerConfig {
    /// Validate configuration bounds.
    ///
    /// SECURITY (FIND-R112-004): Rejects zero-valued budgets and session limits
    /// that would cause division-by-zero or effectively disable workflow tracking.
    pub fn validate(&self) -> Result<(), String> {
        if self.step_budget == 0 {
            return Err("WorkflowTrackerConfig step_budget must be > 0".to_string());
        }
        if self.max_sessions == 0 {
            return Err("WorkflowTrackerConfig max_sessions must be > 0".to_string());
        }
        Ok(())
    }
}

impl Default for WorkflowTrackerConfig {
    fn default() -> Self {
        Self {
            step_budget: 100,
            max_workflows_per_session: 10,
            max_sessions: 10_000,
            session_ttl: Duration::from_secs(3600),
            detect_patterns: true,
            suspicious_patterns: default_suspicious_patterns(),
        }
    }
}

/// A pattern that indicates suspicious workflow behavior.
#[derive(Debug, Clone)]
pub struct SuspiciousPattern {
    /// Pattern name.
    pub name: String,
    /// Sequence of tool patterns to match.
    pub tool_sequence: Vec<String>,
    /// Alert type when matched.
    pub alert_type: WorkflowAlertType,
    /// Severity (1-5).
    pub severity: u8,
}

/// State of an active workflow.
#[derive(Debug)]
#[allow(dead_code)] // Used by feature-gated workflow enforcement module
struct WorkflowState {
    /// Workflow ID.
    id: String,
    /// Actions taken in this workflow.
    actions: VecDeque<WorkflowAction>,
    /// Start time.
    started_at: Instant,
    /// Last activity.
    last_activity: Instant,
    /// Is the workflow still active.
    active: bool,
    /// Custom step budget (None = use default).
    custom_budget: Option<usize>,
}

/// A recorded workflow action.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Used by feature-gated workflow enforcement module
struct WorkflowAction {
    tool: String,
    function: String,
    timestamp: Instant,
    /// Set of resources accessed.
    resources: HashSet<String>,
}

/// Session workflow state.
#[derive(Debug)]
struct SessionWorkflows {
    /// Active workflows.
    workflows: HashMap<String, WorkflowState>,
    /// Recent tool sequence for pattern detection.
    recent_tools: VecDeque<String>,
    /// Last activity.
    last_activity: Instant,
    /// Total steps across all workflows.
    total_steps: usize,
}

/// Tracks workflow state across sessions.
pub struct WorkflowTracker {
    /// Per-session state.
    sessions: RwLock<HashMap<String, SessionWorkflows>>,
    /// Configuration.
    config: WorkflowTrackerConfig,
}

impl WorkflowTracker {
    /// Create a new workflow tracker.
    pub fn new() -> Self {
        Self::with_config(WorkflowTrackerConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: WorkflowTrackerConfig) -> Self {
        let initial_session_capacity = config.max_sessions.min(1024);
        Self {
            sessions: RwLock::new(HashMap::with_capacity(initial_session_capacity)),
            config,
        }
    }

    /// Start a new workflow for a session.
    pub fn start_workflow(&self, session_id: &str, workflow_id: &str) -> bool {
        let mut sessions = match self.sessions.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in WorkflowTracker::start_workflow");
                return false;
            }
        };

        // SECURITY (FIND-R67-5-010): Enforce max_sessions before inserting new session.
        if !sessions.contains_key(session_id) && sessions.len() >= self.config.max_sessions {
            tracing::warn!(
                target: "vellaveto::security",
                max_sessions = self.config.max_sessions,
                current = sessions.len(),
                "WorkflowTracker max_sessions reached, rejecting new session"
            );
            return false;
        }

        // Ensure session exists
        let session = sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionWorkflows {
                workflows: HashMap::with_capacity(self.config.max_workflows_per_session.min(64)),
                recent_tools: VecDeque::with_capacity(20),
                last_activity: Instant::now(),
                total_steps: 0,
            });

        // Check workflow limit
        if session.workflows.len() >= self.config.max_workflows_per_session {
            return false;
        }

        // Create workflow
        let workflow = WorkflowState {
            id: workflow_id.to_string(),
            actions: VecDeque::new(),
            started_at: Instant::now(),
            last_activity: Instant::now(),
            active: true,
            custom_budget: None,
        };

        session.workflows.insert(workflow_id.to_string(), workflow);
        true
    }

    /// Record a workflow step.
    pub fn record_step(&self, session_id: &str, workflow_id: &str, action: &Action) -> StepResult {
        let mut sessions = match self.sessions.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in WorkflowTracker::record_step");
                return StepResult::BudgetExceeded {
                    step_count: 0,
                    budget: 0,
                };
            }
        };

        // SECURITY (FIND-R115-023): Check max_sessions before auto-creating a new session.
        // Without this check, an attacker can create unlimited sessions by providing
        // unique session IDs, bypassing the configured max_sessions limit.
        if !sessions.contains_key(session_id) && sessions.len() >= self.config.max_sessions {
            tracing::warn!(
                target: "vellaveto::security",
                max_sessions = self.config.max_sessions,
                current = sessions.len(),
                "WorkflowTracker max_sessions reached in record_step, rejecting new session"
            );
            return StepResult::BudgetExceeded {
                step_count: 0,
                budget: 0,
            };
        }

        // SECURITY (FIND-027): Use entry API to avoid unwrap() after insert.
        let session = sessions.entry(session_id.to_string()).or_insert_with(|| {
            // Auto-create session with initial workflow
            let mut new_session = SessionWorkflows {
                workflows: HashMap::with_capacity(self.config.max_workflows_per_session.min(64)),
                recent_tools: VecDeque::with_capacity(20),
                last_activity: Instant::now(),
                total_steps: 0,
            };
            let workflow = WorkflowState {
                id: workflow_id.to_string(),
                actions: VecDeque::new(),
                started_at: Instant::now(),
                last_activity: Instant::now(),
                active: true,
                custom_budget: None,
            };
            new_session
                .workflows
                .insert(workflow_id.to_string(), workflow);
            new_session
        });

        session.last_activity = Instant::now();

        // SECURITY (FIND-R115-023): Check max_workflows_per_session before auto-creating
        // a new workflow. Without this check, an attacker can create unlimited workflows
        // by providing unique workflow IDs, bypassing the configured limit.
        if !session.workflows.contains_key(workflow_id)
            && session.workflows.len() >= self.config.max_workflows_per_session
        {
            tracing::warn!(
                target: "vellaveto::security",
                max_workflows = self.config.max_workflows_per_session,
                current = session.workflows.len(),
                session_id = session_id,
                "WorkflowTracker max_workflows_per_session reached in record_step, rejecting new workflow"
            );
            return StepResult::BudgetExceeded {
                step_count: 0,
                budget: 0,
            };
        }

        // Get or create workflow
        let workflow = session
            .workflows
            .entry(workflow_id.to_string())
            .or_insert_with(|| WorkflowState {
                id: workflow_id.to_string(),
                actions: VecDeque::new(),
                started_at: Instant::now(),
                last_activity: Instant::now(),
                active: true,
                custom_budget: None,
            });

        if !workflow.active {
            return StepResult::WorkflowEnded;
        }

        // Extract resources from action
        let mut resources = HashSet::new();
        if !action.target_paths.is_empty() {
            resources.extend(action.target_paths.iter().cloned());
        }
        if !action.target_domains.is_empty() {
            resources.extend(action.target_domains.iter().cloned());
        }

        // Record action
        let workflow_action = WorkflowAction {
            tool: action.tool.clone(),
            function: action.function.clone(),
            timestamp: Instant::now(),
            resources,
        };

        // SECURITY (FIND-R114-018): Enforce bounded actions per workflow.
        // Evict oldest actions (FIFO) when the limit is reached rather than
        // rejecting new actions, so budget tracking remains accurate while
        // preventing unbounded memory growth.
        if workflow.actions.len() >= MAX_WORKFLOW_ACTIONS {
            tracing::warn!(
                target: "vellaveto::security",
                max = MAX_WORKFLOW_ACTIONS,
                session_id = session_id,
                workflow_id = workflow_id,
                "Workflow actions at capacity, evicting oldest action (FIFO)"
            );
            workflow.actions.pop_front();
        }
        workflow.actions.push_back(workflow_action);
        workflow.last_activity = Instant::now();

        // Update recent tools for pattern detection
        if session.recent_tools.len() >= 20 {
            session.recent_tools.pop_front();
        }
        session.recent_tools.push_back(action.tool.clone());

        // SECURITY (FIND-R67-P3-004): Use saturating_add to prevent counter overflow.
        session.total_steps = session.total_steps.saturating_add(1);

        // Check budget
        let budget = workflow.custom_budget.unwrap_or(self.config.step_budget);
        let step_count = workflow.actions.len();

        if step_count > budget {
            StepResult::BudgetExceeded { step_count, budget }
        } else {
            StepResult::Recorded {
                step_count,
                remaining_budget: budget.saturating_sub(step_count),
            }
        }
    }

    /// Check cumulative effects of the workflow.
    pub fn check_cumulative_effects(&self, session_id: &str) -> Option<WorkflowAlert> {
        if !self.config.detect_patterns {
            return None;
        }

        let sessions = match self.sessions.read() {
            Ok(g) => g,
            Err(_) => {
                // SECURITY (FIND-R71-P2-001): Return an alert on lock poisoning (fail-closed).
                // Returning None means "no alert" which is fail-open — an attacker who
                // poisons the lock would bypass all cumulative effect detection.
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in WorkflowTracker::check_cumulative_effects — fail-closed");
                return Some(WorkflowAlert {
                    session_id: session_id.to_string(),
                    alert_type: WorkflowAlertType::InternalError,
                    description: "Cumulative effects check failed: RwLock poisoned (fail-closed)"
                        .to_string(),
                    involved_actions: Vec::new(),
                    severity: 5,
                });
            }
        };
        let session = sessions.get(session_id)?;

        // Check for suspicious patterns
        for pattern in &self.config.suspicious_patterns {
            if self.matches_pattern(&session.recent_tools, &pattern.tool_sequence) {
                return Some(WorkflowAlert {
                    session_id: session_id.to_string(),
                    alert_type: pattern.alert_type.clone(),
                    description: format!("Suspicious pattern detected: {}", pattern.name),
                    involved_actions: session.recent_tools.iter().cloned().collect(),
                    severity: pattern.severity,
                });
            }
        }

        // Check for resource concentration
        if let Some(alert) = self.check_resource_concentration(session_id, session) {
            return Some(alert);
        }

        None
    }

    /// Check for suspicious resource access concentration.
    fn check_resource_concentration(
        &self,
        session_id: &str,
        session: &SessionWorkflows,
    ) -> Option<WorkflowAlert> {
        let mut all_resources: HashMap<String, usize> =
            HashMap::with_capacity(session.total_steps.min(256));

        for workflow in session.workflows.values() {
            for action in &workflow.actions {
                for resource in &action.resources {
                    // SECURITY (FIND-R67-P3-004): Use saturating_add to prevent counter overflow.
                    let count = all_resources.entry(resource.clone()).or_insert(0);
                    *count = count.saturating_add(1);
                }
            }
        }

        // Check if any sensitive resource is accessed repeatedly
        let sensitive_patterns = [".aws", ".ssh", "credentials", "password", "secret", "token"];

        for (resource, count) in &all_resources {
            let resource_lower = resource.to_lowercase();
            if count > &3
                && sensitive_patterns
                    .iter()
                    .any(|p| resource_lower.contains(p))
            {
                return Some(WorkflowAlert {
                    session_id: session_id.to_string(),
                    alert_type: WorkflowAlertType::ExfiltrationChain,
                    description: format!(
                        "Repeated access to sensitive resource: {} ({} times)",
                        resource, count
                    ),
                    involved_actions: vec![resource.clone()],
                    severity: 4,
                });
            }
        }

        None
    }

    /// Predict workflow outcome based on pattern matching.
    pub fn predict_outcome(&self, session_id: &str) -> OutcomePrediction {
        let sessions = match self.sessions.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in WorkflowTracker::predict_outcome");
                return OutcomePrediction {
                    category: OutcomeCategory::LikelyMalicious,
                    confidence: 0.0,
                    reasoning: "RwLock poisoned — fail-closed".to_string(),
                    suggested_action: SuggestedAction::Terminate,
                };
            }
        };

        let session = match sessions.get(session_id) {
            Some(s) => s,
            None => {
                return OutcomePrediction {
                    category: OutcomeCategory::Benign,
                    confidence: 0.5,
                    reasoning: "No workflow data available".to_string(),
                    suggested_action: SuggestedAction::Continue,
                }
            }
        };

        // Analyze workflow patterns
        let mut risk_score: f32 = 0.0;
        let mut reasoning_parts = Vec::with_capacity(8);

        // Check step count
        if session.total_steps > self.config.step_budget / 2 {
            risk_score += 0.2;
            reasoning_parts.push("High step count");
        }

        // Check for pattern matches
        for pattern in &self.config.suspicious_patterns {
            if self.matches_pattern(&session.recent_tools, &pattern.tool_sequence) {
                risk_score += 0.3;
                reasoning_parts.push(&pattern.name);
            }
        }

        // Check tool diversity (many different tools = more suspicious)
        let unique_tools: HashSet<_> = session.recent_tools.iter().collect();
        if unique_tools.len() > 10 {
            risk_score += 0.1;
            reasoning_parts.push("High tool diversity");
        }

        // Determine category and action
        let (category, suggested_action) = if risk_score < 0.2 {
            (OutcomeCategory::Benign, SuggestedAction::Continue)
        } else if risk_score < 0.4 {
            (OutcomeCategory::NeedsMonitoring, SuggestedAction::Monitor)
        } else if risk_score < 0.7 {
            (
                OutcomeCategory::PotentiallyHarmful,
                SuggestedAction::RequestReview,
            )
        } else {
            (OutcomeCategory::LikelyMalicious, SuggestedAction::Terminate)
        };

        OutcomePrediction {
            category,
            confidence: (0.5 + risk_score / 2.0).min(0.95),
            reasoning: if reasoning_parts.is_empty() {
                "Normal workflow behavior".to_string()
            } else {
                reasoning_parts.join(", ")
            },
            suggested_action,
        }
    }

    /// Check if tools match a pattern.
    fn matches_pattern(&self, tools: &VecDeque<String>, pattern: &[String]) -> bool {
        if pattern.is_empty() || tools.len() < pattern.len() {
            return false;
        }

        // Sliding window pattern match
        let tools_vec: Vec<_> = tools.iter().collect();
        for window in tools_vec.windows(pattern.len()) {
            let matches = window
                .iter()
                .zip(pattern.iter())
                .all(|(tool, pat)| tool.to_lowercase().contains(&pat.to_lowercase()));
            if matches {
                return true;
            }
        }

        false
    }

    /// End a workflow.
    pub fn end_workflow(&self, session_id: &str, workflow_id: &str) {
        let mut sessions = match self.sessions.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in WorkflowTracker::end_workflow");
                return;
            }
        };
        if let Some(session) = sessions.get_mut(session_id) {
            if let Some(workflow) = session.workflows.get_mut(workflow_id) {
                workflow.active = false;
            }
        }
    }

    /// Clear a session.
    pub fn clear_session(&self, session_id: &str) {
        let mut sessions = match self.sessions.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in WorkflowTracker::clear_session");
                return;
            }
        };
        sessions.remove(session_id);
    }

    /// Get workflow statistics.
    pub fn get_stats(&self, session_id: &str) -> Option<WorkflowStats> {
        let sessions = match self.sessions.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in WorkflowTracker::get_stats");
                return None;
            }
        };
        let session = sessions.get(session_id)?;

        Some(WorkflowStats {
            workflow_count: session.workflows.len(),
            total_steps: session.total_steps,
            active_workflows: session.workflows.values().filter(|w| w.active).count(),
            session_age: session.last_activity.elapsed(),
        })
    }

    /// Get session count.
    pub fn session_count(&self) -> usize {
        let sessions = match self.sessions.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in WorkflowTracker::session_count");
                return 0;
            }
        };
        sessions.len()
    }

    /// Set custom budget for a workflow.
    pub fn set_workflow_budget(&self, session_id: &str, workflow_id: &str, budget: usize) {
        let mut sessions = match self.sessions.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in WorkflowTracker::set_workflow_budget");
                return;
            }
        };
        if let Some(session) = sessions.get_mut(session_id) {
            if let Some(workflow) = session.workflows.get_mut(workflow_id) {
                workflow.custom_budget = Some(budget);
            }
        }
    }
}

impl Default for WorkflowTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Workflow statistics.
#[derive(Debug, Clone)]
pub struct WorkflowStats {
    /// Number of workflows.
    pub workflow_count: usize,
    /// Total steps across all workflows.
    pub total_steps: usize,
    /// Active workflow count.
    pub active_workflows: usize,
    /// Session age.
    pub session_age: Duration,
}

/// Default suspicious patterns.
fn default_suspicious_patterns() -> Vec<SuspiciousPattern> {
    vec![
        SuspiciousPattern {
            name: "Read-then-network".to_string(),
            tool_sequence: vec!["file".to_string(), "http".to_string()],
            alert_type: WorkflowAlertType::ExfiltrationChain,
            severity: 3,
        },
        SuspiciousPattern {
            name: "Credential-access-chain".to_string(),
            tool_sequence: vec![
                "file".to_string(),
                "file".to_string(),
                "network".to_string(),
            ],
            alert_type: WorkflowAlertType::ExfiltrationChain,
            severity: 4,
        },
        SuspiciousPattern {
            name: "Shell-after-download".to_string(),
            tool_sequence: vec!["http".to_string(), "bash".to_string()],
            alert_type: WorkflowAlertType::SuspiciousPattern,
            severity: 4,
        },
        SuspiciousPattern {
            name: "Privilege-escalation".to_string(),
            tool_sequence: vec!["bash".to_string(), "sudo".to_string()],
            alert_type: WorkflowAlertType::PrivilegeEscalation,
            severity: 5,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_action(tool: &str, function: &str) -> Action {
        Action {
            tool: tool.to_string(),
            function: function.to_string(),
            parameters: json!({}),
            target_paths: Vec::new(),
            target_domains: Vec::new(),
            resolved_ips: Vec::new(),
        }
    }

    #[test]
    fn test_start_and_record_workflow() {
        let tracker = WorkflowTracker::new();

        assert!(tracker.start_workflow("session1", "workflow1"));

        let action = create_action("file", "read");
        let result = tracker.record_step("session1", "workflow1", &action);

        assert!(matches!(result, StepResult::Recorded { step_count: 1, .. }));
    }

    #[test]
    fn test_budget_exceeded() {
        let tracker = WorkflowTracker::with_config(WorkflowTrackerConfig {
            step_budget: 3,
            ..Default::default()
        });

        tracker.start_workflow("session1", "workflow1");

        let action = create_action("file", "read");

        // Record steps up to budget
        for i in 1..=3 {
            let result = tracker.record_step("session1", "workflow1", &action);
            assert!(matches!(result, StepResult::Recorded { step_count, .. } if step_count == i));
        }

        // Next step should exceed budget
        let result = tracker.record_step("session1", "workflow1", &action);
        assert!(matches!(result, StepResult::BudgetExceeded { .. }));
    }

    #[test]
    fn test_auto_create_session() {
        let tracker = WorkflowTracker::new();

        // Record without starting workflow - should auto-create
        let action = create_action("file", "read");
        let result = tracker.record_step("new_session", "new_workflow", &action);

        assert!(matches!(result, StepResult::Recorded { .. }));
        assert_eq!(tracker.session_count(), 1);
    }

    #[test]
    fn test_end_workflow() {
        let tracker = WorkflowTracker::new();

        tracker.start_workflow("session1", "workflow1");
        let action = create_action("file", "read");
        tracker.record_step("session1", "workflow1", &action);

        tracker.end_workflow("session1", "workflow1");

        let result = tracker.record_step("session1", "workflow1", &action);
        assert!(matches!(result, StepResult::WorkflowEnded));
    }

    #[test]
    fn test_suspicious_pattern_detection() {
        let tracker = WorkflowTracker::new();

        tracker.start_workflow("session1", "workflow1");

        // Create exfiltration pattern: file -> http
        let file_action = create_action("file", "read");
        let http_action = create_action("http", "post");

        tracker.record_step("session1", "workflow1", &file_action);
        tracker.record_step("session1", "workflow1", &http_action);

        let alert = tracker.check_cumulative_effects("session1");
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.alert_type, WorkflowAlertType::ExfiltrationChain);
    }

    #[test]
    fn test_predict_outcome_benign() {
        let tracker = WorkflowTracker::new();

        tracker.start_workflow("session1", "workflow1");

        let action = create_action("text", "process");
        tracker.record_step("session1", "workflow1", &action);

        let prediction = tracker.predict_outcome("session1");
        assert_eq!(prediction.category, OutcomeCategory::Benign);
        assert_eq!(prediction.suggested_action, SuggestedAction::Continue);
    }

    #[test]
    fn test_get_stats() {
        let tracker = WorkflowTracker::new();

        tracker.start_workflow("session1", "workflow1");
        tracker.start_workflow("session1", "workflow2");

        let action = create_action("file", "read");
        tracker.record_step("session1", "workflow1", &action);
        tracker.record_step("session1", "workflow1", &action);
        tracker.record_step("session1", "workflow2", &action);

        let stats = tracker.get_stats("session1").unwrap();
        assert_eq!(stats.workflow_count, 2);
        assert_eq!(stats.total_steps, 3);
        assert_eq!(stats.active_workflows, 2);
    }

    #[test]
    fn test_clear_session() {
        let tracker = WorkflowTracker::new();

        tracker.start_workflow("session1", "workflow1");
        assert_eq!(tracker.session_count(), 1);

        tracker.clear_session("session1");
        assert_eq!(tracker.session_count(), 0);
    }

    #[test]
    fn test_custom_workflow_budget() {
        let tracker = WorkflowTracker::with_config(WorkflowTrackerConfig {
            step_budget: 100,
            ..Default::default()
        });

        tracker.start_workflow("session1", "workflow1");
        tracker.set_workflow_budget("session1", "workflow1", 2);

        let action = create_action("file", "read");

        tracker.record_step("session1", "workflow1", &action);
        tracker.record_step("session1", "workflow1", &action);

        // Third step should exceed custom budget
        let result = tracker.record_step("session1", "workflow1", &action);
        assert!(matches!(
            result,
            StepResult::BudgetExceeded { budget: 2, .. }
        ));
    }

    #[test]
    fn test_workflow_limit() {
        let tracker = WorkflowTracker::with_config(WorkflowTrackerConfig {
            max_workflows_per_session: 2,
            ..Default::default()
        });

        assert!(tracker.start_workflow("session1", "workflow1"));
        assert!(tracker.start_workflow("session1", "workflow2"));
        assert!(!tracker.start_workflow("session1", "workflow3")); // Should fail
    }

    #[test]
    fn test_no_session_prediction() {
        let tracker = WorkflowTracker::new();

        let prediction = tracker.predict_outcome("nonexistent");
        assert_eq!(prediction.category, OutcomeCategory::Benign);
        assert!(prediction.reasoning.contains("No workflow data"));
    }

    // ═══════════════════════════════════════════════════════
    // FIND-R114-018: Workflow actions VecDeque must be bounded
    // ═══════════════════════════════════════════════════════

    /// FIND-R114-018: Workflow actions are bounded at MAX_WORKFLOW_ACTIONS with FIFO eviction.
    #[test]
    fn test_workflow_actions_bounded_with_fifo_eviction() {
        // Use a large step budget so we don't hit BudgetExceeded
        let tracker = WorkflowTracker::with_config(WorkflowTrackerConfig {
            step_budget: MAX_WORKFLOW_ACTIONS + 100,
            ..Default::default()
        });

        tracker.start_workflow("session1", "workflow1");

        // Fill the workflow to exactly MAX_WORKFLOW_ACTIONS
        for i in 0..MAX_WORKFLOW_ACTIONS {
            let action = create_action("tool", &format!("action_{}", i));
            let result = tracker.record_step("session1", "workflow1", &action);
            assert!(
                matches!(result, StepResult::Recorded { .. }),
                "Step {} should be recorded",
                i
            );
        }

        // Verify we have exactly MAX_WORKFLOW_ACTIONS actions
        {
            let sessions = tracker.sessions.read().unwrap();
            let session = sessions.get("session1").unwrap();
            let workflow = session.workflows.get("workflow1").unwrap();
            assert_eq!(
                workflow.actions.len(),
                MAX_WORKFLOW_ACTIONS,
                "Actions should be at MAX_WORKFLOW_ACTIONS"
            );
        }

        // Add one more — should evict oldest (FIFO)
        let overflow_action = create_action("tool", "overflow_action");
        let result = tracker.record_step("session1", "workflow1", &overflow_action);
        assert!(matches!(result, StepResult::Recorded { .. }));

        // Verify still at MAX_WORKFLOW_ACTIONS (not MAX + 1)
        {
            let sessions = tracker.sessions.read().unwrap();
            let session = sessions.get("session1").unwrap();
            let workflow = session.workflows.get("workflow1").unwrap();
            assert_eq!(
                workflow.actions.len(),
                MAX_WORKFLOW_ACTIONS,
                "Actions must not exceed MAX_WORKFLOW_ACTIONS after eviction"
            );
            // The oldest action ("action_0") should have been evicted;
            // the newest ("overflow_action") should be at the back
            let newest = workflow.actions.back().unwrap();
            assert_eq!(
                newest.function, "overflow_action",
                "Newest action should be at the back after FIFO eviction"
            );
            let oldest = workflow.actions.front().unwrap();
            assert_eq!(
                oldest.function, "action_1",
                "After evicting action_0, action_1 should be the oldest"
            );
        }
    }

    /// FIND-R114-018: Verify MAX_WORKFLOW_ACTIONS constant is reasonable.
    #[test]
    fn test_max_workflow_actions_constant() {
        assert_eq!(
            MAX_WORKFLOW_ACTIONS, 10_000,
            "MAX_WORKFLOW_ACTIONS should be 10,000"
        );
    }

    // ═══════════════════════════════════════════════════════
    // FIND-R115-023: record_step must enforce max_sessions and max_workflows_per_session
    // ═══════════════════════════════════════════════════════

    /// FIND-R115-023: record_step must reject new sessions when max_sessions is reached.
    #[test]
    fn test_record_step_rejects_new_session_at_max_sessions() {
        let tracker = WorkflowTracker::with_config(WorkflowTrackerConfig {
            max_sessions: 2,
            ..Default::default()
        });

        let action = create_action("file", "read");

        // Create two sessions via record_step (auto-create)
        let result1 = tracker.record_step("session1", "workflow1", &action);
        assert!(matches!(result1, StepResult::Recorded { .. }));

        let result2 = tracker.record_step("session2", "workflow1", &action);
        assert!(matches!(result2, StepResult::Recorded { .. }));

        assert_eq!(tracker.session_count(), 2);

        // Third session should be rejected (max_sessions = 2)
        let result3 = tracker.record_step("session3", "workflow1", &action);
        assert!(
            matches!(result3, StepResult::BudgetExceeded { .. }),
            "FIND-R115-023: New session beyond max_sessions must be rejected in record_step, got: {:?}",
            result3
        );

        // Session count should still be 2
        assert_eq!(tracker.session_count(), 2);
    }

    /// FIND-R115-023: record_step must reject new workflows when max_workflows_per_session is reached.
    #[test]
    fn test_record_step_rejects_new_workflow_at_max_workflows() {
        let tracker = WorkflowTracker::with_config(WorkflowTrackerConfig {
            max_workflows_per_session: 2,
            ..Default::default()
        });

        let action = create_action("file", "read");

        // Create session with first workflow via record_step (auto-create)
        tracker.record_step("session1", "workflow1", &action);

        // Add a second workflow via record_step (auto-create within existing session)
        tracker.record_step("session1", "workflow2", &action);

        // Verify we have 2 workflows
        let stats = tracker.get_stats("session1").unwrap();
        assert_eq!(stats.workflow_count, 2);

        // Third workflow should be rejected (max_workflows_per_session = 2)
        let result = tracker.record_step("session1", "workflow3", &action);
        assert!(
            matches!(result, StepResult::BudgetExceeded { .. }),
            "FIND-R115-023: New workflow beyond max_workflows_per_session must be rejected in record_step, got: {:?}",
            result
        );

        // Workflow count should still be 2
        let stats = tracker.get_stats("session1").unwrap();
        assert_eq!(stats.workflow_count, 2);
    }

    /// FIND-R115-023: Existing sessions can still record steps even when max_sessions is reached.
    #[test]
    fn test_record_step_allows_existing_session_at_max_sessions() {
        let tracker = WorkflowTracker::with_config(WorkflowTrackerConfig {
            max_sessions: 1,
            ..Default::default()
        });

        let action = create_action("file", "read");

        // Create one session
        let result = tracker.record_step("session1", "workflow1", &action);
        assert!(matches!(result, StepResult::Recorded { .. }));

        // Recording another step in the same session should succeed
        let result = tracker.record_step("session1", "workflow1", &action);
        assert!(
            matches!(result, StepResult::Recorded { step_count: 2, .. }),
            "Existing session must still accept steps, got: {:?}",
            result
        );
    }

    /// FIND-R115-023: Existing workflows can still record steps even when max_workflows is reached.
    #[test]
    fn test_record_step_allows_existing_workflow_at_max_workflows() {
        let tracker = WorkflowTracker::with_config(WorkflowTrackerConfig {
            max_workflows_per_session: 1,
            ..Default::default()
        });

        let action = create_action("file", "read");

        // Create session with one workflow
        tracker.record_step("session1", "workflow1", &action);

        // Recording in the same workflow should succeed
        let result = tracker.record_step("session1", "workflow1", &action);
        assert!(
            matches!(result, StepResult::Recorded { step_count: 2, .. }),
            "Existing workflow must still accept steps, got: {:?}",
            result
        );
    }
}
