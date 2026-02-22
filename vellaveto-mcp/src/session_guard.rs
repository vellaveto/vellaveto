//! Stateful Session Reasoning Guards (Phase 23.5).
//!
//! Provides a formal session state machine (Init→Active→Suspicious→Locked→Ended)
//! with configurable transition rules, session-level policy conditions, and
//! integration with `WorkflowTracker` and `GoalTracker`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use thiserror::Error;

use crate::goal_tracking::GoalDriftAlert;
use crate::workflow_tracker::WorkflowAlert;

// ═══════════════════════════════════════════════════════════════════
// Session State Machine
// ═══════════════════════════════════════════════════════════════════

/// Session lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionState {
    /// Session just created, no actions yet.
    Init,
    /// Normal operation.
    Active,
    /// Anomalous behavior detected, monitoring closely.
    Suspicious,
    /// Session locked due to repeated violations.
    Locked,
    /// Session ended normally or forcibly.
    Ended,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionState::Init => write!(f, "Init"),
            SessionState::Active => write!(f, "Active"),
            SessionState::Suspicious => write!(f, "Suspicious"),
            SessionState::Locked => write!(f, "Locked"),
            SessionState::Ended => write!(f, "Ended"),
        }
    }
}

/// Severity of an anomaly signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalySeverity {
    /// Low — worth noting but not alarming.
    Low,
    /// Medium — potentially harmful, warrants closer monitoring.
    Medium,
    /// High — likely malicious, consider locking session.
    High,
    /// Critical — immediate lock recommended.
    Critical,
}

/// Events that trigger state transitions.
// SECURITY (FIND-R56-MCP-002): Custom Debug impl redacts admin_token in AdminUnlock.
#[derive(Clone, Serialize, Deserialize)]
pub enum SessionEvent {
    /// First action received (Init→Active).
    FirstAction,
    /// Normal action within policy (keeps Active).
    NormalAction,
    /// Anomaly detected from any source.
    AnomalyDetected {
        severity: AnomalySeverity,
        description: String,
    },
    /// Policy violation (deny verdict).
    PolicyViolation { reason: String },
    /// Multiple consecutive violations.
    RepeatedViolation { count: u32 },
    /// Cooldown period elapsed (Locked→Suspicious).
    CooldownElapsed,
    /// Admin unlock (Locked→Active).
    ///
    /// SECURITY (FIND-R46-007): The `admin_token` field MUST be verified against
    /// a configured admin credential. Without this, any caller can unlock any
    /// session, resetting violation counters to zero.
    AdminUnlock {
        /// Opaque admin credential token. The session guard verifies this
        /// against the configured `admin_unlock_token` before allowing the
        /// transition.
        admin_token: String,
    },
    /// Session timeout or explicit end.
    SessionEnd,
}

// SECURITY (FIND-R56-MCP-002): Custom Debug impl redacts admin_token in AdminUnlock
// variant to prevent credential leakage in logs and Debug output.
impl std::fmt::Debug for SessionEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionEvent::FirstAction => write!(f, "FirstAction"),
            SessionEvent::NormalAction => write!(f, "NormalAction"),
            SessionEvent::AnomalyDetected {
                severity,
                description,
            } => f
                .debug_struct("AnomalyDetected")
                .field("severity", severity)
                .field("description", description)
                .finish(),
            SessionEvent::PolicyViolation { reason } => f
                .debug_struct("PolicyViolation")
                .field("reason", reason)
                .finish(),
            SessionEvent::RepeatedViolation { count } => f
                .debug_struct("RepeatedViolation")
                .field("count", count)
                .finish(),
            SessionEvent::CooldownElapsed => write!(f, "CooldownElapsed"),
            SessionEvent::AdminUnlock { .. } => f
                .debug_struct("AdminUnlock")
                .field("admin_token", &"[REDACTED]")
                .finish(),
            SessionEvent::SessionEnd => write!(f, "SessionEnd"),
        }
    }
}

/// Result of a state transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionResult {
    /// State before transition.
    pub previous: SessionState,
    /// State after transition.
    pub current: SessionState,
    /// Action to take as a result.
    pub action: TransitionAction,
}

/// Action to take after a state transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitionAction {
    /// No special action needed.
    None,
    /// Log a warning.
    Warn { message: String },
    /// Deny all further actions until state changes.
    DenyAll { reason: String },
    /// Emit audit event.
    AuditEvent { event_type: String },
}

/// Summary of a session's state and history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    /// Current session state.
    pub state: SessionState,
    /// Number of anomalies detected.
    pub anomaly_count: u32,
    /// Number of policy violations.
    pub violation_count: u32,
    /// Unix timestamp when session started.
    pub started_at: u64,
    /// Unix timestamp of last action.
    pub last_action_at: u64,
    /// State transition history: (from, to, timestamp).
    pub transitions: Vec<(SessionState, SessionState, u64)>,
}

/// Errors from session guard operations.
#[derive(Error, Debug)]
pub enum SessionGuardError {
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    #[error("Lock poisoned")]
    LockPoisoned,
}

// ═══════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════

/// Configuration for the session guard.
// SECURITY (FIND-R55-MCP-003): deny_unknown_fields prevents attacker-injected
// fields from being silently accepted in security-critical configuration.
// SECURITY (FIND-R56-MCP-002): Custom Debug impl redacts admin_unlock_token
// to prevent credential leakage in logs, error messages, and Debug output.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGuardConfig {
    /// Anomaly count before transitioning Active→Suspicious.
    #[serde(default = "default_suspicious_threshold")]
    pub suspicious_threshold: u32,
    /// Violation count before transitioning Suspicious→Locked.
    #[serde(default = "default_lock_threshold")]
    pub lock_threshold: u32,
    /// Cooldown period in seconds before Locked→Suspicious.
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u64,
    /// Maximum session duration in seconds (0 = unlimited).
    #[serde(default = "default_max_session_duration")]
    pub max_session_duration_secs: u64,
    /// Maximum number of tracked sessions (evict oldest when exceeded).
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// Admin unlock token. When set, `SessionEvent::AdminUnlock` events are
    /// only honored if the provided `admin_token` matches this value
    /// (constant-time comparison). When `None`, admin unlock is disabled
    /// entirely (fail-closed).
    ///
    /// SECURITY (FIND-R46-007): Without this, any caller can unlock any
    /// session, resetting violation counters to zero.
    #[serde(default)]
    pub admin_unlock_token: Option<String>,
}

// SECURITY (FIND-R56-MCP-002): Custom Debug impl redacts admin_unlock_token.
impl std::fmt::Debug for SessionGuardConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionGuardConfig")
            .field("suspicious_threshold", &self.suspicious_threshold)
            .field("lock_threshold", &self.lock_threshold)
            .field("cooldown_secs", &self.cooldown_secs)
            .field("max_session_duration_secs", &self.max_session_duration_secs)
            .field("max_sessions", &self.max_sessions)
            .field(
                "admin_unlock_token",
                &self.admin_unlock_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

fn default_suspicious_threshold() -> u32 {
    3
}
fn default_lock_threshold() -> u32 {
    5
}
fn default_cooldown_secs() -> u64 {
    300
}
fn default_max_session_duration() -> u64 {
    3600
}
fn default_max_sessions() -> usize {
    10000
}

impl Default for SessionGuardConfig {
    fn default() -> Self {
        Self {
            suspicious_threshold: default_suspicious_threshold(),
            lock_threshold: default_lock_threshold(),
            cooldown_secs: default_cooldown_secs(),
            max_session_duration_secs: default_max_session_duration(),
            max_sessions: default_max_sessions(),
            admin_unlock_token: None,
        }
    }
}

impl SessionGuardConfig {
    /// Validate the configuration, returning an error description on failure.
    ///
    /// # Security (FIND-R111-002)
    ///
    /// Zero thresholds bypass session guard protections:
    /// - `suspicious_threshold = 0` means the session immediately becomes Suspicious
    ///   on the very first action, which may prevent all legitimate use.
    /// - `lock_threshold = 0` means the session immediately locks, denying all
    ///   requests — effectively a DoS through misconfiguration.
    /// - `cooldown_secs = 0` allows instant unlock loops with no delay.
    /// - `max_sessions = 0` prevents any session from being created (fail-open DoS).
    ///
    /// All numeric thresholds must be at least 1.
    pub fn validate(&self) -> Result<(), String> {
        if self.suspicious_threshold == 0 {
            return Err(
                "suspicious_threshold must be at least 1 (zero bypasses anomaly accumulation)"
                    .to_string(),
            );
        }
        if self.lock_threshold == 0 {
            return Err(
                "lock_threshold must be at least 1 (zero causes immediate session lock)"
                    .to_string(),
            );
        }
        if self.cooldown_secs == 0 {
            return Err(
                "cooldown_secs must be at least 1 (zero allows instant unlock loops)".to_string(),
            );
        }
        if self.max_sessions == 0 {
            return Err(
                "max_sessions must be at least 1 (zero prevents all session creation)".to_string(),
            );
        }
        // Validate admin_unlock_token length if present
        if let Some(ref token) = self.admin_unlock_token {
            if token.is_empty() {
                return Err("admin_unlock_token must not be empty when set".to_string());
            }
            const MAX_ADMIN_TOKEN_LEN: usize = 512;
            if token.len() > MAX_ADMIN_TOKEN_LEN {
                return Err(format!(
                    "admin_unlock_token too long: {} bytes (max {})",
                    token.len(),
                    MAX_ADMIN_TOKEN_LEN
                ));
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════
// Session Context (internal)
// ═══════════════════════════════════════════════════════════════════

/// Maximum number of transitions stored per session to prevent unbounded growth.
const MAX_TRANSITION_HISTORY: usize = 1000;

/// SECURITY (FIND-R174-002): Maximum session ID length to prevent HashMap key bloat.
const MAX_SESSION_ID_LEN: usize = 256;

/// SECURITY (FIND-R174-006): Maximum length for event description/reason strings
/// included in TransitionAction messages. Prevents unbounded string growth from
/// user-supplied SessionEvent fields.
const MAX_EVENT_FIELD_LEN: usize = 1024;

/// Truncate a string to `MAX_EVENT_FIELD_LEN` at a UTF-8 char boundary.
fn truncate_event_field(s: &str) -> &str {
    if s.len() <= MAX_EVENT_FIELD_LEN {
        return s;
    }
    let mut end = MAX_EVENT_FIELD_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// SECURITY (FIND-R73-007): Maximum recursion depth for compute_transition().
/// The Init catch-all arm recurses once to reprocess the event in Active state.
/// This guard prevents infinite recursion if a bug causes a state loop.
const MAX_COMPUTE_TRANSITION_DEPTH: u8 = 2;

struct SessionContext {
    state: SessionState,
    anomaly_count: u32,
    violation_count: u32,
    started_at: u64,
    last_action_at: u64,
    /// Timestamp when the session entered the Locked state (for cooldown validation).
    locked_at: Option<u64>,
    transition_history: Vec<(SessionState, SessionState, u64)>,
}

impl SessionContext {
    fn new(now: u64) -> Self {
        Self {
            state: SessionState::Init,
            anomaly_count: 0,
            violation_count: 0,
            started_at: now,
            last_action_at: now,
            locked_at: None,
            transition_history: Vec::new(),
        }
    }

    fn record_transition(&mut self, from: SessionState, to: SessionState, now: u64) {
        self.state = to;
        self.last_action_at = now;
        if to == SessionState::Locked {
            self.locked_at = Some(now);
        }
        // Bound history to prevent unbounded memory growth (FIND-P23-S13)
        if self.transition_history.len() < MAX_TRANSITION_HISTORY {
            self.transition_history.push((from, to, now));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Session Guard
// ═══════════════════════════════════════════════════════════════════

/// Session guard with formal state machine and configurable transitions.
pub struct SessionGuard {
    config: SessionGuardConfig,
    sessions: RwLock<HashMap<String, SessionContext>>,
}

impl SessionGuard {
    /// Create a new session guard with the given configuration.
    pub fn new(config: SessionGuardConfig) -> Self {
        Self {
            config,
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Get the current timestamp (Unix seconds).
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Process an event for a session, returning the transition result.
    pub fn process_event(
        &self,
        session_id: &str,
        event: SessionEvent,
    ) -> Result<TransitionResult, SessionGuardError> {
        self.process_event_at(session_id, event, Self::now())
    }

    /// Process an event at a specific timestamp (for testing).
    pub fn process_event_at(
        &self,
        session_id: &str,
        event: SessionEvent,
        now: u64,
    ) -> Result<TransitionResult, SessionGuardError> {
        // SECURITY (FIND-R174-002): Validate session_id before use as HashMap key.
        if session_id.is_empty() {
            return Err(SessionGuardError::SessionNotFound(
                "session_id must not be empty".to_string(),
            ));
        }
        if session_id.len() > MAX_SESSION_ID_LEN {
            return Err(SessionGuardError::SessionNotFound(format!(
                "session_id length {} exceeds maximum {}",
                session_id.len(),
                MAX_SESSION_ID_LEN
            )));
        }
        if session_id.chars().any(|c| c.is_control()) {
            return Err(SessionGuardError::SessionNotFound(
                "session_id contains control characters".to_string(),
            ));
        }
        if session_id
            .chars()
            .any(vellaveto_types::is_unicode_format_char)
        {
            return Err(SessionGuardError::SessionNotFound(
                "session_id contains Unicode format characters".to_string(),
            ));
        }

        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SessionGuardError::LockPoisoned)?;

        // Create session if it doesn't exist
        if !sessions.contains_key(session_id) {
            // Enforce max_sessions — evict oldest if at capacity.
            // SECURITY: Never evict Locked, Ended, or Suspicious sessions —
            // they carry security state that must be preserved (FIND-P23-S12).
            // SECURITY (FIND-R113-001): Also protect Suspicious sessions to
            // prevent state reset attacks where an attacker accumulates
            // violations near the lock threshold, then evicts to reset counters.
            if sessions.len() >= self.config.max_sessions {
                let evictable = sessions
                    .iter()
                    .filter(|(_, ctx)| {
                        !matches!(
                            ctx.state,
                            SessionState::Locked
                                | SessionState::Ended
                                | SessionState::Suspicious
                        )
                    })
                    .min_by_key(|(_, ctx)| ctx.last_action_at)
                    .map(|(k, _)| k.clone());
                if let Some(key) = evictable {
                    sessions.remove(&key);
                } else {
                    // All sessions are Locked/Ended — cannot evict safely.
                    // Fail-closed: refuse to create new session.
                    return Err(SessionGuardError::SessionNotFound(format!(
                        "Session limit reached ({}) and no evictable sessions",
                        self.config.max_sessions
                    )));
                }
            }
            sessions.insert(session_id.to_string(), SessionContext::new(now));
        }

        let ctx = sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionGuardError::SessionNotFound(session_id.to_string()))?;

        let previous = ctx.state;
        let (new_state, action) = self.compute_transition(ctx, &event, now, 0);

        if new_state != previous {
            ctx.record_transition(previous, new_state, now);
        } else {
            ctx.last_action_at = now;
        }

        Ok(TransitionResult {
            previous,
            current: new_state,
            action,
        })
    }

    fn compute_transition(
        &self,
        ctx: &mut SessionContext,
        event: &SessionEvent,
        now: u64,
        depth: u8,
    ) -> (SessionState, TransitionAction) {
        // SECURITY (FIND-R73-007): Guard against infinite recursion.
        if depth >= MAX_COMPUTE_TRANSITION_DEPTH {
            tracing::error!(
                target: "vellaveto::security",
                depth = depth,
                state = %ctx.state,
                "compute_transition recursion depth exceeded — fail-closed"
            );
            return (
                SessionState::Locked,
                TransitionAction::DenyAll {
                    reason: "Session state machine recursion depth exceeded — fail-closed"
                        .to_string(),
                },
            );
        }

        match (ctx.state, event) {
            // === Init state ===
            (SessionState::Init, SessionEvent::FirstAction) => (
                SessionState::Active,
                TransitionAction::AuditEvent {
                    event_type: "session_activated".to_string(),
                },
            ),
            (SessionState::Init, SessionEvent::SessionEnd) => (
                SessionState::Ended,
                TransitionAction::AuditEvent {
                    event_type: "session_ended".to_string(),
                },
            ),
            // Any other event in Init transitions to Active first
            (SessionState::Init, _) => {
                ctx.state = SessionState::Active;
                if ctx.transition_history.len() < MAX_TRANSITION_HISTORY {
                    ctx.transition_history
                        .push((SessionState::Init, SessionState::Active, now));
                }
                self.compute_transition(ctx, event, now, depth.saturating_add(1))
            }

            // === Active state ===
            (SessionState::Active, SessionEvent::NormalAction) => {
                (SessionState::Active, TransitionAction::None)
            }
            (
                SessionState::Active,
                SessionEvent::AnomalyDetected {
                    severity,
                    description,
                },
            ) => {
                ctx.anomaly_count = ctx.anomaly_count.saturating_add(1);
                // Critical severity → immediate Suspicious
                let immediate = matches!(severity, AnomalySeverity::Critical);
                // SECURITY (FIND-R174-006): Truncate user-supplied description.
                let desc = truncate_event_field(description);
                if immediate || ctx.anomaly_count >= self.config.suspicious_threshold {
                    (
                        SessionState::Suspicious,
                        TransitionAction::Warn {
                            message: format!(
                                "Session transitioning to Suspicious: {} (anomalies: {})",
                                desc, ctx.anomaly_count
                            ),
                        },
                    )
                } else {
                    (
                        SessionState::Active,
                        TransitionAction::Warn {
                            message: format!("Anomaly detected: {}", desc),
                        },
                    )
                }
            }
            (SessionState::Active, SessionEvent::PolicyViolation { reason }) => {
                ctx.violation_count = ctx.violation_count.saturating_add(1);
                ctx.anomaly_count = ctx.anomaly_count.saturating_add(1);
                // SECURITY (FIND-R174-006): Truncate user-supplied reason.
                let rsn = truncate_event_field(reason);
                if ctx.anomaly_count >= self.config.suspicious_threshold {
                    (
                        SessionState::Suspicious,
                        TransitionAction::Warn {
                            message: format!(
                                "Session transitioning to Suspicious after violation: {}",
                                rsn
                            ),
                        },
                    )
                } else {
                    (
                        SessionState::Active,
                        TransitionAction::Warn {
                            message: format!("Policy violation: {}", rsn),
                        },
                    )
                }
            }
            (SessionState::Active, SessionEvent::RepeatedViolation { count }) => {
                // SECURITY (FIND-R174-003): count=0 should be a no-op, not escalate state.
                if *count == 0 {
                    return (SessionState::Active, TransitionAction::None);
                }
                ctx.violation_count = ctx.violation_count.saturating_add(*count);
                ctx.anomaly_count = ctx.anomaly_count.saturating_add(*count);
                (
                    SessionState::Suspicious,
                    TransitionAction::Warn {
                        message: format!(
                            "Repeated violations ({}), transitioning to Suspicious",
                            count
                        ),
                    },
                )
            }
            (SessionState::Active, SessionEvent::SessionEnd) => (
                SessionState::Ended,
                TransitionAction::AuditEvent {
                    event_type: "session_ended".to_string(),
                },
            ),

            // === Suspicious state ===
            (SessionState::Suspicious, SessionEvent::NormalAction) => {
                (SessionState::Suspicious, TransitionAction::None)
            }
            (
                SessionState::Suspicious,
                SessionEvent::AnomalyDetected {
                    severity,
                    description,
                },
            ) => {
                ctx.anomaly_count = ctx.anomaly_count.saturating_add(1);
                let immediate =
                    matches!(severity, AnomalySeverity::Critical | AnomalySeverity::High);
                // SECURITY (FIND-R174-006): Truncate user-supplied description.
                let desc = truncate_event_field(description);
                if immediate || ctx.violation_count >= self.config.lock_threshold {
                    (
                        SessionState::Locked,
                        TransitionAction::DenyAll {
                            reason: format!(
                                "Session locked: {} (violations: {})",
                                desc, ctx.violation_count
                            ),
                        },
                    )
                } else {
                    (
                        SessionState::Suspicious,
                        TransitionAction::Warn {
                            message: format!("Anomaly in suspicious session: {}", desc),
                        },
                    )
                }
            }
            (SessionState::Suspicious, SessionEvent::PolicyViolation { reason }) => {
                ctx.violation_count = ctx.violation_count.saturating_add(1);
                // SECURITY (FIND-R174-006): Truncate user-supplied reason.
                let rsn = truncate_event_field(reason);
                if ctx.violation_count >= self.config.lock_threshold {
                    (
                        SessionState::Locked,
                        TransitionAction::DenyAll {
                            reason: format!(
                                "Session locked after {} violations: {}",
                                ctx.violation_count, rsn
                            ),
                        },
                    )
                } else {
                    (
                        SessionState::Suspicious,
                        TransitionAction::Warn {
                            message: format!("Policy violation in suspicious session: {}", rsn),
                        },
                    )
                }
            }
            (SessionState::Suspicious, SessionEvent::RepeatedViolation { count }) => {
                // SECURITY (FIND-R174-003): count=0 should be a no-op, not escalate state.
                if *count == 0 {
                    return (SessionState::Suspicious, TransitionAction::None);
                }
                ctx.violation_count = ctx.violation_count.saturating_add(*count);
                (
                    SessionState::Locked,
                    TransitionAction::DenyAll {
                        reason: format!(
                            "Session locked: repeated violations ({} total)",
                            ctx.violation_count
                        ),
                    },
                )
            }
            (SessionState::Suspicious, SessionEvent::SessionEnd) => (
                SessionState::Ended,
                TransitionAction::AuditEvent {
                    event_type: "session_ended".to_string(),
                },
            ),

            // === Locked state ===
            (SessionState::Locked, SessionEvent::CooldownElapsed) => {
                // Validate that the cooldown period has actually elapsed (FIND-P23-S09)
                let cooldown_ok = ctx
                    .locked_at
                    .is_some_and(|locked| now.saturating_sub(locked) >= self.config.cooldown_secs);
                if cooldown_ok {
                    (
                        SessionState::Suspicious,
                        TransitionAction::Warn {
                            message: "Cooldown elapsed, session returning to Suspicious"
                                .to_string(),
                        },
                    )
                } else {
                    (
                        SessionState::Locked,
                        TransitionAction::DenyAll {
                            reason: format!(
                                "Cooldown period ({} secs) has not elapsed",
                                self.config.cooldown_secs
                            ),
                        },
                    )
                }
            }
            // SECURITY (FIND-R46-007): AdminUnlock requires a valid admin token.
            // The token is verified with constant-time comparison to prevent
            // timing side-channels. If no admin_unlock_token is configured,
            // admin unlock is disabled entirely (fail-closed).
            (SessionState::Locked, SessionEvent::AdminUnlock { ref admin_token }) => {
                let authorized = match &self.config.admin_unlock_token {
                    Some(expected) => {
                        use subtle::ConstantTimeEq;
                        expected.as_bytes().ct_eq(admin_token.as_bytes()).into()
                    }
                    None => false, // Fail-closed: no configured token → never authorize
                };
                if authorized {
                    ctx.anomaly_count = 0;
                    ctx.violation_count = 0;
                    (
                        SessionState::Active,
                        TransitionAction::AuditEvent {
                            event_type: "session_admin_unlocked".to_string(),
                        },
                    )
                } else {
                    (
                        SessionState::Locked,
                        TransitionAction::DenyAll {
                            reason: "Admin unlock denied: invalid or missing admin token"
                                .to_string(),
                        },
                    )
                }
            }
            (SessionState::Locked, SessionEvent::SessionEnd) => (
                SessionState::Ended,
                TransitionAction::AuditEvent {
                    event_type: "session_ended".to_string(),
                },
            ),
            // All other events in Locked are denied
            (SessionState::Locked, _) => (
                SessionState::Locked,
                TransitionAction::DenyAll {
                    reason: "Session is locked".to_string(),
                },
            ),

            // === Ended state ===
            (SessionState::Ended, _) => (
                SessionState::Ended,
                TransitionAction::DenyAll {
                    reason: "Session has ended".to_string(),
                },
            ),

            // Default: stay in current state
            (state, _) => (state, TransitionAction::None),
        }
    }

    /// Get the current state of a session.
    ///
    /// Fail-closed: if the lock is poisoned, returns `Locked` (deny-all)
    /// rather than `Init` (allow-all). Unknown sessions return `Init`.
    pub fn get_state(&self, session_id: &str) -> SessionState {
        match self.sessions.read() {
            Ok(sessions) => sessions
                .get(session_id)
                .map(|ctx| ctx.state)
                .unwrap_or(SessionState::Init),
            Err(_poisoned) => {
                // Fail-closed: lock poisoned → treat as locked
                SessionState::Locked
            }
        }
    }

    /// Check if a session should deny all actions.
    /// Returns Some(reason) if the session is in a deny-all state, None otherwise.
    ///
    /// Fail-closed: if the lock is poisoned, returns a deny reason.
    pub fn should_deny(&self, session_id: &str) -> Option<String> {
        match self.sessions.read() {
            Ok(sessions) => sessions.get(session_id).and_then(|ctx| match ctx.state {
                SessionState::Locked => Some(format!("Session '{}' is locked", session_id)),
                SessionState::Ended => Some(format!("Session '{}' has ended", session_id)),
                _ => None,
            }),
            Err(_poisoned) => {
                // Fail-closed: lock poisoned → deny
                Some("Session guard lock poisoned — fail-closed deny".to_string())
            }
        }
    }

    /// Get a summary of a session's state and history.
    pub fn session_summary(&self, session_id: &str) -> Option<SessionSummary> {
        self.sessions.read().ok().and_then(|sessions| {
            sessions.get(session_id).map(|ctx| SessionSummary {
                state: ctx.state,
                anomaly_count: ctx.anomaly_count,
                violation_count: ctx.violation_count,
                started_at: ctx.started_at,
                last_action_at: ctx.last_action_at,
                transitions: ctx.transition_history.clone(),
            })
        })
    }

    // ═══════════════════════════════════════════════════════════════
    // Integration with WorkflowTracker and GoalTracker
    // ═══════════════════════════════════════════════════════════════

    /// Integrate an alert from the WorkflowTracker.
    pub fn integrate_workflow_alert(
        &self,
        session_id: &str,
        alert: &WorkflowAlert,
    ) -> Result<TransitionResult, SessionGuardError> {
        let severity = workflow_alert_to_severity(alert.severity);
        self.process_event(
            session_id,
            SessionEvent::AnomalyDetected {
                severity,
                description: format!(
                    "Workflow alert ({:?}): {}",
                    alert.alert_type, alert.description
                ),
            },
        )
    }

    /// Integrate a goal drift alert from the GoalTracker.
    pub fn integrate_goal_drift(
        &self,
        session_id: &str,
        drift: &GoalDriftAlert,
    ) -> Result<TransitionResult, SessionGuardError> {
        // Map similarity score to anomaly severity:
        // 0.0 = completely different (Critical), 1.0 = identical (Low)
        // SECURITY (FIND-R174-001): NaN/Infinity/negative values fail-closed to Critical.
        // NaN causes all `<` comparisons to return false, falling through to Low.
        let severity = if !drift.similarity.is_finite() || drift.similarity < 0.2 {
            AnomalySeverity::Critical
        } else if drift.similarity < 0.4 {
            AnomalySeverity::High
        } else if drift.similarity < 0.6 {
            AnomalySeverity::Medium
        } else {
            AnomalySeverity::Low
        };

        self.process_event(
            session_id,
            SessionEvent::AnomalyDetected {
                severity,
                description: format!(
                    "Goal drift detected (similarity: {:.2}): {}",
                    drift.similarity, drift.description
                ),
            },
        )
    }
}

/// Map workflow alert severity (u8 1-5) to AnomalySeverity.
fn workflow_alert_to_severity(severity: u8) -> AnomalySeverity {
    match severity {
        0..=1 => AnomalySeverity::Low,
        2 => AnomalySeverity::Medium,
        3 => AnomalySeverity::High,
        _ => AnomalySeverity::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow_tracker::WorkflowAlertType;

    fn default_guard() -> SessionGuard {
        SessionGuard::new(SessionGuardConfig::default())
    }

    fn guard_with_thresholds(suspicious: u32, lock: u32) -> SessionGuard {
        SessionGuard::new(SessionGuardConfig {
            suspicious_threshold: suspicious,
            lock_threshold: lock,
            ..Default::default()
        })
    }

    #[test]
    fn test_init_to_active_on_first_action() {
        let guard = default_guard();
        let result = guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        assert_eq!(result.previous, SessionState::Init);
        assert_eq!(result.current, SessionState::Active);
    }

    #[test]
    fn test_active_stays_active_on_normal_action() {
        let guard = default_guard();
        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        let result = guard
            .process_event("s1", SessionEvent::NormalAction)
            .unwrap();
        assert_eq!(result.current, SessionState::Active);
    }

    #[test]
    fn test_active_to_suspicious_on_threshold() {
        let guard = guard_with_thresholds(2, 5);

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();

        // First anomaly — stays Active
        let r1 = guard
            .process_event(
                "s1",
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Low,
                    description: "anomaly 1".to_string(),
                },
            )
            .unwrap();
        assert_eq!(r1.current, SessionState::Active);

        // Second anomaly — triggers Suspicious (threshold=2)
        let r2 = guard
            .process_event(
                "s1",
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Low,
                    description: "anomaly 2".to_string(),
                },
            )
            .unwrap();
        assert_eq!(r2.current, SessionState::Suspicious);
    }

    #[test]
    fn test_critical_anomaly_immediate_suspicious() {
        let guard = guard_with_thresholds(10, 10);
        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();

        let result = guard
            .process_event(
                "s1",
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Critical,
                    description: "critical issue".to_string(),
                },
            )
            .unwrap();
        assert_eq!(result.current, SessionState::Suspicious);
    }

    #[test]
    fn test_suspicious_to_locked_on_violations() {
        let guard = guard_with_thresholds(1, 2);

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();

        // Trigger Suspicious
        guard
            .process_event(
                "s1",
                SessionEvent::PolicyViolation {
                    reason: "v1".to_string(),
                },
            )
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Suspicious);

        // Second violation triggers Locked (lock_threshold=2)
        let result = guard
            .process_event(
                "s1",
                SessionEvent::PolicyViolation {
                    reason: "v2".to_string(),
                },
            )
            .unwrap();
        assert_eq!(result.current, SessionState::Locked);
    }

    #[test]
    fn test_locked_denies_normal_actions() {
        let guard = guard_with_thresholds(1, 1);

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        guard
            .process_event(
                "s1",
                SessionEvent::PolicyViolation {
                    reason: "v1".to_string(),
                },
            )
            .unwrap();
        // Now in Suspicious; one more violation → Locked
        guard
            .process_event(
                "s1",
                SessionEvent::PolicyViolation {
                    reason: "v2".to_string(),
                },
            )
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Locked);

        // Normal action should be denied
        let result = guard
            .process_event("s1", SessionEvent::NormalAction)
            .unwrap();
        assert_eq!(result.current, SessionState::Locked);
        assert!(matches!(result.action, TransitionAction::DenyAll { .. }));
    }

    #[test]
    fn test_locked_cooldown_to_suspicious() {
        let guard = SessionGuard::new(SessionGuardConfig {
            suspicious_threshold: 1,
            lock_threshold: 1,
            cooldown_secs: 60, // 60 second cooldown
            ..Default::default()
        });

        guard
            .process_event_at("s1", SessionEvent::FirstAction, 1000)
            .unwrap();
        guard
            .process_event_at("s1", SessionEvent::RepeatedViolation { count: 2 }, 1001)
            .unwrap();
        // Should be in Suspicious now; one more to lock it
        guard
            .process_event_at("s1", SessionEvent::RepeatedViolation { count: 1 }, 1002)
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Locked);

        // Premature cooldown — should be rejected
        let result = guard
            .process_event_at("s1", SessionEvent::CooldownElapsed, 1010)
            .unwrap();
        assert_eq!(result.current, SessionState::Locked);

        // Proper cooldown — after 60 seconds
        let result = guard
            .process_event_at("s1", SessionEvent::CooldownElapsed, 1062)
            .unwrap();
        assert_eq!(result.current, SessionState::Suspicious);
    }

    #[test]
    fn test_admin_unlock_to_active() {
        let guard = SessionGuard::new(SessionGuardConfig {
            suspicious_threshold: 1,
            lock_threshold: 1,
            admin_unlock_token: Some("correct-token".to_string()),
            ..Default::default()
        });

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 2 })
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 1 })
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Locked);

        let result = guard
            .process_event(
                "s1",
                SessionEvent::AdminUnlock {
                    admin_token: "correct-token".to_string(),
                },
            )
            .unwrap();
        assert_eq!(result.current, SessionState::Active);
    }

    // SECURITY (FIND-R46-007): Admin unlock must be rejected with wrong token
    #[test]
    fn test_admin_unlock_rejected_with_wrong_token() {
        let guard = SessionGuard::new(SessionGuardConfig {
            suspicious_threshold: 1,
            lock_threshold: 1,
            admin_unlock_token: Some("correct-token".to_string()),
            ..Default::default()
        });

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 2 })
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 1 })
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Locked);

        // Wrong token → stays Locked
        let result = guard
            .process_event(
                "s1",
                SessionEvent::AdminUnlock {
                    admin_token: "wrong-token".to_string(),
                },
            )
            .unwrap();
        assert_eq!(result.current, SessionState::Locked);
        assert!(matches!(result.action, TransitionAction::DenyAll { .. }));
    }

    // SECURITY (FIND-R46-007): Admin unlock disabled when no token configured
    #[test]
    fn test_admin_unlock_rejected_when_no_token_configured() {
        let guard = guard_with_thresholds(1, 1);
        // Default config has admin_unlock_token: None

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 2 })
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 1 })
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Locked);

        // Any token → stays Locked because no admin_unlock_token configured
        let result = guard
            .process_event(
                "s1",
                SessionEvent::AdminUnlock {
                    admin_token: "any-token".to_string(),
                },
            )
            .unwrap();
        assert_eq!(result.current, SessionState::Locked);
        assert!(matches!(result.action, TransitionAction::DenyAll { .. }));
    }

    #[test]
    fn test_should_deny_in_locked() {
        let guard = guard_with_thresholds(1, 1);

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        assert!(guard.should_deny("s1").is_none());

        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 2 })
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 1 })
            .unwrap();
        assert!(guard.should_deny("s1").is_some());
    }

    #[test]
    fn test_should_deny_none_in_active() {
        let guard = default_guard();
        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        assert!(guard.should_deny("s1").is_none());
    }

    #[test]
    fn test_session_end_from_any_state() {
        let guard = default_guard();

        // End from Init
        let r = guard.process_event("s1", SessionEvent::SessionEnd).unwrap();
        assert_eq!(r.current, SessionState::Ended);

        // End from Active
        guard
            .process_event("s2", SessionEvent::FirstAction)
            .unwrap();
        let r = guard.process_event("s2", SessionEvent::SessionEnd).unwrap();
        assert_eq!(r.current, SessionState::Ended);
    }

    #[test]
    fn test_ended_state_is_terminal() {
        let guard = default_guard();
        guard.process_event("s1", SessionEvent::SessionEnd).unwrap();

        let r = guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        assert_eq!(r.current, SessionState::Ended);
        assert!(matches!(r.action, TransitionAction::DenyAll { .. }));
    }

    #[test]
    fn test_session_summary() {
        let guard = default_guard();
        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        guard
            .process_event(
                "s1",
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Low,
                    description: "test".to_string(),
                },
            )
            .unwrap();

        let summary = guard.session_summary("s1").unwrap();
        assert_eq!(summary.state, SessionState::Active);
        assert_eq!(summary.anomaly_count, 1);
        assert!(!summary.transitions.is_empty());
    }

    #[test]
    fn test_concurrent_session_isolation() {
        let guard = guard_with_thresholds(1, 1);

        // s1 becomes Suspicious
        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        guard
            .process_event(
                "s1",
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Medium,
                    description: "test".to_string(),
                },
            )
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Suspicious);

        // s2 should still be Active
        guard
            .process_event("s2", SessionEvent::FirstAction)
            .unwrap();
        assert_eq!(guard.get_state("s2"), SessionState::Active);
    }

    #[test]
    fn test_config_defaults() {
        let config = SessionGuardConfig::default();
        assert_eq!(config.suspicious_threshold, 3);
        assert_eq!(config.lock_threshold, 5);
        assert_eq!(config.cooldown_secs, 300);
        assert_eq!(config.max_session_duration_secs, 3600);
        assert_eq!(config.max_sessions, 10000);
    }

    #[test]
    fn test_workflow_alert_integration() {
        let guard = guard_with_thresholds(1, 5);
        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();

        let alert = WorkflowAlert {
            session_id: "s1".to_string(),
            alert_type: WorkflowAlertType::ExfiltrationChain,
            description: "Data exfiltration detected".to_string(),
            involved_actions: vec!["read_file".to_string(), "send_email".to_string()],
            severity: 4,
        };

        let result = guard.integrate_workflow_alert("s1", &alert).unwrap();
        assert_eq!(result.current, SessionState::Suspicious);
    }

    #[test]
    fn test_goal_drift_integration() {
        let guard = guard_with_thresholds(1, 5);
        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();

        let drift = GoalDriftAlert {
            session_id: "s1".to_string(),
            original_goal: "Summarize document".to_string(),
            current_goal: "Delete all files".to_string(),
            similarity: 0.1,
            description: "Goal completely changed".to_string(),
        };

        let result = guard.integrate_goal_drift("s1", &drift).unwrap();
        assert_eq!(result.current, SessionState::Suspicious);
    }

    #[test]
    fn test_max_sessions_eviction() {
        let guard = SessionGuard::new(SessionGuardConfig {
            max_sessions: 3,
            ..Default::default()
        });

        guard
            .process_event_at("s1", SessionEvent::FirstAction, 100)
            .unwrap();
        guard
            .process_event_at("s2", SessionEvent::FirstAction, 200)
            .unwrap();
        guard
            .process_event_at("s3", SessionEvent::FirstAction, 300)
            .unwrap();

        // Adding a 4th should evict s1 (oldest last_action_at among non-Locked/non-Ended)
        guard
            .process_event_at("s4", SessionEvent::FirstAction, 400)
            .unwrap();

        // s1 was evicted — returns Init (unknown session)
        assert_eq!(guard.get_state("s1"), SessionState::Init);
        assert_eq!(guard.get_state("s2"), SessionState::Active);
        assert_eq!(guard.get_state("s3"), SessionState::Active);
        assert_eq!(guard.get_state("s4"), SessionState::Active);
    }

    #[test]
    fn test_locked_sessions_not_evicted() {
        let guard = SessionGuard::new(SessionGuardConfig {
            max_sessions: 2,
            suspicious_threshold: 1,
            lock_threshold: 1,
            ..Default::default()
        });

        // Create and lock s1
        guard
            .process_event_at("s1", SessionEvent::FirstAction, 100)
            .unwrap();
        guard
            .process_event_at("s1", SessionEvent::RepeatedViolation { count: 2 }, 101)
            .unwrap();
        guard
            .process_event_at("s1", SessionEvent::RepeatedViolation { count: 1 }, 102)
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Locked);

        // Create s2
        guard
            .process_event_at("s2", SessionEvent::FirstAction, 200)
            .unwrap();

        // Creating s3 should evict s2 (Active), NOT s1 (Locked)
        guard
            .process_event_at("s3", SessionEvent::FirstAction, 300)
            .unwrap();

        // s1 should still be Locked (not evicted)
        assert_eq!(guard.get_state("s1"), SessionState::Locked);
        // s2 was evicted
        assert_eq!(guard.get_state("s2"), SessionState::Init);
        assert_eq!(guard.get_state("s3"), SessionState::Active);
    }

    /// SECURITY (FIND-R113-001): Suspicious sessions are not evicted.
    #[test]
    fn test_suspicious_sessions_not_evicted() {
        let guard = SessionGuard::new(SessionGuardConfig {
            max_sessions: 2,
            suspicious_threshold: 2,
            lock_threshold: 5,
            ..Default::default()
        });

        // Create s1 and push to Suspicious
        guard
            .process_event_at("s1", SessionEvent::FirstAction, 100)
            .unwrap();
        guard
            .process_event_at(
                "s1",
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Medium,
                    description: "test".to_string(),
                },
                101,
            )
            .unwrap();
        guard
            .process_event_at(
                "s1",
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Medium,
                    description: "test".to_string(),
                },
                102,
            )
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Suspicious);

        // Create s2
        guard
            .process_event_at("s2", SessionEvent::FirstAction, 200)
            .unwrap();

        // Creating s3 should fail (s1=Suspicious, s2=Active — only s2 is evictable,
        // but we need space for s3, so s2 gets evicted)
        guard
            .process_event_at("s3", SessionEvent::FirstAction, 300)
            .unwrap();

        // s1 should still be Suspicious (not evicted)
        assert_eq!(guard.get_state("s1"), SessionState::Suspicious);
        // s2 was evicted
        assert_eq!(guard.get_state("s2"), SessionState::Init);
        assert_eq!(guard.get_state("s3"), SessionState::Active);
    }

    #[test]
    fn test_unknown_session_returns_init() {
        let guard = default_guard();
        assert_eq!(guard.get_state("nonexistent"), SessionState::Init);
    }

    #[test]
    fn test_summary_serialization() {
        let summary = SessionSummary {
            state: SessionState::Active,
            anomaly_count: 2,
            violation_count: 1,
            started_at: 1700000000,
            last_action_at: 1700000100,
            transitions: vec![(SessionState::Init, SessionState::Active, 1700000000)],
        };

        let json = serde_json::to_string(&summary).expect("Should serialize");
        let deserialized: SessionSummary = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized.state, SessionState::Active);
        assert_eq!(deserialized.anomaly_count, 2);
    }

    /// IMP-R122-005: Transitions beyond MAX_TRANSITION_HISTORY are silently
    /// dropped. This test verifies the bound is enforced and the state machine
    /// still works correctly even when the history is full.
    ///
    /// Only actual state changes are recorded in the transition history.
    /// We use SessionContext::record_transition directly to fill the history
    /// quickly, then verify that additional transitions are silently dropped.
    #[test]
    fn test_transition_history_bounded_at_max() {
        let guard = default_guard();
        let sid = "bounded-test";
        let base_ts = 1700000000u64;

        // First action transitions Init → Active (1 transition)
        guard
            .process_event_at(sid, SessionEvent::FirstAction, base_ts)
            .unwrap();

        let summary = guard.session_summary(sid).unwrap();
        assert_eq!(summary.transitions.len(), 1);

        // Manually fill the transition history via the guard's lock.
        // This is a unit test for the bounding behavior, not integration testing.
        {
            let mut sessions = guard.sessions.write().unwrap();
            let ctx = sessions.get_mut(sid).unwrap();
            // Fill from current len (1) up to MAX_TRANSITION_HISTORY
            for i in ctx.transition_history.len()..MAX_TRANSITION_HISTORY {
                ctx.transition_history.push((
                    SessionState::Active,
                    SessionState::Suspicious,
                    base_ts + i as u64,
                ));
            }
            assert_eq!(ctx.transition_history.len(), MAX_TRANSITION_HISTORY);
        }

        let summary = guard.session_summary(sid).unwrap();
        assert_eq!(summary.transitions.len(), MAX_TRANSITION_HISTORY);

        // Now trigger a real state change: anomaly should try to record
        // a transition but the history is full — it should be silently dropped.
        let result = guard
            .process_event_at(
                sid,
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Critical,
                    description: "test".to_string(),
                },
                base_ts + MAX_TRANSITION_HISTORY as u64 + 1,
            )
            .unwrap();

        // The state change DID happen
        assert_eq!(result.current, SessionState::Suspicious);

        let summary2 = guard.session_summary(sid).unwrap();
        // But the transition history was NOT extended
        assert_eq!(
            summary2.transitions.len(),
            MAX_TRANSITION_HISTORY,
            "History must not grow beyond MAX_TRANSITION_HISTORY"
        );
        // State machine still works
        assert_eq!(summary2.state, SessionState::Suspicious);
    }
}
