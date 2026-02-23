//! Just-In-Time (JIT) Access Management for Vellaveto.
//!
//! Provides temporary elevated permissions with automatic expiration,
//! approval workflows, and audit trail.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;
use vellaveto_config::JitAccessConfig;

/// SECURITY (FIND-R51-015): Global session cap for JIT access.
const MAX_TOTAL_JIT_SESSIONS: usize = 100_000;

/// Maximum length for individual permission or tool strings.
const MAX_JIT_STRING_FIELD_LEN: usize = 256;

// SECURITY (IMP-R106-001): Use canonical is_unsafe_char from routes/mod.rs.
use crate::routes::is_unsafe_char;

/// Errors that can occur during JIT access operations.
#[derive(Debug, Error)]
pub enum JitError {
    #[error("JIT access not enabled")]
    NotEnabled,

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Session expired: {0}")]
    SessionExpired(String),

    #[error("Session limit exceeded: {0} active sessions for principal")]
    SessionLimitExceeded(u32),

    #[error("Approval required for JIT access")]
    ApprovalRequired,

    #[error("Permission not granted: {0}")]
    PermissionNotGranted(String),

    #[error("Invalid TTL: {0} seconds exceeds maximum {1}")]
    InvalidTtl(u64, u64),

    /// SECURITY (FIND-R51-015): Global session capacity exceeded.
    #[error("JIT session capacity exceeded")]
    CapacityExceeded,

    /// SECURITY (FIND-R51-016): Invalid input field.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// A JIT access session granting temporary elevated permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitSession {
    /// Unique session identifier.
    pub id: String,
    /// Principal who owns this session.
    pub principal: String,
    /// Granted permissions.
    pub permissions: HashSet<String>,
    /// Tools this session grants access to.
    pub tools: HashSet<String>,
    /// When the session was created.
    pub created_at: u64,
    /// When the session expires.
    pub expires_at: u64,
    /// Whether the session was approved.
    pub approved: bool,
    /// Who approved the session (if applicable).
    pub approved_by: Option<String>,
    /// Reason for the access request.
    pub reason: String,
    /// Whether the session has been revoked.
    pub revoked: bool,
    /// Number of times permissions were used.
    pub use_count: u64,
}

impl JitSession {
    /// Check if the session is valid (not expired and not revoked).
    pub fn is_valid(&self) -> bool {
        !self.revoked && self.expires_at > current_timestamp()
    }

    /// Check if the session has a specific permission.
    pub fn has_permission(&self, permission: &str) -> bool {
        self.is_valid() && self.permissions.contains(permission)
    }

    /// Check if the session grants access to a tool.
    pub fn has_tool_access(&self, tool: &str) -> bool {
        self.is_valid() && self.tools.contains(tool)
    }
}

/// Request for JIT access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitRequest {
    /// Principal requesting access.
    pub principal: String,
    /// Requested permissions.
    pub permissions: HashSet<String>,
    /// Requested tool access.
    pub tools: HashSet<String>,
    /// Requested TTL in seconds.
    pub ttl_secs: u64,
    /// Reason for the request.
    pub reason: String,
}

/// JIT access manager.
pub struct JitAccessManager {
    config: JitAccessConfig,
    /// Active sessions by ID.
    sessions: DashMap<String, JitSession>,
    /// Sessions by principal for limit enforcement.
    principal_sessions: DashMap<String, HashSet<String>>,
    /// Session counter for metrics.
    session_count: AtomicU64,
}

impl JitAccessManager {
    /// Create a new JIT access manager.
    pub fn new(config: &JitAccessConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }

        Some(JitAccessManager {
            config: config.clone(),
            sessions: DashMap::new(),
            principal_sessions: DashMap::new(),
            session_count: AtomicU64::new(0),
        })
    }

    /// Request JIT access.
    pub fn request_access(&self, request: JitRequest) -> Result<JitSession, JitError> {
        // SECURITY (FIND-R51-016): Bound JIT request fields.
        if request.principal.len() > 256 {
            return Err(JitError::InvalidInput(
                "principal exceeds max length (256)".to_string(),
            ));
        }
        if request.reason.len() > 1024 {
            return Err(JitError::InvalidInput(
                "reason exceeds max length (1024)".to_string(),
            ));
        }
        if request.permissions.len() > 100 {
            return Err(JitError::InvalidInput(
                "too many permissions (max 100)".to_string(),
            ));
        }
        if request.tools.len() > 100 {
            return Err(JitError::InvalidInput(
                "too many tools (max 100)".to_string(),
            ));
        }

        // SECURITY: Reject control/format characters in string fields.
        if request.principal.chars().any(is_unsafe_char) {
            return Err(JitError::InvalidInput(
                "principal contains control or format characters".to_string(),
            ));
        }
        if request.reason.chars().any(is_unsafe_char) {
            return Err(JitError::InvalidInput(
                "reason contains control or format characters".to_string(),
            ));
        }
        for perm in &request.permissions {
            if perm.len() > MAX_JIT_STRING_FIELD_LEN {
                return Err(JitError::InvalidInput(format!(
                    "permission string too long ({} > {})",
                    perm.len(),
                    MAX_JIT_STRING_FIELD_LEN
                )));
            }
            if perm.chars().any(is_unsafe_char) {
                return Err(JitError::InvalidInput(
                    "permission contains control or format characters".to_string(),
                ));
            }
        }
        for tool in &request.tools {
            if tool.len() > MAX_JIT_STRING_FIELD_LEN {
                return Err(JitError::InvalidInput(format!(
                    "tool string too long ({} > {})",
                    tool.len(),
                    MAX_JIT_STRING_FIELD_LEN
                )));
            }
            if tool.chars().any(is_unsafe_char) {
                return Err(JitError::InvalidInput(
                    "tool contains control or format characters".to_string(),
                ));
            }
        }

        // SECURITY (FIND-R51-015): Global session cap.
        if self.sessions.len() >= MAX_TOTAL_JIT_SESSIONS {
            return Err(JitError::CapacityExceeded);
        }

        // Validate TTL
        if request.ttl_secs > self.config.max_ttl_secs {
            return Err(JitError::InvalidTtl(
                request.ttl_secs,
                self.config.max_ttl_secs,
            ));
        }

        // Check session limit
        let active_count = self.count_active_sessions(&request.principal);
        if active_count >= self.config.max_sessions_per_principal {
            return Err(JitError::SessionLimitExceeded(
                self.config.max_sessions_per_principal,
            ));
        }

        // Create session
        let now = current_timestamp();
        let ttl = if request.ttl_secs == 0 {
            self.config.default_ttl_secs
        } else {
            request.ttl_secs
        };

        let session = JitSession {
            id: Uuid::new_v4().to_string(),
            principal: request.principal.clone(),
            permissions: request.permissions,
            tools: request.tools,
            created_at: now,
            expires_at: now + ttl,
            approved: !self.config.require_approval,
            approved_by: None,
            reason: request.reason,
            revoked: false,
            use_count: 0,
        };

        // If approval is required, return the pending session
        if self.config.require_approval && !session.approved {
            return Err(JitError::ApprovalRequired);
        }

        // Store the session
        self.store_session(session.clone());

        Ok(session)
    }

    /// Approve a pending JIT session.
    pub fn approve_session(
        &self,
        session_id: &str,
        approver: &str,
    ) -> Result<JitSession, JitError> {
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| JitError::SessionNotFound(session_id.to_string()))?;

        if !session.is_valid() {
            return Err(JitError::SessionExpired(session_id.to_string()));
        }

        session.approved = true;
        session.approved_by = Some(approver.to_string());

        Ok(session.clone())
    }

    /// Revoke a JIT session.
    pub fn revoke_session(&self, session_id: &str) -> Result<JitSession, JitError> {
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| JitError::SessionNotFound(session_id.to_string()))?;

        session.revoked = true;

        Ok(session.clone())
    }

    /// Check if a principal has a valid session with the given permission.
    pub fn check_permission(&self, principal: &str, permission: &str) -> Result<bool, JitError> {
        let session_ids = self
            .principal_sessions
            .get(principal)
            .map(|s| s.clone())
            .unwrap_or_default();

        for session_id in session_ids {
            if let Some(mut session) = self.sessions.get_mut(&session_id) {
                if session.has_permission(permission) && session.approved {
                    // SECURITY (CA-001): Use saturating_add to prevent counter overflow.
                    session.use_count = session.use_count.saturating_add(1);
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Check if a principal has a valid session with tool access.
    pub fn check_tool_access(&self, principal: &str, tool: &str) -> Result<bool, JitError> {
        let session_ids = self
            .principal_sessions
            .get(principal)
            .map(|s| s.clone())
            .unwrap_or_default();

        for session_id in session_ids {
            if let Some(mut session) = self.sessions.get_mut(&session_id) {
                if session.has_tool_access(tool) && session.approved {
                    // SECURITY (CA-001): Use saturating_add to prevent counter overflow.
                    session.use_count = session.use_count.saturating_add(1);
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Get a session by ID.
    pub fn get_session(&self, session_id: &str) -> Option<JitSession> {
        self.sessions.get(session_id).map(|s| s.clone())
    }

    /// List all sessions for a principal.
    pub fn list_sessions(&self, principal: &str) -> Vec<JitSession> {
        let session_ids = self
            .principal_sessions
            .get(principal)
            .map(|s| s.clone())
            .unwrap_or_default();

        session_ids
            .iter()
            .filter_map(|id| self.sessions.get(id).map(|s| s.clone()))
            .collect()
    }

    /// List all active sessions.
    pub fn list_all_sessions(&self) -> Vec<JitSession> {
        self.sessions
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Revoke all sessions for a principal (used when alerts are triggered).
    pub fn revoke_all_for_principal(&self, principal: &str) -> Vec<String> {
        let session_ids = self
            .principal_sessions
            .get(principal)
            .map(|s| s.clone())
            .unwrap_or_default();

        let mut revoked = Vec::new();

        for session_id in session_ids {
            if let Some(mut session) = self.sessions.get_mut(&session_id) {
                if !session.revoked {
                    session.revoked = true;
                    revoked.push(session_id);
                }
            }
        }

        revoked
    }

    /// Clean up expired sessions.
    pub fn cleanup_expired(&self) -> usize {
        let now = current_timestamp();
        let mut expired = Vec::new();

        for entry in self.sessions.iter() {
            if entry.value().expires_at < now {
                expired.push(entry.key().clone());
            }
        }

        let count = expired.len();

        for session_id in expired {
            if let Some((_, session)) = self.sessions.remove(&session_id) {
                if let Some(mut principal_sessions) =
                    self.principal_sessions.get_mut(&session.principal)
                {
                    principal_sessions.remove(&session_id);
                }
            }
        }

        count
    }

    /// Get configuration.
    pub fn config(&self) -> &JitAccessConfig {
        &self.config
    }

    /// Check if auto-revoke on alert is enabled.
    pub fn auto_revoke_on_alert(&self) -> bool {
        self.config.auto_revoke_on_alert
    }

    /// Count active (non-expired, non-revoked) sessions for a principal.
    fn count_active_sessions(&self, principal: &str) -> u32 {
        let session_ids = self
            .principal_sessions
            .get(principal)
            .map(|s| s.clone())
            .unwrap_or_default();

        session_ids
            .iter()
            .filter(|id| {
                self.sessions
                    .get(*id)
                    .map(|s| s.is_valid())
                    .unwrap_or(false)
            })
            .count() as u32
    }

    /// Store a session.
    fn store_session(&self, session: JitSession) {
        let principal = session.principal.clone();
        let session_id = session.id.clone();

        self.sessions.insert(session_id.clone(), session);

        self.principal_sessions
            .entry(principal)
            .or_default()
            .insert(session_id);

        // SECURITY (CA-007): SeqCst + saturating arithmetic for security-adjacent
        // session counter. Even though currently used only for metrics, upgrading
        // prevents future misuse if this counter is later used in authorization decisions.
        let _ = self
            .session_count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_add(1))
            });
    }

    /// Get total session count (for metrics).
    pub fn total_session_count(&self) -> u64 {
        self.session_count.load(Ordering::SeqCst)
    }
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> JitAccessConfig {
        JitAccessConfig {
            enabled: true,
            default_ttl_secs: 3600,
            max_ttl_secs: 86400,
            require_approval: false,
            require_reason: false,
            allowed_elevations: vec!["admin".to_string(), "sudo".to_string()],
            max_sessions_per_principal: 5,
            auto_revoke_on_alert: true,
            notification_webhook: None,
            require_reauth: false,
        }
    }

    #[test]
    fn test_jit_disabled() {
        let config = JitAccessConfig {
            enabled: false,
            ..Default::default()
        };
        let manager = JitAccessManager::new(&config);
        assert!(manager.is_none());
    }

    #[test]
    fn test_jit_request_access() {
        let manager = JitAccessManager::new(&test_config()).unwrap();

        let request = JitRequest {
            principal: "user1".to_string(),
            permissions: ["admin".to_string()].into_iter().collect(),
            tools: ["filesystem".to_string()].into_iter().collect(),
            ttl_secs: 3600,
            reason: "Need to debug issue".to_string(),
        };

        let session = manager.request_access(request).unwrap();
        assert!(session.is_valid());
        assert!(session.approved);
        assert!(session.has_permission("admin"));
        assert!(session.has_tool_access("filesystem"));
    }

    #[test]
    fn test_jit_ttl_validation() {
        let manager = JitAccessManager::new(&test_config()).unwrap();

        let request = JitRequest {
            principal: "user1".to_string(),
            permissions: HashSet::new(),
            tools: HashSet::new(),
            ttl_secs: 100_000, // Exceeds max
            reason: "test".to_string(),
        };

        let result = manager.request_access(request);
        assert!(matches!(result, Err(JitError::InvalidTtl(_, _))));
    }

    #[test]
    fn test_jit_session_limit() {
        let mut config = test_config();
        config.max_sessions_per_principal = 2;
        let manager = JitAccessManager::new(&config).unwrap();

        // Create 2 sessions
        for i in 0..2 {
            let request = JitRequest {
                principal: "user1".to_string(),
                permissions: HashSet::new(),
                tools: HashSet::new(),
                ttl_secs: 3600,
                reason: format!("test {}", i),
            };
            manager.request_access(request).unwrap();
        }

        // Third should fail
        let request = JitRequest {
            principal: "user1".to_string(),
            permissions: HashSet::new(),
            tools: HashSet::new(),
            ttl_secs: 3600,
            reason: "test".to_string(),
        };
        let result = manager.request_access(request);
        assert!(matches!(result, Err(JitError::SessionLimitExceeded(_))));
    }

    #[test]
    fn test_jit_revoke_session() {
        let manager = JitAccessManager::new(&test_config()).unwrap();

        let request = JitRequest {
            principal: "user1".to_string(),
            permissions: ["admin".to_string()].into_iter().collect(),
            tools: HashSet::new(),
            ttl_secs: 3600,
            reason: "test".to_string(),
        };

        let session = manager.request_access(request).unwrap();
        assert!(session.is_valid());

        let revoked = manager.revoke_session(&session.id).unwrap();
        assert!(revoked.revoked);

        // Permission check should fail
        let has_perm = manager.check_permission("user1", "admin").unwrap();
        assert!(!has_perm);
    }

    #[test]
    fn test_jit_require_approval() {
        let mut config = test_config();
        config.require_approval = true;
        let manager = JitAccessManager::new(&config).unwrap();

        let request = JitRequest {
            principal: "user1".to_string(),
            permissions: HashSet::new(),
            tools: HashSet::new(),
            ttl_secs: 3600,
            reason: "test".to_string(),
        };

        let result = manager.request_access(request);
        assert!(matches!(result, Err(JitError::ApprovalRequired)));
    }

    #[test]
    fn test_jit_check_tool_access() {
        let manager = JitAccessManager::new(&test_config()).unwrap();

        let request = JitRequest {
            principal: "user1".to_string(),
            permissions: HashSet::new(),
            tools: ["filesystem".to_string(), "database".to_string()]
                .into_iter()
                .collect(),
            ttl_secs: 3600,
            reason: "test".to_string(),
        };

        manager.request_access(request).unwrap();

        assert!(manager.check_tool_access("user1", "filesystem").unwrap());
        assert!(manager.check_tool_access("user1", "database").unwrap());
        assert!(!manager.check_tool_access("user1", "network").unwrap());
    }

    #[test]
    fn test_jit_list_sessions() {
        let manager = JitAccessManager::new(&test_config()).unwrap();

        for i in 0..3 {
            let request = JitRequest {
                principal: "user1".to_string(),
                permissions: HashSet::new(),
                tools: HashSet::new(),
                ttl_secs: 3600,
                reason: format!("test {}", i),
            };
            manager.request_access(request).unwrap();
        }

        let sessions = manager.list_sessions("user1");
        assert_eq!(sessions.len(), 3);
    }

    #[test]
    fn test_jit_revoke_all_for_principal() {
        let manager = JitAccessManager::new(&test_config()).unwrap();

        for i in 0..3 {
            let request = JitRequest {
                principal: "user1".to_string(),
                permissions: HashSet::new(),
                tools: HashSet::new(),
                ttl_secs: 3600,
                reason: format!("test {}", i),
            };
            manager.request_access(request).unwrap();
        }

        let revoked = manager.revoke_all_for_principal("user1");
        assert_eq!(revoked.len(), 3);

        // All sessions should be revoked
        let sessions = manager.list_sessions("user1");
        assert!(sessions.iter().all(|s| s.revoked));
    }

    #[test]
    fn test_jit_request_principal_control_chars() {
        let manager = JitAccessManager::new(&test_config()).unwrap();
        let request = JitRequest {
            principal: "user\x00evil".to_string(),
            permissions: HashSet::new(),
            tools: HashSet::new(),
            ttl_secs: 3600,
            reason: "test".to_string(),
        };
        let result = manager.request_access(request);
        assert!(matches!(result, Err(JitError::InvalidInput(_))));
    }

    #[test]
    fn test_jit_request_reason_control_chars() {
        let manager = JitAccessManager::new(&test_config()).unwrap();
        let request = JitRequest {
            principal: "user1".to_string(),
            permissions: HashSet::new(),
            tools: HashSet::new(),
            ttl_secs: 3600,
            reason: "reason\nnewline".to_string(),
        };
        let result = manager.request_access(request);
        assert!(matches!(result, Err(JitError::InvalidInput(_))));
    }

    #[test]
    fn test_jit_request_permission_control_chars() {
        let manager = JitAccessManager::new(&test_config()).unwrap();
        let request = JitRequest {
            principal: "user1".to_string(),
            permissions: ["admin\x07bell".to_string()].into_iter().collect(),
            tools: HashSet::new(),
            ttl_secs: 3600,
            reason: "test".to_string(),
        };
        let result = manager.request_access(request);
        assert!(matches!(result, Err(JitError::InvalidInput(_))));
    }

    #[test]
    fn test_jit_request_tool_unicode_format_chars() {
        let manager = JitAccessManager::new(&test_config()).unwrap();
        let request = JitRequest {
            principal: "user1".to_string(),
            permissions: HashSet::new(),
            tools: ["fs\u{200B}read".to_string()].into_iter().collect(),
            ttl_secs: 3600,
            reason: "test".to_string(),
        };
        let result = manager.request_access(request);
        assert!(matches!(result, Err(JitError::InvalidInput(_))));
    }

    #[test]
    fn test_jit_request_tool_string_too_long() {
        let manager = JitAccessManager::new(&test_config()).unwrap();
        let request = JitRequest {
            principal: "user1".to_string(),
            permissions: HashSet::new(),
            tools: ["x".repeat(257)].into_iter().collect(),
            ttl_secs: 3600,
            reason: "test".to_string(),
        };
        let result = manager.request_access(request);
        assert!(matches!(result, Err(JitError::InvalidInput(_))));
    }
}
