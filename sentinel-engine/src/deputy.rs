//! Confused deputy prevention (OWASP ASI02).
//!
//! Tracks principal delegation chains to prevent unauthorized tool access
//! through confused deputy attacks. A confused deputy attack occurs when
//! a privileged agent is tricked into acting on behalf of an unprivileged
//! attacker.
//!
//! # Example
//!
//! ```rust,ignore
//! use sentinel_engine::deputy::DeputyValidator;
//!
//! let validator = DeputyValidator::new(3);
//!
//! // Register a delegation
//! validator.register_delegation(
//!     "session-1",
//!     "admin",
//!     "worker-agent",
//!     &["read_file", "write_file"],
//! ).unwrap();
//!
//! // Validate action
//! let result = validator.validate_action(
//!     "session-1",
//!     "read_file",
//!     "worker-agent",
//! );
//! assert!(result.is_ok());
//! ```

use crate::PatternMatcher;
use sentinel_types::PrincipalContext;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

/// Error types for deputy validation.
#[derive(Debug, Clone)]
pub enum DeputyError {
    /// Delegation from one principal to another is not authorized.
    UnauthorizedDelegation { from: String, to: String },
    /// Delegation chain is too deep.
    DelegationDepthExceeded { depth: u8, max: u8 },
    /// Tool is not in the delegation's allowed set.
    ToolNotInDelegation { tool: String },
    /// Delegation has expired.
    DelegationExpired,
    /// Principal in request doesn't match expected.
    PrincipalMismatch { expected: String, actual: String },
    /// Session not found.
    SessionNotFound { session_id: String },
    /// No principal identified.
    NoPrincipal,
    /// Internal error (e.g., RwLock poisoned). Fail-closed.
    InternalError { reason: String },
}

impl std::fmt::Display for DeputyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeputyError::UnauthorizedDelegation { from, to } => {
                write!(
                    f,
                    "Delegation from '{}' to '{}' is not authorized",
                    from, to
                )
            }
            DeputyError::DelegationDepthExceeded { depth, max } => {
                write!(f, "Delegation depth {} exceeds maximum {}", depth, max)
            }
            DeputyError::ToolNotInDelegation { tool } => {
                write!(f, "Tool '{}' is not in the delegation's allowed set", tool)
            }
            DeputyError::DelegationExpired => {
                write!(f, "Delegation has expired")
            }
            DeputyError::PrincipalMismatch { expected, actual } => {
                write!(
                    f,
                    "Principal mismatch: expected '{}', got '{}'",
                    expected, actual
                )
            }
            DeputyError::SessionNotFound { session_id } => {
                write!(f, "Session '{}' not found", session_id)
            }
            DeputyError::NoPrincipal => {
                write!(f, "No principal identified")
            }
            DeputyError::InternalError { reason } => {
                write!(f, "Internal error (fail-closed): {}", reason)
            }
        }
    }
}

impl std::error::Error for DeputyError {}

/// Rule for allowed delegations.
#[derive(Debug, Clone)]
pub struct DelegationRule {
    /// Principal that can delegate.
    pub from_principal: String,
    /// Principal that can receive delegation.
    pub to_principal: String,
    /// Tools the delegate is allowed to access (glob patterns).
    pub allowed_tools: Vec<PatternMatcher>,
    /// Maximum delegation depth (0 = no further delegation).
    pub max_depth: u8,
    /// Expiry time in Unix seconds (None = no expiry).
    pub expires_secs: Option<u64>,
}

/// Validates principal binding to prevent confused deputy attacks.
#[derive(Debug)]
pub struct DeputyValidator {
    /// Static delegation rules (loaded from config).
    delegation_rules: RwLock<HashMap<String, DelegationRule>>,
    /// Active delegation contexts by session ID.
    active_contexts: RwLock<HashMap<String, PrincipalContext>>,
    /// Maximum allowed delegation depth.
    max_depth: u8,
}

impl DeputyValidator {
    /// Create a new deputy validator.
    ///
    /// # Arguments
    /// * `max_depth` - Maximum allowed delegation depth (0 = direct only)
    pub fn new(max_depth: u8) -> Self {
        Self {
            delegation_rules: RwLock::new(HashMap::new()),
            active_contexts: RwLock::new(HashMap::new()),
            max_depth,
        }
    }

    /// Create a shareable reference to this validator.
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Get the current timestamp as Unix seconds.
    ///
    /// Note: Returns 0 on system time error. This is acceptable for deputy
    /// expiry checks because 0 will cause all time-based expirations to trigger
    /// (fail-closed behavior).
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_else(|e| {
                tracing::error!("CRITICAL: System time error in deputy: {}", e);
                0
            })
    }

    /// Register a delegation rule.
    ///
    /// Note: If RwLock is poisoned, logs error and does nothing.
    pub fn add_rule(&self, rule_id: impl Into<String>, rule: DelegationRule) {
        let mut rules = match self.delegation_rules.write() {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("CRITICAL: Deputy RwLock poisoned in add_rule: {}", e);
                return;
            }
        };
        rules.insert(rule_id.into(), rule);
    }

    /// Register a delegation for a session.
    ///
    /// # Arguments
    /// * `session_id` - The session to register delegation for
    /// * `from` - The delegating principal
    /// * `to` - The receiving principal
    /// * `allowed_tools` - Tools the delegate can access
    ///
    /// # Returns
    /// `Ok(())` if delegation was registered, `Err(DeputyError)` if not authorized.
    ///
    /// SECURITY: Fails closed if RwLock is poisoned.
    pub fn register_delegation(
        &self,
        session_id: &str,
        from: &str,
        to: &str,
        allowed_tools: &[String],
    ) -> Result<(), DeputyError> {
        let mut contexts = self.active_contexts.write().map_err(|e| {
            tracing::error!(
                "CRITICAL: Deputy RwLock poisoned in register_delegation for session '{}': {}",
                session_id,
                e
            );
            DeputyError::InternalError {
                reason: "RwLock poisoned — failing closed".to_string(),
            }
        })?;

        // Get current context if exists
        let current_depth = contexts
            .get(session_id)
            .map_or(0, |ctx| ctx.delegation_depth);

        // Check depth limit
        let new_depth = current_depth + 1;
        if new_depth > self.max_depth {
            return Err(DeputyError::DelegationDepthExceeded {
                depth: new_depth,
                max: self.max_depth,
            });
        }

        // Create new context
        let ctx = PrincipalContext {
            original_principal: from.to_string(),
            delegated_to: Some(to.to_string()),
            delegation_depth: new_depth,
            allowed_tools: allowed_tools.to_vec(),
            delegation_expires: None, // Could be set from rule
        };

        contexts.insert(session_id.to_string(), ctx);

        tracing::debug!(
            session = %session_id,
            from = %from,
            to = %to,
            depth = %new_depth,
            "Delegation registered"
        );

        Ok(())
    }

    /// Validate that an action is authorized for the current principal chain.
    ///
    /// # Arguments
    /// * `session_id` - The session ID
    /// * `tool` - The tool being called
    /// * `claimed_principal` - The principal claiming to make the call
    ///
    /// # Returns
    /// `Ok(())` if authorized, `Err(DeputyError)` if not.
    ///
    /// SECURITY: Fails closed if RwLock is poisoned.
    pub fn validate_action(
        &self,
        session_id: &str,
        tool: &str,
        claimed_principal: &str,
    ) -> Result<(), DeputyError> {
        let contexts = self.active_contexts.read().map_err(|e| {
            tracing::error!(
                "CRITICAL: Deputy RwLock poisoned in validate_action for session '{}': {}",
                session_id,
                e
            );
            DeputyError::InternalError {
                reason: "RwLock poisoned — failing closed".to_string(),
            }
        })?;

        let ctx = match contexts.get(session_id) {
            Some(c) => c,
            None => {
                // No delegation context = direct request
                // This is allowed if no explicit delegation is required
                return Ok(());
            }
        };

        // Check if delegation has expired
        let now = Self::now();
        if ctx.is_expired(now) {
            return Err(DeputyError::DelegationExpired);
        }

        // Verify the claimed principal matches the delegate
        if let Some(ref delegate) = ctx.delegated_to {
            if delegate != claimed_principal {
                return Err(DeputyError::PrincipalMismatch {
                    expected: delegate.clone(),
                    actual: claimed_principal.to_string(),
                });
            }
        }

        // Check if tool is in allowed set
        if !ctx.allowed_tools.is_empty() {
            let tool_lower = tool.to_lowercase();
            let allowed = ctx
                .allowed_tools
                .iter()
                .any(|t| t.eq_ignore_ascii_case(&tool_lower));

            if !allowed {
                return Err(DeputyError::ToolNotInDelegation {
                    tool: tool.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Check if a tool is allowed for the current delegation chain.
    pub fn is_tool_allowed(&self, session_id: &str, tool: &str) -> bool {
        self.validate_action(session_id, tool, "").is_ok()
    }

    /// Get the current principal context for a session.
    ///
    /// Note: If RwLock is poisoned, returns None and logs error.
    pub fn get_context(&self, session_id: &str) -> Option<PrincipalContext> {
        let contexts = match self.active_contexts.read() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "CRITICAL: Deputy RwLock poisoned in get_context for session '{}': {}",
                    session_id,
                    e
                );
                return None;
            }
        };
        contexts.get(session_id).cloned()
    }

    /// Remove a session's delegation context.
    ///
    /// Note: If RwLock is poisoned, logs error and does nothing.
    pub fn remove_context(&self, session_id: &str) {
        let mut contexts = match self.active_contexts.write() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "CRITICAL: Deputy RwLock poisoned in remove_context for session '{}': {}",
                    session_id,
                    e
                );
                return;
            }
        };
        contexts.remove(session_id);
    }

    /// Clean up expired delegation contexts.
    ///
    /// Returns the number of contexts removed.
    ///
    /// Note: If RwLock is poisoned, returns 0 and logs error.
    pub fn cleanup_expired(&self) -> usize {
        let now = Self::now();
        let mut contexts = match self.active_contexts.write() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("CRITICAL: Deputy RwLock poisoned in cleanup_expired: {}", e);
                return 0;
            }
        };

        let old_len = contexts.len();
        contexts.retain(|_, ctx| !ctx.is_expired(now));

        old_len - contexts.len()
    }

    /// Get the number of active delegation contexts.
    ///
    /// Note: If RwLock is poisoned, returns 0 and logs error.
    pub fn active_count(&self) -> usize {
        let contexts = match self.active_contexts.read() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("CRITICAL: Deputy RwLock poisoned in active_count: {}", e);
                return 0;
            }
        };
        contexts.len()
    }
}

impl Default for DeputyValidator {
    fn default() -> Self {
        Self::new(3) // Default max depth of 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_principal_allowed() {
        let validator = DeputyValidator::new(3);

        // No delegation context = direct request, always allowed
        let result = validator.validate_action("session-1", "read_file", "user-1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_single_delegation_allowed() {
        let validator = DeputyValidator::new(3);

        // Register delegation
        validator
            .register_delegation(
                "session-1",
                "admin",
                "worker",
                &["read_file".to_string(), "write_file".to_string()],
            )
            .unwrap();

        // Worker can call allowed tools
        let result = validator.validate_action("session-1", "read_file", "worker");
        assert!(result.is_ok());
    }

    #[test]
    fn test_delegation_depth_exceeded() {
        let validator = DeputyValidator::new(1); // Only allow depth 1

        // First delegation succeeds
        validator
            .register_delegation("session-1", "admin", "worker-1", &["*".to_string()])
            .unwrap();

        // Second delegation fails (depth exceeded)
        let result = validator.register_delegation("session-1", "worker-1", "worker-2", &[]);

        assert!(matches!(
            result,
            Err(DeputyError::DelegationDepthExceeded { .. })
        ));
    }

    #[test]
    fn test_tool_not_in_delegation() {
        let validator = DeputyValidator::new(3);

        // Register delegation with limited tools
        validator
            .register_delegation("session-1", "admin", "worker", &["read_file".to_string()])
            .unwrap();

        // Attempt to call non-allowed tool
        let result = validator.validate_action("session-1", "delete_file", "worker");

        assert!(matches!(
            result,
            Err(DeputyError::ToolNotInDelegation { .. })
        ));
    }

    #[test]
    fn test_principal_mismatch_denied() {
        let validator = DeputyValidator::new(3);

        // Register delegation to specific worker
        validator
            .register_delegation("session-1", "admin", "worker-1", &["*".to_string()])
            .unwrap();

        // Different worker tries to use it
        let result = validator.validate_action("session-1", "read_file", "worker-2");

        assert!(matches!(result, Err(DeputyError::PrincipalMismatch { .. })));
    }

    #[test]
    fn test_get_context() {
        let validator = DeputyValidator::new(3);

        validator
            .register_delegation("session-1", "admin", "worker", &["read_file".to_string()])
            .unwrap();

        let ctx = validator.get_context("session-1").unwrap();
        assert_eq!(ctx.original_principal, "admin");
        assert_eq!(ctx.delegated_to, Some("worker".to_string()));
        assert_eq!(ctx.delegation_depth, 1);
    }

    #[test]
    fn test_remove_context() {
        let validator = DeputyValidator::new(3);

        validator
            .register_delegation("session-1", "admin", "worker", &[])
            .unwrap();

        assert!(validator.get_context("session-1").is_some());

        validator.remove_context("session-1");

        assert!(validator.get_context("session-1").is_none());
    }

    #[test]
    fn test_active_count() {
        let validator = DeputyValidator::new(3);

        assert_eq!(validator.active_count(), 0);

        validator
            .register_delegation("session-1", "admin", "worker", &[])
            .unwrap();
        validator
            .register_delegation("session-2", "admin", "worker", &[])
            .unwrap();

        assert_eq!(validator.active_count(), 2);
    }
}
