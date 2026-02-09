//! A2A protocol error types.
//!
//! Error types for A2A (Agent-to-Agent) protocol handling, following the
//! fail-closed design principle: all errors result in request denial.

use thiserror::Error;

/// Errors that can occur during A2A protocol handling.
#[derive(Debug, Error)]
pub enum A2aError {
    /// The A2A message could not be parsed or is malformed.
    #[error("Invalid A2A message: {0}")]
    InvalidMessage(String),

    /// Agent card could not be found at the expected well-known URL.
    #[error("Agent card not found at {url}")]
    AgentCardNotFound { url: String },

    /// Agent card validation failed (schema mismatch, missing fields, etc.).
    #[error("Agent card validation failed: {0}")]
    AgentCardInvalid(String),

    /// Request requires authentication that was not provided.
    #[error("Authentication required: {method}")]
    AuthenticationRequired { method: String },

    /// Provided authentication credentials were rejected.
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Requested task does not exist or has expired.
    #[error("Task not found: {task_id}")]
    TaskNotFound { task_id: String },

    /// The requested operation is not allowed on a task in its current state.
    #[error("Task operation not allowed: {operation} on task in state {state}")]
    TaskOperationNotAllowed { operation: String, state: String },

    /// The message exceeds the configured maximum size.
    #[error("Message too large: {size} bytes exceeds maximum {max} bytes")]
    MessageTooLarge { size: usize, max: usize },

    /// An error occurred while communicating with the upstream A2A server.
    #[error("Upstream error: {0}")]
    Upstream(String),

    /// The request was denied by policy evaluation.
    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    /// The request timed out waiting for a response.
    #[error("Request timeout")]
    Timeout,

    /// Injection attack detected in message content.
    #[error("Injection detected: {0}")]
    InjectionDetected(String),

    /// DLP policy violation detected in message content.
    #[error("DLP violation: {0}")]
    DlpViolation(String),

    /// JSON-RPC batch requests are not allowed (security hardening).
    #[error("Batch requests are not allowed")]
    BatchNotAllowed,

    /// JSON serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// I/O error during communication.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Circuit breaker is open; upstream is unavailable.
    #[error("Circuit breaker open: upstream {upstream} is unavailable")]
    CircuitBreakerOpen { upstream: String },

    /// Shadow agent detected; request is blocked.
    #[error("Shadow agent detected: {0}")]
    ShadowAgentDetected(String),
}

impl A2aError {
    /// Returns the JSON-RPC error code for this error type.
    ///
    /// Error codes follow the JSON-RPC 2.0 specification:
    /// - -32700: Parse error
    /// - -32600: Invalid request
    /// - -32601: Method not found
    /// - -32602: Invalid params
    /// - -32603: Internal error
    /// - -32000 to -32099: Server errors (reserved)
    ///
    /// We use custom codes in the -32001 to -32099 range for A2A-specific errors.
    pub fn code(&self) -> i32 {
        match self {
            A2aError::InvalidMessage(_) => -32600,
            A2aError::Serialization(_) => -32700,
            A2aError::AuthenticationRequired { .. } => -32001,
            A2aError::AuthenticationFailed(_) => -32002,
            A2aError::PolicyDenied(_) => -32003,
            A2aError::TaskNotFound { .. } => -32004,
            A2aError::TaskOperationNotAllowed { .. } => -32005,
            A2aError::MessageTooLarge { .. } => -32006,
            A2aError::Timeout => -32007,
            A2aError::InjectionDetected(_) => -32008,
            A2aError::DlpViolation(_) => -32009,
            A2aError::BatchNotAllowed => -32010,
            A2aError::CircuitBreakerOpen { .. } => -32011,
            A2aError::ShadowAgentDetected(_) => -32012,
            A2aError::AgentCardNotFound { .. } => -32020,
            A2aError::AgentCardInvalid(_) => -32021,
            A2aError::Upstream(_) => -32603,
            A2aError::Io(_) => -32603,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = A2aError::InvalidMessage("missing method field".to_string());
        assert_eq!(err.to_string(), "Invalid A2A message: missing method field");

        let err = A2aError::MessageTooLarge {
            size: 20_000_000,
            max: 10_000_000,
        };
        assert!(err.to_string().contains("20000000"));
        assert!(err.to_string().contains("10000000"));
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(A2aError::InvalidMessage("".to_string()).code(), -32600);
        assert_eq!(
            A2aError::AuthenticationRequired {
                method: "bearer".to_string()
            }
            .code(),
            -32001
        );
        assert_eq!(A2aError::PolicyDenied("".to_string()).code(), -32003);
        assert_eq!(A2aError::Timeout.code(), -32007);
        assert_eq!(A2aError::BatchNotAllowed.code(), -32010);
    }

    #[test]
    fn test_error_from_serde_json() {
        let bad_json = "{ invalid json }";
        let serde_err: Result<serde_json::Value, _> = serde_json::from_str(bad_json);
        let a2a_err: A2aError = serde_err.unwrap_err().into();
        assert!(matches!(a2a_err, A2aError::Serialization(_)));
        assert_eq!(a2a_err.code(), -32700);
    }
}
