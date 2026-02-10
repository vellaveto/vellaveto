//! Error types for the policy engine.
//!
//! This module defines the error types used throughout the policy evaluation process.

use thiserror::Error;

/// Errors that can occur during policy evaluation.
#[derive(Error, Debug)]
pub enum EngineError {
    /// No policies are defined, evaluation cannot proceed.
    #[error("No policies defined")]
    NoPolicies,

    /// A general evaluation error occurred.
    #[error("Evaluation error: {0}")]
    EvaluationError(String),

    /// An invalid condition was found in a policy.
    #[error("Invalid condition in policy '{policy_id}': {reason}")]
    InvalidCondition {
        /// The ID of the policy containing the invalid condition.
        policy_id: String,
        /// A description of why the condition is invalid.
        reason: String,
    },

    /// A JSON parsing or serialization error occurred.
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Path normalization failed (fail-closed behavior).
    #[error("Path normalization failed (fail-closed): {reason}")]
    PathNormalization {
        /// A description of why path normalization failed.
        reason: String,
    },
}

/// Error during policy compilation at load time.
///
/// This error is returned when a policy cannot be compiled due to invalid
/// configuration, such as malformed regex patterns or invalid constraint types.
#[derive(Debug, Clone)]
pub struct PolicyValidationError {
    /// The unique identifier of the policy that failed validation.
    pub policy_id: String,
    /// The human-readable name of the policy.
    pub policy_name: String,
    /// A description of why validation failed.
    pub reason: String,
}

impl std::fmt::Display for PolicyValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Policy '{}' ({}): {}",
            self.policy_name, self.policy_id, self.reason
        )
    }
}

impl std::error::Error for PolicyValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_error_display() {
        let err = EngineError::NoPolicies;
        assert_eq!(err.to_string(), "No policies defined");

        let err = EngineError::EvaluationError("test error".to_string());
        assert_eq!(err.to_string(), "Evaluation error: test error");

        let err = EngineError::InvalidCondition {
            policy_id: "p1".to_string(),
            reason: "bad pattern".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Invalid condition in policy 'p1': bad pattern"
        );

        let err = EngineError::PathNormalization {
            reason: "null byte".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Path normalization failed (fail-closed): null byte"
        );
    }

    #[test]
    fn test_policy_validation_error_display() {
        let err = PolicyValidationError {
            policy_id: "p1".to_string(),
            policy_name: "Test Policy".to_string(),
            reason: "invalid regex".to_string(),
        };
        assert_eq!(err.to_string(), "Policy 'Test Policy' (p1): invalid regex");
    }
}
