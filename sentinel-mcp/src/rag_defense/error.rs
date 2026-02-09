//! Error types for RAG poisoning defense.
//!
//! All errors are fail-closed: when these errors occur, the action is denied.

use thiserror::Error;

/// Errors that can occur during RAG defense operations.
#[derive(Debug, Error, Clone)]
pub enum RagDefenseError {
    /// Document verification failed.
    #[error("Document verification failed: {0}")]
    DocumentVerification(String),

    /// Document trust score is below threshold.
    #[error("Document trust score {score:.2} below threshold {threshold:.2}")]
    LowTrustScore {
        /// Actual trust score.
        score: f64,
        /// Required threshold.
        threshold: f64,
    },

    /// Content hash does not match expected value.
    #[error("Content hash mismatch: expected {expected}, got {actual}")]
    ContentHashMismatch {
        /// Expected hash.
        expected: String,
        /// Actual hash.
        actual: String,
    },

    /// Retrieval result limit exceeded.
    #[error("Retrieval limit exceeded: {count} > {max}")]
    RetrievalLimitExceeded {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Embedding anomaly detected.
    #[error("Embedding anomaly detected: similarity {similarity:.3} below threshold {threshold:.3}")]
    EmbeddingAnomaly {
        /// Actual similarity to baseline.
        similarity: f64,
        /// Required threshold.
        threshold: f64,
    },

    /// Context budget exceeded.
    #[error("Context budget exceeded: {tokens} tokens > {budget} budget")]
    ContextBudgetExceeded {
        /// Requested tokens.
        tokens: u32,
        /// Available budget.
        budget: u32,
    },

    /// Unverified document blocked.
    #[error("Unverified document blocked: {doc_id}")]
    UnverifiedDocument {
        /// Document ID.
        doc_id: String,
    },

    /// Document age exceeds maximum allowed.
    #[error("Document too old: {age_hours}h > {max_hours}h maximum")]
    DocumentTooOld {
        /// Actual age in hours.
        age_hours: u64,
        /// Maximum allowed age in hours.
        max_hours: u64,
    },

    /// Session document limit exceeded.
    #[error("Session document limit exceeded: {count} > {max}")]
    SessionDocumentLimit {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Diversity check failed - too many similar results.
    #[error("Retrieval diversity too low: {similarity:.3} similarity between results")]
    LowDiversity {
        /// Maximum similarity between results.
        similarity: f64,
    },

    /// DLP scan detected sensitive data.
    #[error("Sensitive data detected in retrieval: {finding}")]
    SensitiveDataDetected {
        /// DLP finding description.
        finding: String,
    },

    /// Embedding baseline insufficient for detection.
    #[error("Insufficient baseline: {samples} samples < {required} required")]
    InsufficientBaseline {
        /// Actual sample count.
        samples: u32,
        /// Required sample count.
        required: u32,
    },

    /// Agent embedding limit exceeded.
    #[error("Agent embedding limit exceeded: {count} > {max}")]
    AgentEmbeddingLimit {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Invalid embedding dimension.
    #[error("Invalid embedding dimension: expected {expected}, got {actual}")]
    InvalidEmbeddingDimension {
        /// Expected dimension.
        expected: usize,
        /// Actual dimension.
        actual: usize,
    },

    /// Internal error during RAG defense processing.
    #[error("Internal RAG defense error: {0}")]
    Internal(String),
}

impl RagDefenseError {
    /// Returns true if this error indicates a security violation that should be blocked.
    pub fn is_security_violation(&self) -> bool {
        matches!(
            self,
            Self::LowTrustScore { .. }
                | Self::ContentHashMismatch { .. }
                | Self::EmbeddingAnomaly { .. }
                | Self::UnverifiedDocument { .. }
                | Self::SensitiveDataDetected { .. }
        )
    }

    /// Returns true if this error indicates a limit exceeded.
    pub fn is_limit_exceeded(&self) -> bool {
        matches!(
            self,
            Self::RetrievalLimitExceeded { .. }
                | Self::ContextBudgetExceeded { .. }
                | Self::SessionDocumentLimit { .. }
                | Self::AgentEmbeddingLimit { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = RagDefenseError::LowTrustScore {
            score: 0.3,
            threshold: 0.5,
        };
        assert!(err.to_string().contains("0.30"));
        assert!(err.to_string().contains("0.50"));
    }

    #[test]
    fn test_security_violation_classification() {
        assert!(RagDefenseError::LowTrustScore {
            score: 0.3,
            threshold: 0.5
        }
        .is_security_violation());

        assert!(!RagDefenseError::RetrievalLimitExceeded { count: 25, max: 20 }.is_security_violation());
    }

    #[test]
    fn test_limit_exceeded_classification() {
        assert!(RagDefenseError::RetrievalLimitExceeded { count: 25, max: 20 }.is_limit_exceeded());

        assert!(!RagDefenseError::LowTrustScore {
            score: 0.3,
            threshold: 0.5
        }
        .is_limit_exceeded());
    }
}
