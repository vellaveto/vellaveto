// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

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
    #[error(
        "Embedding anomaly detected: similarity {similarity:.3} below threshold {threshold:.3}"
    )]
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

        assert!(
            !RagDefenseError::RetrievalLimitExceeded { count: 25, max: 20 }.is_security_violation()
        );
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

    /// Verify is_security_violation for all relevant variants.
    #[test]
    fn test_is_security_violation_exhaustive() {
        // These should be security violations
        assert!(RagDefenseError::ContentHashMismatch {
            expected: "a".to_string(),
            actual: "b".to_string()
        }
        .is_security_violation());
        assert!(RagDefenseError::EmbeddingAnomaly {
            similarity: 0.1,
            threshold: 0.5
        }
        .is_security_violation());
        assert!(RagDefenseError::UnverifiedDocument {
            doc_id: "doc1".to_string()
        }
        .is_security_violation());
        assert!(RagDefenseError::SensitiveDataDetected {
            finding: "SSN".to_string()
        }
        .is_security_violation());

        // These should NOT be security violations
        assert!(
            !RagDefenseError::ContextBudgetExceeded {
                tokens: 100,
                budget: 50
            }
            .is_security_violation()
        );
        assert!(
            !RagDefenseError::DocumentTooOld {
                age_hours: 100,
                max_hours: 24
            }
            .is_security_violation()
        );
        assert!(!RagDefenseError::DocumentVerification("fail".to_string()).is_security_violation());
        assert!(!RagDefenseError::Internal("oops".to_string()).is_security_violation());
        assert!(
            !RagDefenseError::LowDiversity { similarity: 0.99 }.is_security_violation()
        );
        assert!(
            !RagDefenseError::InsufficientBaseline {
                samples: 1,
                required: 10
            }
            .is_security_violation()
        );
        assert!(
            !RagDefenseError::InvalidEmbeddingDimension {
                expected: 768,
                actual: 512
            }
            .is_security_violation()
        );
    }

    /// Verify is_limit_exceeded for all relevant variants.
    #[test]
    fn test_is_limit_exceeded_exhaustive() {
        assert!(
            RagDefenseError::ContextBudgetExceeded {
                tokens: 100,
                budget: 50
            }
            .is_limit_exceeded()
        );
        assert!(
            RagDefenseError::SessionDocumentLimit {
                count: 10,
                max: 5
            }
            .is_limit_exceeded()
        );
        assert!(
            RagDefenseError::AgentEmbeddingLimit {
                count: 200,
                max: 100
            }
            .is_limit_exceeded()
        );

        // These should NOT be limit-exceeded
        assert!(!RagDefenseError::ContentHashMismatch {
            expected: "a".to_string(),
            actual: "b".to_string()
        }
        .is_limit_exceeded());
        assert!(!RagDefenseError::Internal("oops".to_string()).is_limit_exceeded());
        assert!(
            !RagDefenseError::DocumentTooOld {
                age_hours: 100,
                max_hours: 24
            }
            .is_limit_exceeded()
        );
    }

    /// Verify display strings for all error variants.
    #[test]
    fn test_error_display_all_variants() {
        assert_eq!(
            RagDefenseError::DocumentVerification("bad doc".to_string()).to_string(),
            "Document verification failed: bad doc"
        );
        assert!(
            RagDefenseError::ContentHashMismatch {
                expected: "abc".to_string(),
                actual: "def".to_string()
            }
            .to_string()
            .contains("abc")
        );
        assert!(
            RagDefenseError::RetrievalLimitExceeded {
                count: 30,
                max: 20
            }
            .to_string()
            .contains("30 > 20")
        );
        assert!(
            RagDefenseError::ContextBudgetExceeded {
                tokens: 500,
                budget: 200
            }
            .to_string()
            .contains("500 tokens > 200")
        );
        assert!(
            RagDefenseError::UnverifiedDocument {
                doc_id: "doc42".to_string()
            }
            .to_string()
            .contains("doc42")
        );
        assert!(
            RagDefenseError::DocumentTooOld {
                age_hours: 72,
                max_hours: 24
            }
            .to_string()
            .contains("72h > 24h")
        );
        assert!(
            RagDefenseError::SessionDocumentLimit {
                count: 15,
                max: 10
            }
            .to_string()
            .contains("15 > 10")
        );
        assert!(
            RagDefenseError::SensitiveDataDetected {
                finding: "credit card".to_string()
            }
            .to_string()
            .contains("credit card")
        );
        assert!(
            RagDefenseError::InsufficientBaseline {
                samples: 3,
                required: 10
            }
            .to_string()
            .contains("3 samples < 10")
        );
        assert!(
            RagDefenseError::InvalidEmbeddingDimension {
                expected: 768,
                actual: 512
            }
            .to_string()
            .contains("768")
        );
        assert_eq!(
            RagDefenseError::Internal("boom".to_string()).to_string(),
            "Internal RAG defense error: boom"
        );
    }

    /// Verify that error types implement Clone correctly.
    #[test]
    fn test_error_clone() {
        let err = RagDefenseError::LowTrustScore {
            score: 0.3,
            threshold: 0.5,
        };
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }
}
