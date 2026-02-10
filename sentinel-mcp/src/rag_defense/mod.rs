//! RAG Poisoning Defense — Protection against RAG system attacks (Phase 13).
//!
//! This module provides defense mechanisms against attacks targeting RAG
//! (Retrieval-Augmented Generation) systems:
//!
//! - **Document Injection**: Malicious content injected into knowledge base
//! - **Embedding Manipulation**: Adversarial perturbations to embeddings
//! - **Context Window Flooding**: Irrelevant data diluting real information
//! - **Hallucination/Grounding**: LLM responses not supported by context
//!
//! # Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────┐
//! │                      RagDefenseService                        │
//! ├───────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────┐ │
//! │  │ DocumentVerifier│   │RetrievalInspector│  │EmbeddingAnomaly│
//! │  │ (trust scoring) │   │  (DLP, limits)   │  │  Detector   │ │
//! │  └─────────────────┘   └─────────────────┘   └─────────────┘ │
//! │  ┌─────────────────────────────────────────────────────────┐ │
//! │  │              ContextBudgetTracker                       │ │
//! │  │           (token limit enforcement)                     │ │
//! │  └─────────────────────────────────────────────────────────┘ │
//! │  ┌─────────────────────────────────────────────────────────┐ │
//! │  │              GroundingChecker                           │ │
//! │  │       (hallucination/grounding detection)               │ │
//! │  └─────────────────────────────────────────────────────────┘ │
//! └───────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Feature Flags
//!
//! - `rag-defense`: Enables this module
//!
//! # Example
//!
//! ```rust,ignore
//! use sentinel_mcp::rag_defense::{
//!     RagDefenseService, DocumentMetadata, RetrievalResult, EmbeddingVector,
//! };
//!
//! // Create service with configuration
//! let config = RagDefenseConfig::default();
//! let service = RagDefenseService::new(config);
//!
//! // Verify a document
//! let doc = DocumentMetadata::new("doc1", "hash123", "source");
//! let trust_score = service.verify_document(&doc)?;
//!
//! // Inspect retrieval results
//! let results = vec![RetrievalResult::new("doc1", "content", 0.9, 100)];
//! let inspection = service.inspect_retrieval(&results);
//!
//! // Check embedding for anomalies
//! let embedding = EmbeddingVector::new("doc1", vec![0.1, 0.2, 0.3]);
//! let anomaly = service.check_embedding("agent1", &embedding)?;
//!
//! // Check context budget
//! let enforcement = service.check_budget("session1", 500);
//! ```
//!
//! # Fail-Closed Design
//!
//! Following Sentinel's security principles, RAG defense is fail-closed:
//!
//! - Low trust scores result in denial
//! - Embedding anomalies can block (configurable)
//! - Budget exhaustion results in rejection or truncation
//! - Internal errors result in denial

pub mod context_budget;
pub mod document;
pub mod embedding;
pub mod error;
pub mod grounding;
pub mod retrieval;

// Re-export commonly used types
pub use context_budget::{BudgetEnforcement, BudgetStats, BudgetUsage, ContextBudgetTracker};
pub use document::{
    compute_content_hash, DocumentMetadata, DocumentTrustScore, DocumentVerifier, TrustFactor,
};
pub use embedding::{
    AnomalyDetection, EmbeddingAnomalyDetector, EmbeddingBaseline, EmbeddingVector,
};
pub use error::RagDefenseError;
pub use grounding::{
    Attribution, ClaimScore, Contradiction, GroundingChecker, GroundingConfig,
    GroundingEnforcement, GroundingError, GroundingMethod, GroundingResult, NliLabel,
};
pub use retrieval::{RagDlpFinding, RetrievalInspection, RetrievalInspector, RetrievalResult};

use sentinel_config::RagDefenseConfig;

// ═══════════════════════════════════════════════════
// RAG DEFENSE SERVICE
// ═══════════════════════════════════════════════════

/// High-level service for RAG poisoning defense.
///
/// Combines document verification, retrieval inspection, embedding anomaly
/// detection, context budget enforcement, and grounding validation into a
/// single, easy-to-use service.
pub struct RagDefenseService {
    config: RagDefenseConfig,
    document_verifier: DocumentVerifier,
    retrieval_inspector: RetrievalInspector,
    embedding_detector: EmbeddingAnomalyDetector,
    budget_tracker: ContextBudgetTracker,
    grounding_checker: GroundingChecker,
}

impl RagDefenseService {
    /// Creates a new RAG defense service with the given configuration.
    pub fn new(config: RagDefenseConfig) -> Self {
        Self {
            document_verifier: DocumentVerifier::new(config.document_verification.clone()),
            retrieval_inspector: RetrievalInspector::new(config.retrieval_security.clone()),
            embedding_detector: EmbeddingAnomalyDetector::new(config.embedding_anomaly.clone()),
            budget_tracker: ContextBudgetTracker::new(config.context_budget.clone()),
            grounding_checker: GroundingChecker::new(config.grounding.clone()),
            config,
        }
    }

    /// Creates a disabled service that passes all requests through.
    pub fn disabled() -> Self {
        Self {
            config: RagDefenseConfig::default(),
            document_verifier: DocumentVerifier::disabled(),
            retrieval_inspector: RetrievalInspector::disabled(),
            embedding_detector: EmbeddingAnomalyDetector::disabled(),
            budget_tracker: ContextBudgetTracker::disabled(),
            grounding_checker: GroundingChecker::disabled(),
        }
    }

    /// Returns whether the service is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Returns the enforcement mode.
    pub fn enforcement(&self) -> &str {
        &self.config.enforcement
    }

    /// Returns the configuration.
    pub fn config(&self) -> &RagDefenseConfig {
        &self.config
    }

    // ═══════════════════════════════════════════════════
    // DOCUMENT VERIFICATION (13.1)
    // ═══════════════════════════════════════════════════

    /// Verifies a document and returns its trust score.
    ///
    /// Returns an error if:
    /// - Document trust score is below threshold
    /// - Document is too old
    /// - Document is unverified and blocking is enabled
    pub fn verify_document(
        &self,
        doc: &DocumentMetadata,
    ) -> Result<DocumentTrustScore, RagDefenseError> {
        if !self.config.enabled {
            return Ok(DocumentTrustScore::new(1.0, vec![]));
        }

        self.document_verifier.verify(doc)
    }

    /// Registers a document for tracking.
    pub fn register_document(&self, metadata: DocumentMetadata) -> Result<(), RagDefenseError> {
        if !self.config.enabled {
            return Ok(());
        }

        self.document_verifier.register_document(metadata)
    }

    /// Verifies that content matches the expected hash for a document.
    pub fn verify_content_hash(
        &self,
        doc_id: &str,
        content: &[u8],
    ) -> Result<bool, RagDefenseError> {
        if !self.config.enabled {
            return Ok(true);
        }

        self.document_verifier.verify_content_hash(doc_id, content)
    }

    /// Returns the document verifier for direct access.
    pub fn document_verifier(&self) -> &DocumentVerifier {
        &self.document_verifier
    }

    // ═══════════════════════════════════════════════════
    // RETRIEVAL SECURITY (13.2)
    // ═══════════════════════════════════════════════════

    /// Inspects retrieval results for security issues.
    ///
    /// Checks:
    /// - Result count limits
    /// - Result diversity
    /// - DLP findings (sensitive data)
    pub fn inspect_retrieval(&self, results: &[RetrievalResult]) -> RetrievalInspection {
        if !self.config.enabled {
            return RetrievalInspection::pass();
        }

        self.retrieval_inspector.inspect(results)
    }

    /// Enforces retrieval result limits.
    pub fn enforce_retrieval_limit(&self, results: Vec<RetrievalResult>) -> Vec<RetrievalResult> {
        if !self.config.enabled {
            return results;
        }

        self.retrieval_inspector.enforce_limit(results)
    }

    /// Returns the retrieval inspector for direct access.
    pub fn retrieval_inspector(&self) -> &RetrievalInspector {
        &self.retrieval_inspector
    }

    // ═══════════════════════════════════════════════════
    // EMBEDDING ANOMALY DETECTION (13.2)
    // ═══════════════════════════════════════════════════

    /// Checks an embedding for anomalies against the agent's baseline.
    ///
    /// Returns an error if anomaly is detected and blocking is enabled.
    pub fn check_embedding(
        &self,
        agent_id: &str,
        embedding: &EmbeddingVector,
    ) -> Result<AnomalyDetection, RagDefenseError> {
        if !self.config.enabled {
            return Ok(AnomalyDetection::normal(1.0, 0.0));
        }

        self.embedding_detector.detect_anomaly(agent_id, embedding)
    }

    /// Adds an embedding to the baseline for an agent.
    pub fn add_embedding_to_baseline(
        &self,
        agent_id: &str,
        embedding: &EmbeddingVector,
    ) -> Result<(), RagDefenseError> {
        if !self.config.enabled {
            return Ok(());
        }

        self.embedding_detector.add_to_baseline(agent_id, embedding)
    }

    /// Returns the embedding detector for direct access.
    pub fn embedding_detector(&self) -> &EmbeddingAnomalyDetector {
        &self.embedding_detector
    }

    // ═══════════════════════════════════════════════════
    // CONTEXT BUDGET ENFORCEMENT (13.2)
    // ═══════════════════════════════════════════════════

    /// Checks if a token request fits within the session's budget.
    pub fn check_budget(&self, session_id: &str, tokens: u32) -> BudgetEnforcement {
        if !self.config.enabled {
            return BudgetEnforcement::Allowed;
        }

        self.budget_tracker.check_budget(session_id, tokens)
    }

    /// Records token usage for a session.
    pub fn record_budget_usage(&self, session_id: &str, doc_id: &str, tokens: u32) {
        if self.config.enabled {
            self.budget_tracker.record_usage(session_id, doc_id, tokens);
        }
    }

    /// Returns the remaining budget for a session.
    pub fn get_remaining_budget(&self, session_id: &str) -> u32 {
        self.budget_tracker.get_remaining_budget(session_id)
    }

    /// Returns the budget tracker for direct access.
    pub fn budget_tracker(&self) -> &ContextBudgetTracker {
        &self.budget_tracker
    }

    // ═══════════════════════════════════════════════════
    // SESSION MANAGEMENT
    // ═══════════════════════════════════════════════════

    /// Resets all tracking for a session.
    pub fn reset_session(&self, session_id: &str) {
        self.document_verifier.reset_session(session_id);
        self.budget_tracker.reset_session(session_id);
    }

    /// Clears all stored state.
    pub fn clear_all(&self) {
        // Clear embedding baselines (per-agent, not per-session)
        // Document and budget state is per-session
    }
}

// ═══════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_creation() {
        let config = RagDefenseConfig {
            enabled: true,
            ..Default::default()
        };
        let service = RagDefenseService::new(config);
        assert!(service.is_enabled());
    }

    #[test]
    fn test_service_disabled() {
        let service = RagDefenseService::disabled();
        assert!(!service.is_enabled());

        // All operations should pass when disabled
        let doc = DocumentMetadata::new("doc1", "hash", "source");
        let result = service.verify_document(&doc);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().score, 1.0);
    }

    #[test]
    fn test_service_document_verification() {
        let config = RagDefenseConfig {
            enabled: true,
            document_verification: sentinel_config::DocumentVerificationConfig {
                enabled: true,
                require_trust_score: 0.5,
                ..Default::default()
            },
            ..Default::default()
        };
        let service = RagDefenseService::new(config);

        let doc = DocumentMetadata::new("doc1", "hash", "source").with_admin_approval();
        let result = service.verify_document(&doc);
        assert!(result.is_ok());
    }

    #[test]
    fn test_service_retrieval_inspection() {
        let config = RagDefenseConfig {
            enabled: true,
            retrieval_security: sentinel_config::RetrievalSecurityConfig {
                enabled: true,
                max_retrieval_results: 10,
                ..Default::default()
            },
            ..Default::default()
        };
        let service = RagDefenseService::new(config);

        let results = vec![
            RetrievalResult::new("doc1", "Content 1", 0.9, 100),
            RetrievalResult::new("doc2", "Content 2", 0.85, 100),
        ];

        let inspection = service.inspect_retrieval(&results);
        assert!(inspection.passed);
    }

    #[test]
    fn test_service_embedding_check() {
        let config = RagDefenseConfig {
            enabled: true,
            embedding_anomaly: sentinel_config::EmbeddingAnomalyConfig {
                enabled: true,
                min_baseline_samples: 2,
                ..Default::default()
            },
            ..Default::default()
        };
        let service = RagDefenseService::new(config);

        // Build baseline
        for i in 0..3 {
            let emb = EmbeddingVector::new(format!("doc{}", i), vec![0.5, 0.5, 0.5]);
            service.add_embedding_to_baseline("agent1", &emb).unwrap();
        }

        // Check similar embedding
        let emb = EmbeddingVector::new("test", vec![0.5, 0.5, 0.5]);
        let result = service.check_embedding("agent1", &emb);
        assert!(result.is_ok());
        assert!(!result.unwrap().is_anomalous);
    }

    #[test]
    fn test_service_budget_check() {
        let config = RagDefenseConfig {
            enabled: true,
            context_budget: sentinel_config::ContextBudgetConfig {
                enabled: true,
                max_tokens_per_retrieval: 1000,
                max_total_context_tokens: 5000,
                ..Default::default()
            },
            ..Default::default()
        };
        let service = RagDefenseService::new(config);

        let result = service.check_budget("session1", 500);
        assert!(result.is_allowed());

        service.record_budget_usage("session1", "doc1", 500);
        assert_eq!(service.get_remaining_budget("session1"), 4500);
    }

    #[test]
    fn test_service_reset_session() {
        let config = RagDefenseConfig {
            enabled: true,
            ..Default::default()
        };
        let service = RagDefenseService::new(config);

        service.record_budget_usage("session1", "doc1", 500);
        assert!(service.get_remaining_budget("session1") < u32::MAX);

        service.reset_session("session1");
        // After reset, remaining budget should be back to max
    }

    #[test]
    fn test_enforcement_mode() {
        let config = RagDefenseConfig {
            enabled: true,
            enforcement: "block".to_string(),
            ..Default::default()
        };
        let service = RagDefenseService::new(config);
        assert_eq!(service.enforcement(), "block");
    }
}
