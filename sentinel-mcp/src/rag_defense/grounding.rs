//! Hallucination/Grounding Detection — Validate LLM responses against context (Phase 13.2).
//!
//! This module provides detection of LLM hallucinations by comparing generated
//! responses against retrieved context using Natural Language Inference (NLI).
//!
//! # Approach
//!
//! The grounding check validates that claims in the LLM response are:
//! 1. **Entailed** by the retrieved context (factually supported)
//! 2. **Not contradicted** by the retrieved context
//! 3. **Attributed** to specific source documents when possible
//!
//! # Scoring
//!
//! - **1.0**: Fully grounded (all claims supported by context)
//! - **0.7-0.99**: Mostly grounded (minor unsupported details)
//! - **0.5-0.69**: Partially grounded (some claims not in context)
//! - **0.0-0.49**: Poorly grounded (significant hallucination)
//!
//! # Example
//!
//! ```rust,ignore
//! use sentinel_mcp::rag_defense::grounding::{GroundingChecker, GroundingConfig};
//!
//! let config = GroundingConfig::default();
//! let checker = GroundingChecker::new(config);
//!
//! let context = vec![
//!     "The Eiffel Tower is located in Paris, France.",
//!     "It was built in 1889 for the World's Fair.",
//! ];
//!
//! let response = "The Eiffel Tower is in Paris and was built in 1889.";
//! let result = checker.check_grounding(&context, response)?;
//!
//! if result.is_grounded() {
//!     println!("Response is grounded (score: {:.2})", result.score);
//! } else {
//!     println!("Potential hallucination detected: {:?}", result.ungrounded_claims);
//! }
//! ```
//!
//! # Integration with LLM Backends
//!
//! For high-accuracy grounding checks, this module can use the semantic guardrails
//! LLM backend to perform NLI inference. Without an LLM backend, it falls back to
//! lexical similarity which is less accurate but faster.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// Re-export GroundingConfig from sentinel-config
pub use sentinel_config::GroundingConfig;

/// Enforcement action for grounding violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum GroundingEnforcement {
    /// Log warning but allow response. Default.
    #[default]
    Warn,
    /// Block response with low grounding score.
    Block,
    /// Add disclaimer to response.
    Annotate,
}

/// Result of a grounding check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundingResult {
    /// Overall grounding score (0.0-1.0).
    pub score: f32,

    /// Whether the response passes the grounding threshold.
    pub passed: bool,

    /// Individual claim scores.
    pub claim_scores: Vec<ClaimScore>,

    /// Claims that could not be grounded in context.
    pub ungrounded_claims: Vec<String>,

    /// Claims that contradict the context.
    pub contradictions: Vec<Contradiction>,

    /// Attribution mapping (claim -> source document).
    pub attributions: Vec<Attribution>,

    /// Method used for grounding check (NLI or Lexical).
    pub method: GroundingMethod,
}

impl GroundingResult {
    /// Check if the response is adequately grounded.
    pub fn is_grounded(&self) -> bool {
        self.passed
    }

    /// Get claims that are well-grounded (score >= 0.7).
    pub fn grounded_claims(&self) -> Vec<&ClaimScore> {
        self.claim_scores
            .iter()
            .filter(|c| c.score >= 0.7)
            .collect()
    }

    /// Get claims with potential hallucination (score < 0.5).
    pub fn hallucinated_claims(&self) -> Vec<&ClaimScore> {
        self.claim_scores.iter().filter(|c| c.score < 0.5).collect()
    }
}

/// Score for an individual claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimScore {
    /// The claim text.
    pub claim: String,

    /// Grounding score (0.0-1.0).
    pub score: f32,

    /// Most relevant context passage.
    pub best_evidence: Option<String>,

    /// NLI label if available (entailment, neutral, contradiction).
    pub nli_label: Option<NliLabel>,
}

/// NLI classification label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NliLabel {
    /// Claim is supported by context.
    Entailment,
    /// Claim is neither supported nor contradicted.
    Neutral,
    /// Claim contradicts the context.
    Contradiction,
}

/// A contradiction between response and context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contradiction {
    /// The contradicting claim in the response.
    pub claim: String,

    /// The contradicting evidence in context.
    pub evidence: String,

    /// Confidence in the contradiction (0.0-1.0).
    pub confidence: f32,
}

/// Attribution of a claim to a source document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribution {
    /// The claim text.
    pub claim: String,

    /// Source document ID.
    pub source_id: String,

    /// Relevant passage from source.
    pub passage: String,

    /// Attribution confidence (0.0-1.0).
    pub confidence: f32,
}

/// Method used for grounding check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GroundingMethod {
    /// LLM-based Natural Language Inference.
    Nli,
    /// Lexical overlap (fallback).
    Lexical,
    /// Disabled (returns pass).
    Disabled,
}

/// Grounding/hallucination detection checker.
pub struct GroundingChecker {
    config: GroundingConfig,
}

impl GroundingChecker {
    /// Create a new grounding checker with the given configuration.
    pub fn new(config: GroundingConfig) -> Self {
        Self { config }
    }

    /// Create a disabled checker that always passes.
    pub fn disabled() -> Self {
        Self {
            config: GroundingConfig::default(),
        }
    }

    /// Check if grounding validation is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check grounding of a response against context.
    ///
    /// # Arguments
    ///
    /// * `context` - Retrieved context passages
    /// * `response` - LLM-generated response to validate
    ///
    /// # Returns
    ///
    /// Grounding result with score and details.
    pub fn check_grounding(
        &self,
        context: &[&str],
        response: &str,
    ) -> Result<GroundingResult, GroundingError> {
        if !self.config.enabled {
            return Ok(GroundingResult {
                score: 1.0,
                passed: true,
                claim_scores: vec![],
                ungrounded_claims: vec![],
                contradictions: vec![],
                attributions: vec![],
                method: GroundingMethod::Disabled,
            });
        }

        if context.is_empty() {
            return Ok(GroundingResult {
                score: 0.0,
                passed: false,
                claim_scores: vec![],
                ungrounded_claims: vec![response.to_string()],
                contradictions: vec![],
                attributions: vec![],
                method: GroundingMethod::Lexical,
            });
        }

        // Extract claims from response
        let claims = self.extract_claims(response);

        if claims.is_empty() {
            // No claims to check - pass
            return Ok(GroundingResult {
                score: 1.0,
                passed: true,
                claim_scores: vec![],
                ungrounded_claims: vec![],
                contradictions: vec![],
                attributions: vec![],
                method: GroundingMethod::Lexical,
            });
        }

        // Check each claim against context
        let claim_scores: Vec<ClaimScore> = claims
            .iter()
            .take(self.config.max_claims)
            .map(|claim| self.score_claim(claim, context))
            .collect();

        // Calculate overall score
        let score = if claim_scores.is_empty() {
            1.0
        } else {
            claim_scores.iter().map(|c| c.score).sum::<f32>() / claim_scores.len() as f32
        };

        // Identify ungrounded claims
        let ungrounded_claims: Vec<String> = claim_scores
            .iter()
            .filter(|c| c.score < 0.5)
            .map(|c| c.claim.clone())
            .collect();

        // Identify contradictions
        let contradictions: Vec<Contradiction> = claim_scores
            .iter()
            .filter(|c| c.nli_label == Some(NliLabel::Contradiction))
            .map(|c| Contradiction {
                claim: c.claim.clone(),
                evidence: c.best_evidence.clone().unwrap_or_default(),
                confidence: 1.0 - c.score,
            })
            .collect();

        // Build attributions
        let attributions: Vec<Attribution> = claim_scores
            .iter()
            .filter(|c| c.score >= 0.7 && c.best_evidence.is_some())
            .map(|c| Attribution {
                claim: c.claim.clone(),
                source_id: "context".to_string(), // Would need doc IDs for proper attribution
                passage: c.best_evidence.clone().unwrap_or_default(),
                confidence: c.score,
            })
            .collect();

        let passed = score >= self.config.min_score;

        Ok(GroundingResult {
            score,
            passed,
            claim_scores,
            ungrounded_claims,
            contradictions,
            attributions,
            method: GroundingMethod::Lexical, // TODO: Use NLI when available
        })
    }

    /// Check grounding with source document IDs.
    pub fn check_grounding_with_sources(
        &self,
        context: &[(&str, &str)], // (doc_id, content)
        response: &str,
    ) -> Result<GroundingResult, GroundingError> {
        if !self.config.enabled {
            return Ok(GroundingResult {
                score: 1.0,
                passed: true,
                claim_scores: vec![],
                ungrounded_claims: vec![],
                contradictions: vec![],
                attributions: vec![],
                method: GroundingMethod::Disabled,
            });
        }

        // Extract just the content for grounding check
        let content: Vec<&str> = context.iter().map(|(_, c)| *c).collect();
        let mut result = self.check_grounding(&content, response)?;

        // Update attributions with actual source IDs
        for attribution in &mut result.attributions {
            for (doc_id, content) in context {
                if content.contains(&attribution.passage) {
                    attribution.source_id = doc_id.to_string();
                    break;
                }
            }
        }

        Ok(result)
    }

    /// Extract claims (sentences) from a response.
    fn extract_claims(&self, response: &str) -> Vec<String> {
        // Simple sentence-based claim extraction
        // In production, would use more sophisticated NLP
        response
            .split(|c| c == '.' || c == '!' || c == '?')
            .map(|s| s.trim().to_string())
            .filter(|s| s.len() >= self.config.min_claim_length)
            .collect()
    }

    /// Score a single claim against context.
    fn score_claim(&self, claim: &str, context: &[&str]) -> ClaimScore {
        // Lexical overlap scoring (fallback when NLI not available)
        let claim_words: HashSet<&str> = claim
            .split_whitespace()
            .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
            .filter(|w| w.len() > 2)
            .collect();

        let mut best_score = 0.0f32;
        let mut best_evidence = None;

        for passage in context {
            let passage_words: HashSet<&str> = passage
                .split_whitespace()
                .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
                .filter(|w| w.len() > 2)
                .collect();

            if claim_words.is_empty() || passage_words.is_empty() {
                continue;
            }

            // Jaccard similarity
            let intersection = claim_words.intersection(&passage_words).count();
            let union = claim_words.union(&passage_words).count();
            let similarity = if union > 0 {
                intersection as f32 / union as f32
            } else {
                0.0
            };

            if similarity > best_score {
                best_score = similarity;
                best_evidence = Some(passage.to_string());
            }
        }

        // Convert similarity to grounding score
        // Low similarity doesn't necessarily mean hallucination (could be paraphrase)
        let grounding_score = if best_score >= 0.5 {
            0.9 + (best_score - 0.5) * 0.2 // 0.9-1.0
        } else if best_score >= 0.3 {
            0.7 + (best_score - 0.3) * 1.0 // 0.7-0.9
        } else if best_score >= 0.1 {
            0.3 + (best_score - 0.1) * 2.0 // 0.3-0.7
        } else {
            best_score * 3.0 // 0.0-0.3
        };

        // Determine NLI label based on score
        let nli_label = if grounding_score >= 0.7 {
            Some(NliLabel::Entailment)
        } else if grounding_score >= 0.3 {
            Some(NliLabel::Neutral)
        } else {
            // Low score could be contradiction or just unsupported
            None
        };

        ClaimScore {
            claim: claim.to_string(),
            score: grounding_score.min(1.0),
            best_evidence,
            nli_label,
        }
    }
}

/// Errors from grounding detection.
#[derive(Debug, Clone, thiserror::Error)]
pub enum GroundingError {
    #[error("NLI evaluation failed: {0}")]
    NliError(String),

    #[error("Context parsing failed: {0}")]
    ContextError(String),

    #[error("Response too long: {len} chars exceeds limit of {max}")]
    ResponseTooLong { len: usize, max: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grounding_disabled() {
        let checker = GroundingChecker::disabled();
        let result = checker.check_grounding(&["Context"], "Response").unwrap();
        assert!(result.is_grounded());
        assert_eq!(result.score, 1.0);
    }

    #[test]
    fn test_grounding_enabled() {
        let config = GroundingConfig {
            enabled: true,
            min_score: 0.5,
            ..Default::default()
        };
        let checker = GroundingChecker::new(config);

        let context = vec!["The Eiffel Tower is located in Paris, France."];
        let response = "The Eiffel Tower is in Paris.";

        let result = checker.check_grounding(&context, response).unwrap();
        assert!(result.score > 0.5);
    }

    #[test]
    fn test_hallucination_detection() {
        let config = GroundingConfig {
            enabled: true,
            min_score: 0.7,
            ..Default::default()
        };
        let checker = GroundingChecker::new(config);

        let context = vec!["The Eiffel Tower is located in Paris."];
        let response = "The Eiffel Tower was built on the moon in 2050.";

        let result = checker.check_grounding(&context, response).unwrap();
        assert!(result.score < 0.7);
        assert!(!result.ungrounded_claims.is_empty());
    }

    #[test]
    fn test_empty_context() {
        let config = GroundingConfig {
            enabled: true,
            ..Default::default()
        };
        let checker = GroundingChecker::new(config);

        let result = checker.check_grounding(&[], "Some response").unwrap();
        assert_eq!(result.score, 0.0);
        assert!(!result.passed);
    }

    #[test]
    fn test_claim_extraction() {
        let config = GroundingConfig {
            enabled: true,
            min_claim_length: 5,
            ..Default::default()
        };
        let checker = GroundingChecker::new(config);

        let claims = checker.extract_claims("First claim. Second claim! Third claim?");
        assert_eq!(claims.len(), 3);
    }

    #[test]
    fn test_grounding_with_sources() {
        let config = GroundingConfig {
            enabled: true,
            min_score: 0.5,
            ..Default::default()
        };
        let checker = GroundingChecker::new(config);

        let context = vec![
            ("doc1", "Paris is the capital of France."),
            ("doc2", "The Eiffel Tower is in Paris."),
        ];

        let response = "The Eiffel Tower is located in Paris, the capital of France.";
        let result = checker
            .check_grounding_with_sources(&context, response)
            .unwrap();

        assert!(result.passed);
    }

    #[test]
    fn test_enforcement_modes() {
        assert_eq!(GroundingEnforcement::default(), GroundingEnforcement::Warn);
    }
}
