//! Embedding anomaly detection for RAG defense.
//!
//! Detects adversarial embedding perturbations by comparing new embeddings
//! against a learned baseline per agent. Embeddings that deviate significantly
//! from the baseline are flagged as potentially malicious.

use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use vellaveto_config::EmbeddingAnomalyConfig;

use super::error::RagDefenseError;

/// An embedding vector for anomaly detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingVector {
    /// The embedding values.
    pub values: Vec<f32>,
    /// Document ID this embedding is for.
    pub doc_id: String,
    /// When this embedding was created.
    pub timestamp: DateTime<Utc>,
}

impl EmbeddingVector {
    /// Creates a new embedding vector.
    pub fn new(doc_id: impl Into<String>, values: Vec<f32>) -> Self {
        Self {
            values,
            doc_id: doc_id.into(),
            timestamp: Utc::now(),
        }
    }

    /// Returns the dimensionality of the embedding.
    pub fn dimension(&self) -> usize {
        self.values.len()
    }
}

/// Baseline statistics for embedding anomaly detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingBaseline {
    /// Centroid (mean) of baseline embeddings.
    pub centroid: Vec<f32>,
    /// Number of samples in the baseline.
    pub sample_count: u32,
    /// Standard deviation of distances from centroid.
    pub std_dev: f64,
    /// When the baseline was last updated.
    pub last_updated: DateTime<Utc>,
}

impl EmbeddingBaseline {
    /// Creates a new baseline from a single embedding.
    fn from_embedding(embedding: &EmbeddingVector) -> Self {
        Self {
            centroid: embedding.values.clone(),
            sample_count: 1,
            std_dev: 0.0,
            last_updated: Utc::now(),
        }
    }

    /// Updates the baseline with a new embedding using online mean algorithm.
    fn update(&mut self, embedding: &EmbeddingVector) {
        self.sample_count += 1;
        let n = self.sample_count as f32;

        // Update centroid using Welford's online algorithm
        for (i, value) in embedding.values.iter().enumerate() {
            if i < self.centroid.len() {
                let delta = value - self.centroid[i];
                self.centroid[i] += delta / n;
            }
        }

        self.last_updated = Utc::now();
    }
}

/// Result of anomaly detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetection {
    /// Whether the embedding is anomalous.
    pub is_anomalous: bool,
    /// Similarity to the baseline centroid (0.0-1.0).
    pub similarity_to_baseline: f64,
    /// Threshold used for detection.
    pub threshold: f64,
    /// Explanation of the detection result.
    pub explanation: Option<String>,
}

impl AnomalyDetection {
    /// Creates a detection result indicating normal behavior.
    pub fn normal(similarity: f64, threshold: f64) -> Self {
        Self {
            is_anomalous: false,
            similarity_to_baseline: similarity,
            threshold,
            explanation: None,
        }
    }

    /// Creates a detection result indicating anomalous behavior.
    pub fn anomalous(similarity: f64, threshold: f64, explanation: impl Into<String>) -> Self {
        Self {
            is_anomalous: true,
            similarity_to_baseline: similarity,
            threshold,
            explanation: Some(explanation.into()),
        }
    }

    /// Creates a detection result when baseline is insufficient.
    pub fn insufficient_baseline(samples: u32, required: u32) -> Self {
        Self {
            is_anomalous: false,
            similarity_to_baseline: 1.0,
            threshold: 0.0,
            explanation: Some(format!(
                "Insufficient baseline: {} samples < {} required",
                samples, required
            )),
        }
    }
}

/// SECURITY (FIND-R69-005): Maximum agent baselines to prevent OOM.
const MAX_AGENT_BASELINES: usize = 50_000;

/// Detects anomalous embeddings by comparing to learned baselines.
pub struct EmbeddingAnomalyDetector {
    config: EmbeddingAnomalyConfig,
    /// Baselines per agent ID.
    baselines: RwLock<HashMap<String, EmbeddingBaseline>>,
    /// Recent embeddings per agent for baseline learning.
    recent_embeddings: RwLock<HashMap<String, VecDeque<EmbeddingVector>>>,
}

impl EmbeddingAnomalyDetector {
    /// Creates a new embedding anomaly detector.
    pub fn new(config: EmbeddingAnomalyConfig) -> Self {
        Self {
            config,
            baselines: RwLock::new(HashMap::new()),
            recent_embeddings: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a disabled detector that passes all embeddings.
    pub fn disabled() -> Self {
        Self::new(EmbeddingAnomalyConfig {
            enabled: false,
            ..Default::default()
        })
    }

    /// Returns whether detection is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Adds an embedding to the baseline for an agent.
    pub fn add_to_baseline(
        &self,
        agent_id: &str,
        embedding: &EmbeddingVector,
    ) -> Result<(), RagDefenseError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check agent embedding limit
        let count = self.embedding_count_for_agent(agent_id);
        if count >= self.config.max_embeddings_per_agent {
            return Err(RagDefenseError::AgentEmbeddingLimit {
                count,
                max: self.config.max_embeddings_per_agent,
            });
        }

        // Add to recent embeddings
        if let Ok(mut recent) = self.recent_embeddings.write() {
            // SECURITY (FIND-R69-005): Cap number of tracked agents.
            if !recent.contains_key(agent_id) && recent.len() >= MAX_AGENT_BASELINES {
                tracing::warn!(max = MAX_AGENT_BASELINES, "Embedding agent baselines at capacity");
                return Err(RagDefenseError::Internal(
                    "Embedding agent tracker at capacity".to_string(),
                ));
            }
            let queue = recent
                .entry(agent_id.to_string())
                .or_insert_with(VecDeque::new);

            // Keep limited history
            if queue.len() >= self.config.max_embeddings_per_agent {
                queue.pop_front();
            }
            queue.push_back(embedding.clone());
        }

        // Update baseline
        self.update_centroid(agent_id, embedding);

        Ok(())
    }

    /// Detects if an embedding is anomalous for an agent.
    pub fn detect_anomaly(
        &self,
        agent_id: &str,
        embedding: &EmbeddingVector,
    ) -> Result<AnomalyDetection, RagDefenseError> {
        if !self.config.enabled {
            return Ok(AnomalyDetection::normal(1.0, self.config.threshold));
        }

        let baselines = self.baselines.read().map_err(|_| {
            RagDefenseError::Internal("Failed to acquire baseline read lock".to_string())
        })?;

        let baseline = match baselines.get(agent_id) {
            Some(b) => b,
            None => {
                // No baseline yet, can't detect anomalies
                return Ok(AnomalyDetection::insufficient_baseline(
                    0,
                    self.config.min_baseline_samples,
                ));
            }
        };

        // Check if baseline has enough samples
        if baseline.sample_count < self.config.min_baseline_samples {
            return Ok(AnomalyDetection::insufficient_baseline(
                baseline.sample_count,
                self.config.min_baseline_samples,
            ));
        }

        // Check dimension match
        if embedding.dimension() != baseline.centroid.len() {
            return Err(RagDefenseError::InvalidEmbeddingDimension {
                expected: baseline.centroid.len(),
                actual: embedding.dimension(),
            });
        }

        // Compute cosine similarity to centroid
        let similarity = cosine_similarity(&embedding.values, &baseline.centroid);

        if similarity < self.config.threshold {
            if self.config.block_on_anomaly {
                return Err(RagDefenseError::EmbeddingAnomaly {
                    similarity,
                    threshold: self.config.threshold,
                });
            }

            Ok(AnomalyDetection::anomalous(
                similarity,
                self.config.threshold,
                format!(
                    "Embedding deviates from baseline: similarity {:.3} < threshold {:.3}",
                    similarity, self.config.threshold
                ),
            ))
        } else {
            Ok(AnomalyDetection::normal(similarity, self.config.threshold))
        }
    }

    /// Updates the centroid for an agent with a new embedding.
    fn update_centroid(&self, agent_id: &str, embedding: &EmbeddingVector) {
        if let Ok(mut baselines) = self.baselines.write() {
            baselines
                .entry(agent_id.to_string())
                .and_modify(|b| b.update(embedding))
                .or_insert_with(|| EmbeddingBaseline::from_embedding(embedding));
        }
    }

    /// Returns the number of embeddings tracked for an agent.
    fn embedding_count_for_agent(&self, agent_id: &str) -> usize {
        self.recent_embeddings
            .read()
            .ok()
            .and_then(|r| r.get(agent_id).map(|q| q.len()))
            .unwrap_or(0)
    }

    /// Returns the baseline for an agent.
    pub fn get_baseline(&self, agent_id: &str) -> Option<EmbeddingBaseline> {
        self.baselines.read().ok()?.get(agent_id).cloned()
    }

    /// Clears the baseline for an agent.
    pub fn clear_baseline(&self, agent_id: &str) {
        if let Ok(mut baselines) = self.baselines.write() {
            baselines.remove(agent_id);
        }
        if let Ok(mut recent) = self.recent_embeddings.write() {
            recent.remove(agent_id);
        }
    }

    /// Returns the number of agents with baselines.
    pub fn baseline_count(&self) -> usize {
        self.baselines.read().map(|b| b.len()).unwrap_or(0)
    }
}

/// Computes cosine similarity between two vectors.
fn cosine_similarity(a: &[f32], b: &[f32]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }

    let mut dot_product: f64 = 0.0;
    let mut norm_a: f64 = 0.0;
    let mut norm_b: f64 = 0.0;

    for i in 0..a.len() {
        let ai = a[i] as f64;
        let bi = b[i] as f64;
        dot_product += ai * bi;
        norm_a += ai * ai;
        norm_b += bi * bi;
    }

    let denominator = (norm_a.sqrt()) * (norm_b.sqrt());
    if denominator == 0.0 {
        return 0.0;
    }

    (dot_product / denominator).clamp(-1.0, 1.0)
}

/// Computes Euclidean distance between two vectors.
#[allow(dead_code)] // Alternative distance metric available for future similarity strategies
fn euclidean_distance(a: &[f32], b: &[f32]) -> f64 {
    if a.len() != b.len() {
        return f64::MAX;
    }

    let sum: f64 = a
        .iter()
        .zip(b.iter())
        .map(|(ai, bi)| {
            let diff = (*ai as f64) - (*bi as f64);
            diff * diff
        })
        .sum();

    sum.sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_embedding(doc_id: &str, values: &[f32]) -> EmbeddingVector {
        EmbeddingVector::new(doc_id, values.to_vec())
    }

    #[test]
    fn test_embedding_vector_creation() {
        let emb = EmbeddingVector::new("doc1", vec![0.1, 0.2, 0.3]);
        assert_eq!(emb.doc_id, "doc1");
        assert_eq!(emb.dimension(), 3);
    }

    #[test]
    fn test_cosine_similarity_identical() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        let sim = cosine_similarity(&a, &b);
        assert!((sim - 1.0).abs() < 0.0001);
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0];
        let sim = cosine_similarity(&a, &b);
        assert!(sim.abs() < 0.0001);
    }

    #[test]
    fn test_cosine_similarity_opposite() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![-1.0, 0.0, 0.0];
        let sim = cosine_similarity(&a, &b);
        assert!((sim + 1.0).abs() < 0.0001);
    }

    #[test]
    fn test_detector_disabled() {
        let detector = EmbeddingAnomalyDetector::disabled();
        let emb = make_embedding("doc1", &[0.1, 0.2, 0.3]);

        let result = detector.detect_anomaly("agent1", &emb);
        assert!(result.is_ok());
        assert!(!result.unwrap().is_anomalous);
    }

    #[test]
    fn test_detector_insufficient_baseline() {
        let config = EmbeddingAnomalyConfig {
            enabled: true,
            min_baseline_samples: 5,
            ..Default::default()
        };
        let detector = EmbeddingAnomalyDetector::new(config);

        // Add only one embedding to baseline
        let emb1 = make_embedding("doc1", &[0.1, 0.2, 0.3]);
        detector.add_to_baseline("agent1", &emb1).unwrap();

        // Detection should report insufficient baseline
        let emb2 = make_embedding("doc2", &[0.1, 0.2, 0.3]);
        let result = detector.detect_anomaly("agent1", &emb2).unwrap();

        assert!(!result.is_anomalous);
        assert!(result.explanation.is_some());
        assert!(result
            .explanation
            .unwrap()
            .contains("Insufficient baseline"));
    }

    #[test]
    fn test_detector_normal_embedding() {
        let config = EmbeddingAnomalyConfig {
            enabled: true,
            min_baseline_samples: 2,
            threshold: 0.9,
            ..Default::default()
        };
        let detector = EmbeddingAnomalyDetector::new(config);

        // Build baseline with similar embeddings
        for i in 0..5 {
            let emb = make_embedding(&format!("doc{}", i), &[0.5, 0.5, 0.5]);
            detector.add_to_baseline("agent1", &emb).unwrap();
        }

        // Test with similar embedding - should be normal
        let test_emb = make_embedding("test", &[0.5, 0.5, 0.5]);
        let result = detector.detect_anomaly("agent1", &test_emb).unwrap();

        assert!(!result.is_anomalous);
        assert!(result.similarity_to_baseline > 0.99);
    }

    #[test]
    fn test_detector_anomalous_embedding() {
        let config = EmbeddingAnomalyConfig {
            enabled: true,
            min_baseline_samples: 2,
            threshold: 0.9,
            block_on_anomaly: false,
            ..Default::default()
        };
        let detector = EmbeddingAnomalyDetector::new(config);

        // Build baseline with similar embeddings
        for i in 0..5 {
            let emb = make_embedding(&format!("doc{}", i), &[1.0, 0.0, 0.0]);
            detector.add_to_baseline("agent1", &emb).unwrap();
        }

        // Test with orthogonal embedding - should be anomalous
        let test_emb = make_embedding("test", &[0.0, 1.0, 0.0]);
        let result = detector.detect_anomaly("agent1", &test_emb).unwrap();

        assert!(result.is_anomalous);
        assert!(result.similarity_to_baseline < 0.5);
    }

    #[test]
    fn test_detector_block_on_anomaly() {
        let config = EmbeddingAnomalyConfig {
            enabled: true,
            min_baseline_samples: 2,
            threshold: 0.9,
            block_on_anomaly: true,
            ..Default::default()
        };
        let detector = EmbeddingAnomalyDetector::new(config);

        // Build baseline
        for i in 0..5 {
            let emb = make_embedding(&format!("doc{}", i), &[1.0, 0.0, 0.0]);
            detector.add_to_baseline("agent1", &emb).unwrap();
        }

        // Test with anomalous embedding - should return error
        let test_emb = make_embedding("test", &[0.0, 1.0, 0.0]);
        let result = detector.detect_anomaly("agent1", &test_emb);

        assert!(matches!(
            result,
            Err(RagDefenseError::EmbeddingAnomaly { .. })
        ));
    }

    #[test]
    fn test_detector_dimension_mismatch() {
        let config = EmbeddingAnomalyConfig {
            enabled: true,
            min_baseline_samples: 2,
            ..Default::default()
        };
        let detector = EmbeddingAnomalyDetector::new(config);

        // Build baseline with 3D embeddings
        for i in 0..3 {
            let emb = make_embedding(&format!("doc{}", i), &[1.0, 0.0, 0.0]);
            detector.add_to_baseline("agent1", &emb).unwrap();
        }

        // Test with 4D embedding - should error
        let test_emb = make_embedding("test", &[1.0, 0.0, 0.0, 0.0]);
        let result = detector.detect_anomaly("agent1", &test_emb);

        assert!(matches!(
            result,
            Err(RagDefenseError::InvalidEmbeddingDimension { .. })
        ));
    }

    #[test]
    fn test_clear_baseline() {
        let config = EmbeddingAnomalyConfig::default();
        let detector = EmbeddingAnomalyDetector::new(config);

        let emb = make_embedding("doc1", &[0.1, 0.2, 0.3]);
        detector.add_to_baseline("agent1", &emb).unwrap();

        assert!(detector.get_baseline("agent1").is_some());

        detector.clear_baseline("agent1");

        assert!(detector.get_baseline("agent1").is_none());
    }

    #[test]
    fn test_agent_embedding_limit() {
        let config = EmbeddingAnomalyConfig {
            enabled: true,
            max_embeddings_per_agent: 3,
            ..Default::default()
        };
        let detector = EmbeddingAnomalyDetector::new(config);

        // Add up to limit
        for i in 0..3 {
            let emb = make_embedding(&format!("doc{}", i), &[0.1, 0.2, 0.3]);
            assert!(detector.add_to_baseline("agent1", &emb).is_ok());
        }

        // Exceeding limit should error
        let emb = make_embedding("doc4", &[0.1, 0.2, 0.3]);
        let result = detector.add_to_baseline("agent1", &emb);
        assert!(matches!(
            result,
            Err(RagDefenseError::AgentEmbeddingLimit { .. })
        ));
    }
}
