use serde::{Deserialize, Serialize};

use crate::default_true;

// ═══════════════════════════════════════════════════════════════════════════════
// RAG POISONING DEFENSE CONFIGURATION (Phase 13)
// ═══════════════════════════════════════════════════════════════════════════════

/// RAG (Retrieval-Augmented Generation) poisoning defense configuration.
///
/// Protects against:
/// - **Document injection**: Malicious content in knowledge base
/// - **Embedding manipulation**: Adversarial perturbations
/// - **Context window flooding**: Irrelevant data diluting real information
///
/// # TOML Example
///
/// ```toml
/// [rag_defense]
/// enabled = true
/// enforcement = "block"
/// cache_ttl_secs = 300
/// cache_max_size = 10000
///
/// [rag_defense.document_verification]
/// enabled = true
/// require_trust_score = 0.5
/// max_doc_age_hours = 2160
/// require_content_hash = true
/// block_unverified = false
/// max_docs_per_session = 100
///
/// [rag_defense.retrieval_security]
/// enabled = true
/// max_retrieval_results = 20
/// enforce_diversity = true
/// similarity_threshold = 0.95
/// run_dlp_on_results = true
/// block_sensitive_results = false
///
/// [rag_defense.embedding_anomaly]
/// enabled = true
/// threshold = 0.85
/// min_baseline_samples = 10
/// max_embeddings_per_agent = 1000
/// block_on_anomaly = false
///
/// [rag_defense.context_budget]
/// enabled = true
/// max_tokens_per_retrieval = 4096
/// max_total_context_tokens = 16384
/// enforcement = "truncate"
/// alert_threshold = 0.8
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RagDefenseConfig {
    /// Enable RAG defense. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Enforcement mode: "warn", "block", "require_approval". Default: "warn".
    #[serde(default = "default_rag_enforcement")]
    pub enforcement: String,

    /// Document verification configuration.
    #[serde(default)]
    pub document_verification: DocumentVerificationConfig,

    /// Retrieval security configuration.
    #[serde(default)]
    pub retrieval_security: RetrievalSecurityConfig,

    /// Embedding anomaly detection configuration.
    #[serde(default)]
    pub embedding_anomaly: EmbeddingAnomalyConfig,

    /// Context budget enforcement configuration.
    #[serde(default)]
    pub context_budget: ContextBudgetConfig,

    /// Grounding/hallucination detection configuration.
    #[serde(default)]
    pub grounding: GroundingConfig,

    /// Cache TTL in seconds. Default: 300 (5 minutes).
    #[serde(default = "default_rag_cache_ttl")]
    pub cache_ttl_secs: u64,

    /// Maximum cache entries. Default: 10000.
    #[serde(default = "default_rag_cache_size")]
    pub cache_max_size: usize,
}

fn default_rag_enforcement() -> String {
    "warn".to_string()
}

fn default_rag_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_rag_cache_size() -> usize {
    10000
}

impl Default for RagDefenseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            enforcement: default_rag_enforcement(),
            document_verification: DocumentVerificationConfig::default(),
            retrieval_security: RetrievalSecurityConfig::default(),
            embedding_anomaly: EmbeddingAnomalyConfig::default(),
            context_budget: ContextBudgetConfig::default(),
            grounding: GroundingConfig::default(),
            cache_ttl_secs: default_rag_cache_ttl(),
            cache_max_size: default_rag_cache_size(),
        }
    }
}

/// Document verification configuration for RAG defense.
///
/// Controls trust scoring and verification of documents in the knowledge base.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DocumentVerificationConfig {
    /// Enable document verification. Default: true (when parent enabled).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Minimum trust score required (0.0-1.0). Default: 0.5.
    #[serde(default = "default_doc_trust_score")]
    pub require_trust_score: f64,

    /// Maximum document age in hours. Default: 2160 (90 days).
    #[serde(default = "default_doc_max_age")]
    pub max_doc_age_hours: u64,

    /// Require content hash verification. Default: true.
    #[serde(default = "default_true")]
    pub require_content_hash: bool,

    /// Block unverified documents. Default: false.
    #[serde(default)]
    pub block_unverified: bool,

    /// Maximum documents per session. Default: 100.
    #[serde(default = "default_doc_max_per_session")]
    pub max_docs_per_session: usize,
}

fn default_doc_trust_score() -> f64 {
    0.5
}

fn default_doc_max_age() -> u64 {
    2160 // 90 days
}

fn default_doc_max_per_session() -> usize {
    100
}

impl Default for DocumentVerificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_trust_score: default_doc_trust_score(),
            max_doc_age_hours: default_doc_max_age(),
            require_content_hash: true,
            block_unverified: false,
            max_docs_per_session: default_doc_max_per_session(),
        }
    }
}

/// Retrieval security configuration for RAG defense.
///
/// Controls inspection and filtering of retrieval results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RetrievalSecurityConfig {
    /// Enable retrieval security. Default: true (when parent enabled).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum retrieval results allowed. Default: 20.
    #[serde(default = "default_retrieval_max_results")]
    pub max_retrieval_results: u32,

    /// Enforce result diversity. Default: true.
    #[serde(default = "default_true")]
    pub enforce_diversity: bool,

    /// Similarity threshold for diversity (0.0-1.0). Default: 0.95.
    /// Results with similarity above this are flagged as duplicates.
    #[serde(default = "default_retrieval_similarity")]
    pub similarity_threshold: f64,

    /// Run DLP scanning on retrieval results. Default: true.
    #[serde(default = "default_true")]
    pub run_dlp_on_results: bool,

    /// Block results containing sensitive data. Default: false.
    #[serde(default)]
    pub block_sensitive_results: bool,
}

fn default_retrieval_max_results() -> u32 {
    20
}

fn default_retrieval_similarity() -> f64 {
    0.95
}

impl Default for RetrievalSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_retrieval_results: default_retrieval_max_results(),
            enforce_diversity: true,
            similarity_threshold: default_retrieval_similarity(),
            run_dlp_on_results: true,
            block_sensitive_results: false,
        }
    }
}

/// Embedding anomaly detection configuration for RAG defense.
///
/// Detects adversarial embedding perturbations by comparing against baseline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EmbeddingAnomalyConfig {
    /// Enable embedding anomaly detection. Default: true (when parent enabled).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Similarity threshold for anomaly detection (0.0-1.0). Default: 0.85.
    /// Embeddings with similarity below this to baseline are flagged.
    #[serde(default = "default_embedding_threshold")]
    pub threshold: f64,

    /// Minimum baseline samples before detection activates. Default: 10.
    #[serde(default = "default_embedding_min_baseline")]
    pub min_baseline_samples: u32,

    /// Maximum embeddings to track per agent. Default: 1000.
    #[serde(default = "default_embedding_max_per_agent")]
    pub max_embeddings_per_agent: usize,

    /// Block on anomaly detection. Default: false.
    #[serde(default)]
    pub block_on_anomaly: bool,
}

fn default_embedding_threshold() -> f64 {
    0.85
}

fn default_embedding_min_baseline() -> u32 {
    10
}

fn default_embedding_max_per_agent() -> usize {
    1000
}

impl Default for EmbeddingAnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: default_embedding_threshold(),
            min_baseline_samples: default_embedding_min_baseline(),
            max_embeddings_per_agent: default_embedding_max_per_agent(),
            block_on_anomaly: false,
        }
    }
}

/// Context budget enforcement configuration for RAG defense.
///
/// Prevents context window flooding by enforcing token budgets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextBudgetConfig {
    /// Enable context budget enforcement. Default: true (when parent enabled).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum tokens per single retrieval. Default: 4096.
    #[serde(default = "default_budget_per_retrieval")]
    pub max_tokens_per_retrieval: u32,

    /// Maximum total context tokens per session. Default: 16384.
    #[serde(default = "default_budget_total")]
    pub max_total_context_tokens: u32,

    /// Enforcement mode: "truncate", "reject", "warn". Default: "truncate".
    #[serde(default = "default_budget_enforcement")]
    pub enforcement: String,

    /// Alert threshold as fraction of budget (0.0-1.0). Default: 0.8.
    #[serde(default = "default_budget_alert")]
    pub alert_threshold: f64,
}

fn default_budget_per_retrieval() -> u32 {
    4096
}

fn default_budget_total() -> u32 {
    16384
}

fn default_budget_enforcement() -> String {
    "truncate".to_string()
}

fn default_budget_alert() -> f64 {
    0.8
}

impl Default for ContextBudgetConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_tokens_per_retrieval: default_budget_per_retrieval(),
            max_total_context_tokens: default_budget_total(),
            enforcement: default_budget_enforcement(),
            alert_threshold: default_budget_alert(),
        }
    }
}

// ═══════════════════════════════════════════════════
// GROUNDING/HALLUCINATION DETECTION CONFIGURATION
// ═══════════════════════════════════════════════════

/// Grounding/hallucination detection configuration.
///
/// Controls validation of LLM responses against retrieved context to detect
/// hallucinations (claims not supported by the provided context).
///
/// # TOML Example
///
/// ```toml
/// [rag_defense.grounding]
/// enabled = true
/// min_score = 0.7
/// enforcement = "warn"
/// use_llm_nli = false
/// min_claim_length = 10
/// max_claims = 20
/// lexical_overlap_threshold = 0.3
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroundingConfig {
    /// Enable grounding validation. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Minimum groundedness score (0.0-1.0). Default: 0.7.
    #[serde(default = "default_grounding_min_score")]
    pub min_score: f32,

    /// Enforcement mode: "warn", "block", "annotate". Default: "warn".
    #[serde(default = "default_grounding_enforcement")]
    pub enforcement: String,

    /// Use LLM-based NLI for grounding check. Default: false.
    /// Requires semantic-guardrails feature and configured LLM backend.
    #[serde(default)]
    pub use_llm_nli: bool,

    /// Minimum claim length to check (shorter claims are ignored). Default: 10.
    #[serde(default = "default_grounding_min_claim")]
    pub min_claim_length: usize,

    /// Maximum claims to check per response. Default: 20.
    #[serde(default = "default_grounding_max_claims")]
    pub max_claims: usize,

    /// Lexical overlap threshold for fallback mode. Default: 0.3.
    #[serde(default = "default_grounding_lexical_threshold")]
    pub lexical_overlap_threshold: f32,
}

fn default_grounding_min_score() -> f32 {
    0.7
}

fn default_grounding_enforcement() -> String {
    "warn".to_string()
}

fn default_grounding_min_claim() -> usize {
    10
}

fn default_grounding_max_claims() -> usize {
    20
}

fn default_grounding_lexical_threshold() -> f32 {
    0.3
}

impl Default for GroundingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_score: default_grounding_min_score(),
            enforcement: default_grounding_enforcement(),
            use_llm_nli: false,
            min_claim_length: default_grounding_min_claim(),
            max_claims: default_grounding_max_claims(),
            lexical_overlap_threshold: default_grounding_lexical_threshold(),
        }
    }
}
