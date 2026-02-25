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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// Valid enforcement modes for RagDefenseConfig.
const VALID_RAG_ENFORCEMENTS: &[&str] = &["warn", "block", "require_approval"];
/// Valid enforcement modes for ContextBudgetConfig.
const VALID_BUDGET_ENFORCEMENTS: &[&str] = &["truncate", "reject", "warn"];
/// Valid enforcement modes for GroundingConfig.
const VALID_GROUNDING_ENFORCEMENTS: &[&str] = &["warn", "block", "annotate"];

/// Maximum cache TTL (7 days).
const MAX_RAG_CACHE_TTL_SECS: u64 = 7 * 24 * 3600;
/// Maximum cache size.
const MAX_RAG_CACHE_SIZE: usize = 1_000_000;
/// Maximum document age (10 years).
const MAX_DOC_AGE_HOURS: u64 = 10 * 365 * 24;
/// Maximum documents per session.
const MAX_DOCS_PER_SESSION: usize = 100_000;
/// Maximum retrieval results.
const MAX_RETRIEVAL_RESULTS: u32 = 10_000;
/// Maximum baseline samples.
const MAX_BASELINE_SAMPLES: u32 = 100_000;
/// Maximum embeddings per agent.
const MAX_EMBEDDINGS_PER_AGENT: usize = 1_000_000;
/// Maximum tokens per retrieval.
const MAX_TOKENS_PER_RETRIEVAL: u32 = 1_000_000;
/// Maximum total context tokens per session.
const MAX_TOTAL_CONTEXT_TOKENS: u32 = 10_000_000;
/// Maximum claim length.
const MAX_CLAIM_LENGTH: usize = 100_000;
/// Maximum claims to check.
const MAX_CLAIMS: usize = 10_000;

impl RagDefenseConfig {
    /// Validate all float fields are finite and in [0.0, 1.0], enforcement strings are known,
    /// and integer fields have sane upper bounds.
    /// SECURITY (FIND-R55-CFG-001, FIND-R55-CFG-005): NaN/Infinity bypass threshold comparisons;
    /// unknown enforcement strings fall through match arms to permissive defaults.
    /// SECURITY (IMP-R106-002): Integer fields need upper bounds to prevent OOM.
    pub fn validate(&self) -> Result<(), String> {
        if !VALID_RAG_ENFORCEMENTS.contains(&self.enforcement.as_str()) {
            return Err(format!(
                "rag_defense.enforcement must be one of {:?}, got {:?}",
                VALID_RAG_ENFORCEMENTS, self.enforcement
            ));
        }

        // Float field validation
        let trust = self.document_verification.require_trust_score;
        if !trust.is_finite() || !(0.0..=1.0).contains(&trust) {
            return Err(format!(
                "rag_defense.document_verification.require_trust_score must be finite and in [0.0, 1.0], got {}",
                trust
            ));
        }
        let sim = self.retrieval_security.similarity_threshold;
        if !sim.is_finite() || !(0.0..=1.0).contains(&sim) {
            return Err(format!(
                "rag_defense.retrieval_security.similarity_threshold must be finite and in [0.0, 1.0], got {}",
                sim
            ));
        }
        let emb = self.embedding_anomaly.threshold;
        if !emb.is_finite() || !(0.0..=1.0).contains(&emb) {
            return Err(format!(
                "rag_defense.embedding_anomaly.threshold must be finite and in [0.0, 1.0], got {}",
                emb
            ));
        }
        if !VALID_BUDGET_ENFORCEMENTS.contains(&self.context_budget.enforcement.as_str()) {
            return Err(format!(
                "rag_defense.context_budget.enforcement must be one of {:?}, got {:?}",
                VALID_BUDGET_ENFORCEMENTS, self.context_budget.enforcement
            ));
        }
        let alert = self.context_budget.alert_threshold;
        if !alert.is_finite() || !(0.0..=1.0).contains(&alert) {
            return Err(format!(
                "rag_defense.context_budget.alert_threshold must be finite and in [0.0, 1.0], got {}",
                alert
            ));
        }
        if !VALID_GROUNDING_ENFORCEMENTS.contains(&self.grounding.enforcement.as_str()) {
            return Err(format!(
                "rag_defense.grounding.enforcement must be one of {:?}, got {:?}",
                VALID_GROUNDING_ENFORCEMENTS, self.grounding.enforcement
            ));
        }
        let min_score = self.grounding.min_score;
        if !min_score.is_finite() || !(0.0..=1.0).contains(&min_score) {
            return Err(format!(
                "rag_defense.grounding.min_score must be finite and in [0.0, 1.0], got {}",
                min_score
            ));
        }
        let lex = self.grounding.lexical_overlap_threshold;
        if !lex.is_finite() || !(0.0..=1.0).contains(&lex) {
            return Err(format!(
                "rag_defense.grounding.lexical_overlap_threshold must be finite and in [0.0, 1.0], got {}",
                lex
            ));
        }

        // SECURITY (FIND-R102-001): Reject zero cache TTL — a zero value disables
        // caching entirely, amplifying upstream load and enabling DoS.
        if self.cache_ttl_secs == 0 {
            return Err("rag_defense.cache_ttl_secs must be > 0".to_string());
        }
        // SECURITY (IMP-R106-002): Integer field upper bounds to prevent OOM from
        // attacker-crafted configs.
        if self.cache_ttl_secs > MAX_RAG_CACHE_TTL_SECS {
            return Err(format!(
                "rag_defense.cache_ttl_secs {} exceeds maximum {}",
                self.cache_ttl_secs, MAX_RAG_CACHE_TTL_SECS
            ));
        }
        if self.cache_max_size > MAX_RAG_CACHE_SIZE {
            return Err(format!(
                "rag_defense.cache_max_size {} exceeds maximum {}",
                self.cache_max_size, MAX_RAG_CACHE_SIZE
            ));
        }
        if self.document_verification.max_doc_age_hours > MAX_DOC_AGE_HOURS {
            return Err(format!(
                "rag_defense.document_verification.max_doc_age_hours {} exceeds maximum {}",
                self.document_verification.max_doc_age_hours, MAX_DOC_AGE_HOURS
            ));
        }
        if self.document_verification.max_docs_per_session > MAX_DOCS_PER_SESSION {
            return Err(format!(
                "rag_defense.document_verification.max_docs_per_session {} exceeds maximum {}",
                self.document_verification.max_docs_per_session, MAX_DOCS_PER_SESSION
            ));
        }
        if self.retrieval_security.max_retrieval_results == 0 {
            return Err(
                "rag_defense.retrieval_security.max_retrieval_results must be > 0".to_string(),
            );
        }
        if self.retrieval_security.max_retrieval_results > MAX_RETRIEVAL_RESULTS {
            return Err(format!(
                "rag_defense.retrieval_security.max_retrieval_results {} exceeds maximum {}",
                self.retrieval_security.max_retrieval_results, MAX_RETRIEVAL_RESULTS
            ));
        }
        if self.embedding_anomaly.min_baseline_samples > MAX_BASELINE_SAMPLES {
            return Err(format!(
                "rag_defense.embedding_anomaly.min_baseline_samples {} exceeds maximum {}",
                self.embedding_anomaly.min_baseline_samples, MAX_BASELINE_SAMPLES
            ));
        }
        if self.embedding_anomaly.max_embeddings_per_agent > MAX_EMBEDDINGS_PER_AGENT {
            return Err(format!(
                "rag_defense.embedding_anomaly.max_embeddings_per_agent {} exceeds maximum {}",
                self.embedding_anomaly.max_embeddings_per_agent, MAX_EMBEDDINGS_PER_AGENT
            ));
        }
        if self.context_budget.max_tokens_per_retrieval == 0 {
            return Err(
                "rag_defense.context_budget.max_tokens_per_retrieval must be > 0".to_string(),
            );
        }
        if self.context_budget.max_tokens_per_retrieval > MAX_TOKENS_PER_RETRIEVAL {
            return Err(format!(
                "rag_defense.context_budget.max_tokens_per_retrieval {} exceeds maximum {}",
                self.context_budget.max_tokens_per_retrieval, MAX_TOKENS_PER_RETRIEVAL
            ));
        }
        if self.context_budget.max_total_context_tokens == 0 {
            return Err(
                "rag_defense.context_budget.max_total_context_tokens must be > 0".to_string(),
            );
        }
        if self.context_budget.max_total_context_tokens > MAX_TOTAL_CONTEXT_TOKENS {
            return Err(format!(
                "rag_defense.context_budget.max_total_context_tokens {} exceeds maximum {}",
                self.context_budget.max_total_context_tokens, MAX_TOTAL_CONTEXT_TOKENS
            ));
        }
        if self.grounding.min_claim_length > MAX_CLAIM_LENGTH {
            return Err(format!(
                "rag_defense.grounding.min_claim_length {} exceeds maximum {}",
                self.grounding.min_claim_length, MAX_CLAIM_LENGTH
            ));
        }
        if self.grounding.max_claims == 0 {
            return Err("rag_defense.grounding.max_claims must be > 0".to_string());
        }
        if self.grounding.max_claims > MAX_CLAIMS {
            return Err(format!(
                "rag_defense.grounding.max_claims {} exceeds maximum {}",
                self.grounding.max_claims, MAX_CLAIMS
            ));
        }

        Ok(())
    }
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
