use serde::{Deserialize, Serialize};

use crate::default_true;

// ═══════════════════════════════════════════════════════════════════════════════
// SEMANTIC GUARDRAILS CONFIGURATION (Phase 12)
// ═══════════════════════════════════════════════════════════════════════════════

/// Semantic guardrails configuration for LLM-based policy evaluation.
///
/// Enables intent classification, natural language policies, and jailbreak detection
/// beyond pattern matching.
///
/// # TOML Example
///
/// ```toml
/// [semantic_guardrails]
/// enabled = true
/// model = "openai:gpt-4o-mini"
/// cache_ttl_secs = 300
/// cache_max_size = 10000
/// max_latency_ms = 500
/// fallback_on_timeout = "deny"
/// min_confidence = 0.7
///
/// [semantic_guardrails.openai]
/// model = "gpt-4o-mini"
/// api_key_env = "OPENAI_API_KEY"
/// timeout_ms = 3000
/// max_tokens = 256
///
/// [semantic_guardrails.anthropic]
/// model = "claude-3-haiku-20240307"
/// api_key_env = "ANTHROPIC_API_KEY"
/// timeout_ms = 3000
/// max_tokens = 256
///
/// [semantic_guardrails.intent_classification]
/// enabled = true
/// confidence_threshold = 0.6
/// track_intent_chains = true
///
/// [semantic_guardrails.jailbreak_detection]
/// enabled = true
/// confidence_threshold = 0.7
/// block_on_detection = true
///
/// [[semantic_guardrails.nl_policies]]
/// id = "no-file-delete"
/// name = "Prevent file deletion"
/// statement = "Never allow file deletion outside of /tmp directory"
/// tool_patterns = ["filesystem:*", "shell:*"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SemanticGuardrailsConfig {
    /// Enable semantic guardrails. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Model specification (e.g., "openai:gpt-4o-mini", "anthropic:claude-3-haiku").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// Cache TTL in seconds. Default: 300 (5 minutes).
    #[serde(default = "default_semantic_cache_ttl")]
    pub cache_ttl_secs: u64,

    /// Maximum cache entries. Default: 10000.
    #[serde(default = "default_semantic_cache_size")]
    pub cache_max_size: usize,

    /// Maximum latency before fallback. Default: 500ms.
    #[serde(default = "default_semantic_max_latency")]
    pub max_latency_ms: u64,

    /// Fallback behavior on timeout: "deny", "allow", "pattern_match". Default: "deny".
    #[serde(default = "default_semantic_fallback")]
    pub fallback_on_timeout: String,

    /// Minimum confidence for allow decisions. Default: 0.7.
    #[serde(default = "default_semantic_confidence")]
    pub min_confidence: f64,

    /// OpenAI backend configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openai: Option<OpenAiBackendConfig>,

    /// Anthropic backend configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anthropic: Option<AnthropicBackendConfig>,

    /// Intent classification configuration.
    #[serde(default)]
    pub intent_classification: IntentClassificationConfig,

    /// Jailbreak detection configuration.
    #[serde(default)]
    pub jailbreak_detection: JailbreakDetectionConfig,

    /// Natural language policies.
    #[serde(default)]
    pub nl_policies: Vec<NlPolicyConfig>,
}

/// Maximum number of natural language policies.
const MAX_NL_POLICIES: usize = 100;

/// Maximum length for fallback_on_timeout string.
const MAX_FALLBACK_STRING_LEN: usize = 64;

/// Maximum model string length.
const MAX_MODEL_STRING_LEN: usize = 256;

/// Maximum cache TTL (24 hours).
const MAX_CACHE_TTL_SECS: u64 = 86_400;

/// Maximum cache size entries.
const MAX_CACHE_MAX_SIZE: usize = 1_000_000;

/// Maximum latency threshold (30 seconds).
const MAX_LATENCY_MS: u64 = 30_000;

/// Valid fallback_on_timeout values.
const VALID_FALLBACK_VALUES: &[&str] = &["deny", "allow", "pattern_match"];

/// Maximum backend model name length.
const MAX_BACKEND_MODEL_LEN: usize = 256;

/// Maximum backend api_key_env length.
const MAX_BACKEND_API_KEY_ENV_LEN: usize = 256;

/// Maximum backend endpoint URL length.
const MAX_BACKEND_ENDPOINT_LEN: usize = 2048;

/// Maximum backend timeout (60 seconds).
const MAX_BACKEND_TIMEOUT_MS: u64 = 60_000;

/// Maximum backend max_tokens.
const MAX_BACKEND_MAX_TOKENS: u32 = 16_384;

impl SemanticGuardrailsConfig {
    /// Validate all float fields and collection bounds.
    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (FIND-R100-001): Validate model string bounds + control chars.
        if let Some(ref model) = self.model {
            if model.len() > MAX_MODEL_STRING_LEN {
                return Err(format!(
                    "semantic_guardrails.model length {} exceeds maximum {}",
                    model.len(),
                    MAX_MODEL_STRING_LEN
                ));
            }
            if vellaveto_types::has_dangerous_chars(model) {
                return Err("semantic_guardrails.model contains control or format characters".to_string());
            }
        }

        // SECURITY (FIND-R100-002): Validate cache_ttl_secs bounds.
        if self.cache_ttl_secs == 0 {
            return Err("semantic_guardrails.cache_ttl_secs must be > 0".to_string());
        }
        if self.cache_ttl_secs > MAX_CACHE_TTL_SECS {
            return Err(format!(
                "semantic_guardrails.cache_ttl_secs {} exceeds maximum {} (24 hours)",
                self.cache_ttl_secs, MAX_CACHE_TTL_SECS
            ));
        }

        // SECURITY (FIND-R100-003): Validate cache_max_size bounds.
        if self.cache_max_size == 0 {
            return Err("semantic_guardrails.cache_max_size must be > 0".to_string());
        }
        if self.cache_max_size > MAX_CACHE_MAX_SIZE {
            return Err(format!(
                "semantic_guardrails.cache_max_size {} exceeds maximum {}",
                self.cache_max_size, MAX_CACHE_MAX_SIZE
            ));
        }

        // SECURITY (FIND-R100-004): Validate max_latency_ms bounds.
        if self.max_latency_ms == 0 {
            return Err("semantic_guardrails.max_latency_ms must be > 0".to_string());
        }
        if self.max_latency_ms > MAX_LATENCY_MS {
            return Err(format!(
                "semantic_guardrails.max_latency_ms {} exceeds maximum {} (30 seconds)",
                self.max_latency_ms, MAX_LATENCY_MS
            ));
        }

        // min_confidence: must be finite and in [0.0, 1.0]
        if !self.min_confidence.is_finite()
            || self.min_confidence < 0.0
            || self.min_confidence > 1.0
        {
            return Err(format!(
                "semantic_guardrails.min_confidence must be in [0.0, 1.0], got {}",
                self.min_confidence
            ));
        }
        // intent_classification.confidence_threshold
        if !self.intent_classification.confidence_threshold.is_finite()
            || self.intent_classification.confidence_threshold < 0.0
            || self.intent_classification.confidence_threshold > 1.0
        {
            return Err(format!(
                "intent_classification.confidence_threshold must be in [0.0, 1.0], got {}",
                self.intent_classification.confidence_threshold
            ));
        }
        // jailbreak_detection.confidence_threshold
        if !self.jailbreak_detection.confidence_threshold.is_finite()
            || self.jailbreak_detection.confidence_threshold < 0.0
            || self.jailbreak_detection.confidence_threshold > 1.0
        {
            return Err(format!(
                "jailbreak_detection.confidence_threshold must be in [0.0, 1.0], got {}",
                self.jailbreak_detection.confidence_threshold
            ));
        }
        // SECURITY (FIND-R100-005): Validate fallback_on_timeout against known values.
        if self.fallback_on_timeout.len() > MAX_FALLBACK_STRING_LEN {
            return Err("semantic_guardrails.fallback_on_timeout too long".to_string());
        }
        if vellaveto_types::has_dangerous_chars(&self.fallback_on_timeout) {
            return Err(
                "semantic_guardrails.fallback_on_timeout contains control or format characters".to_string(),
            );
        }
        if !VALID_FALLBACK_VALUES.contains(&self.fallback_on_timeout.as_str()) {
            return Err(format!(
                "semantic_guardrails.fallback_on_timeout must be one of {:?}, got '{}'",
                VALID_FALLBACK_VALUES, self.fallback_on_timeout
            ));
        }

        // SECURITY (FIND-R84-005): Validate backend configurations.
        if let Some(ref openai) = self.openai {
            openai
                .validate()
                .map_err(|e| format!("semantic_guardrails.openai: {}", e))?;
        }
        if let Some(ref anthropic) = self.anthropic {
            anthropic
                .validate()
                .map_err(|e| format!("semantic_guardrails.anthropic: {}", e))?;
        }

        // nl_policies: bounded count
        if self.nl_policies.len() > MAX_NL_POLICIES {
            return Err(format!(
                "semantic_guardrails.nl_policies has {} entries, max is {}",
                self.nl_policies.len(),
                MAX_NL_POLICIES
            ));
        }
        // SECURITY (FIND-R84-004): Validate each NL policy entry for bounds + control chars.
        for (i, policy) in self.nl_policies.iter().enumerate() {
            policy
                .validate()
                .map_err(|e| format!("semantic_guardrails.nl_policies[{}]: {}", i, e))?;
        }
        Ok(())
    }
}

impl Default for SemanticGuardrailsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model: None,
            cache_ttl_secs: default_semantic_cache_ttl(),
            cache_max_size: default_semantic_cache_size(),
            max_latency_ms: default_semantic_max_latency(),
            fallback_on_timeout: default_semantic_fallback(),
            min_confidence: default_semantic_confidence(),
            openai: None,
            anthropic: None,
            intent_classification: IntentClassificationConfig::default(),
            jailbreak_detection: JailbreakDetectionConfig::default(),
            nl_policies: Vec::new(),
        }
    }
}

fn default_semantic_cache_ttl() -> u64 {
    300
}

fn default_semantic_cache_size() -> usize {
    10000
}

fn default_semantic_max_latency() -> u64 {
    500
}

fn default_semantic_fallback() -> String {
    "deny".to_string()
}

fn default_semantic_confidence() -> f64 {
    0.7
}

/// OpenAI backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OpenAiBackendConfig {
    /// Model name. Default: "gpt-4o-mini".
    #[serde(default = "default_openai_model")]
    pub model: String,

    /// Environment variable containing API key.
    #[serde(default = "default_openai_api_key_env")]
    pub api_key_env: String,

    /// Request timeout in milliseconds. Default: 3000.
    #[serde(default = "default_openai_timeout")]
    pub timeout_ms: u64,

    /// Maximum tokens in response. Default: 256.
    #[serde(default = "default_openai_max_tokens")]
    pub max_tokens: u32,

    /// Optional custom endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

fn default_openai_model() -> String {
    "gpt-4o-mini".to_string()
}

fn default_openai_api_key_env() -> String {
    "OPENAI_API_KEY".to_string()
}

fn default_openai_timeout() -> u64 {
    3000
}

fn default_openai_max_tokens() -> u32 {
    256
}

impl OpenAiBackendConfig {
    /// Validate OpenAI backend configuration fields.
    pub fn validate(&self) -> Result<(), String> {
        validate_backend_config(
            "openai",
            &self.model,
            &self.api_key_env,
            self.timeout_ms,
            self.max_tokens,
            self.endpoint.as_deref(),
        )
    }
}

impl Default for OpenAiBackendConfig {
    fn default() -> Self {
        Self {
            model: default_openai_model(),
            api_key_env: default_openai_api_key_env(),
            timeout_ms: default_openai_timeout(),
            max_tokens: default_openai_max_tokens(),
            endpoint: None,
        }
    }
}

/// Anthropic backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AnthropicBackendConfig {
    /// Model name. Default: "claude-3-haiku-20240307".
    #[serde(default = "default_anthropic_model")]
    pub model: String,

    /// Environment variable containing API key.
    #[serde(default = "default_anthropic_api_key_env")]
    pub api_key_env: String,

    /// Request timeout in milliseconds. Default: 3000.
    #[serde(default = "default_anthropic_timeout")]
    pub timeout_ms: u64,

    /// Maximum tokens in response. Default: 256.
    #[serde(default = "default_anthropic_max_tokens")]
    pub max_tokens: u32,

    /// Optional custom endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

fn default_anthropic_model() -> String {
    "claude-3-haiku-20240307".to_string()
}

fn default_anthropic_api_key_env() -> String {
    "ANTHROPIC_API_KEY".to_string()
}

fn default_anthropic_timeout() -> u64 {
    3000
}

fn default_anthropic_max_tokens() -> u32 {
    256
}

impl AnthropicBackendConfig {
    /// Validate Anthropic backend configuration fields.
    pub fn validate(&self) -> Result<(), String> {
        validate_backend_config(
            "anthropic",
            &self.model,
            &self.api_key_env,
            self.timeout_ms,
            self.max_tokens,
            self.endpoint.as_deref(),
        )
    }
}

impl Default for AnthropicBackendConfig {
    fn default() -> Self {
        Self {
            model: default_anthropic_model(),
            api_key_env: default_anthropic_api_key_env(),
            timeout_ms: default_anthropic_timeout(),
            max_tokens: default_anthropic_max_tokens(),
            endpoint: None,
        }
    }
}

/// SECURITY (FIND-R84-005): Shared validation for LLM backend configurations.
/// Validates model name, api_key_env, timeout, max_tokens, and endpoint URL.
fn validate_backend_config(
    backend_name: &str,
    model: &str,
    api_key_env: &str,
    timeout_ms: u64,
    max_tokens: u32,
    endpoint: Option<&str>,
) -> Result<(), String> {
    // Model name validation
    if model.is_empty() {
        return Err(format!("{}.model must not be empty", backend_name));
    }
    if model.len() > MAX_BACKEND_MODEL_LEN {
        return Err(format!(
            "{}.model length {} exceeds maximum {}",
            backend_name,
            model.len(),
            MAX_BACKEND_MODEL_LEN
        ));
    }
    if vellaveto_types::has_dangerous_chars(model) {
        return Err(format!(
            "{}.model contains control or format characters",
            backend_name
        ));
    }

    // api_key_env validation
    if api_key_env.is_empty() {
        return Err(format!("{}.api_key_env must not be empty", backend_name));
    }
    if api_key_env.len() > MAX_BACKEND_API_KEY_ENV_LEN {
        return Err(format!(
            "{}.api_key_env length {} exceeds maximum {}",
            backend_name,
            api_key_env.len(),
            MAX_BACKEND_API_KEY_ENV_LEN
        ));
    }
    if vellaveto_types::has_dangerous_chars(api_key_env) {
        return Err(format!(
            "{}.api_key_env contains control or format characters",
            backend_name
        ));
    }

    // Timeout bounds
    if timeout_ms == 0 {
        return Err(format!("{}.timeout_ms must be > 0", backend_name));
    }
    if timeout_ms > MAX_BACKEND_TIMEOUT_MS {
        return Err(format!(
            "{}.timeout_ms {} exceeds maximum {} (60 seconds)",
            backend_name, timeout_ms, MAX_BACKEND_TIMEOUT_MS
        ));
    }

    // Max tokens bounds
    if max_tokens == 0 {
        return Err(format!("{}.max_tokens must be > 0", backend_name));
    }
    if max_tokens > MAX_BACKEND_MAX_TOKENS {
        return Err(format!(
            "{}.max_tokens {} exceeds maximum {}",
            backend_name, max_tokens, MAX_BACKEND_MAX_TOKENS
        ));
    }

    // Endpoint URL validation (SSRF prevention)
    if let Some(url) = endpoint {
        if url.len() > MAX_BACKEND_ENDPOINT_LEN {
            return Err(format!(
                "{}.endpoint length {} exceeds maximum {}",
                backend_name,
                url.len(),
                MAX_BACKEND_ENDPOINT_LEN
            ));
        }
        if vellaveto_types::has_dangerous_chars(url) {
            return Err(format!(
                "{}.endpoint contains control or format characters",
                backend_name
            ));
        }
        // SECURITY (IMP-R126-012): Delegate to canonical SSRF validation from
        // vellaveto-types. The previous inline check was weaker — it missed
        // RFC 1918 private ranges (10.x, 172.16-31.x, 192.168.x) and CGNAT.
        vellaveto_types::validate_url_no_ssrf(url).map_err(|e| {
            format!("{}.endpoint {}", backend_name, e)
        })?;
        // Reject userinfo (@) in URL — defense-in-depth for API endpoints.
        let after_scheme = url.strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or("");
        let authority = after_scheme.split('/').next().unwrap_or("");
        if authority.contains('@') {
            return Err(format!(
                "{}.endpoint must not contain userinfo (@)",
                backend_name
            ));
        }
        // Additional check: reject cloud metadata endpoints by hostname suffix.
        let lower = url.to_lowercase();
        let host_part = lower
            .strip_prefix("https://")
            .or_else(|| lower.strip_prefix("http://"))
            .unwrap_or("");
        let host = host_part.split('/').next().unwrap_or("")
            .split(':').next().unwrap_or("");
        if host.ends_with(".internal") || host == "169.254.169.254" {
            return Err(format!(
                "{}.endpoint must not target metadata endpoints (got '{}')",
                backend_name, host
            ));
        }
    }

    Ok(())
}

/// Intent classification configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IntentClassificationConfig {
    /// Enable intent classification. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Minimum confidence threshold for intent. Default: 0.6.
    #[serde(default = "default_intent_confidence")]
    pub confidence_threshold: f64,

    /// Track intent chains across session. Default: true.
    #[serde(default = "default_true")]
    pub track_intent_chains: bool,

    /// Maximum intent chain size per session. Default: 50.
    #[serde(default = "default_intent_chain_size")]
    pub max_chain_size: usize,
}

fn default_intent_confidence() -> f64 {
    0.6
}

fn default_intent_chain_size() -> usize {
    50
}

impl Default for IntentClassificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            confidence_threshold: default_intent_confidence(),
            track_intent_chains: true,
            max_chain_size: default_intent_chain_size(),
        }
    }
}

/// Jailbreak detection configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct JailbreakDetectionConfig {
    /// Enable jailbreak detection. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Minimum confidence for jailbreak detection. Default: 0.7.
    #[serde(default = "default_jailbreak_confidence")]
    pub confidence_threshold: f64,

    /// Block requests on jailbreak detection. Default: true.
    #[serde(default = "default_true")]
    pub block_on_detection: bool,
}

fn default_jailbreak_confidence() -> f64 {
    0.7
}

impl Default for JailbreakDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            confidence_threshold: default_jailbreak_confidence(),
            block_on_detection: true,
        }
    }
}

/// Natural language policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NlPolicyConfig {
    /// Unique policy identifier.
    pub id: String,

    /// Human-readable policy name.
    #[serde(default)]
    pub name: String,

    /// Natural language policy statement.
    pub statement: String,

    /// Tool patterns this policy applies to.
    #[serde(default)]
    pub tool_patterns: Vec<String>,

    /// Whether policy is enabled. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Policy priority (higher = evaluated first). Default: 0.
    #[serde(default)]
    pub priority: i32,
}

/// Maximum NL policy ID/name length.
const MAX_NL_POLICY_ID_LEN: usize = 256;
/// Maximum NL policy statement length.
const MAX_NL_POLICY_STATEMENT_LEN: usize = 4096;
/// Maximum tool patterns per NL policy.
const MAX_NL_TOOL_PATTERNS: usize = 50;

impl NlPolicyConfig {
    /// Validate NL policy fields for bounds and control character injection.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("nl_policy.id is empty".to_string());
        }
        if self.id.len() > MAX_NL_POLICY_ID_LEN {
            return Err(format!(
                "nl_policy.id length {} exceeds maximum {}",
                self.id.len(),
                MAX_NL_POLICY_ID_LEN
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.id) {
            return Err("nl_policy.id contains control or format characters".to_string());
        }
        if self.name.len() > MAX_NL_POLICY_ID_LEN {
            return Err(format!(
                "nl_policy.name length {} exceeds maximum {}",
                self.name.len(),
                MAX_NL_POLICY_ID_LEN
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.name) {
            return Err("nl_policy.name contains control or format characters".to_string());
        }
        if self.statement.is_empty() {
            return Err("nl_policy.statement is empty".to_string());
        }
        if self.statement.len() > MAX_NL_POLICY_STATEMENT_LEN {
            return Err(format!(
                "nl_policy.statement length {} exceeds maximum {}",
                self.statement.len(),
                MAX_NL_POLICY_STATEMENT_LEN
            ));
        }
        // SECURITY (FIND-R86-002): Reject control/format characters in statement to prevent
        // log injection and prompt injection via invisible characters.
        if vellaveto_types::has_dangerous_chars(&self.statement) {
            return Err("nl_policy.statement contains control or format characters".to_string());
        }
        if self.tool_patterns.len() > MAX_NL_TOOL_PATTERNS {
            return Err(format!(
                "nl_policy.tool_patterns has {} entries, max is {}",
                self.tool_patterns.len(),
                MAX_NL_TOOL_PATTERNS
            ));
        }
        // SECURITY (FIND-R86-002): Validate individual tool_patterns entries
        // for length and control characters.
        for (i, pattern) in self.tool_patterns.iter().enumerate() {
            if pattern.len() > MAX_NL_POLICY_ID_LEN {
                return Err(format!(
                    "nl_policy.tool_patterns[{}] length {} exceeds maximum {}",
                    i,
                    pattern.len(),
                    MAX_NL_POLICY_ID_LEN
                ));
            }
            if vellaveto_types::has_dangerous_chars(pattern) {
                return Err(format!(
                    "nl_policy.tool_patterns[{}] contains control or format characters",
                    i
                ));
            }
        }
        Ok(())
    }
}
