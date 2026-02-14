pub mod observability;
pub mod validation;

// ═══════════════════════════════════════════════════════════════════════════════
// EXTRACTED SUBMODULES (modularization refactor)
// ═══════════════════════════════════════════════════════════════════════════════
pub mod detection;
pub mod enterprise;
pub mod etdi;
pub mod extension;
pub mod manifest;
pub mod mcp_protocol;
pub mod memory_nhi;
pub mod rag_defense_config;
pub mod semantic_guardrails_config;
pub mod supply_chain;
pub mod threat_detection;

// ═══════════════════════════════════════════════════════════════════════════════
// EXTRACTED CONFIG SUBMODULES (Phase 16.6 split)
// ═══════════════════════════════════════════════════════════════════════════════
pub mod a2a;
pub mod cluster;
pub mod compliance;
pub mod config_validate;
pub mod grpc_transport;
pub mod limits;
pub mod policy_rule;
pub mod tool_registry;

#[cfg(test)]
mod tests;

// ═══════════════════════════════════════════════════════════════════════════════
// RE-EXPORTS — preserve the public API
// ═══════════════════════════════════════════════════════════════════════════════

pub use observability::{
    ArizeConfig, HeliconeConfig, LangfuseConfig, ObservabilityConfig, OtlpConfig, OtlpProtocol,
    WebhookExporterConfig,
};

pub use detection::{
    AuditConfig, AuditExportConfig, CustomPiiPattern, DlpConfig, InjectionConfig,
    MemoryTrackingConfig, RateLimitConfig,
};

pub use supply_chain::{SupplyChainConfig, MAX_BINARY_SIZE};

pub use manifest::{
    ManifestAnnotations, ManifestConfig, ManifestEnforcement, ManifestToolEntry,
    ManifestVerification, ToolManifest,
};

pub use mcp_protocol::{
    AsyncTaskConfig, CimdConfig, ElicitationConfig, ResourceIndicatorConfig, SamplingConfig,
    StepUpAuthConfig, MAX_ALLOWED_MODELS, MAX_BLOCKED_FIELD_TYPES,
};

pub use etdi::{AllowedSignersConfig, AttestationConfig, EtdiConfig, VersionPinningConfig};

pub use threat_detection::{
    AdvancedThreatConfig, BehavioralDetectionConfig, CircuitBreakerConfig, CrossAgentConfig,
    DataFlowTrackingConfig, DeputyConfig, SamplingDetectionConfig, SchemaPoisoningConfig,
    SemanticDetectionConfig, ShadowAgentConfig, MAX_ALLOWED_SAMPLING_MODELS, MAX_BEHAVIORAL_AGENTS,
    MAX_BEHAVIORAL_TOOLS_PER_AGENT, MAX_CLUSTER_KEY_PREFIX_LEN, MAX_CLUSTER_REDIS_POOL_SIZE,
    MAX_CROSS_AGENT_TRUSTED_AGENTS, MAX_DATA_FLOW_FINDINGS, MAX_DATA_FLOW_FINGERPRINTS,
    MAX_KNOWN_AGENTS, MAX_NON_DELEGATABLE_TOOLS, MAX_PROTECTED_TOOL_PATTERNS,
    MAX_SEMANTIC_EXTRA_TEMPLATES, MAX_TRACKED_SCHEMAS,
};

pub use enterprise::{
    JitAccessConfig, OpaConfig, SpiffeConfig, ThreatIntelConfig, ThreatIntelProvider, TlsConfig,
    TlsKexPolicy, TlsMode,
};

pub use memory_nhi::{
    DpopConfig, MemorySecurityConfig, NamespaceConfig, NhiConfig, VerificationConfig,
};

pub use semantic_guardrails_config::{
    AnthropicBackendConfig, IntentClassificationConfig, JailbreakDetectionConfig, NlPolicyConfig,
    OpenAiBackendConfig, SemanticGuardrailsConfig,
};

pub use rag_defense_config::{
    ContextBudgetConfig, DocumentVerificationConfig, EmbeddingAnomalyConfig, GroundingConfig,
    RagDefenseConfig, RetrievalSecurityConfig,
};

// Re-exports from Phase 16.6 split submodules
pub use a2a::A2aConfig;
pub use compliance::{
    AiActRiskClass, ComplianceConfig, EuAiActConfig, Soc2Config, TrustServicesCategory,
};
pub use cluster::ClusterConfig;
pub use config_validate::{
    MAX_ALLOWED_SERVERS, MAX_CUSTOM_PII_PATTERNS, MAX_DISABLED_INJECTION_PATTERNS,
    MAX_EXTRA_INJECTION_PATTERNS, MAX_KNOWN_TOOL_NAMES, MAX_POLICIES, MAX_TRUSTED_KEYS,
};
pub use extension::ExtensionConfig;
pub use grpc_transport::GrpcTransportConfig;
pub use limits::LimitsConfig;
pub use policy_rule::PolicyRule;
pub use tool_registry::ToolRegistryConfig;

use sentinel_types::{Policy, PolicyType};
use serde::{Deserialize, Serialize};

pub(crate) fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub policies: Vec<PolicyRule>,

    /// Optional injection scanning configuration.
    /// When absent, defaults are used (scanning enabled, default patterns only).
    #[serde(default)]
    pub injection: InjectionConfig,

    /// Optional DLP (Data Loss Prevention) scanning configuration.
    /// When absent, defaults are used (scanning enabled, block on finding).
    #[serde(default)]
    pub dlp: DlpConfig,

    /// Optional rate limiting configuration.
    /// When absent, all rate limits are unconfigured (env vars or defaults apply).
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Optional audit log configuration (redaction level).
    #[serde(default)]
    pub audit: AuditConfig,

    /// Optional supply chain verification configuration.
    #[serde(default)]
    pub supply_chain: SupplyChainConfig,

    /// Optional tool manifest verification configuration.
    #[serde(default)]
    pub manifest: ManifestConfig,

    /// Memory poisoning defense configuration.
    #[serde(default)]
    pub memory_tracking: MemoryTrackingConfig,

    /// Elicitation interception configuration (MCP 2025-06-18).
    #[serde(default)]
    pub elicitation: ElicitationConfig,

    /// Sampling request policy configuration.
    #[serde(default)]
    pub sampling: SamplingConfig,

    /// Audit log export configuration for SIEM integration.
    #[serde(default)]
    pub audit_export: AuditExportConfig,

    /// Maximum percent-decoding iterations for path normalization.
    /// Paths requiring more iterations fail-closed to `"/"` (attack indicator).
    /// Default: 20 (from `sentinel_engine::DEFAULT_MAX_PATH_DECODE_ITERATIONS`).
    /// Set to 0 to disable iterative decoding (single pass only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_path_decode_iterations: Option<u32>,

    /// Known tool names used for squatting detection. Tools with names
    /// similar to these (Levenshtein distance <= 2 or homoglyph matches)
    /// are flagged. When empty, the built-in default list is used.
    #[serde(default)]
    pub known_tool_names: Vec<String>,

    /// Tool registry configuration.
    #[serde(default)]
    pub tool_registry: ToolRegistryConfig,

    /// Allowed origins for CSRF / DNS rebinding protection.
    ///
    /// When non-empty, the HTTP proxy validates that the `Origin` header (if present)
    /// matches one of these values. When empty, the proxy uses automatic localhost
    /// detection based on the bind address: if bound to `127.0.0.1`, `localhost`,
    /// or `[::1]`, only localhost origins are accepted.
    ///
    /// Requests without an `Origin` header are always allowed (non-browser clients).
    ///
    /// # TOML Example
    ///
    /// ```toml
    /// allowed_origins = ["http://localhost:3001", "http://127.0.0.1:3001"]
    /// ```
    #[serde(default)]
    pub allowed_origins: Vec<String>,

    /// Behavioral anomaly detection configuration (P4.1).
    #[serde(default)]
    pub behavioral: BehavioralDetectionConfig,

    /// Cross-request data flow tracking configuration (P4.2).
    #[serde(default)]
    pub data_flow: DataFlowTrackingConfig,

    /// Semantic injection detection configuration (P4.3).
    /// Requires the `semantic-detection` feature flag on `sentinel-mcp`.
    #[serde(default)]
    pub semantic_detection: SemanticDetectionConfig,

    /// Distributed clustering configuration (P3.4).
    /// When enabled, Sentinel instances share approval and rate limit state
    /// via Redis, enabling horizontal scaling behind a load balancer.
    #[serde(default)]
    pub cluster: ClusterConfig,

    // ═══════════════════════════════════════════════════
    // MCP 2025-11-25 CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Async task lifecycle configuration (MCP 2025-11-25).
    #[serde(default)]
    pub async_tasks: AsyncTaskConfig,

    /// RFC 8707 Resource Indicator configuration.
    #[serde(default)]
    pub resource_indicator: ResourceIndicatorConfig,

    /// CIMD (Capability-Indexed Message Dispatch) configuration.
    #[serde(default)]
    pub cimd: CimdConfig,

    /// Step-up authentication configuration.
    #[serde(default)]
    pub step_up_auth: StepUpAuthConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 2: ADVANCED THREAT DETECTION CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Circuit breaker configuration for cascading failure protection.
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,

    /// Confused deputy prevention configuration.
    #[serde(default)]
    pub deputy: DeputyConfig,

    /// Shadow agent detection configuration.
    #[serde(default)]
    pub shadow_agent: ShadowAgentConfig,

    /// Schema poisoning detection configuration.
    #[serde(default)]
    pub schema_poisoning: SchemaPoisoningConfig,

    /// Sampling attack detection configuration.
    #[serde(default)]
    pub sampling_detection: SamplingDetectionConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 3.2: CROSS-AGENT SECURITY CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Cross-agent security configuration for multi-agent systems.
    /// Controls trust relationships, message signing, and privilege escalation detection.
    #[serde(default)]
    pub cross_agent: CrossAgentConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 3.3: ADVANCED THREAT DETECTION CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Advanced threat detection configuration.
    /// Controls goal tracking, workflow monitoring, namespace security, and more.
    #[serde(default)]
    pub advanced_threat: AdvancedThreatConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 5: ENTERPRISE HARDENING CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// TLS/mTLS configuration for secure transport.
    #[serde(default)]
    pub tls: TlsConfig,

    /// SPIFFE/SPIRE workload identity configuration.
    #[serde(default)]
    pub spiffe: SpiffeConfig,

    /// OPA (Open Policy Agent) integration configuration.
    #[serde(default)]
    pub opa: OpaConfig,

    /// Threat intelligence feed configuration.
    #[serde(default)]
    pub threat_intel: ThreatIntelConfig,

    /// Just-In-Time (JIT) access configuration.
    #[serde(default)]
    pub jit_access: JitAccessConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 8: ETDI CRYPTOGRAPHIC TOOL SECURITY
    // ═══════════════════════════════════════════════════
    /// ETDI (Enhanced Tool Definition Interface) configuration.
    /// Provides cryptographic verification of tool definitions to prevent
    /// rug-pulls, tool squatting, and supply chain attacks.
    #[serde(default)]
    pub etdi: EtdiConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 9: MEMORY INJECTION DEFENSE (MINJA)
    // ═══════════════════════════════════════════════════
    /// Memory security configuration for MINJA defense.
    /// Controls taint propagation, provenance tracking, trust decay,
    /// quarantine, and namespace isolation.
    #[serde(default)]
    pub memory_security: MemorySecurityConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 10: NON-HUMAN IDENTITY (NHI) LIFECYCLE
    // ═══════════════════════════════════════════════════
    /// Non-Human Identity (NHI) lifecycle management configuration.
    /// Controls agent identity registration, attestation, behavioral
    /// baselines, credential rotation, and delegation chains.
    #[serde(default)]
    pub nhi: NhiConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 13: RAG POISONING DEFENSE CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// RAG (Retrieval-Augmented Generation) poisoning defense configuration.
    /// Protects against document injection, embedding manipulation, and
    /// context window flooding in RAG systems.
    #[serde(default)]
    pub rag_defense: RagDefenseConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 14: A2A PROTOCOL SECURITY
    // ═══════════════════════════════════════════════════
    /// A2A (Agent-to-Agent) protocol security configuration.
    /// Secures A2A traffic using message interception, policy evaluation,
    /// agent card verification, and existing security managers.
    #[serde(default)]
    pub a2a: A2aConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 15: OBSERVABILITY PLATFORM INTEGRATION
    // ═══════════════════════════════════════════════════
    /// AI observability platform integration configuration.
    /// Enables deep integration with platforms like Langfuse, Arize, and Helicone
    /// for tracing, evaluation, and observability of security decisions.
    #[serde(default)]
    pub observability: ObservabilityConfig,

    // ═══════════════════════════════════════════════════
    // SERVER CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Metrics endpoint authentication (FIND-004).
    /// When true (default), `/metrics` and `/api/metrics` endpoints require
    /// API key authentication. Set to false to allow unauthenticated access
    /// for Prometheus scrapers in trusted network environments.
    ///
    /// SECURITY NOTE: Metrics expose policy counts, pending approval counts,
    /// and evaluation statistics. Only disable authentication when the metrics
    /// endpoint is protected by network-level controls (e.g., internal VPC only).
    #[serde(default = "default_true")]
    pub metrics_require_auth: bool,

    // ═══════════════════════════════════════════════════
    // RUNTIME LIMITS CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Runtime limits for proxy and MCP processing.
    /// Controls memory bounds, timeouts, and chain lengths.
    #[serde(default)]
    pub limits: LimitsConfig,

    // ═══════════════════════════════════════════════════
    // COMPLIANCE EVIDENCE CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Compliance evidence generation configuration (EU AI Act, SOC 2).
    #[serde(default)]
    pub compliance: ComplianceConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 17.4: PROTOCOL EXTENSION FRAMEWORK
    // ═══════════════════════════════════════════════════
    /// Protocol extension framework configuration.
    /// When enabled, allows registering extensions that handle `x-` prefixed methods.
    #[serde(default)]
    pub extension: ExtensionConfig,
}

impl PolicyConfig {
    /// Parse config from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }

    /// Parse config from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_str)
    }

    /// Convert PolicyRules into sentinel_types::Policy structs.
    pub fn to_policies(&self) -> Vec<Policy> {
        self.policies
            .iter()
            .map(|rule| {
                let id = rule
                    .id
                    .clone()
                    .unwrap_or_else(|| format!("{}:{}", rule.tool_pattern, rule.function_pattern));
                // SECURITY (R19-CFG-1): Default to 0, not 100
                let priority = rule.priority.unwrap_or(0);
                Policy {
                    id,
                    name: rule.name.clone(),
                    policy_type: rule.policy_type.clone(),
                    priority,
                    // SECURITY (R12-CFG-1): Preserve path_rules and network_rules
                    // from config. Previously hardcoded to None, silently discarding
                    // all file-path and domain constraints from config-defined policies.
                    path_rules: rule.path_rules.clone(),
                    network_rules: rule.network_rules.clone(),
                }
            })
            .collect()
    }
}
