//! MCP stdio proxy bridge.
//!
//! Sits between an agent (stdin/stdout) and a child MCP server (spawned subprocess).
//! Intercepts `tools/call` requests, evaluates them against policies, and either
//! forwards allowed calls or returns denial responses directly.

mod builder;
mod evaluation;
mod helpers;
mod relay;
#[cfg(test)]
mod tests;

use vellaveto_approval::ApprovalStore;
use vellaveto_audit::AuditLogger;
use vellaveto_config::ManifestConfig;
use vellaveto_engine::circuit_breaker::CircuitBreakerManager;
use vellaveto_engine::deputy::DeputyValidator;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::Policy;

use crate::auth_level::AuthLevelTracker;
use crate::inspection::InjectionScanner;
use crate::output_validation::OutputSchemaRegistry;
pub use crate::rug_pull::ToolAnnotations;
use crate::sampling_detector::SamplingDetector;
use crate::schema_poisoning::SchemaLineageTracker;
use crate::shadow_agent::ShadowAgentDetector;
use crate::task_state::TaskStateManager;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Default request timeout: 30 seconds.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The proxy bridge that sits between agent and child MCP server.
pub struct ProxyBridge {
    engine: PolicyEngine,
    policies: Vec<Policy>,
    audit: Arc<AuditLogger>,
    request_timeout: Duration,
    enable_trace: bool,
    /// Optional custom injection scanner. When `None`, uses the default
    /// patterns via `scan_response_for_injection()`.
    injection_scanner: Option<InjectionScanner>,
    /// When true, injection scanning is completely disabled.
    injection_disabled: bool,
    /// When true, injection matches block the response instead of just logging (H4).
    injection_blocking: bool,
    /// Optional approval store for RequireApproval verdicts.
    approval_store: Option<Arc<ApprovalStore>>,
    /// Optional manifest verification config. When set, the first tools/list
    /// response is pinned and subsequent responses are verified against it.
    manifest_config: Option<ManifestConfig>,
    /// Optional path for persisting flagged (rug-pulled) tool names as JSONL.
    /// When set, flagged tools are appended to this file and loaded on startup.
    flagged_tools_path: Option<PathBuf>,
    /// Output schema registry for structuredContent validation (MCP 2025-06-18).
    /// Populated from tools/list responses, validated on tools/call responses.
    output_schema_registry: Arc<OutputSchemaRegistry>,
    /// When true, block responses that fail output schema validation.
    /// Default: false (warn-only).
    output_schema_blocking: bool,
    /// When true, scan tool responses for secrets (DLP response scanning).
    /// Default: true.
    response_dlp_enabled: bool,
    /// When true, block responses containing secrets. Default: false (log-only).
    response_dlp_blocking: bool,
    /// Known legitimate tool names for squatting detection.
    /// Built from DEFAULT_KNOWN_TOOLS + any config overrides.
    known_tools: HashSet<String>,
    /// Elicitation interception configuration (MCP 2025-06-18).
    /// Controls whether `elicitation/create` requests are allowed or blocked.
    elicitation_config: vellaveto_config::ElicitationConfig,
    /// Sampling request policy configuration.
    /// Controls whether `sampling/createMessage` requests are allowed or blocked.
    sampling_config: vellaveto_config::SamplingConfig,
    /// Tool registry for tracking tool trust scores (P2.1).
    /// None when tool registry is disabled.
    tool_registry: Option<Arc<crate::tool_registry::ToolRegistry>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 1 & 2 Security Managers (Phase 3.1 Integration)
    // ═══════════════════════════════════════════════════════════════════
    /// Task state manager for async task lifecycle tracking (Phase 1).
    task_state: Option<Arc<TaskStateManager>>,

    /// Auth level tracker for step-up authentication (Phase 1).
    auth_level: Option<Arc<AuthLevelTracker>>,

    /// Circuit breaker for cascading failure protection (Phase 2, ASI08).
    circuit_breaker: Option<Arc<CircuitBreakerManager>>,

    /// Deputy validator for confused deputy prevention (Phase 2, ASI02).
    deputy: Option<Arc<DeputyValidator>>,

    /// Shadow agent detector for agent impersonation detection (Phase 2).
    shadow_agent: Option<Arc<ShadowAgentDetector>>,

    /// Schema lineage tracker for schema poisoning detection (Phase 2, ASI05).
    schema_lineage: Option<Arc<SchemaLineageTracker>>,

    /// Sampling detector for sampling attack prevention (Phase 2).
    sampling_detector: Option<Arc<SamplingDetector>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 8: ETDI Cryptographic Tool Security
    // ═══════════════════════════════════════════════════════════════════
    /// ETDI signature verifier for tool definition verification.
    etdi_verifier: Option<Arc<crate::etdi::ToolSignatureVerifier>>,
    /// ETDI attestation chain manager.
    etdi_attestations: Option<Arc<crate::etdi::AttestationChain>>,
    /// ETDI version pin manager.
    etdi_version_pins: Option<Arc<crate::etdi::VersionPinManager>>,
    /// Whether to require ETDI signatures for all tools.
    etdi_require_signatures: bool,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 9: Memory Injection Defense (MINJA)
    // ═══════════════════════════════════════════════════════════════════
    /// Memory security manager for MINJA defense.
    /// When set, memory entries are tracked for taint propagation,
    /// provenance, and namespace isolation.
    memory_security: Option<Arc<crate::memory_security::MemorySecurityManager>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 19: EU AI Act Article 50 Runtime Transparency
    // ═══════════════════════════════════════════════════════════════════
    /// When true, inject `_meta.vellaveto_ai_mediated = true` into responses.
    transparency_marking: bool,
    /// Tool patterns requiring human oversight (Art 14 glob patterns).
    human_oversight_tools: Vec<String>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 24: Art 50(2) Decision Explanations
    // ═══════════════════════════════════════════════════════════════════
    /// Verbosity level for per-verdict decision explanations.
    explanation_verbosity: vellaveto_types::ExplanationVerbosity,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 30: MCP 2025-11-25 Spec Compliance
    // ═══════════════════════════════════════════════════════════════════
    /// SECURITY (FIND-R78-001): When true, validate tool names against MCP spec
    /// format before evaluation. Parity with HTTP/WebSocket/gRPC proxy modes.
    strict_tool_name_validation: bool,
}

impl ProxyBridge {
    pub fn new(engine: PolicyEngine, policies: Vec<Policy>, audit: Arc<AuditLogger>) -> Self {
        Self {
            engine,
            policies,
            audit,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            enable_trace: false,
            injection_scanner: None,
            injection_disabled: false,
            injection_blocking: false,
            approval_store: None,
            manifest_config: None,
            flagged_tools_path: None,
            output_schema_registry: Arc::new(OutputSchemaRegistry::new()),
            output_schema_blocking: false,
            response_dlp_enabled: true,
            response_dlp_blocking: false,
            known_tools: crate::rug_pull::build_known_tools(&[]),
            elicitation_config: vellaveto_config::ElicitationConfig::default(),
            sampling_config: vellaveto_config::SamplingConfig::default(),
            tool_registry: None,
            // Phase 1 & 2 managers (default: disabled)
            task_state: None,
            auth_level: None,
            circuit_breaker: None,
            deputy: None,
            shadow_agent: None,
            schema_lineage: None,
            sampling_detector: None,
            // Phase 8: ETDI (default: disabled)
            etdi_verifier: None,
            etdi_attestations: None,
            etdi_version_pins: None,
            etdi_require_signatures: false,
            // Phase 9: MINJA (default: disabled)
            memory_security: None,
            // Phase 19: Transparency (default: disabled)
            transparency_marking: false,
            human_oversight_tools: Vec::new(),
            // Phase 24: Art 50(2) explanations (default: disabled)
            explanation_verbosity: vellaveto_types::ExplanationVerbosity::None,
            // Phase 30: MCP 2025-11-25 tool name validation (default: disabled)
            strict_tool_name_validation: false,
        }
    }
}
