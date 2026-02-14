//! MCP Streamable HTTP reverse proxy.
//!
//! Implements the Streamable HTTP transport (MCP spec 2025-11-25) as a
//! reverse proxy that intercepts tool calls, evaluates policies, and
//! forwards allowed requests to an upstream MCP server.

mod auth;
pub mod call_chain;
pub mod discovery;
#[allow(dead_code)] // Wired into gateway health checker in future phases
mod fallback;
pub mod gateway;
#[cfg(feature = "grpc")]
pub mod grpc;
mod handlers;
mod helpers;
mod inspection;
pub mod origin;
#[cfg(test)]
mod tests;
mod upstream;
pub mod websocket;

pub use call_chain::PrivilegeEscalationCheck;
pub use discovery::handle_transport_discovery;
pub use handlers::{handle_mcp_delete, handle_mcp_post, handle_protected_resource_metadata};
pub use websocket::{handle_ws_upgrade, WebSocketConfig};

use hmac::Hmac;
use sentinel_approval::ApprovalStore;
use sentinel_audit::AuditLogger;
use sentinel_config::ManifestConfig;
use sentinel_engine::PolicyEngine;
use sentinel_engine::{circuit_breaker::CircuitBreakerManager, deputy::DeputyValidator};
use sentinel_mcp::extension_registry::ExtensionRegistry;
use sentinel_mcp::inspection::InjectionScanner;
use sentinel_mcp::output_validation::OutputSchemaRegistry;
use sentinel_mcp::{
    auth_level::AuthLevelTracker, sampling_detector::SamplingDetector,
    schema_poisoning::SchemaLineageTracker, shadow_agent::ShadowAgentDetector,
};
use sentinel_types::Policy;
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::oauth::OAuthValidator;
use crate::session::SessionStore;

/// HMAC-SHA256 type alias for call chain signing (FIND-015).
pub type HmacSha256 = Hmac<Sha256>;

/// Query parameters for POST /mcp.
#[derive(Debug, serde::Deserialize, Default)]
pub struct McpQueryParams {
    /// When true, include evaluation trace in the response.
    #[serde(default)]
    pub trace: bool,
}

/// Shared state for the HTTP proxy handlers.
#[derive(Clone)]
pub struct ProxyState {
    pub engine: Arc<PolicyEngine>,
    pub policies: Arc<Vec<Policy>>,
    pub audit: Arc<AuditLogger>,
    pub sessions: Arc<SessionStore>,
    pub upstream_url: String,
    pub http_client: reqwest::Client,
    /// OAuth 2.1 JWT validator. When `Some`, all MCP requests require a valid Bearer token.
    pub oauth: Option<Arc<OAuthValidator>>,
    /// Custom injection scanner. When `Some`, uses configured patterns instead of defaults.
    pub injection_scanner: Option<Arc<InjectionScanner>>,
    /// When true, injection scanning is completely disabled.
    pub injection_disabled: bool,
    /// When true, injection matches block the response instead of just logging (H4).
    pub injection_blocking: bool,
    /// API key for authenticating requests. None disables auth (--allow-anonymous).
    pub api_key: Option<Arc<String>>,
    /// Optional approval store for RequireApproval verdicts.
    /// When set, creates pending approvals with approval_id in error response data.
    pub approval_store: Option<Arc<ApprovalStore>>,
    /// Optional manifest verification config. When set, tools/list responses
    /// are verified against a pinned manifest per session.
    pub manifest_config: Option<ManifestConfig>,
    /// Allowed origins for CSRF / DNS rebinding protection. If non-empty,
    /// Origin must be in the allowlist. If empty and the proxy is bound to a
    /// loopback address, only localhost origins are accepted. If empty and
    /// bound to a non-loopback address, falls back to same-origin check
    /// (Origin host must match Host header).
    /// Requests without an Origin header are always allowed (non-browser clients).
    pub allowed_origins: Vec<String>,
    /// The socket address the proxy is bound to. Used for automatic localhost
    /// origin validation when `allowed_origins` is empty.
    pub bind_addr: SocketAddr,
    /// When true, re-serialize parsed JSON-RPC messages before forwarding to
    /// upstream. This closes the TOCTOU gap where the proxy evaluates a parsed
    /// representation but forwards original bytes that could differ (e.g., due to
    /// duplicate keys or parser-specific handling). Duplicate keys are always
    /// rejected regardless of this setting.
    pub canonicalize: bool,
    /// Output schema registry for structuredContent validation (MCP 2025-06-18).
    pub output_schema_registry: Arc<OutputSchemaRegistry>,
    /// When true, scan tool responses for secrets (DLP response scanning).
    pub response_dlp_enabled: bool,
    /// When true, block responses that contain detected secrets instead of just logging.
    /// SECURITY (R18-DLP-BLOCK): Without this, DLP is log-only and secrets still reach the client.
    pub response_dlp_blocking: bool,
    /// Known legitimate tool names for squatting detection.
    /// Built from DEFAULT_KNOWN_TOOLS + any config overrides.
    pub known_tools: std::collections::HashSet<String>,
    /// Elicitation interception configuration (MCP 2025-06-18).
    /// Controls whether `elicitation/create` requests are allowed or blocked.
    pub elicitation_config: sentinel_config::ElicitationConfig,
    /// Sampling request policy configuration.
    /// Controls whether `sampling/createMessage` requests are allowed or blocked.
    pub sampling_config: sentinel_config::SamplingConfig,
    /// Tool registry for tracking tool trust scores (P2.1).
    /// None when tool registry is disabled.
    pub tool_registry: Option<Arc<sentinel_mcp::tool_registry::ToolRegistry>>,
    /// HMAC-SHA256 key for signing and verifying X-Upstream-Agents call chain entries (FIND-015).
    /// When `Some`, Sentinel signs its own chain entries and verifies incoming ones.
    /// When `None`, chain signing/verification is disabled (backward compatible).
    pub call_chain_hmac_key: Option<[u8; 32]>,
    /// When true, the `?trace=true` query parameter is honored and evaluation
    /// traces are included in responses. When false (the default), trace output
    /// is silently suppressed regardless of the client query parameter.
    ///
    /// SECURITY: Traces expose internal policy names, patterns, and constraint
    /// configurations. Leaving this disabled prevents information leakage to
    /// authenticated clients.
    pub trace_enabled: bool,

    // =========================================================================
    // Phase 3.1 Security Managers
    // =========================================================================
    /// Circuit breaker for cascading failure prevention (OWASP ASI08).
    /// When a tool fails repeatedly, the circuit opens and subsequent calls are rejected.
    pub circuit_breaker: Option<Arc<CircuitBreakerManager>>,

    /// Shadow agent detector for agent impersonation detection.
    /// Tracks known agent fingerprints and alerts on impersonation attempts.
    pub shadow_agent: Option<Arc<ShadowAgentDetector>>,

    /// Deputy validator for confused deputy attack prevention (OWASP ASI02).
    /// Tracks delegation chains and validates action permissions.
    pub deputy: Option<Arc<DeputyValidator>>,

    /// Schema lineage tracker for schema poisoning detection (OWASP ASI05).
    /// Tracks tool schema changes and alerts on suspicious mutations.
    pub schema_lineage: Option<Arc<SchemaLineageTracker>>,

    /// Auth level tracker for step-up authentication.
    /// Tracks session auth levels and enforces step-up requirements.
    pub auth_level: Option<Arc<AuthLevelTracker>>,

    /// Sampling detector for sampling attack prevention.
    /// Tracks sampling request patterns and enforces rate limits.
    pub sampling_detector: Option<Arc<SamplingDetector>>,

    // =========================================================================
    // Runtime Limits
    // =========================================================================
    /// Configurable runtime limits for memory bounds, timeouts, and chain lengths.
    /// Provides operator control over previously hardcoded security constants.
    pub limits: sentinel_config::LimitsConfig,

    // =========================================================================
    // WebSocket Transport (Phase 17.1 — SEP-1288)
    // =========================================================================
    /// WebSocket transport configuration. When `Some`, the `/mcp/ws` endpoint
    /// is active with the specified message size, idle timeout, and rate limit.
    /// When `None`, WebSocket requests use default configuration.
    pub ws_config: Option<WebSocketConfig>,

    // =========================================================================
    // Protocol Extensions (Phase 17.4)
    // =========================================================================
    /// Extension registry for `x-` prefixed protocol extensions.
    /// When `Some`, extension method calls are routed to registered handlers
    /// before falling back to upstream forwarding.
    pub extension_registry: Option<Arc<ExtensionRegistry>>,

    // =========================================================================
    // Phase 18: Transport Discovery & Negotiation
    // =========================================================================
    /// Transport discovery and negotiation configuration.
    pub transport_config: sentinel_config::TransportConfig,

    /// gRPC listen port, when gRPC transport is enabled.
    /// Used by the discovery endpoint to advertise the gRPC endpoint.
    pub grpc_port: Option<u16>,

    // =========================================================================
    // Phase 20: MCP Gateway Mode
    // =========================================================================
    /// Multi-backend gateway router. When `Some`, tool calls are routed to
    /// different upstream MCP servers based on tool name prefix matching.
    /// When `None`, all requests use `upstream_url` (single-server mode).
    pub gateway: Option<Arc<gateway::GatewayRouter>>,

    // =========================================================================
    // Phase 21: Advanced Authorization (ABAC)
    // =========================================================================
    /// ABAC policy engine for Cedar-style permit/forbid evaluation.
    /// When `Some`, refines Allow verdicts from the PolicyEngine.
    /// When `None`, behavior is identical to pre-Phase 21.
    pub abac_engine: Option<Arc<sentinel_engine::abac::AbacEngine>>,
    /// Least-agency tracker for permission usage monitoring.
    /// When `Some`, records which permissions each agent actually uses.
    pub least_agency: Option<Arc<sentinel_engine::least_agency::LeastAgencyTracker>>,
    /// Continuous authorization config for risk-based deny.
    pub continuous_auth_config: Option<sentinel_config::abac::ContinuousAuthConfig>,
}

/// Per-request trust signal for forwarded-header handling.
#[derive(Clone, Copy, Debug)]
pub struct TrustedProxyContext {
    pub from_trusted_proxy: bool,
}

/// MCP Session ID header name.
const MCP_SESSION_ID: &str = "mcp-session-id";

/// MCP protocol version header (MCP 2025-06-18 spec requirement).
const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";

/// The protocol version this proxy speaks.
const MCP_PROTOCOL_VERSION: &str = "2025-11-25";

/// Supported MCP protocol versions for incoming requests.
/// The proxy accepts these versions for backwards compatibility.
/// `2026-06` is a placeholder for the upcoming MCP June 2026 specification.
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2026-06", "2025-11-25", "2025-06-18", "2025-03-26"];

/// Header for client transport preference negotiation (MCP June 2026).
/// Clients may send a comma-separated list of preferred transports.
/// Used in request handling when transport-preference-aware routing is active.
#[allow(dead_code)] // Wired into request handlers in Phase 20
const MCP_TRANSPORT_PREFERENCE_HEADER: &str = "mcp-transport-preference";

/// OWASP ASI08: Header for tracking upstream agents in multi-hop MCP scenarios.
/// Contains a JSON-encoded array of CallChainEntry objects from previous hops.
/// This header is added by Sentinel when forwarding requests downstream
/// and read when receiving requests from upstream.
pub const X_UPSTREAM_AGENTS: &str = "x-upstream-agents";

/// OWASP ASI07: Header for cryptographically attested agent identity.
/// Contains a signed JWT with claims identifying the agent (issuer, subject, custom claims).
/// Provides stronger identity guarantees than the simple agent_id string derived from OAuth.
const X_AGENT_IDENTITY: &str = "x-agent-identity";
