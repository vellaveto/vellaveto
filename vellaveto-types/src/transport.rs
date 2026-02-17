//! Transport protocol and SDK tier types for MCP June 2026 spec compliance.
//!
//! These types support transport discovery, negotiation, and SDK capability
//! advertisement across all Vellaveto transport modes (HTTP, WebSocket, gRPC, stdio).

use serde::{Deserialize, Serialize};

/// Supported MCP transport protocols, ordered by preference (highest first).
///
/// The `Ord` implementation reflects the default priority ordering:
/// gRPC > WebSocket > HTTP > stdio. Negotiation logic uses this ordering
/// when no explicit client preference is provided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    /// gRPC transport (highest throughput, bidirectional streaming).
    Grpc = 0,
    /// WebSocket transport (bidirectional, persistent connection).
    WebSocket = 1,
    /// Streamable HTTP transport (request/response + SSE).
    Http = 2,
    /// Standard I/O transport (stdin/stdout, local only).
    Stdio = 3,
}

/// A single transport endpoint advertisement for discovery responses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransportEndpoint {
    /// The transport protocol type.
    pub protocol: TransportProtocol,
    /// The endpoint URL (e.g., `http://localhost:3001/mcp`).
    pub url: String,
    /// Whether this transport is currently available and accepting connections.
    pub available: bool,
    /// MCP protocol versions supported on this transport.
    pub protocol_versions: Vec<String>,
}

/// SDK maturity tier levels per MCP June 2026 draft.
///
/// The `Ord` implementation provides `Core < Standard < Extended < Full`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SdkTier {
    /// Minimal MCP implementation: tool calling + policy evaluation.
    Core = 0,
    /// Core + audit logging, DLP scanning, injection detection.
    Standard = 1,
    /// Standard + multi-transport, advanced threat detection, compliance.
    Extended = 2,
    /// Extended + all optional features (semantic guardrails, RAG defense, A2A).
    Full = 3,
}

/// Record of a single transport fallback attempt (Phase 29).
///
/// Captures the outcome (success/failure), duration, and optional error
/// for one leg of a cross-transport fallback sequence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransportAttempt {
    /// The transport protocol that was tried.
    pub protocol: TransportProtocol,
    /// The endpoint URL that was targeted.
    pub endpoint_url: String,
    /// Whether this attempt succeeded.
    pub succeeded: bool,
    /// Wall-clock duration of this attempt in milliseconds.
    pub duration_ms: u64,
    /// Error message if the attempt failed.
    pub error: Option<String>,
}

/// Full audit trail for a cross-transport fallback negotiation (Phase 29).
///
/// Captures every attempt made during a fallback sequence and which
/// transport (if any) ultimately handled the request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FallbackNegotiationHistory {
    /// Ordered list of transport attempts (first = highest priority).
    pub attempts: Vec<TransportAttempt>,
    /// The transport that successfully handled the request, if any.
    pub successful_transport: Option<TransportProtocol>,
    /// Total wall-clock duration of the entire fallback sequence in milliseconds.
    pub total_duration_ms: u64,
}

/// Declared SDK capabilities for a Vellaveto instance.
///
/// Advertised via the `/.well-known/mcp-transport` discovery endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SdkCapabilities {
    /// The declared SDK tier level.
    pub tier: SdkTier,
    /// Individual capability strings (e.g., `"policy-evaluation"`, `"dlp-scanning"`).
    pub capabilities: Vec<String>,
    /// MCP protocol versions this SDK supports.
    pub supported_versions: Vec<String>,
}

impl SdkCapabilities {
    /// Maximum number of individual capability strings.
    const MAX_CAPABILITIES: usize = 100;
    /// Maximum number of supported protocol versions.
    const MAX_VERSIONS: usize = 20;

    /// Validate structural bounds on `SdkCapabilities`.
    ///
    /// SECURITY (FIND-R49-002): Unbounded capability/version vectors could be
    /// used for memory exhaustion via oversized discovery responses.
    pub fn validate(&self) -> Result<(), String> {
        if self.capabilities.len() > Self::MAX_CAPABILITIES {
            return Err(format!(
                "capabilities count {} exceeds maximum {}",
                self.capabilities.len(),
                Self::MAX_CAPABILITIES,
            ));
        }
        if self.supported_versions.len() > Self::MAX_VERSIONS {
            return Err(format!(
                "supported_versions count {} exceeds maximum {}",
                self.supported_versions.len(),
                Self::MAX_VERSIONS,
            ));
        }
        Ok(())
    }
}
