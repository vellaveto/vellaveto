//! Transport protocol and SDK tier types for MCP June 2026 spec compliance.
//!
//! These types support transport discovery, negotiation, and SDK capability
//! advertisement across all Sentinel transport modes (HTTP, WebSocket, gRPC, stdio).

use serde::{Deserialize, Serialize};

/// Supported MCP transport protocols, ordered by preference (highest first).
///
/// The `Ord` implementation reflects the default priority ordering:
/// gRPC > WebSocket > HTTP > stdio. Negotiation logic uses this ordering
/// when no explicit client preference is provided.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord,
)]
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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
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

/// Declared SDK capabilities for a Sentinel instance.
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
