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
#[serde(deny_unknown_fields)]
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

impl TransportEndpoint {
    /// Maximum number of protocol versions per endpoint.
    ///
    /// SECURITY (FIND-R113-001): Bound protocol_versions to prevent memory exhaustion.
    pub const MAX_PROTOCOL_VERSIONS: usize = 20;
    /// Maximum length for the endpoint URL.
    ///
    /// SECURITY (FIND-R113-001): Bound URL to prevent memory exhaustion.
    pub const MAX_URL_LEN: usize = 2048;
    /// Maximum length of a single protocol version string.
    const MAX_VERSION_LEN: usize = 64;

    /// Validate structural bounds on deserialized data.
    ///
    /// SECURITY (FIND-R113-001): Prevents memory exhaustion via oversized
    /// TransportEndpoint payloads and rejects control/format characters.
    pub fn validate(&self) -> Result<(), String> {
        if self.url.len() > Self::MAX_URL_LEN {
            return Err(format!(
                "TransportEndpoint url length {} exceeds max {}",
                self.url.len(),
                Self::MAX_URL_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.url)
        {
            return Err(
                "TransportEndpoint url contains control or format characters".to_string(),
            );
        }
        if self.protocol_versions.len() > Self::MAX_PROTOCOL_VERSIONS {
            return Err(format!(
                "TransportEndpoint protocol_versions count {} exceeds max {}",
                self.protocol_versions.len(),
                Self::MAX_PROTOCOL_VERSIONS,
            ));
        }
        for (i, ver) in self.protocol_versions.iter().enumerate() {
            if ver.len() > Self::MAX_VERSION_LEN {
                return Err(format!(
                    "TransportEndpoint protocol_versions[{}] length {} exceeds max {}",
                    i,
                    ver.len(),
                    Self::MAX_VERSION_LEN,
                ));
            }
            if ver
                .chars()
                .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
            {
                return Err(format!(
                    "TransportEndpoint protocol_versions[{}] contains control or format characters",
                    i,
                ));
            }
        }
        Ok(())
    }
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
#[serde(deny_unknown_fields)]
pub struct TransportAttempt {
    /// The transport protocol that was tried.
    pub protocol: TransportProtocol,
    /// The endpoint URL that was targeted.
    pub endpoint_url: String,
    /// Whether this attempt succeeded.
    pub succeeded: bool,
    /// Wall-clock duration of this attempt in milliseconds.
    pub duration_ms: u64,
    /// Human-readable error message if the attempt failed (`succeeded == false`).
    ///
    /// `None` when the attempt succeeded. Contains transport-level error details
    /// (e.g., connection refused, timeout, TLS handshake failure) for audit trail
    /// and debugging purposes. Sensitive details (credentials, internal IPs) are
    /// redacted before population.
    pub error: Option<String>,
}

impl TransportAttempt {
    /// Maximum length for endpoint URL.
    const MAX_URL_LEN: usize = 2048;
    /// Maximum length for error message.
    const MAX_ERROR_LEN: usize = 4096;

    /// Validate structural bounds on deserialized data.
    ///
    /// SECURITY (FIND-R113-P3): Prevents memory exhaustion and control char
    /// injection via oversized TransportAttempt payloads.
    pub fn validate(&self) -> Result<(), String> {
        if self.endpoint_url.len() > Self::MAX_URL_LEN {
            return Err(format!(
                "TransportAttempt endpoint_url length {} exceeds max {}",
                self.endpoint_url.len(),
                Self::MAX_URL_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.endpoint_url)
        {
            return Err(
                "TransportAttempt endpoint_url contains control or format characters".to_string(),
            );
        }
        if let Some(ref err) = self.error {
            if err.len() > Self::MAX_ERROR_LEN {
                return Err(format!(
                    "TransportAttempt error length {} exceeds max {}",
                    err.len(),
                    Self::MAX_ERROR_LEN,
                ));
            }
            // SECURITY (FIND-R157-007): Reject control/format chars in error
            // messages to prevent log injection via crafted transport errors.
            if crate::core::has_dangerous_chars(err) {
                return Err(
                    "TransportAttempt error contains control or format characters".to_string(),
                );
            }
        }
        Ok(())
    }
}

/// Full audit trail for a cross-transport fallback negotiation (Phase 29).
///
/// Captures every attempt made during a fallback sequence and which
/// transport (if any) ultimately handled the request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FallbackNegotiationHistory {
    /// Ordered list of transport attempts (first = highest priority).
    pub attempts: Vec<TransportAttempt>,
    /// The transport that successfully handled the request, if any.
    pub successful_transport: Option<TransportProtocol>,
    /// Total wall-clock duration of the entire fallback sequence in milliseconds.
    pub total_duration_ms: u64,
}

impl FallbackNegotiationHistory {
    /// Maximum number of attempts in a single fallback sequence.
    ///
    /// SECURITY (FIND-R113-P3): Bound attempts vector to prevent memory exhaustion.
    pub const MAX_ATTEMPTS: usize = 100;

    /// Validate structural bounds on deserialized data.
    pub fn validate(&self) -> Result<(), String> {
        if self.attempts.len() > Self::MAX_ATTEMPTS {
            return Err(format!(
                "FallbackNegotiationHistory attempts count {} exceeds max {}",
                self.attempts.len(),
                Self::MAX_ATTEMPTS,
            ));
        }
        for (i, attempt) in self.attempts.iter().enumerate() {
            attempt.validate().map_err(|e| format!("attempts[{}]: {}", i, e))?;
        }
        Ok(())
    }
}

/// Declared SDK capabilities for a Vellaveto instance.
///
/// Advertised via the `/.well-known/mcp-transport` discovery endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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
    pub const MAX_CAPABILITIES: usize = 100;
    /// Maximum number of supported protocol versions.
    pub const MAX_VERSIONS: usize = 20;

    /// Maximum length of a single capability string.
    const MAX_CAPABILITY_LEN: usize = 256;
    /// Maximum length of a single version string.
    const MAX_VERSION_LEN: usize = 64;

    /// Validate structural bounds on `SdkCapabilities`.
    ///
    /// SECURITY (FIND-R49-002): Unbounded capability/version vectors could be
    /// used for memory exhaustion via oversized discovery responses.
    /// SECURITY (FIND-R113-P3): Control/format char validation on string entries.
    pub fn validate(&self) -> Result<(), String> {
        if self.capabilities.len() > Self::MAX_CAPABILITIES {
            return Err(format!(
                "capabilities count {} exceeds maximum {}",
                self.capabilities.len(),
                Self::MAX_CAPABILITIES,
            ));
        }
        for (i, cap) in self.capabilities.iter().enumerate() {
            if cap.len() > Self::MAX_CAPABILITY_LEN {
                return Err(format!(
                    "capabilities[{}] length {} exceeds max {}",
                    i,
                    cap.len(),
                    Self::MAX_CAPABILITY_LEN,
                ));
            }
            if cap
                .chars()
                .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
            {
                return Err(format!(
                    "capabilities[{}] contains control or format characters",
                    i,
                ));
            }
        }
        if self.supported_versions.len() > Self::MAX_VERSIONS {
            return Err(format!(
                "supported_versions count {} exceeds maximum {}",
                self.supported_versions.len(),
                Self::MAX_VERSIONS,
            ));
        }
        for (i, ver) in self.supported_versions.iter().enumerate() {
            if ver.len() > Self::MAX_VERSION_LEN {
                return Err(format!(
                    "supported_versions[{}] length {} exceeds max {}",
                    i,
                    ver.len(),
                    Self::MAX_VERSION_LEN,
                ));
            }
            if ver
                .chars()
                .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
            {
                return Err(format!(
                    "supported_versions[{}] contains control or format characters",
                    i,
                ));
            }
        }
        Ok(())
    }
}
