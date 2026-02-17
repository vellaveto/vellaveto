//! Protocol extension types for the MCP extension framework.
//!
//! Extensions allow third-party capabilities to be registered with Vellaveto
//! using the `x-` method prefix convention. Each extension declares its methods,
//! capabilities, and optional Ed25519 signature for verification.

use serde::{Deserialize, Serialize};

/// Maximum number of methods per extension descriptor.
pub const MAX_EXTENSION_METHODS: usize = 64;

/// Maximum number of capabilities per extension descriptor.
///
/// SECURITY (FIND-R51-013): Unbounded capabilities vector could be used
/// for memory exhaustion via crafted extension descriptors.
pub const MAX_EXTENSION_CAPABILITIES: usize = 64;

/// Maximum length of a single capability string.
///
/// SECURITY (FIND-R51-013): Individual capability strings must be bounded
/// to prevent memory exhaustion.
pub const MAX_EXTENSION_CAPABILITY_LEN: usize = 512;

/// Maximum length of an extension ID.
pub const MAX_EXTENSION_ID_LEN: usize = 256;

/// A protocol extension descriptor.
///
/// Describes a loadable extension that handles `x-<id>/...` method calls.
/// Extensions are isolated via resource limits and can optionally be
/// signed for integrity verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtensionDescriptor {
    /// Unique extension identifier (e.g., "vellaveto-audit").
    /// Used as the `x-<id>/` prefix for method routing.
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Declared capabilities (informational).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Methods this extension handles (e.g., `["x-vellaveto-audit/query"]`).
    #[serde(default)]
    pub methods: Vec<String>,
    /// Optional Ed25519 signature over the canonical descriptor (hex-encoded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Optional Ed25519 public key of the signer (hex-encoded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

impl ExtensionDescriptor {
    /// Validate the structural integrity of the descriptor.
    pub fn validate(&self) -> Result<(), ExtensionError> {
        if self.id.is_empty() {
            return Err(ExtensionError::Validation(
                "extension id must not be empty".to_string(),
            ));
        }
        if self.id.len() > MAX_EXTENSION_ID_LEN {
            return Err(ExtensionError::Validation(format!(
                "extension id length {} exceeds max {}",
                self.id.len(),
                MAX_EXTENSION_ID_LEN
            )));
        }
        if self.name.is_empty() {
            return Err(ExtensionError::Validation(
                "extension name must not be empty".to_string(),
            ));
        }
        if self.version.is_empty() {
            return Err(ExtensionError::Validation(
                "extension version must not be empty".to_string(),
            ));
        }
        if self.methods.len() > MAX_EXTENSION_METHODS {
            return Err(ExtensionError::Validation(format!(
                "too many methods: {} (max {})",
                self.methods.len(),
                MAX_EXTENSION_METHODS
            )));
        }
        // SECURITY (FIND-R51-013): Bound capabilities vector size.
        if self.capabilities.len() > MAX_EXTENSION_CAPABILITIES {
            return Err(ExtensionError::Validation(format!(
                "too many capabilities: {} (max {})",
                self.capabilities.len(),
                MAX_EXTENSION_CAPABILITIES
            )));
        }
        // SECURITY (FIND-R51-013): Bound individual capability string lengths.
        for (i, cap) in self.capabilities.iter().enumerate() {
            if cap.len() > MAX_EXTENSION_CAPABILITY_LEN {
                return Err(ExtensionError::Validation(format!(
                    "capability[{}] length {} exceeds max {}",
                    i,
                    cap.len(),
                    MAX_EXTENSION_CAPABILITY_LEN
                )));
            }
        }
        Ok(())
    }
}

/// Resource limits for extension isolation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtensionResourceLimits {
    /// Maximum concurrent in-flight requests to this extension.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_requests: usize,
    /// Maximum requests per second to this extension.
    #[serde(default = "default_max_rps")]
    pub max_requests_per_sec: u32,
}

fn default_max_concurrent() -> usize {
    10
}

fn default_max_rps() -> u32 {
    100
}

impl Default for ExtensionResourceLimits {
    fn default() -> Self {
        Self {
            max_concurrent_requests: default_max_concurrent(),
            max_requests_per_sec: default_max_rps(),
        }
    }
}

/// Result of extension capability negotiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionNegotiationResult {
    /// Extension IDs that were accepted.
    pub accepted: Vec<String>,
    /// Extension IDs that were rejected, with reasons.
    pub rejected: Vec<(String, String)>,
}

/// Errors from extension operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionError {
    /// Structural validation failed.
    Validation(String),
    /// Extension not found.
    NotFound(String),
    /// Extension already registered.
    AlreadyRegistered(String),
    /// Method not handled by any extension.
    MethodNotFound(String),
    /// Extension blocked by configuration.
    Blocked(String),
    /// Handler execution failed.
    HandlerFailed(String),
}

impl std::fmt::Display for ExtensionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtensionError::Validation(msg) => write!(f, "Extension validation: {}", msg),
            ExtensionError::NotFound(msg) => write!(f, "Extension not found: {}", msg),
            ExtensionError::AlreadyRegistered(msg) => {
                write!(f, "Extension already registered: {}", msg)
            }
            ExtensionError::MethodNotFound(msg) => {
                write!(f, "Extension method not found: {}", msg)
            }
            ExtensionError::Blocked(msg) => write!(f, "Extension blocked: {}", msg),
            ExtensionError::HandlerFailed(msg) => write!(f, "Extension handler failed: {}", msg),
        }
    }
}

impl std::error::Error for ExtensionError {}
