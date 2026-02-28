// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

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

/// Maximum length of a single method string.
///
/// SECURITY (FIND-R129-002): Individual method strings must be bounded
/// to prevent memory exhaustion and match capability validation parity.
pub const MAX_EXTENSION_METHOD_LEN: usize = 512;

/// Maximum length of the extension name field.
pub const MAX_EXTENSION_NAME_LEN: usize = 256;

/// Maximum length of the extension version field.
pub const MAX_EXTENSION_VERSION_LEN: usize = 64;

/// Maximum length of an extension ID.
pub const MAX_EXTENSION_ID_LEN: usize = 256;

/// A protocol extension descriptor.
///
/// Describes a loadable extension that handles `x-<id>/...` method calls.
/// Extensions are isolated via resource limits and can optionally be
/// signed for integrity verification.
///
/// Uses a custom `Debug` implementation that redacts `signature` and `public_key`
/// to prevent secret leakage in logs/debug output (FIND-R53-P3-004).
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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

// SECURITY (FIND-R53-P3-004): Custom Debug to redact optional signature and public_key.
impl std::fmt::Debug for ExtensionDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionDescriptor")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("version", &self.version)
            .field("capabilities", &self.capabilities)
            .field("methods", &self.methods)
            .field("signature", &self.signature.as_ref().map(|_| "[REDACTED]"))
            .field(
                "public_key",
                &self.public_key.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
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
        // SECURITY (FIND-R129-002): Bound name length and reject control chars.
        if self.name.len() > MAX_EXTENSION_NAME_LEN {
            return Err(ExtensionError::Validation(format!(
                "extension name length {} exceeds max {}",
                self.name.len(),
                MAX_EXTENSION_NAME_LEN
            )));
        }
        if crate::core::has_dangerous_chars(&self.name) {
            return Err(ExtensionError::Validation(
                "extension name contains control or format characters".to_string(),
            ));
        }
        if self.version.is_empty() {
            return Err(ExtensionError::Validation(
                "extension version must not be empty".to_string(),
            ));
        }
        // SECURITY (FIND-R129-002): Bound version length and reject control chars.
        if self.version.len() > MAX_EXTENSION_VERSION_LEN {
            return Err(ExtensionError::Validation(format!(
                "extension version length {} exceeds max {}",
                self.version.len(),
                MAX_EXTENSION_VERSION_LEN
            )));
        }
        if crate::core::has_dangerous_chars(&self.version) {
            return Err(ExtensionError::Validation(
                "extension version contains control or format characters".to_string(),
            ));
        }
        // SECURITY (FIND-R129-002): Validate id for control/format characters.
        if crate::core::has_dangerous_chars(&self.id) {
            return Err(ExtensionError::Validation(
                "extension id contains control or format characters".to_string(),
            ));
        }
        if self.methods.len() > MAX_EXTENSION_METHODS {
            return Err(ExtensionError::Validation(format!(
                "too many methods: {} (max {})",
                self.methods.len(),
                MAX_EXTENSION_METHODS
            )));
        }
        // SECURITY (FIND-R129-002): Validate individual method strings.
        for (i, method) in self.methods.iter().enumerate() {
            if method.is_empty() {
                return Err(ExtensionError::Validation(format!(
                    "method[{}] must not be empty",
                    i
                )));
            }
            if method.len() > MAX_EXTENSION_METHOD_LEN {
                return Err(ExtensionError::Validation(format!(
                    "method[{}] length {} exceeds max {}",
                    i,
                    method.len(),
                    MAX_EXTENSION_METHOD_LEN
                )));
            }
            if method
                .chars()
                .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
            {
                return Err(ExtensionError::Validation(format!(
                    "method[{}] contains control or format characters",
                    i
                )));
            }
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
            if cap.is_empty() {
                return Err(ExtensionError::Validation(format!(
                    "capability[{}] must not be empty",
                    i
                )));
            }
            if cap.len() > MAX_EXTENSION_CAPABILITY_LEN {
                return Err(ExtensionError::Validation(format!(
                    "capability[{}] length {} exceeds max {}",
                    i,
                    cap.len(),
                    MAX_EXTENSION_CAPABILITY_LEN
                )));
            }
            // SECURITY (FIND-R129-002): Validate capability content for control chars.
            if cap
                .chars()
                .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
            {
                return Err(ExtensionError::Validation(format!(
                    "capability[{}] contains control or format characters",
                    i
                )));
            }
        }
        Ok(())
    }
}

/// Resource limits for extension isolation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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

impl ExtensionResourceLimits {
    /// Maximum allowed concurrent requests.
    const MAX_CONCURRENT: usize = 10_000;
    /// Maximum allowed requests per second.
    const MAX_RPS: u32 = 100_000;

    /// Validate resource limits are within reasonable bounds.
    ///
    /// SECURITY (IMP-R120-014): Prevents attacker-controlled extension configs
    /// from setting extreme values that cause resource exhaustion or
    /// division-by-zero (if max_requests_per_sec is used as a denominator).
    pub fn validate(&self) -> Result<(), String> {
        if self.max_concurrent_requests == 0 {
            return Err("max_concurrent_requests must be > 0".to_string());
        }
        if self.max_concurrent_requests > Self::MAX_CONCURRENT {
            return Err(format!(
                "max_concurrent_requests {} exceeds max {}",
                self.max_concurrent_requests,
                Self::MAX_CONCURRENT
            ));
        }
        if self.max_requests_per_sec == 0 {
            return Err("max_requests_per_sec must be > 0".to_string());
        }
        if self.max_requests_per_sec > Self::MAX_RPS {
            return Err(format!(
                "max_requests_per_sec {} exceeds max {}",
                self.max_requests_per_sec,
                Self::MAX_RPS
            ));
        }
        Ok(())
    }
}

/// Result of extension capability negotiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionNegotiationResult {
    /// Extension IDs that were accepted.
    pub accepted: Vec<String>,
    /// Extension IDs that were rejected, with reasons.
    pub rejected: Vec<(String, String)>,
}

impl ExtensionNegotiationResult {
    /// Maximum number of accepted extensions per negotiation.
    const MAX_ACCEPTED: usize = 256;
    /// Maximum number of rejected extensions per negotiation.
    const MAX_REJECTED: usize = 256;

    /// Validate structural bounds on deserialized data.
    ///
    /// SECURITY (FIND-R113-P3): Prevents memory exhaustion via unbounded
    /// accepted/rejected vectors in negotiation results.
    pub fn validate(&self) -> Result<(), String> {
        if self.accepted.len() > Self::MAX_ACCEPTED {
            return Err(format!(
                "ExtensionNegotiationResult accepted count {} exceeds max {}",
                self.accepted.len(),
                Self::MAX_ACCEPTED,
            ));
        }
        if self.rejected.len() > Self::MAX_REJECTED {
            return Err(format!(
                "ExtensionNegotiationResult rejected count {} exceeds max {}",
                self.rejected.len(),
                Self::MAX_REJECTED,
            ));
        }
        Ok(())
    }
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
