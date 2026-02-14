//! Protocol extension configuration.
//!
//! Controls which extensions are allowed, signature requirements, and
//! resource limits for extension isolation.

use vellaveto_types::ExtensionResourceLimits;
use serde::{Deserialize, Serialize};

/// Maximum number of trusted public keys.
pub const MAX_TRUSTED_EXTENSION_KEYS: usize = 64;

/// Maximum number of allow/block patterns.
pub const MAX_EXTENSION_PATTERNS: usize = 256;

/// Configuration for the protocol extension framework.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ExtensionConfig {
    /// Whether extensions are enabled. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Glob patterns for allowed extension IDs. Empty = allow all (subject to blocklist).
    #[serde(default)]
    pub allowed_extensions: Vec<String>,
    /// Glob patterns for blocked extension IDs. Checked after allow list.
    #[serde(default)]
    pub blocked_extensions: Vec<String>,
    /// When true, only extensions with valid Ed25519 signatures are loaded.
    #[serde(default)]
    pub require_signatures: bool,
    /// Trusted Ed25519 public keys (hex-encoded). Only relevant when `require_signatures` is true.
    #[serde(default)]
    pub trusted_public_keys: Vec<String>,
    /// Default resource limits applied to all extensions unless overridden.
    #[serde(default)]
    pub default_resource_limits: ExtensionResourceLimits,
}

impl ExtensionConfig {
    /// Validate the extension configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.allowed_extensions.len() > MAX_EXTENSION_PATTERNS {
            return Err(format!(
                "too many allowed_extensions: {} (max {})",
                self.allowed_extensions.len(),
                MAX_EXTENSION_PATTERNS
            ));
        }
        if self.blocked_extensions.len() > MAX_EXTENSION_PATTERNS {
            return Err(format!(
                "too many blocked_extensions: {} (max {})",
                self.blocked_extensions.len(),
                MAX_EXTENSION_PATTERNS
            ));
        }
        if self.trusted_public_keys.len() > MAX_TRUSTED_EXTENSION_KEYS {
            return Err(format!(
                "too many trusted_public_keys: {} (max {})",
                self.trusted_public_keys.len(),
                MAX_TRUSTED_EXTENSION_KEYS
            ));
        }
        if self.default_resource_limits.max_concurrent_requests == 0 {
            return Err("max_concurrent_requests must be > 0".to_string());
        }
        if self.default_resource_limits.max_requests_per_sec == 0 {
            return Err("max_requests_per_sec must be > 0".to_string());
        }
        Ok(())
    }
}
