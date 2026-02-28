// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Protocol extension configuration.
//!
//! Controls which extensions are allowed, signature requirements, and
//! resource limits for extension isolation.

use serde::{Deserialize, Serialize};
use vellaveto_types::ExtensionResourceLimits;

/// Maximum number of trusted public keys.
pub const MAX_TRUSTED_EXTENSION_KEYS: usize = 64;

/// Maximum number of allow/block patterns.
pub const MAX_EXTENSION_PATTERNS: usize = 256;

/// Maximum length for a single extension pattern string.
const MAX_EXTENSION_PATTERN_LEN: usize = 256;

/// Maximum length for a trusted public key hex string (Ed25519 = 64 hex chars).
const MAX_TRUSTED_KEY_LEN: usize = 128;

/// Configuration for the protocol extension framework.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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

        // SECURITY (FIND-R100-006): Per-string validation for extension patterns.
        for (i, pat) in self.allowed_extensions.iter().enumerate() {
            if pat.is_empty() {
                return Err(format!(
                    "extension.allowed_extensions[{}] must not be empty",
                    i
                ));
            }
            if pat.len() > MAX_EXTENSION_PATTERN_LEN {
                return Err(format!(
                    "extension.allowed_extensions[{}] length {} exceeds maximum {}",
                    i,
                    pat.len(),
                    MAX_EXTENSION_PATTERN_LEN
                ));
            }
            if vellaveto_types::has_dangerous_chars(pat) {
                return Err(format!(
                    "extension.allowed_extensions[{}] contains control or format characters",
                    i
                ));
            }
        }
        for (i, pat) in self.blocked_extensions.iter().enumerate() {
            if pat.is_empty() {
                return Err(format!(
                    "extension.blocked_extensions[{}] must not be empty",
                    i
                ));
            }
            if pat.len() > MAX_EXTENSION_PATTERN_LEN {
                return Err(format!(
                    "extension.blocked_extensions[{}] length {} exceeds maximum {}",
                    i,
                    pat.len(),
                    MAX_EXTENSION_PATTERN_LEN
                ));
            }
            if vellaveto_types::has_dangerous_chars(pat) {
                return Err(format!(
                    "extension.blocked_extensions[{}] contains control or format characters",
                    i
                ));
            }
        }
        for (i, key) in self.trusted_public_keys.iter().enumerate() {
            if key.is_empty() {
                return Err(format!(
                    "extension.trusted_public_keys[{}] must not be empty",
                    i
                ));
            }
            if key.len() > MAX_TRUSTED_KEY_LEN {
                return Err(format!(
                    "extension.trusted_public_keys[{}] length {} exceeds maximum {}",
                    i,
                    key.len(),
                    MAX_TRUSTED_KEY_LEN
                ));
            }
            if !key.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "extension.trusted_public_keys[{}] must be hex-encoded",
                    i
                ));
            }
        }

        Ok(())
    }
}
