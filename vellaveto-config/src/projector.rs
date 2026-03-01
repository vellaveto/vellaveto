// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Model projector configuration (Phase 35).

use serde::{Deserialize, Serialize};

/// Model projector configuration (Phase 35).
///
/// Controls automatic tool schema transformation for different model families,
/// schema compression, and malformed call repair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProjectorConfig {
    /// Enable the model projector. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Default model family for schema projection.
    /// Must be one of the `VALID_FAMILIES` or `"custom:<name>"`.
    /// Default: `"generic"`.
    #[serde(default = "default_model_family")]
    pub default_model_family: String,
    /// Automatically detect the model family from request headers.
    /// Default: true.
    #[serde(default = "default_auto_detect")]
    pub auto_detect_model: bool,
    /// Enable progressive schema compression. Default: false.
    #[serde(default)]
    pub compress_schemas: bool,
    /// Optional token budget for projected schemas. Default: None (no limit).
    /// Range: [1, 1_000_000].
    #[serde(default)]
    pub max_schema_tokens: Option<usize>,
    /// Enable automatic repair of malformed tool calls. Default: true.
    #[serde(default = "default_repair")]
    pub repair_malformed_calls: bool,
}

fn default_model_family() -> String {
    "generic".to_string()
}

fn default_auto_detect() -> bool {
    true
}

fn default_repair() -> bool {
    true
}

/// Maximum token budget for projected schemas (1 million tokens).
pub const MAX_SCHEMA_TOKENS: usize = 1_000_000;

/// Recognized model family identifiers for built-in projections.
pub const VALID_FAMILIES: &[&str] = &["claude", "openai", "deepseek", "qwen", "generic"];

impl Default for ProjectorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_model_family: default_model_family(),
            auto_detect_model: default_auto_detect(),
            compress_schemas: false,
            max_schema_tokens: None,
            repair_malformed_calls: default_repair(),
        }
    }
}

/// Maximum length for the default_model_family string.
/// SECURITY (FIND-R115-064): Prevents unbounded custom family names in config.
const MAX_MODEL_FAMILY_LEN: usize = 128;

impl ProjectorConfig {
    /// Validate projector configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (FIND-R115-064): Validate length bounds on default_model_family.
        // Without this, "custom:<1MB string>" passes validation, causing memory
        // issues during schema projection lookups.
        if self.default_model_family.len() > MAX_MODEL_FAMILY_LEN {
            return Err(format!(
                "projector.default_model_family exceeds max length ({} > {})",
                self.default_model_family.len(),
                MAX_MODEL_FAMILY_LEN
            ));
        }
        // SECURITY (FIND-R115-064, FIND-R158-001): Reject control + format chars.
        if vellaveto_types::has_dangerous_chars(&self.default_model_family) {
            return Err(
                "projector.default_model_family contains control or format characters".to_string(),
            );
        }
        if !VALID_FAMILIES.contains(&self.default_model_family.as_str())
            && !self.default_model_family.starts_with("custom:")
        {
            return Err(format!(
                "projector.default_model_family '{}': must be one of {:?} or 'custom:<name>'",
                self.default_model_family, VALID_FAMILIES
            ));
        }
        // SECURITY (FIND-R115-064): Validate the custom family name after the
        // "custom:" prefix is non-empty.
        if self.default_model_family.starts_with("custom:") {
            let name = &self.default_model_family["custom:".len()..];
            if name.is_empty() {
                return Err(
                    "projector.default_model_family 'custom:' must have a non-empty name after the prefix".to_string(),
                );
            }
        }
        if let Some(tokens) = self.max_schema_tokens {
            if tokens == 0 || tokens > MAX_SCHEMA_TOKENS {
                return Err(format!(
                    "projector.max_schema_tokens must be 1..={}, got {}",
                    MAX_SCHEMA_TOKENS, tokens
                ));
            }
        }
        Ok(())
    }
}
