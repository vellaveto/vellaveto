// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Gateway types for multi-backend MCP routing (Phase 20).
//!
//! These types define the building blocks for Vellaveto's gateway mode,
//! where tool calls are routed to different upstream MCP servers based
//! on tool name prefix matching.

use serde::{Deserialize, Serialize};

/// Health status of an upstream backend.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendHealth {
    /// Backend is responding normally.
    #[default]
    Healthy,
    /// Backend has experienced failures but is recovering.
    Degraded,
    /// Backend has exceeded the failure threshold and is excluded from routing.
    Unhealthy,
}

fn default_weight() -> u8 {
    100
}

/// An upstream MCP server backend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UpstreamBackend {
    /// Unique identifier for this backend.
    pub id: String,
    /// URL of the upstream MCP server.
    pub url: String,
    /// Tool name prefixes this backend handles. Empty = catch-all default.
    pub tool_prefixes: Vec<String>,
    /// Routing weight (1-100). Higher weight = preferred when multiple
    /// backends match. Default: 100.
    #[serde(default = "default_weight")]
    pub weight: u8,
    /// Current health status. Skipped during serialization.
    #[serde(skip, default)]
    pub health: BackendHealth,
}

impl UpstreamBackend {
    /// Validate structural invariants of an `UpstreamBackend`.
    ///
    /// Checks:
    /// - `id` is not empty
    /// - `url` is not empty
    /// - `url` starts with `http://` or `https://`
    /// - `url` host is not a loopback, link-local, or private IP (SSRF)
    ///
    /// SECURITY (FIND-P2-009): Backends with empty URLs could cause panics
    /// or undefined behavior in HTTP clients. Restricting schemes to HTTP(S)
    /// prevents SSRF via `file://`, `gopher://`, etc.
    ///
    /// SECURITY (FIND-R51-011): After scheme validation, parse the URL host
    /// and reject localhost, loopback, link-local, and private IP ranges to
    /// prevent SSRF attacks routing traffic to internal services.
    /// Maximum length for backend ID.
    const MAX_ID_LEN: usize = 256;
    /// Maximum length per tool prefix.
    const MAX_PREFIX_LEN: usize = 256;
    /// Maximum number of tool prefixes per backend.
    const MAX_PREFIXES: usize = 1000;

    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("UpstreamBackend id must not be empty".to_string());
        }
        // SECURITY (FIND-R174-004): Validate id length and characters.
        if self.id.len() > Self::MAX_ID_LEN {
            return Err(format!(
                "UpstreamBackend id length {} exceeds maximum {}",
                self.id.len(),
                Self::MAX_ID_LEN
            ));
        }
        if crate::core::has_dangerous_chars(&self.id) {
            return Err(
                "UpstreamBackend id contains control or Unicode format characters".to_string(),
            );
        }
        // SECURITY (FIND-R174-004): Validate tool_prefixes count and entries.
        if self.tool_prefixes.len() > Self::MAX_PREFIXES {
            return Err(format!(
                "UpstreamBackend '{}' tool_prefixes count {} exceeds maximum {}",
                self.id,
                self.tool_prefixes.len(),
                Self::MAX_PREFIXES
            ));
        }
        for (i, prefix) in self.tool_prefixes.iter().enumerate() {
            if prefix.len() > Self::MAX_PREFIX_LEN {
                return Err(format!(
                    "UpstreamBackend '{}' tool_prefixes[{}] length {} exceeds maximum {}",
                    self.id,
                    i,
                    prefix.len(),
                    Self::MAX_PREFIX_LEN
                ));
            }
            if crate::core::has_dangerous_chars(prefix) {
                return Err(format!(
                    "UpstreamBackend '{}' tool_prefixes[{}] contains control or Unicode format characters",
                    self.id, i
                ));
            }
        }
        if self.url.is_empty() {
            return Err(format!(
                "UpstreamBackend '{}' url must not be empty",
                self.id
            ));
        }
        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            return Err(format!(
                "UpstreamBackend '{}' url must start with http:// or https://, got: {}",
                self.id,
                self.url.chars().take(40).collect::<String>()
            ));
        }
        // SECURITY (FIND-R51-011): Reject SSRF vectors in URL host.
        Self::validate_url_ssrf(&self.url)
            .map_err(|e| format!("UpstreamBackend '{}' url {}", self.id, e))?;
        Ok(())
    }

    /// SECURITY (FIND-R51-011): Validate a backend URL against SSRF vectors.
    ///
    /// Delegates to [`crate::core::validate_url_no_ssrf`] (IMP-R120-009).
    fn validate_url_ssrf(url: &str) -> Result<(), String> {
        crate::core::validate_url_no_ssrf(url)
    }
}

/// Result of a routing decision.
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    /// ID of the selected backend.
    pub backend_id: String,
    /// URL to forward the request to.
    pub upstream_url: String,
}

/// A tool name conflict detected across multiple backends.
#[derive(Debug, Clone)]
pub struct ToolConflict {
    /// The conflicting tool name.
    pub tool_name: String,
    /// Backend IDs that advertise this tool.
    pub backends: Vec<String>,
}
