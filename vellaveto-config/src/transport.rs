// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Transport discovery and negotiation configuration.
//!
//! Controls which transports are advertised via `/.well-known/mcp-transport`,
//! upstream fallback priorities, and transport restrictions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vellaveto_types::TransportProtocol;

/// Maximum fallback retries to prevent retry storms.
pub const MAX_FALLBACK_RETRIES: u32 = 10;

/// Minimum fallback timeout in seconds.
pub const MIN_FALLBACK_TIMEOUT_SECS: u64 = 1;

/// Maximum fallback timeout in seconds.
pub const MAX_FALLBACK_TIMEOUT_SECS: u64 = 120;

/// Maximum number of transport override entries (FIND-R41-009).
pub const MAX_TRANSPORT_OVERRIDES: usize = 100;

/// Maximum length for a transport override glob key (FIND-R41-014).
pub const MAX_GLOB_KEY_LEN: usize = 256;

/// Minimum circuit breaker failure threshold.
pub const MIN_CB_FAILURE_THRESHOLD: u32 = 1;

/// Maximum circuit breaker failure threshold.
pub const MAX_CB_FAILURE_THRESHOLD: u32 = 50;

/// Minimum circuit breaker open duration in seconds.
pub const MIN_CB_OPEN_DURATION_SECS: u64 = 1;

/// Maximum circuit breaker open duration in seconds.
pub const MAX_CB_OPEN_DURATION_SECS: u64 = 600;

fn default_discovery_enabled() -> bool {
    true
}

fn default_advertise_capabilities() -> bool {
    true
}

fn default_max_fallback_retries() -> u32 {
    1
}

fn default_fallback_timeout_secs() -> u64 {
    10
}

fn default_cb_failure_threshold() -> u32 {
    3
}

fn default_cb_open_duration_secs() -> u64 {
    30
}

/// Transport discovery and negotiation configuration.
///
/// Controls the `/.well-known/mcp-transport` discovery endpoint, upstream
/// transport priorities, and transport restrictions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    /// Enable the `/.well-known/mcp-transport` discovery endpoint.
    /// Default: true.
    #[serde(default = "default_discovery_enabled")]
    pub discovery_enabled: bool,

    /// Ordered list of upstream transport protocols to try.
    /// Empty means HTTP-only (implicit default).
    #[serde(default)]
    pub upstream_priorities: Vec<TransportProtocol>,

    /// Transports that must not be advertised or used.
    /// Useful for disabling gRPC or WebSocket in restricted environments.
    #[serde(default)]
    pub restricted_transports: Vec<TransportProtocol>,

    /// Whether to include SDK capabilities in discovery responses.
    /// Default: true.
    #[serde(default = "default_advertise_capabilities")]
    pub advertise_capabilities: bool,

    /// Maximum number of fallback attempts when the primary transport fails.
    /// Default: 1. Max: 10.
    #[serde(default = "default_max_fallback_retries")]
    pub max_fallback_retries: u32,

    /// Timeout per fallback attempt in seconds.
    /// Default: 10. Range: 1–120.
    #[serde(default = "default_fallback_timeout_secs")]
    pub fallback_timeout_secs: u64,

    // =========================================================================
    // Phase 29: Cross-Transport Smart Fallback
    // =========================================================================
    /// Enable cross-transport fallback (Phase 29). When true, failed transports
    /// trigger automatic fallback to the next transport in priority order.
    /// Default: false (backward compatible — no behavioral change without opt-in).
    #[serde(default)]
    pub cross_transport_fallback: bool,

    /// Per-tool transport preference overrides. Keys are tool-name globs
    /// (e.g., `"fs_*"`, `"db_*"`), values are ordered transport lists.
    /// Takes precedence over `upstream_priorities` for matching tools.
    #[serde(default)]
    pub transport_overrides: HashMap<String, Vec<TransportProtocol>>,

    /// Number of consecutive failures before the transport circuit breaker opens.
    /// Default: 3. Range: 1–50.
    #[serde(default = "default_cb_failure_threshold")]
    pub transport_circuit_breaker_failure_threshold: u32,

    /// Duration in seconds the transport circuit breaker stays open before
    /// transitioning to half-open. Default: 30. Range: 1–600.
    #[serde(default = "default_cb_open_duration_secs")]
    pub transport_circuit_breaker_open_duration_secs: u64,

    /// Enable stdio as a fallback transport. Default: false.
    /// Requires `stdio_command` to be set.
    #[serde(default)]
    pub stdio_fallback_enabled: bool,

    /// Command to spawn for stdio transport fallback.
    /// Required when `stdio_fallback_enabled` is true.
    #[serde(default)]
    pub stdio_command: Option<String>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            discovery_enabled: default_discovery_enabled(),
            upstream_priorities: Vec::new(),
            restricted_transports: Vec::new(),
            advertise_capabilities: default_advertise_capabilities(),
            max_fallback_retries: default_max_fallback_retries(),
            fallback_timeout_secs: default_fallback_timeout_secs(),
            cross_transport_fallback: false,
            transport_overrides: HashMap::new(),
            transport_circuit_breaker_failure_threshold: default_cb_failure_threshold(),
            transport_circuit_breaker_open_duration_secs: default_cb_open_duration_secs(),
            stdio_fallback_enabled: false,
            stdio_command: None,
        }
    }
}

impl TransportConfig {
    /// Validate transport configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_fallback_retries > MAX_FALLBACK_RETRIES {
            return Err(format!(
                "transport.max_fallback_retries must be <= {}, got {}",
                MAX_FALLBACK_RETRIES, self.max_fallback_retries
            ));
        }

        if self.fallback_timeout_secs < MIN_FALLBACK_TIMEOUT_SECS
            || self.fallback_timeout_secs > MAX_FALLBACK_TIMEOUT_SECS
        {
            return Err(format!(
                "transport.fallback_timeout_secs must be in [{}, {}], got {}",
                MIN_FALLBACK_TIMEOUT_SECS, MAX_FALLBACK_TIMEOUT_SECS, self.fallback_timeout_secs
            ));
        }

        // A transport cannot appear in both priorities and restricted lists.
        for proto in &self.upstream_priorities {
            if self.restricted_transports.contains(proto) {
                return Err(format!(
                    "transport {:?} appears in both upstream_priorities and restricted_transports",
                    proto
                ));
            }
        }

        // SECURITY (FIND-R42-015): Reject duplicate protocols in upstream_priorities.
        {
            let mut seen = std::collections::HashSet::new();
            for proto in &self.upstream_priorities {
                if !seen.insert(proto) {
                    return Err(format!(
                        "transport.upstream_priorities contains duplicate protocol {:?}",
                        proto
                    ));
                }
            }
        }

        // SECURITY (FIND-R43-003): Reject duplicate protocols in restricted_transports.
        {
            let mut seen = std::collections::HashSet::new();
            for proto in &self.restricted_transports {
                if !seen.insert(proto) {
                    return Err(format!(
                        "transport.restricted_transports contains duplicate protocol {:?}",
                        proto
                    ));
                }
            }
        }

        // Phase 29: Cross-transport fallback validation.
        if self.transport_circuit_breaker_failure_threshold < MIN_CB_FAILURE_THRESHOLD
            || self.transport_circuit_breaker_failure_threshold > MAX_CB_FAILURE_THRESHOLD
        {
            return Err(format!(
                "transport.transport_circuit_breaker_failure_threshold must be in [{}, {}], got {}",
                MIN_CB_FAILURE_THRESHOLD,
                MAX_CB_FAILURE_THRESHOLD,
                self.transport_circuit_breaker_failure_threshold
            ));
        }

        if self.transport_circuit_breaker_open_duration_secs < MIN_CB_OPEN_DURATION_SECS
            || self.transport_circuit_breaker_open_duration_secs > MAX_CB_OPEN_DURATION_SECS
        {
            return Err(format!(
                "transport.transport_circuit_breaker_open_duration_secs must be in [{}, {}], got {}",
                MIN_CB_OPEN_DURATION_SECS,
                MAX_CB_OPEN_DURATION_SECS,
                self.transport_circuit_breaker_open_duration_secs
            ));
        }

        // SECURITY (FIND-R43-022): Reject match-all patterns (not just "*") when other overrides exist.
        // Patterns like "**", "*?", "???", etc. consisting entirely of wildcard characters
        // effectively match everything and would shadow all specific overrides.
        if self.transport_overrides.len() > 1 {
            for glob in self.transport_overrides.keys() {
                if !glob.is_empty() && glob.chars().all(|c| c == '*' || c == '?') {
                    return Err(format!(
                        "transport.transport_overrides: match-all wildcard pattern \"{}\" cannot coexist with other patterns",
                        glob
                    ));
                }
            }
        }

        // SECURITY (FIND-R41-009): Bound the number of transport override entries.
        if self.transport_overrides.len() > MAX_TRANSPORT_OVERRIDES {
            return Err(format!(
                "transport.transport_overrides has {} entries (max {})",
                self.transport_overrides.len(),
                MAX_TRANSPORT_OVERRIDES
            ));
        }

        // transport_overrides values must be non-empty and not contain restricted transports.
        for (glob, protos) in &self.transport_overrides {
            // SECURITY (FIND-R41-014): Validate glob key length and content.
            if glob.len() > MAX_GLOB_KEY_LEN {
                return Err(format!(
                    "transport.transport_overrides key \"{}...\" exceeds max length of {}",
                    &glob[..32.min(glob.len())],
                    MAX_GLOB_KEY_LEN
                ));
            }
            if glob.is_empty() {
                return Err("transport.transport_overrides contains empty key".to_string());
            }
            // SECURITY (FIND-R44-007, FIND-R52-008): Reject control and format characters
            // in glob keys to prevent log injection and invisible character bypass.
            if vellaveto_types::has_dangerous_chars(glob) {
                return Err(format!(
                    "transport.transport_overrides key contains control or format characters (key: {:?})",
                    &glob[..glob.len().min(32)]
                ));
            }
            if protos.is_empty() {
                return Err(format!(
                    "transport.transport_overrides[\"{}\"] must not be empty",
                    glob
                ));
            }
            // SECURITY (FIND-R42-013): Check for duplicate protocols in override values.
            let mut seen_protos = std::collections::HashSet::new();
            for proto in protos {
                if !seen_protos.insert(proto) {
                    return Err(format!(
                        "transport.transport_overrides[\"{}\"] contains duplicate protocol {:?}",
                        glob, proto
                    ));
                }
                if self.restricted_transports.contains(proto) {
                    return Err(format!(
                        "transport.transport_overrides[\"{}\"] contains restricted transport {:?}",
                        glob, proto
                    ));
                }
            }
        }

        // SECURITY (FIND-R43-001): Always validate stdio_command content when
        // present, even if stdio_fallback_enabled is false. A malicious command
        // stored in config could be activated later (config reload, flag toggle)
        // without re-validation. Validate-on-store, not validate-on-use.
        if let Some(cmd) = &self.stdio_command {
            let cmd_trimmed = cmd.trim();
            if !cmd_trimmed.is_empty() {
                // SECURITY (FIND-R44-005): Reject null bytes in stdio_command.
                // Null bytes cause CString truncation in Command::new(),
                // executing a different path than what validation inspected.
                if cmd_trimmed.contains('\0') {
                    return Err("transport.stdio_command contains null byte".to_string());
                }
                if !cmd_trimmed.starts_with('/') {
                    return Err(
                        "transport.stdio_command must be an absolute path (starts with '/')"
                            .to_string(),
                    );
                }
                const SHELL_METACHARACTERS: &[char] = &[
                    ';', '|', '&', '$', '`', '(', ')', '>', '<', '!', '{', '}', '[', ']', '*', '?',
                    '#', '~', '\n', '\r',
                ];
                if cmd_trimmed.contains(SHELL_METACHARACTERS) {
                    return Err("transport.stdio_command contains shell metacharacters — \
                         must be a plain absolute path to an executable"
                        .to_string());
                }
            }
        }

        // stdio_fallback_enabled requires a non-empty stdio_command.
        // SECURITY (FIND-R41-002): Validate the command is an absolute path
        // with no shell metacharacters to prevent command injection.
        if self.stdio_fallback_enabled {
            match &self.stdio_command {
                None => {
                    return Err(
                        "transport.stdio_fallback_enabled requires stdio_command to be set"
                            .to_string(),
                    );
                }
                Some(cmd) => {
                    let cmd_trimmed = cmd.trim();
                    if cmd_trimmed.is_empty() {
                        return Err(
                            "transport.stdio_command must not be empty when stdio_fallback_enabled"
                                .to_string(),
                        );
                    }
                    // Content validation already done above (FIND-R43-001).
                }
            }
        }

        Ok(())
    }
}
