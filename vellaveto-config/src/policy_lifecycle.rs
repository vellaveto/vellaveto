// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Policy lifecycle management configuration.
//!
//! Controls versioned policy workflows: approval requirements, staging periods,
//! notification webhooks, and per-policy version limits.

use serde::{Deserialize, Serialize};
use vellaveto_types::{has_dangerous_chars, validate_url_no_ssrf, MAX_VERSIONS_PER_POLICY};

/// Configuration for the policy lifecycle management subsystem (Phase 47).
///
/// When `enabled` is false (default), all lifecycle API endpoints return 404.
/// This is the fail-closed default — no lifecycle features active unless
/// explicitly opted in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleConfig {
    /// Whether policy lifecycle management is enabled.
    /// Default: false (fail-closed).
    #[serde(default)]
    pub enabled: bool,

    /// Number of approvals required before a draft can be promoted to staging/active.
    /// 0 means auto-promote (no approval workflow). Max: MAX_REQUIRED_APPROVERS (20).
    #[serde(default)]
    pub required_approvals: u32,

    /// Roles that can auto-approve (bypass the approval count requirement).
    /// Each entry must be non-empty, max 256 chars, no control/format chars.
    #[serde(default)]
    pub auto_approve_roles: Vec<String>,

    /// Duration in seconds for the staging evaluation period.
    /// 0 means skip staging entirely (Draft → Active).
    /// Default: 3600 (1 hour).
    #[serde(default = "default_staging_period_secs")]
    pub staging_period_secs: u64,

    /// Optional webhook URL for lifecycle event notifications.
    /// Validated for SSRF (no private IPs, no loopback, http(s) only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_webhook_url: Option<String>,

    /// Maximum number of versions retained per policy.
    /// Oldest archived versions are pruned when this limit is exceeded.
    /// Range: [1, MAX_VERSIONS_PER_POLICY].
    #[serde(default = "default_max_versions_per_policy")]
    pub max_versions_per_policy: usize,
}

fn default_staging_period_secs() -> u64 {
    3600
}

fn default_max_versions_per_policy() -> usize {
    50
}

impl Default for PolicyLifecycleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            required_approvals: 0,
            auto_approve_roles: Vec::new(),
            staging_period_secs: 3600,
            notification_webhook_url: None,
            max_versions_per_policy: 50,
        }
    }
}

/// Maximum number of auto-approve roles.
const MAX_AUTO_APPROVE_ROLES: usize = 50;
/// Maximum length of an auto-approve role string.
const MAX_ROLE_LEN: usize = 256;
/// Maximum staging period (30 days in seconds).
const MAX_STAGING_PERIOD_SECS: u64 = 30 * 24 * 3600;

impl PolicyLifecycleConfig {
    /// Validate all configuration fields.
    pub fn validate(&self) -> Result<(), String> {
        // required_approvals
        if self.required_approvals as usize > vellaveto_types::MAX_REQUIRED_APPROVERS {
            return Err(format!(
                "policy_lifecycle.required_approvals ({}) exceeds max ({})",
                self.required_approvals,
                vellaveto_types::MAX_REQUIRED_APPROVERS
            ));
        }
        // auto_approve_roles
        if self.auto_approve_roles.len() > MAX_AUTO_APPROVE_ROLES {
            return Err(format!(
                "policy_lifecycle.auto_approve_roles count ({}) exceeds max ({})",
                self.auto_approve_roles.len(),
                MAX_AUTO_APPROVE_ROLES
            ));
        }
        for (i, role) in self.auto_approve_roles.iter().enumerate() {
            if role.is_empty() || role.trim().is_empty() {
                return Err(format!(
                    "policy_lifecycle.auto_approve_roles[{}] is empty",
                    i
                ));
            }
            if role.len() > MAX_ROLE_LEN {
                return Err(format!(
                    "policy_lifecycle.auto_approve_roles[{}] exceeds {} chars",
                    i, MAX_ROLE_LEN
                ));
            }
            if has_dangerous_chars(role) {
                return Err(format!(
                    "policy_lifecycle.auto_approve_roles[{}] contains invalid characters",
                    i
                ));
            }
        }
        // staging_period_secs
        if self.staging_period_secs > MAX_STAGING_PERIOD_SECS {
            return Err(format!(
                "policy_lifecycle.staging_period_secs ({}) exceeds max ({})",
                self.staging_period_secs, MAX_STAGING_PERIOD_SECS
            ));
        }
        // notification_webhook_url
        if let Some(ref url) = self.notification_webhook_url {
            if url.is_empty() {
                return Err("policy_lifecycle.notification_webhook_url is empty".to_string());
            }
            if has_dangerous_chars(url) {
                return Err(
                    "policy_lifecycle.notification_webhook_url contains invalid characters"
                        .to_string(),
                );
            }
            validate_url_no_ssrf(url)
                .map_err(|e| format!("policy_lifecycle.notification_webhook_url: {}", e))?;
        }
        // max_versions_per_policy
        if self.max_versions_per_policy == 0 {
            return Err("policy_lifecycle.max_versions_per_policy must be >= 1".to_string());
        }
        if self.max_versions_per_policy > MAX_VERSIONS_PER_POLICY {
            return Err(format!(
                "policy_lifecycle.max_versions_per_policy ({}) exceeds max ({})",
                self.max_versions_per_policy, MAX_VERSIONS_PER_POLICY
            ));
        }
        Ok(())
    }
}
