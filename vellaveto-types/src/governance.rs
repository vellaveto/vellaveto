//! Governance types for Shadow AI Discovery and Least Agency Enforcement (Phase 26).
//!
//! These types support:
//! - **Shadow AI Discovery (26.1):** Passive detection of unregistered agents,
//!   unapproved tools, and unknown MCP servers from traffic patterns.
//! - **Least Agency Enforcement (26.2):** Auto-revocation of unused permissions
//!   with audit event emission.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ═══════════════════════════════════════════════════════════════════════════════
// ENFORCEMENT MODE
// ═══════════════════════════════════════════════════════════════════════════════

/// Enforcement mode for governance controls.
///
/// - `Monitor`: Log findings but do not block (default, safe rollout).
/// - `Enforce`: Actively deny or revoke based on governance policy.
///
/// # Default: `Monitor` (intentional)
///
/// The default is `Monitor` (fail-open for governance) to support gradual
/// rollout. Organizations should switch to `Enforce` once governance policies
/// have been validated in monitoring mode. This is intentionally different
/// from the core policy engine's fail-closed default — governance findings
/// are informational until the operator explicitly opts into enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    #[default]
    Monitor,
    Enforce,
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHADOW AI DISCOVERY TYPES (Phase 26.1)
// ═══════════════════════════════════════════════════════════════════════════════

/// An agent observed in traffic that is not in the registered agent list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnregisteredAgent {
    pub agent_id: String,
    pub first_seen: String,
    pub last_seen: String,
    pub request_count: u64,
    pub tools_used: HashSet<String>,
    pub risk_score: f64,
}

impl UnregisteredAgent {
    /// Maximum number of tools tracked per unregistered agent.
    const MAX_TOOLS_USED: usize = 1000;
    /// Maximum length for `agent_id` field.
    ///
    /// SECURITY (FIND-R113-014): Bound string fields.
    const MAX_AGENT_ID_LEN: usize = 256;
    /// Maximum length for timestamp fields (`first_seen`, `last_seen`).
    ///
    /// SECURITY (FIND-R113-014): Bound string fields.
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for individual tool name entries in `tools_used`.
    ///
    /// SECURITY (FIND-R113-014): Bound per-entry lengths.
    const MAX_TOOL_NAME_LEN: usize = 256;

    /// Validate structural invariants: finite scores, range checks, collection bounds.
    ///
    /// SECURITY (FIND-P2-007): Non-finite risk_score could bypass threshold
    /// comparisons (NaN comparisons always return false).
    /// SECURITY (FIND-R49-008): Bound inner HashSet to prevent memory abuse.
    /// SECURITY (FIND-R113-014): Control/format char validation on string fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.agent_id.len() > Self::MAX_AGENT_ID_LEN {
            return Err(format!(
                "UnregisteredAgent agent_id length {} exceeds max {}",
                self.agent_id.len(),
                Self::MAX_AGENT_ID_LEN
            ));
        }
        if self.first_seen.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "UnregisteredAgent '{}' first_seen length {} exceeds max {}",
                self.agent_id,
                self.first_seen.len(),
                Self::MAX_TIMESTAMP_LEN
            ));
        }
        if self.last_seen.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "UnregisteredAgent '{}' last_seen length {} exceeds max {}",
                self.agent_id,
                self.last_seen.len(),
                Self::MAX_TIMESTAMP_LEN
            ));
        }
        // SECURITY (FIND-R113-014): Control/format char validation.
        if self
            .agent_id
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err(
                "UnregisteredAgent agent_id contains control or format characters".to_string(),
            );
        }
        if self
            .first_seen
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err(
                "UnregisteredAgent first_seen contains control or format characters".to_string(),
            );
        }
        if self
            .last_seen
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err(
                "UnregisteredAgent last_seen contains control or format characters".to_string(),
            );
        }
        if !self.risk_score.is_finite() {
            return Err(format!(
                "UnregisteredAgent '{}' has non-finite risk_score: {}",
                self.agent_id, self.risk_score
            ));
        }
        // SECURITY (FIND-R51-001): Validate risk_score is in documented [0.0, 1.0] range.
        if self.risk_score < 0.0 || self.risk_score > 1.0 {
            return Err(format!(
                "UnregisteredAgent '{}' risk_score must be in [0.0, 1.0], got {}",
                self.agent_id, self.risk_score
            ));
        }
        if self.tools_used.len() > Self::MAX_TOOLS_USED {
            return Err(format!(
                "UnregisteredAgent '{}' tools_used count {} exceeds max {}",
                self.agent_id,
                self.tools_used.len(),
                Self::MAX_TOOLS_USED
            ));
        }
        // SECURITY (FIND-R113-014): Per-entry length bounds on tools_used.
        for tool in &self.tools_used {
            if tool.len() > Self::MAX_TOOL_NAME_LEN {
                return Err(format!(
                    "UnregisteredAgent '{}' tools_used entry length {} exceeds max {}",
                    self.agent_id,
                    tool.len(),
                    Self::MAX_TOOL_NAME_LEN
                ));
            }
        }
        Ok(())
    }

    /// Deprecated alias for [`UnregisteredAgent::validate()`].
    #[deprecated(since = "4.0.1", note = "renamed to validate()")]
    pub fn validate_finite(&self) -> Result<(), String> {
        self.validate()
    }
}

/// A tool observed in traffic that is not in the approved tools list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnapprovedTool {
    pub tool_name: String,
    pub first_seen: String,
    pub request_count: u64,
    pub requesting_agents: HashSet<String>,
}

impl UnapprovedTool {
    /// Maximum number of requesting agents tracked per unapproved tool.
    const MAX_REQUESTING_AGENTS: usize = 1000;
    /// Maximum length for `tool_name` field.
    ///
    /// SECURITY (FIND-R113-014): Bound string fields.
    const MAX_TOOL_NAME_LEN: usize = 256;
    /// Maximum length for `first_seen` timestamp field.
    ///
    /// SECURITY (FIND-R113-014): Bound string fields.
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for individual agent name entries in `requesting_agents`.
    ///
    /// SECURITY (FIND-R113-014): Bound per-entry lengths.
    const MAX_AGENT_NAME_LEN: usize = 256;

    /// Validate structural bounds, control/format character safety, and per-entry lengths.
    ///
    /// SECURITY (FIND-R49-008): Validate inner HashSet bounds.
    /// SECURITY (FIND-R113-014): Control/format char validation on string fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.tool_name.len() > Self::MAX_TOOL_NAME_LEN {
            return Err(format!(
                "UnapprovedTool tool_name length {} exceeds max {}",
                self.tool_name.len(),
                Self::MAX_TOOL_NAME_LEN
            ));
        }
        if self.first_seen.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "UnapprovedTool '{}' first_seen length {} exceeds max {}",
                self.tool_name,
                self.first_seen.len(),
                Self::MAX_TIMESTAMP_LEN
            ));
        }
        // SECURITY (FIND-R113-014): Control/format char validation.
        if self
            .tool_name
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err(
                "UnapprovedTool tool_name contains control or format characters".to_string(),
            );
        }
        if self
            .first_seen
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err(
                "UnapprovedTool first_seen contains control or format characters".to_string(),
            );
        }
        if self.requesting_agents.len() > Self::MAX_REQUESTING_AGENTS {
            return Err(format!(
                "UnapprovedTool '{}' requesting_agents count {} exceeds max {}",
                self.tool_name,
                self.requesting_agents.len(),
                Self::MAX_REQUESTING_AGENTS
            ));
        }
        // SECURITY (FIND-R113-014): Per-entry length bounds on requesting_agents.
        for agent in &self.requesting_agents {
            if agent.len() > Self::MAX_AGENT_NAME_LEN {
                return Err(format!(
                    "UnapprovedTool '{}' requesting_agents entry length {} exceeds max {}",
                    self.tool_name,
                    agent.len(),
                    Self::MAX_AGENT_NAME_LEN
                ));
            }
        }
        Ok(())
    }
}

/// An MCP server observed in traffic that is not in the known servers list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownMcpServer {
    pub server_id: String,
    pub first_seen: String,
    pub connection_count: u64,
    pub advertised_tools: HashSet<String>,
}

impl UnknownMcpServer {
    /// Maximum number of advertised tools tracked per unknown server.
    const MAX_ADVERTISED_TOOLS: usize = 1000;
    /// Maximum length for `server_id` field.
    ///
    /// SECURITY (FIND-R113-014): Bound string fields.
    const MAX_SERVER_ID_LEN: usize = 256;
    /// Maximum length for `first_seen` timestamp field.
    ///
    /// SECURITY (FIND-R113-014): Bound string fields.
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for individual tool name entries in `advertised_tools`.
    ///
    /// SECURITY (FIND-R113-014): Bound per-entry lengths.
    const MAX_TOOL_NAME_LEN: usize = 256;

    /// Validate structural bounds, control/format character safety, and per-entry lengths.
    ///
    /// SECURITY (FIND-R49-008): Validate inner HashSet bounds.
    /// SECURITY (FIND-R113-014): Control/format char validation on string fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.server_id.len() > Self::MAX_SERVER_ID_LEN {
            return Err(format!(
                "UnknownMcpServer server_id length {} exceeds max {}",
                self.server_id.len(),
                Self::MAX_SERVER_ID_LEN
            ));
        }
        if self.first_seen.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "UnknownMcpServer '{}' first_seen length {} exceeds max {}",
                self.server_id,
                self.first_seen.len(),
                Self::MAX_TIMESTAMP_LEN
            ));
        }
        // SECURITY (FIND-R113-014): Control/format char validation.
        if self
            .server_id
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err(
                "UnknownMcpServer server_id contains control or format characters".to_string(),
            );
        }
        if self
            .first_seen
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err(
                "UnknownMcpServer first_seen contains control or format characters".to_string(),
            );
        }
        if self.advertised_tools.len() > Self::MAX_ADVERTISED_TOOLS {
            return Err(format!(
                "UnknownMcpServer '{}' advertised_tools count {} exceeds max {}",
                self.server_id,
                self.advertised_tools.len(),
                Self::MAX_ADVERTISED_TOOLS
            ));
        }
        // SECURITY (FIND-R113-014): Per-entry length bounds on advertised_tools.
        for tool in &self.advertised_tools {
            if tool.len() > Self::MAX_TOOL_NAME_LEN {
                return Err(format!(
                    "UnknownMcpServer '{}' advertised_tools entry length {} exceeds max {}",
                    self.server_id,
                    tool.len(),
                    Self::MAX_TOOL_NAME_LEN
                ));
            }
        }
        Ok(())
    }
}

/// Full shadow AI discovery report — inventory of all unregistered entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowAiReport {
    pub unregistered_agents: Vec<UnregisteredAgent>,
    pub unapproved_tools: Vec<UnapprovedTool>,
    pub unknown_servers: Vec<UnknownMcpServer>,
    pub total_risk_score: f64,
}

impl ShadowAiReport {
    /// Maximum number of unregistered agents (matches runtime cap).
    const MAX_UNREGISTERED_AGENTS: usize = 1000;
    /// Maximum number of unapproved tools (matches runtime cap).
    const MAX_UNAPPROVED_TOOLS: usize = 500;
    /// Maximum number of unknown servers (matches runtime cap).
    const MAX_UNKNOWN_SERVERS: usize = 100;

    /// Validate structural invariants: finite scores, range checks, collection bounds,
    /// and nested element validation.
    ///
    /// SECURITY (FIND-P2-007): Non-finite total_risk_score could bypass
    /// threshold comparisons. Also validates nested UnregisteredAgent scores.
    /// SECURITY (FIND-R49-007): Validate collection bounds matching runtime caps.
    pub fn validate(&self) -> Result<(), String> {
        if !self.total_risk_score.is_finite() {
            return Err(format!(
                "ShadowAiReport has non-finite total_risk_score: {}",
                self.total_risk_score
            ));
        }
        // SECURITY (FIND-R51-001): Validate total_risk_score is in documented [0.0, 1.0] range.
        if self.total_risk_score < 0.0 || self.total_risk_score > 1.0 {
            return Err(format!(
                "ShadowAiReport total_risk_score must be in [0.0, 1.0], got {}",
                self.total_risk_score
            ));
        }
        if self.unregistered_agents.len() > Self::MAX_UNREGISTERED_AGENTS {
            return Err(format!(
                "ShadowAiReport unregistered_agents count {} exceeds max {}",
                self.unregistered_agents.len(),
                Self::MAX_UNREGISTERED_AGENTS
            ));
        }
        if self.unapproved_tools.len() > Self::MAX_UNAPPROVED_TOOLS {
            return Err(format!(
                "ShadowAiReport unapproved_tools count {} exceeds max {}",
                self.unapproved_tools.len(),
                Self::MAX_UNAPPROVED_TOOLS
            ));
        }
        if self.unknown_servers.len() > Self::MAX_UNKNOWN_SERVERS {
            return Err(format!(
                "ShadowAiReport unknown_servers count {} exceeds max {}",
                self.unknown_servers.len(),
                Self::MAX_UNKNOWN_SERVERS
            ));
        }
        #[allow(deprecated)]
        for agent in &self.unregistered_agents {
            agent.validate_finite()?;
        }
        for tool in &self.unapproved_tools {
            tool.validate()?;
        }
        for server in &self.unknown_servers {
            server.validate()?;
        }
        Ok(())
    }

    /// Deprecated alias for [`ShadowAiReport::validate()`].
    #[deprecated(since = "4.0.1", note = "renamed to validate()")]
    pub fn validate_finite(&self) -> Result<(), String> {
        self.validate()
    }
}
