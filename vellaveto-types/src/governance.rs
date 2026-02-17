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

    /// Validate that all f64 fields are finite (not NaN or Infinity).
    ///
    /// SECURITY (FIND-P2-007): Non-finite risk_score could bypass threshold
    /// comparisons (NaN comparisons always return false).
    /// SECURITY (FIND-R49-008): Bound inner HashSet to prevent memory abuse.
    pub fn validate_finite(&self) -> Result<(), String> {
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
        Ok(())
    }
}

/// A tool observed in traffic that is not in the approved tools list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnapprovedTool {
    pub tool_name: String,
    pub first_seen: String,
    pub request_count: u64,
    pub requesting_agents: HashSet<String>,
}

impl UnapprovedTool {
    /// Maximum number of requesting agents tracked per unapproved tool.
    const MAX_REQUESTING_AGENTS: usize = 1000;

    /// SECURITY (FIND-R49-008): Validate inner HashSet bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.requesting_agents.len() > Self::MAX_REQUESTING_AGENTS {
            return Err(format!(
                "UnapprovedTool '{}' requesting_agents count {} exceeds max {}",
                self.tool_name,
                self.requesting_agents.len(),
                Self::MAX_REQUESTING_AGENTS
            ));
        }
        Ok(())
    }
}

/// An MCP server observed in traffic that is not in the known servers list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnknownMcpServer {
    pub server_id: String,
    pub first_seen: String,
    pub connection_count: u64,
    pub advertised_tools: HashSet<String>,
}

impl UnknownMcpServer {
    /// Maximum number of advertised tools tracked per unknown server.
    const MAX_ADVERTISED_TOOLS: usize = 1000;

    /// SECURITY (FIND-R49-008): Validate inner HashSet bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.advertised_tools.len() > Self::MAX_ADVERTISED_TOOLS {
            return Err(format!(
                "UnknownMcpServer '{}' advertised_tools count {} exceeds max {}",
                self.server_id,
                self.advertised_tools.len(),
                Self::MAX_ADVERTISED_TOOLS
            ));
        }
        Ok(())
    }
}

/// Full shadow AI discovery report — inventory of all unregistered entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Validate that all f64 fields are finite (not NaN or Infinity).
    ///
    /// SECURITY (FIND-P2-007): Non-finite total_risk_score could bypass
    /// threshold comparisons. Also validates nested UnregisteredAgent scores.
    /// SECURITY (FIND-R49-007): Validate collection bounds matching runtime caps.
    pub fn validate_finite(&self) -> Result<(), String> {
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
}
