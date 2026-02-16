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

/// A tool observed in traffic that is not in the approved tools list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnapprovedTool {
    pub tool_name: String,
    pub first_seen: String,
    pub request_count: u64,
    pub requesting_agents: HashSet<String>,
}

/// An MCP server observed in traffic that is not in the known servers list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnknownMcpServer {
    pub server_id: String,
    pub first_seen: String,
    pub connection_count: u64,
    pub advertised_tools: HashSet<String>,
}

/// Full shadow AI discovery report — inventory of all unregistered entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowAiReport {
    pub unregistered_agents: Vec<UnregisteredAgent>,
    pub unapproved_tools: Vec<UnapprovedTool>,
    pub unknown_servers: Vec<UnknownMcpServer>,
    pub total_risk_score: f64,
}
