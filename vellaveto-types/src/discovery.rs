//! Tool Discovery types for the Adaptive Tool Layer (Phase 34).
//!
//! These types support:
//! - **Tool Discovery (34.1):** Searchable tool metadata index with TF-IDF scoring.
//! - **Schema Lifecycle (34.3):** TTL-based tool expiry and eviction.
//!
//! Tools are identified by `tool_id` = `"server_name:tool_name"` and carry
//! searchable metadata (description, domain tags, sensitivity level, token cost).

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════════════════
// TOOL SENSITIVITY
// ═══════════════════════════════════════════════════════════════════════════════

/// Sensitivity classification for discovered tools.
///
/// Used by policy evaluation to determine whether a tool requires
/// elevated permissions or approval before use.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ToolSensitivity {
    Low,
    Medium,
    /// SECURITY (FIND-R46-013): Default to High for fail-closed behavior.
    /// Unknown tools should be treated as high-sensitivity until explicitly
    /// downgraded by policy. This prevents misconfigured tools from bypassing
    /// elevated permission requirements.
    #[default]
    High,
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOOL METADATA
// ═══════════════════════════════════════════════════════════════════════════════

/// A tool's searchable metadata, extracted from MCP `tools/list` responses.
///
/// This is the canonical representation of a tool in the discovery index.
/// The `tool_id` is formed as `"server_id:name"` and must be unique within
/// the index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolMetadata {
    /// Unique identifier: `"server_id:tool_name"`.
    pub tool_id: String,
    /// Tool name as reported by the MCP server.
    pub name: String,
    /// Human-readable description of the tool's purpose.
    pub description: String,
    /// Originating MCP server identifier.
    pub server_id: String,
    /// JSON Schema for input parameters.
    pub input_schema: serde_json::Value,
    /// SHA-256 hex digest of the canonical input schema.
    pub schema_hash: String,
    /// Sensitivity classification.
    pub sensitivity: ToolSensitivity,
    /// Domain tags for categorical filtering (e.g., `["filesystem", "network"]`).
    pub domain_tags: Vec<String>,
    /// Estimated token cost for including this tool's schema in a prompt.
    pub token_cost: usize,
}

// ═══════════════════════════════════════════════════════════════════════════════
// DISCOVERY RESULT
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of a discovery query — a ranked list of matching tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResult {
    /// Ranked list of discovered tools (highest relevance first).
    pub tools: Vec<DiscoveredTool>,
    /// The original search query.
    pub query: String,
    /// Total number of tools considered before filtering.
    pub total_candidates: usize,
    /// Number of tools removed by policy filtering.
    pub policy_filtered: usize,
}

/// A single discovered tool with its relevance score and TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredTool {
    /// Full tool metadata.
    pub metadata: ToolMetadata,
    /// Relevance score in [0.0, 1.0] — higher is more relevant.
    pub relevance_score: f64,
    /// Time-to-live in seconds before this discovery result expires.
    pub ttl_secs: u64,
}
