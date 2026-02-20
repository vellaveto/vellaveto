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
#[serde(deny_unknown_fields)]
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

impl ToolMetadata {
    /// Maximum serialized size of `input_schema` in bytes.
    ///
    /// SECURITY (FIND-R51-015): Matches SchemaRecord::MAX_SCHEMA_SIZE (64 KiB).
    /// Unbounded input_schema could be used for memory exhaustion.
    pub const MAX_INPUT_SCHEMA_SIZE: usize = 65536;

    /// Maximum length of tool name in bytes.
    ///
    /// SECURITY (FIND-R121-001): Unbounded name from malicious MCP server
    /// causes memory exhaustion during TF-IDF indexing.
    pub const MAX_NAME_LENGTH: usize = 256;

    /// Maximum length of tool description in bytes.
    ///
    /// SECURITY (FIND-R121-001): Unbounded description from malicious MCP
    /// server causes memory exhaustion in `build_searchable_text()`.
    pub const MAX_DESCRIPTION_LENGTH: usize = 4096;

    /// Maximum number of domain tags per tool.
    ///
    /// SECURITY (FIND-R121-001): Matches `MAX_DOMAIN_TAGS_PER_TOOL` from
    /// discovery config.
    pub const MAX_DOMAIN_TAGS: usize = 20;

    /// Maximum length of a single domain tag in bytes.
    ///
    /// SECURITY (FIND-R121-001): Matches `MAX_DOMAIN_TAG_LENGTH` from
    /// discovery config.
    pub const MAX_DOMAIN_TAG_LENGTH: usize = 64;

    /// Validate bounds on deserialized data.
    ///
    /// SECURITY (FIND-R51-015): Checks that the serialized size of
    /// `input_schema` does not exceed `MAX_INPUT_SCHEMA_SIZE`.
    /// SECURITY (FIND-R121-001): Also validates name, description,
    /// and domain_tags bounds to prevent memory exhaustion.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.len() > Self::MAX_NAME_LENGTH {
            return Err(format!(
                "ToolMetadata '{}' name length {} exceeds max {}",
                self.tool_id,
                self.name.len(),
                Self::MAX_NAME_LENGTH
            ));
        }
        if self.description.len() > Self::MAX_DESCRIPTION_LENGTH {
            return Err(format!(
                "ToolMetadata '{}' description length {} exceeds max {}",
                self.tool_id,
                self.description.len(),
                Self::MAX_DESCRIPTION_LENGTH
            ));
        }
        if self.domain_tags.len() > Self::MAX_DOMAIN_TAGS {
            return Err(format!(
                "ToolMetadata '{}' domain_tags count {} exceeds max {}",
                self.tool_id,
                self.domain_tags.len(),
                Self::MAX_DOMAIN_TAGS
            ));
        }
        for tag in &self.domain_tags {
            if tag.len() > Self::MAX_DOMAIN_TAG_LENGTH {
                return Err(format!(
                    "ToolMetadata '{}' domain_tag length {} exceeds max {}",
                    self.tool_id,
                    tag.len(),
                    Self::MAX_DOMAIN_TAG_LENGTH
                ));
            }
        }
        let schema_size = serde_json::to_string(&self.input_schema)
            .map_err(|e| {
                format!(
                    "ToolMetadata '{}' input_schema serialization failed: {}",
                    self.tool_id, e
                )
            })?
            .len();
        if schema_size > Self::MAX_INPUT_SCHEMA_SIZE {
            return Err(format!(
                "ToolMetadata '{}' input_schema serialized size {} exceeds max {}",
                self.tool_id,
                schema_size,
                Self::MAX_INPUT_SCHEMA_SIZE
            ));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DISCOVERY RESULT
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of a discovery query — a ranked list of matching tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct DiscoveredTool {
    /// Full tool metadata.
    pub metadata: ToolMetadata,
    /// Relevance score in [0.0, 1.0] — higher is more relevant.
    pub relevance_score: f64,
    /// Time-to-live in seconds before this discovery result expires.
    pub ttl_secs: u64,
}

impl DiscoveredTool {
    /// Validate structural invariants: finite score, range check.
    ///
    /// SECURITY (FIND-P2-007): Non-finite relevance_score could cause
    /// incorrect ranking or bypass score threshold checks.
    pub fn validate(&self) -> Result<(), String> {
        if !self.relevance_score.is_finite() {
            return Err(format!(
                "DiscoveredTool '{}' has non-finite relevance_score: {}",
                self.metadata.tool_id, self.relevance_score
            ));
        }
        // SECURITY (FIND-R51-001): Validate relevance_score is in documented [0.0, 1.0] range.
        if self.relevance_score < 0.0 || self.relevance_score > 1.0 {
            return Err(format!(
                "DiscoveredTool '{}' relevance_score must be in [0.0, 1.0], got {}",
                self.metadata.tool_id, self.relevance_score
            ));
        }
        Ok(())
    }

    /// Deprecated alias for [`DiscoveredTool::validate()`].
    #[deprecated(since = "4.0.1", note = "renamed to validate()")]
    pub fn validate_finite(&self) -> Result<(), String> {
        self.validate()
    }
}
