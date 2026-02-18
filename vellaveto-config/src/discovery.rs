//! Discovery configuration for the Adaptive Tool Layer (Phase 34).
//!
//! Controls the tool discovery index: capacity bounds, relevance scoring
//! thresholds, TTL defaults, and token budgets.

use serde::{Deserialize, Serialize};

/// Maximum number of index entries (tools) in the discovery index.
pub const MAX_DISCOVERY_INDEX_ENTRIES: usize = 50_000;

/// Maximum number of results returned per discovery query.
pub const MAX_DISCOVERY_RESULTS: usize = 20;

/// Maximum TTL for discovered tool schemas (24 hours).
pub const MAX_DISCOVERY_TTL_SECS: u64 = 86_400;

/// Maximum token budget for returned schemas (1M tokens).
pub const MAX_DISCOVERY_TOKEN_BUDGET: usize = 1_000_000;

/// Maximum length of a single domain tag string.
pub const MAX_DOMAIN_TAG_LENGTH: usize = 64;

/// Maximum number of domain tags per tool.
pub const MAX_DOMAIN_TAGS_PER_TOOL: usize = 20;

/// Discovery service configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryConfig {
    /// Enable the tool discovery service.
    /// Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Maximum number of results returned per query.
    /// Default: 5, max: 20.
    #[serde(default = "default_max_results")]
    pub max_results: usize,

    /// Default time-to-live (seconds) for discovered tool schemas.
    /// After expiry, the agent must re-discover tools.
    /// Default: 300 (5 minutes).
    #[serde(default = "default_ttl_secs")]
    pub default_ttl_secs: u64,

    /// Maximum number of tools in the discovery index.
    /// Oldest entries are evicted when this limit is reached.
    /// Default: 10,000.
    #[serde(default = "default_max_index_entries")]
    pub max_index_entries: usize,

    /// Minimum relevance score [0.0, 1.0] for a tool to appear in results.
    /// Default: 0.1.
    #[serde(default = "default_min_relevance_score")]
    pub min_relevance_score: f64,

    /// Optional token budget — limits total tokens of returned schemas.
    /// When set, tools are returned in relevance order until the budget
    /// is exhausted. `None` means no budget (return up to `max_results`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_budget: Option<usize>,

    /// Automatically index tools from `tools/list` MCP responses.
    /// Default: true.
    #[serde(default = "crate::default_true")]
    pub auto_index_on_tools_list: bool,
}

fn default_max_results() -> usize {
    5
}

fn default_ttl_secs() -> u64 {
    300
}

fn default_max_index_entries() -> usize {
    10_000
}

fn default_min_relevance_score() -> f64 {
    0.1
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_results: default_max_results(),
            default_ttl_secs: default_ttl_secs(),
            max_index_entries: default_max_index_entries(),
            min_relevance_score: default_min_relevance_score(),
            token_budget: None,
            auto_index_on_tools_list: true,
        }
    }
}

impl DiscoveryConfig {
    /// Validate discovery configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_results == 0 {
            return Err("discovery.max_results must be > 0".to_string());
        }
        if self.max_results > MAX_DISCOVERY_RESULTS {
            return Err(format!(
                "discovery.max_results must be <= {}, got {}",
                MAX_DISCOVERY_RESULTS, self.max_results
            ));
        }
        if self.default_ttl_secs == 0 {
            return Err("discovery.default_ttl_secs must be > 0".to_string());
        }
        if self.default_ttl_secs > MAX_DISCOVERY_TTL_SECS {
            return Err(format!(
                "discovery.default_ttl_secs must be <= {} (24 hours), got {}",
                MAX_DISCOVERY_TTL_SECS, self.default_ttl_secs
            ));
        }
        if self.max_index_entries == 0 {
            return Err("discovery.max_index_entries must be > 0".to_string());
        }
        if self.max_index_entries > MAX_DISCOVERY_INDEX_ENTRIES {
            return Err(format!(
                "discovery.max_index_entries must be <= {}, got {}",
                MAX_DISCOVERY_INDEX_ENTRIES, self.max_index_entries
            ));
        }
        if !self.min_relevance_score.is_finite() {
            return Err(format!(
                "discovery.min_relevance_score must be finite, got {}",
                self.min_relevance_score
            ));
        }
        if self.min_relevance_score < 0.0 || self.min_relevance_score > 1.0 {
            return Err(format!(
                "discovery.min_relevance_score must be in [0.0, 1.0], got {}",
                self.min_relevance_score
            ));
        }
        if let Some(budget) = self.token_budget {
            if budget == 0 {
                return Err("discovery.token_budget must be > 0 when set".to_string());
            }
            if budget > MAX_DISCOVERY_TOKEN_BUDGET {
                return Err(format!(
                    "discovery.token_budget must be <= {}, got {}",
                    MAX_DISCOVERY_TOKEN_BUDGET, budget
                ));
            }
        }
        Ok(())
    }
}
