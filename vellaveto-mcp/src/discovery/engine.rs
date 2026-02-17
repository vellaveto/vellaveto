//! Discovery engine — orchestrates search, policy filtering, and token budgets (Phase 34.2).
//!
//! The `DiscoveryEngine` wraps a `ToolIndex` and applies policy filtering,
//! token budget enforcement, and MCP `tools/list` response parsing.

use serde_json::Value;
use vellaveto_config::DiscoveryConfig;
use vellaveto_types::{DiscoveredTool, DiscoveryResult, ToolMetadata, ToolSensitivity};

use super::error::DiscoveryError;
use super::index::ToolIndex;

// ═══════════════════════════════════════════════════════════════════════════════
// DISCOVERY ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

/// Orchestrates tool discovery: search, filter, budget enforcement.
pub struct DiscoveryEngine {
    index: ToolIndex,
    config: DiscoveryConfig,
}

impl DiscoveryEngine {
    /// Create a new discovery engine with the given configuration.
    pub fn new(config: DiscoveryConfig) -> Self {
        let index = ToolIndex::new(config.max_index_entries);
        Self { index, config }
    }

    /// Main entry point: search the index, filter by policy, respect token budget.
    ///
    /// The `policy_filter` closure receives a `&ToolMetadata` and returns `true`
    /// if the agent is allowed to discover this tool. Tools failing the filter
    /// are counted in `policy_filtered` but not returned.
    pub fn discover(
        &self,
        query: &str,
        max_results: usize,
        token_budget: Option<usize>,
        policy_filter: &dyn Fn(&ToolMetadata) -> bool,
    ) -> Result<DiscoveryResult, DiscoveryError> {
        let effective_max = max_results.min(self.config.max_results);
        let min_score = self.config.min_relevance_score;
        let effective_budget = token_budget.or(self.config.token_budget);

        // Search the index — get more candidates than needed to account for filtering
        let candidates = self.index.search(query, effective_max * 3)?;
        let total_candidates = candidates.len();

        // Apply policy filter and relevance threshold
        let mut policy_filtered = 0usize;
        let mut tools: Vec<DiscoveredTool> = Vec::new();
        let mut token_total = 0usize;

        for (tool_id, score) in candidates {
            if score < min_score {
                continue;
            }

            let metadata = match self.index.get(&tool_id)? {
                Some(m) => m,
                None => continue,
            };

            if !policy_filter(&metadata) {
                policy_filtered += 1;
                continue;
            }

            // Check token budget
            if let Some(budget) = effective_budget {
                if token_total.saturating_add(metadata.token_cost) > budget {
                    break;
                }
                token_total = token_total.saturating_add(metadata.token_cost);
            }

            tools.push(DiscoveredTool {
                metadata,
                relevance_score: score,
                ttl_secs: self.config.default_ttl_secs,
            });

            if tools.len() >= effective_max {
                break;
            }
        }

        Ok(DiscoveryResult {
            tools,
            query: query.to_string(),
            total_candidates,
            policy_filtered,
        })
    }

    /// Ingest tools from an MCP `tools/list` response.
    ///
    /// Parses the response JSON to extract tool metadata and adds each tool
    /// to the index. Returns the number of tools successfully ingested.
    pub fn ingest_tools_list(
        &self,
        server_id: &str,
        tools_response: &Value,
    ) -> Result<usize, DiscoveryError> {
        let tools_array = match tools_response.get("tools").and_then(|t| t.as_array()) {
            Some(arr) => arr,
            None => return Ok(0),
        };

        let mut ingested = 0usize;
        for tool_value in tools_array {
            let name = match tool_value.get("name").and_then(|n| n.as_str()) {
                Some(n) => n,
                None => continue,
            };

            let description = tool_value
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("");

            let input_schema = tool_value
                .get("inputSchema")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));

            // Compute schema hash
            let schema_hash = compute_schema_hash(&input_schema);

            // Estimate token cost (rough heuristic: 1 token ≈ 4 chars of JSON)
            let schema_str = serde_json::to_string(&input_schema).unwrap_or_default();
            let token_cost = (schema_str.len() + name.len() + description.len()) / 4;

            let metadata = ToolMetadata {
                tool_id: format!("{}:{}", server_id, name),
                name: name.to_string(),
                description: description.to_string(),
                server_id: server_id.to_string(),
                input_schema,
                schema_hash,
                sensitivity: infer_sensitivity(name, description),
                domain_tags: infer_domain_tags(name, description),
                token_cost: token_cost.max(1),
            };

            match self.index.ingest(&metadata) {
                Ok(()) => ingested += 1,
                Err(DiscoveryError::IndexFull(_)) => break,
                Err(_) => continue,
            }
        }

        // Rebuild IDF after batch ingestion
        if ingested > 0 {
            self.index.rebuild_idf()?;
        }

        Ok(ingested)
    }

    /// Get index statistics.
    pub fn index_stats(&self) -> Result<IndexStats, DiscoveryError> {
        Ok(IndexStats {
            total_tools: self.index.len()?,
            max_capacity: self.config.max_index_entries,
            config_enabled: self.config.enabled,
        })
    }

    /// Direct access to the underlying index for advanced operations.
    pub fn index(&self) -> &ToolIndex {
        &self.index
    }
}

/// Statistics about the discovery index.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IndexStats {
    pub total_tools: usize,
    pub max_capacity: usize,
    pub config_enabled: bool,
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/// Compute SHA-256 hash of a JSON value (canonical form).
fn compute_schema_hash(schema: &Value) -> String {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::to_string(schema).unwrap_or_default();
    let hash = Sha256::digest(canonical.as_bytes());
    hex::encode(hash)
}

/// Infer sensitivity from tool name and description.
///
/// Simple keyword heuristic — security-critical tools get High,
/// data-modifying tools get Medium, read-only tools get Low.
fn infer_sensitivity(name: &str, description: &str) -> ToolSensitivity {
    let text = format!("{} {}", name, description).to_lowercase();

    const HIGH_KEYWORDS: &[&str] = &[
        "delete",
        "drop",
        "destroy",
        "exec",
        "execute",
        "shell",
        "sudo",
        "admin",
        "credential",
        "password",
        "secret",
        "token",
        "key",
        "encrypt",
        "decrypt",
        "sign",
        "root",
        "privilege",
    ];
    const MEDIUM_KEYWORDS: &[&str] = &[
        "write", "create", "update", "modify", "insert", "upload", "send", "post", "put", "patch",
        "move", "rename", "config",
    ];

    if HIGH_KEYWORDS.iter().any(|kw| text.contains(kw)) {
        return ToolSensitivity::High;
    }
    if MEDIUM_KEYWORDS.iter().any(|kw| text.contains(kw)) {
        return ToolSensitivity::Medium;
    }
    ToolSensitivity::Low
}

/// Infer domain tags from tool name and description.
///
/// Maps common keywords to domain categories.
fn infer_domain_tags(name: &str, description: &str) -> Vec<String> {
    let text = format!("{} {}", name, description).to_lowercase();
    let mut tags = Vec::new();

    const DOMAIN_MAP: &[(&[&str], &str)] = &[
        (
            &["file", "directory", "path", "folder", "disk", "filesystem"],
            "filesystem",
        ),
        (
            &[
                "http", "url", "api", "request", "fetch", "download", "upload",
            ],
            "network",
        ),
        (
            &["sql", "database", "query", "table", "column", "row"],
            "database",
        ),
        (&["git", "commit", "branch", "merge", "repo", "pull"], "vcs"),
        (
            &["shell", "bash", "command", "terminal", "exec", "process"],
            "shell",
        ),
        (
            &["search", "find", "grep", "pattern", "match", "regex"],
            "search",
        ),
        (
            &["image", "photo", "picture", "video", "audio", "media"],
            "media",
        ),
        (
            &["email", "mail", "message", "notification", "alert"],
            "communication",
        ),
        (
            &["encrypt", "decrypt", "hash", "sign", "certificate", "tls"],
            "security",
        ),
        (
            &["docker", "container", "kubernetes", "pod", "deploy"],
            "infrastructure",
        ),
    ];

    for (keywords, tag) in DOMAIN_MAP {
        if keywords.iter().any(|kw| text.contains(kw)) {
            tags.push(tag.to_string());
        }
    }

    tags
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_config() -> DiscoveryConfig {
        DiscoveryConfig {
            enabled: true,
            max_results: 5,
            default_ttl_secs: 300,
            max_index_entries: 1000,
            min_relevance_score: 0.05,
            token_budget: None,
            auto_index_on_tools_list: true,
        }
    }

    fn make_tools_list_response() -> Value {
        json!({
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read the contents of a text file from the local filesystem",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "File path to read"}
                        },
                        "required": ["path"]
                    }
                },
                {
                    "name": "write_file",
                    "description": "Write text data to a file on the local filesystem",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "content": {"type": "string"}
                        },
                        "required": ["path", "content"]
                    }
                },
                {
                    "name": "http_get",
                    "description": "Make an HTTP GET request to fetch data from a remote URL",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"}
                        },
                        "required": ["url"]
                    }
                },
                {
                    "name": "sql_query",
                    "description": "Execute a SQL query against a PostgreSQL database",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "database": {"type": "string"}
                        },
                        "required": ["query"]
                    }
                },
                {
                    "name": "delete_file",
                    "description": "Delete a file from the filesystem permanently",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"}
                        },
                        "required": ["path"]
                    }
                }
            ]
        })
    }

    // ── Engine creation ─────────────────────────────────────────────────

    #[test]
    fn test_engine_new() {
        let engine = DiscoveryEngine::new(test_config());
        let stats = engine.index_stats().unwrap();
        assert_eq!(stats.total_tools, 0);
        assert!(stats.config_enabled);
    }

    // ── Ingest tools/list ───────────────────────────────────────────────

    #[test]
    fn test_ingest_tools_list_basic() {
        let engine = DiscoveryEngine::new(test_config());
        let response = make_tools_list_response();
        let count = engine.ingest_tools_list("test_server", &response).unwrap();
        assert_eq!(count, 5);
        assert_eq!(engine.index_stats().unwrap().total_tools, 5);
    }

    #[test]
    fn test_ingest_tools_list_empty() {
        let engine = DiscoveryEngine::new(test_config());
        let count = engine
            .ingest_tools_list("srv", &json!({"tools": []}))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_ingest_tools_list_no_tools_key() {
        let engine = DiscoveryEngine::new(test_config());
        let count = engine
            .ingest_tools_list("srv", &json!({"other": "data"}))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_ingest_tools_list_skips_nameless() {
        let engine = DiscoveryEngine::new(test_config());
        let response = json!({
            "tools": [
                {"description": "No name tool"},
                {"name": "valid_tool", "description": "Has a name"}
            ]
        });
        let count = engine.ingest_tools_list("srv", &response).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_ingest_tools_list_tool_id_format() {
        let engine = DiscoveryEngine::new(test_config());
        let response = json!({"tools": [{"name": "my_tool", "description": "desc"}]});
        engine.ingest_tools_list("my_server", &response).unwrap();
        let meta = engine.index().get("my_server:my_tool").unwrap();
        assert!(meta.is_some());
        assert_eq!(meta.unwrap().server_id, "my_server");
    }

    // ── Discover (search + filter) ──────────────────────────────────────

    #[test]
    fn test_discover_basic() {
        let engine = DiscoveryEngine::new(test_config());
        engine
            .ingest_tools_list("srv", &make_tools_list_response())
            .unwrap();

        let result = engine
            .discover("read file filesystem", 5, None, &|_| true)
            .unwrap();
        assert!(!result.tools.is_empty());
        assert_eq!(result.query, "read file filesystem");
        assert_eq!(result.policy_filtered, 0);
    }

    #[test]
    fn test_discover_empty_query() {
        let engine = DiscoveryEngine::new(test_config());
        engine
            .ingest_tools_list("srv", &make_tools_list_response())
            .unwrap();

        let result = engine.discover("", 5, None, &|_| true).unwrap();
        assert!(result.tools.is_empty());
    }

    #[test]
    fn test_discover_no_matches() {
        let engine = DiscoveryEngine::new(test_config());
        engine
            .ingest_tools_list("srv", &make_tools_list_response())
            .unwrap();

        let result = engine
            .discover("quantum entanglement physics", 5, None, &|_| true)
            .unwrap();
        assert!(result.tools.is_empty());
    }

    #[test]
    fn test_discover_policy_filter_denies_all() {
        let engine = DiscoveryEngine::new(test_config());
        engine
            .ingest_tools_list("srv", &make_tools_list_response())
            .unwrap();

        let result = engine.discover("file", 5, None, &|_| false).unwrap();
        assert!(result.tools.is_empty());
        assert!(result.policy_filtered > 0);
    }

    #[test]
    fn test_discover_policy_filter_selective() {
        let engine = DiscoveryEngine::new(test_config());
        engine
            .ingest_tools_list("srv", &make_tools_list_response())
            .unwrap();

        // Only allow tools with Low sensitivity
        let result = engine
            .discover("file", 5, None, &|m: &ToolMetadata| {
                m.sensitivity == ToolSensitivity::Low
            })
            .unwrap();

        for tool in &result.tools {
            assert_eq!(tool.metadata.sensitivity, ToolSensitivity::Low);
        }
    }

    #[test]
    fn test_discover_max_results_respected() {
        let engine = DiscoveryEngine::new(test_config());
        engine
            .ingest_tools_list("srv", &make_tools_list_response())
            .unwrap();

        let result = engine.discover("file", 2, None, &|_| true).unwrap();
        assert!(result.tools.len() <= 2);
    }

    #[test]
    fn test_discover_config_max_results_caps() {
        let mut config = test_config();
        config.max_results = 2;
        let engine = DiscoveryEngine::new(config);
        engine
            .ingest_tools_list("srv", &make_tools_list_response())
            .unwrap();

        // Request 10 but config caps at 2
        let result = engine.discover("file", 10, None, &|_| true).unwrap();
        assert!(result.tools.len() <= 2);
    }

    #[test]
    fn test_discover_token_budget() {
        let engine = DiscoveryEngine::new(test_config());
        engine
            .ingest_tools_list("srv", &make_tools_list_response())
            .unwrap();

        // Very small budget — should limit results
        let result = engine.discover("file", 5, Some(50), &|_| true).unwrap();
        // With a 50-token budget, we should get at most a few tools
        assert!(result.tools.len() <= 3);
    }

    #[test]
    fn test_discover_ttl_from_config() {
        let mut config = test_config();
        config.default_ttl_secs = 600;
        let engine = DiscoveryEngine::new(config);
        engine
            .ingest_tools_list("srv", &make_tools_list_response())
            .unwrap();

        let result = engine.discover("file", 5, None, &|_| true).unwrap();
        for tool in &result.tools {
            assert_eq!(tool.ttl_secs, 600);
        }
    }

    #[test]
    fn test_discover_scores_bounded() {
        let engine = DiscoveryEngine::new(test_config());
        engine
            .ingest_tools_list("srv", &make_tools_list_response())
            .unwrap();

        let result = engine.discover("file", 10, None, &|_| true).unwrap();
        for tool in &result.tools {
            assert!(
                tool.relevance_score >= 0.0 && tool.relevance_score <= 1.0,
                "Score out of bounds: {}",
                tool.relevance_score
            );
        }
    }

    // ── Sensitivity inference ───────────────────────────────────────────

    #[test]
    fn test_infer_sensitivity_high() {
        assert_eq!(
            infer_sensitivity("delete_file", "Delete a file"),
            ToolSensitivity::High
        );
        assert_eq!(
            infer_sensitivity("exec", "Execute command"),
            ToolSensitivity::High
        );
        assert_eq!(
            infer_sensitivity("get_secret", "Fetch secret"),
            ToolSensitivity::High
        );
    }

    #[test]
    fn test_infer_sensitivity_medium() {
        assert_eq!(
            infer_sensitivity("write_file", "Write to file"),
            ToolSensitivity::Medium
        );
        assert_eq!(
            infer_sensitivity("create_user", "Create new user"),
            ToolSensitivity::Medium
        );
        assert_eq!(
            infer_sensitivity("upload", "Upload data"),
            ToolSensitivity::Medium
        );
    }

    #[test]
    fn test_infer_sensitivity_low() {
        assert_eq!(
            infer_sensitivity("read_file", "Read file contents"),
            ToolSensitivity::Low
        );
        assert_eq!(
            infer_sensitivity("list", "List items"),
            ToolSensitivity::Low
        );
        assert_eq!(
            infer_sensitivity("search", "Search for data"),
            ToolSensitivity::Low
        );
    }

    // ── Domain tag inference ────────────────────────────────────────────

    #[test]
    fn test_infer_domain_tags_filesystem() {
        let tags = infer_domain_tags("read_file", "Read a file from disk");
        assert!(tags.contains(&"filesystem".to_string()));
    }

    #[test]
    fn test_infer_domain_tags_network() {
        let tags = infer_domain_tags("http_get", "Fetch URL via HTTP");
        assert!(tags.contains(&"network".to_string()));
    }

    #[test]
    fn test_infer_domain_tags_database() {
        let tags = infer_domain_tags("sql_query", "Execute SQL query on database");
        assert!(tags.contains(&"database".to_string()));
    }

    #[test]
    fn test_infer_domain_tags_multiple() {
        let tags = infer_domain_tags("upload_file", "Upload a file via HTTP to cloud");
        assert!(tags.contains(&"filesystem".to_string()));
        assert!(tags.contains(&"network".to_string()));
    }

    #[test]
    fn test_infer_domain_tags_none() {
        let tags = infer_domain_tags("noop", "Does nothing useful");
        assert!(tags.is_empty());
    }

    // ── Schema hash ─────────────────────────────────────────────────────

    #[test]
    fn test_compute_schema_hash_deterministic() {
        let schema = json!({"type": "object", "properties": {"a": {"type": "string"}}});
        let hash1 = compute_schema_hash(&schema);
        let hash2 = compute_schema_hash(&schema);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_compute_schema_hash_different_schemas() {
        let schema1 = json!({"type": "object"});
        let schema2 = json!({"type": "array"});
        assert_ne!(compute_schema_hash(&schema1), compute_schema_hash(&schema2));
    }

    // ── Index stats ─────────────────────────────────────────────────────

    #[test]
    fn test_index_stats_empty() {
        let engine = DiscoveryEngine::new(test_config());
        let stats = engine.index_stats().unwrap();
        assert_eq!(stats.total_tools, 0);
        assert_eq!(stats.max_capacity, 1000);
    }

    #[test]
    fn test_index_stats_after_ingest() {
        let engine = DiscoveryEngine::new(test_config());
        engine
            .ingest_tools_list("srv", &make_tools_list_response())
            .unwrap();
        let stats = engine.index_stats().unwrap();
        assert_eq!(stats.total_tools, 5);
    }
}
