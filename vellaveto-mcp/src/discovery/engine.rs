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
            // SECURITY (FIND-R64-005): NaN scores from TF-IDF filtered out (fail-closed).
            if !score.is_finite() || score < min_score {
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

            // Estimate token cost (rough heuristic: 1 token ~ 4 chars of JSON)
            // SECURITY (FIND-R55-MCP-009): Log warning on serialization failure instead
            // of silently using empty string for token cost estimation.
            // SECURITY (FIND-R196-003): Truncate tool name in log output before
            // validation to prevent log injection from malicious MCP servers.
            // The raw `name` comes from untrusted input and may contain control
            // characters; truncation limits blast radius.
            let safe_name: String = name.chars().take(64).collect();
            let schema_str = match serde_json::to_string(&input_schema) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        "ingest_tools_list: failed to serialize input_schema for token cost of '{}': {}",
                        safe_name,
                        e
                    );
                    String::new()
                }
            };
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

            // SECURITY (FIND-R121-001): Validate metadata bounds before ingesting.
            // Without this, a malicious MCP server can send tools with multi-MB
            // name/description fields causing memory exhaustion during indexing.
            if let Err(e) = metadata.validate() {
                // SECURITY (FIND-R196-003): Use safe_name (truncated) in log output
                // instead of raw metadata.tool_id to prevent log injection.
                tracing::warn!(
                    "ingest_tools_list: skipping tool '{}:{}': {}",
                    server_id,
                    safe_name,
                    e
                );
                continue;
            }

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
///
/// SECURITY (FIND-R55-MCP-009): Logs a warning on serialization failure instead
/// of silently using an empty string, which would produce identical hashes for
/// all failing schemas (collision risk).
fn compute_schema_hash(schema: &Value) -> String {
    use sha2::{Digest, Sha256};
    let canonical = match serde_json::to_string(schema) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "compute_schema_hash: failed to serialize schema: {}; using empty canonical form",
                e
            );
            String::new()
        }
    };
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

    // SECURITY (FIND-R196-004): Use word-boundary matching instead of simple
    // substring matching. Without this, "key" matches "keyboard", "token"
    // matches "tokenizer", "sign" matches "design", causing false-positive
    // High sensitivity that blocks legitimate tools. Word boundary = adjacent
    // char is non-alphanumeric or start/end of string.
    if HIGH_KEYWORDS.iter().any(|kw| contains_word(&text, kw)) {
        return ToolSensitivity::High;
    }
    if MEDIUM_KEYWORDS.iter().any(|kw| contains_word(&text, kw)) {
        return ToolSensitivity::Medium;
    }
    ToolSensitivity::Low
}

/// Check if `text` contains `keyword` at a word boundary.
///
/// SECURITY (FIND-R196-004): A word boundary is any character that is not
/// an ASCII alphanumeric character (letters or digits). The text is expected
/// to be already lowercased. This prevents "key" from matching "keyboard",
/// "token" from matching "tokenizer", etc.
fn contains_word(text: &str, keyword: &str) -> bool {
    let text_bytes = text.as_bytes();
    let kw_len = keyword.len();
    for (i, _) in text.match_indices(keyword) {
        let left_ok = i == 0 || !text_bytes[i - 1].is_ascii_alphanumeric();
        let right_ok = i + kw_len >= text.len() || !text_bytes[i + kw_len].is_ascii_alphanumeric();
        if left_ok && right_ok {
            return true;
        }
    }
    false
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

    // SECURITY (FIND-R182-007): Use word-boundary matching instead of substring
    // to prevent false positives (e.g. "api" matching inside "capital").
    let words: Vec<&str> = text
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|s| !s.is_empty())
        .collect();

    for (keywords, tag) in DOMAIN_MAP {
        if keywords.iter().any(|kw| words.iter().any(|w| w == kw)) {
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

    // ── FIND-R196-004: Word-boundary matching ─────────────────────────

    #[test]
    fn test_infer_sensitivity_word_boundary_avoids_false_positives() {
        // "keyboard" should NOT match "key", "design" should NOT match "sign"
        assert_eq!(
            infer_sensitivity("keyboard_layout", "A keyboard design tool"),
            ToolSensitivity::Low
        );
        // "tokenizer" should NOT match "token"
        assert_eq!(
            infer_sensitivity("tokenizer", "Tokenize text strings"),
            ToolSensitivity::Low
        );
    }

    #[test]
    fn test_infer_sensitivity_word_boundary_detects_real_keywords() {
        // "key" as whole word in description
        assert_eq!(
            infer_sensitivity("get_api_key", "Fetch an API key"),
            ToolSensitivity::High
        );
        // "token" separated by underscore
        assert_eq!(
            infer_sensitivity("revoke_token", "Revoke auth token"),
            ToolSensitivity::High
        );
    }

    #[test]
    fn test_contains_word_basic() {
        assert!(contains_word("hello world", "hello"));
        assert!(contains_word("hello world", "world"));
        assert!(!contains_word("helloworld", "hello"));
        assert!(contains_word("get_key_here", "key"));
        assert!(!contains_word("keyboard", "key"));
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

    #[test]
    fn test_infer_domain_tags_no_substring_false_positive() {
        // FIND-R182-007: "api" must not match inside "capital", "row" must not
        // match inside "browse", "path" must not match inside "empathy".
        let tags = infer_domain_tags("capital_gain", "Browse results with empathy");
        assert!(
            !tags.contains(&"network".to_string()),
            "should not match 'api' inside 'capital'"
        );
        assert!(
            !tags.contains(&"database".to_string()),
            "should not match 'row' inside 'browse'"
        );
        assert!(
            !tags.contains(&"filesystem".to_string()),
            "should not match 'path' inside 'empathy'"
        );
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

    // ── FIND-R121-001: Validate metadata during ingestion ─────────────

    #[test]
    fn test_ingest_rejects_oversized_name() {
        let engine = DiscoveryEngine::new(test_config());
        let response = json!({
            "tools": [{
                "name": "x".repeat(257),
                "description": "normal description"
            }]
        });
        let count = engine.ingest_tools_list("srv", &response).unwrap();
        assert_eq!(count, 0, "oversized name should be rejected");
    }

    #[test]
    fn test_ingest_rejects_oversized_description() {
        let engine = DiscoveryEngine::new(test_config());
        let response = json!({
            "tools": [{
                "name": "valid_tool",
                "description": "x".repeat(4097)
            }]
        });
        let count = engine.ingest_tools_list("srv", &response).unwrap();
        assert_eq!(count, 0, "oversized description should be rejected");
    }

    #[test]
    fn test_ingest_accepts_at_limit_name() {
        let engine = DiscoveryEngine::new(test_config());
        let name = "x".repeat(256);
        let response = json!({
            "tools": [{
                "name": name,
                "description": "normal description"
            }]
        });
        let count = engine.ingest_tools_list("srv", &response).unwrap();
        assert_eq!(count, 1, "name at limit should be accepted");
    }

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

    // ── R227: Production wiring integration tests ─────────────────────

    /// R227: Verify that tools ingested from a JSON-RPC result payload
    /// (as extracted from `msg.get("result")` in `handle_tools_list_response`)
    /// appear in discovery search results.
    #[test]
    fn test_ingest_from_jsonrpc_result_searchable() {
        let engine = DiscoveryEngine::new(test_config());
        // Simulate the result payload extracted from a JSON-RPC response
        let result_payload = json!({
            "tools": [
                {
                    "name": "kubernetes_deploy",
                    "description": "Deploy a containerized application to a Kubernetes cluster",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "image": {"type": "string"},
                            "namespace": {"type": "string"}
                        }
                    }
                },
                {
                    "name": "slack_notify",
                    "description": "Send a notification message to a Slack channel",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "channel": {"type": "string"},
                            "message": {"type": "string"}
                        }
                    }
                }
            ]
        });
        let count = engine
            .ingest_tools_list("my_mcp_server", &result_payload)
            .unwrap();
        assert_eq!(count, 2);

        // Verify tools are discoverable via search
        let result = engine
            .discover("deploy kubernetes", 5, None, &|_| true)
            .unwrap();
        assert!(
            !result.tools.is_empty(),
            "kubernetes_deploy should be discoverable"
        );
        assert!(
            result
                .tools
                .iter()
                .any(|t| t.metadata.name == "kubernetes_deploy"),
            "Expected kubernetes_deploy in results"
        );

        // Verify server_id is set correctly
        let meta = engine
            .index()
            .get("my_mcp_server:kubernetes_deploy")
            .unwrap();
        assert!(meta.is_some());
        assert_eq!(meta.unwrap().server_id, "my_mcp_server");
    }

    /// R227: Multiple ingest calls from different servers should accumulate.
    #[test]
    fn test_ingest_multiple_servers_accumulates() {
        let engine = DiscoveryEngine::new(test_config());
        let server_a = json!({
            "tools": [{"name": "tool_a", "description": "Server A tool"}]
        });
        let server_b = json!({
            "tools": [{"name": "tool_b", "description": "Server B tool"}]
        });
        engine.ingest_tools_list("server_a", &server_a).unwrap();
        engine.ingest_tools_list("server_b", &server_b).unwrap();
        assert_eq!(engine.index_stats().unwrap().total_tools, 2);

        // Both tools discoverable
        let meta_a = engine.index().get("server_a:tool_a").unwrap();
        let meta_b = engine.index().get("server_b:tool_b").unwrap();
        assert!(meta_a.is_some());
        assert!(meta_b.is_some());
    }
}
