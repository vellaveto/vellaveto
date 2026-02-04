//! Shared rug-pull detection logic for MCP proxies.
//!
//! Rug-pull attacks manipulate tool annotations or tool lists between
//! `tools/list` responses. This module provides a unified detection
//! algorithm used by both the stdio and HTTP proxy implementations.
//!
//! Three attack types are detected:
//! 1. **Annotation changes** — tool claims different capabilities than before
//! 2. **Tool additions** — new tools appear after the initial `tools/list`
//! 3. **Tool removals** — known tools disappear from `tools/list`

use sentinel_audit::AuditLogger;
use sentinel_types::{Action, Verdict};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Tool annotations extracted from `tools/list` responses.
///
/// Per MCP spec 2025-11-25, these are behavioral hints from the server.
/// **IMPORTANT:** Annotations MUST be treated as untrusted unless the server is trusted.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ToolAnnotations {
    #[serde(default)]
    pub read_only_hint: bool,
    #[serde(default = "default_true")]
    pub destructive_hint: bool,
    #[serde(default)]
    pub idempotent_hint: bool,
    #[serde(default = "default_true")]
    pub open_world_hint: bool,
    /// SHA-256 hash of the tool's `inputSchema` JSON for rug-pull schema change detection.
    /// `None` when no `inputSchema` was present in the tool definition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema_hash: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for ToolAnnotations {
    fn default() -> Self {
        Self {
            read_only_hint: false,
            destructive_hint: true,
            idempotent_hint: false,
            open_world_hint: true,
            input_schema_hash: None,
        }
    }
}

/// Result of rug-pull detection analysis on a `tools/list` response.
#[derive(Debug, Default)]
pub struct RugPullResult {
    /// Tools whose annotations changed since last `tools/list`.
    pub changed_tools: Vec<String>,
    /// Tools that appeared after the initial `tools/list`.
    pub new_tools: Vec<String>,
    /// Tools that disappeared from `tools/list`.
    pub removed_tools: Vec<String>,
    /// Updated map of tool name → annotations (replaces the previous known state).
    pub updated_known: HashMap<String, ToolAnnotations>,
    /// Total number of tools in the current response.
    pub tool_count: usize,
}

impl RugPullResult {
    /// Tools that should be flagged for blocking (changed + newly added).
    pub fn flagged_tool_names(&self) -> Vec<&str> {
        self.changed_tools
            .iter()
            .chain(self.new_tools.iter())
            .map(|s| s.as_str())
            .collect()
    }

    /// Whether any rug-pull indicators were detected.
    pub fn has_detections(&self) -> bool {
        !self.changed_tools.is_empty()
            || !self.new_tools.is_empty()
            || !self.removed_tools.is_empty()
    }
}

/// Parse tool annotations from a JSON annotation object.
///
/// Uses MCP spec 2025-11-25 defaults when fields are absent.
pub fn parse_annotations(ann: &serde_json::Value) -> ToolAnnotations {
    ToolAnnotations {
        read_only_hint: ann
            .get("readOnlyHint")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        destructive_hint: ann
            .get("destructiveHint")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        idempotent_hint: ann
            .get("idempotentHint")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        open_world_hint: ann
            .get("openWorldHint")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        // Schema hash is computed separately in detect_rug_pull from the
        // tool's inputSchema field, not from annotations.
        input_schema_hash: None,
    }
}

/// Compute a SHA-256 hash of a JSON value's canonical string representation.
///
/// Used to fingerprint `inputSchema` for rug-pull schema change detection.
/// Returns `None` if the value is `Null`.
pub fn compute_schema_hash(schema: &serde_json::Value) -> Option<String> {
    if schema.is_null() {
        return None;
    }
    // serde_json::to_string produces deterministic output for the same Value
    // because serde_json::Value normalises the JSON structure.
    let canonical = serde_json::to_string(schema).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    Some(format!("{:x}", digest))
}

/// Analyze a `tools/list` response for rug-pull indicators.
///
/// Compares the current response against previously known tool annotations.
/// Returns a [`RugPullResult`] describing all detected changes.
///
/// # Arguments
/// - `response` — the full JSON-RPC response (must have `result.tools` array)
/// - `known` — previously known tool annotations (empty on first call)
/// - `is_first_list` — whether this is the initial `tools/list` for this session
pub fn detect_rug_pull(
    response: &serde_json::Value,
    known: &HashMap<String, ToolAnnotations>,
    is_first_list: bool,
) -> RugPullResult {
    let tools = match response
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
    {
        Some(tools) => tools,
        None => return RugPullResult::default(),
    };

    let mut result = RugPullResult {
        tool_count: tools.len(),
        ..Default::default()
    };
    let mut current_tool_names = HashSet::new();
    let mut updated_known = known.clone();

    for tool in tools {
        // SECURITY: Normalize tool names to prevent Unicode homoglyph bypass.
        // Without normalization, a server could use "bаsh" (Cyrillic 'а') to
        // evade flagging of "bash" (Latin 'a'). Same normalization as
        // classify_message() for consistency.
        let name = match tool.get("name").and_then(|n| n.as_str()) {
            Some(n) => crate::extractor::normalize_method(n),
            None => continue,
        };

        current_tool_names.insert(name.clone());

        let mut annotations = if let Some(ann) = tool.get("annotations") {
            parse_annotations(ann)
        } else {
            ToolAnnotations::default()
        };

        // Compute inputSchema hash for schema change detection (Phase 4C)
        if let Some(schema) = tool.get("inputSchema") {
            annotations.input_schema_hash = compute_schema_hash(schema);
        }

        // Annotation change detection (includes inputSchema hash via PartialEq)
        if let Some(prev) = known.get(&name) {
            if *prev != annotations {
                // Log specific schema change if applicable
                if prev.input_schema_hash != annotations.input_schema_hash {
                    tracing::warn!(
                        "SECURITY: Tool '{}' inputSchema changed! \
                         Previous hash: {:?}, Current hash: {:?}. \
                         This may indicate a rug-pull schema attack.",
                        name,
                        prev.input_schema_hash,
                        annotations.input_schema_hash,
                    );
                }
                result.changed_tools.push(name.clone());
                tracing::warn!(
                    "SECURITY: Tool '{}' annotations changed! Previous: {:?}, Current: {:?}. \
                     This may indicate a rug-pull attack.",
                    name,
                    prev,
                    annotations
                );
            }
        } else if !is_first_list {
            // New tool added after initial tools/list — suspicious
            result.new_tools.push(name.clone());
            tracing::warn!(
                "SECURITY: New tool '{}' appeared after initial tools/list. \
                 This may indicate a tool injection attack.",
                name,
            );
        }

        updated_known.insert(name, annotations);
    }

    // Detect removed tools (present in known but absent from current response)
    if !is_first_list {
        for prev_name in known.keys() {
            if !current_tool_names.contains(prev_name) {
                result.removed_tools.push(prev_name.clone());
                tracing::warn!(
                    "SECURITY: Tool '{}' was removed from tools/list. \
                     This may indicate a rug-pull attack (tool removal).",
                    prev_name,
                );
            }
        }
        for name in &result.removed_tools {
            updated_known.remove(name);
        }
    }

    result.updated_known = updated_known;

    tracing::info!(
        "tools/list: {} tools, {} new, {} changed, {} removed",
        result.tool_count,
        result.new_tools.len(),
        result.changed_tools.len(),
        result.removed_tools.len(),
    );

    result
}

/// Audit rug-pull detection events to the audit log.
///
/// Creates separate audit entries for annotation changes, tool removals,
/// and tool additions. Each event is logged as a `Verdict::Deny` with
/// the `sentinel` tool namespace.
///
/// # Arguments
/// - `result` — the detection result from [`detect_rug_pull`]
/// - `audit` — the audit logger
/// - `source` — identifier for the proxy type (e.g., `"proxy"` or `"http_proxy"`)
pub async fn audit_rug_pull_events(result: &RugPullResult, audit: &AuditLogger, source: &str) {
    if !result.changed_tools.is_empty() {
        let action = Action::new(
            "sentinel",
            "tool_annotation_change",
            json!({
                "changed_tools": result.changed_tools,
                "total_tools": result.tool_count,
            }),
        );
        let verdict = Verdict::Deny {
            reason: format!(
                "Tool annotation change detected for: {}",
                result.changed_tools.join(", ")
            ),
        };
        if let Err(e) = audit
            .log_entry(
                &action,
                &verdict,
                json!({"source": source, "event": "rug_pull_annotation_change"}),
            )
            .await
        {
            tracing::warn!("Failed to audit annotation change: {}", e);
        }
    }

    if !result.removed_tools.is_empty() {
        let action = Action::new(
            "sentinel",
            "tool_removal_detected",
            json!({
                "removed_tools": result.removed_tools,
                "remaining_tools": result.tool_count,
            }),
        );
        let verdict = Verdict::Deny {
            reason: format!("Tool removal detected: {}", result.removed_tools.join(", ")),
        };
        if let Err(e) = audit
            .log_entry(
                &action,
                &verdict,
                json!({"source": source, "event": "rug_pull_tool_removal"}),
            )
            .await
        {
            tracing::warn!("Failed to audit tool removal: {}", e);
        }
    }

    if !result.new_tools.is_empty() {
        let action = Action::new(
            "sentinel",
            "tool_addition_detected",
            json!({
                "new_tools": result.new_tools,
                "total_tools": result.tool_count,
            }),
        );
        let verdict = Verdict::Deny {
            reason: format!(
                "New tool added after initial tools/list: {}",
                result.new_tools.join(", ")
            ),
        };
        if let Err(e) = audit
            .log_entry(
                &action,
                &verdict,
                json!({"source": source, "event": "rug_pull_tool_addition"}),
            )
            .await
        {
            tracing::warn!("Failed to audit tool addition: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_annotations_defaults() {
        let ann = json!({});
        let result = parse_annotations(&ann);
        assert_eq!(result, ToolAnnotations::default());
    }

    #[test]
    fn test_parse_annotations_custom() {
        let ann = json!({
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false,
        });
        let result = parse_annotations(&ann);
        assert!(result.read_only_hint);
        assert!(!result.destructive_hint);
        assert!(result.idempotent_hint);
        assert!(!result.open_world_hint);
    }

    #[test]
    fn test_detect_first_list_no_detections() {
        let response = json!({
            "result": {
                "tools": [
                    {"name": "read_file", "annotations": {"readOnlyHint": true}},
                    {"name": "write_file"},
                ]
            }
        });
        let known = HashMap::new();
        let result = detect_rug_pull(&response, &known, true);

        assert!(result.changed_tools.is_empty());
        assert!(result.new_tools.is_empty());
        assert!(result.removed_tools.is_empty());
        assert_eq!(result.tool_count, 2);
        assert_eq!(result.updated_known.len(), 2);
        assert!(!result.has_detections());
    }

    #[test]
    fn test_detect_annotation_change() {
        let mut known = HashMap::new();
        known.insert(
            "write_file".to_string(),
            ToolAnnotations {
                read_only_hint: false,
                destructive_hint: true,
                idempotent_hint: false,
                open_world_hint: true,
                input_schema_hash: None,
            },
        );

        // Same tool now claims to be read-only
        let response = json!({
            "result": {
                "tools": [
                    {"name": "write_file", "annotations": {"readOnlyHint": true, "destructiveHint": false}},
                ]
            }
        });
        let result = detect_rug_pull(&response, &known, false);

        assert_eq!(result.changed_tools, vec!["write_file"]);
        assert!(result.new_tools.is_empty());
        assert!(result.removed_tools.is_empty());
        assert!(result.has_detections());
        assert_eq!(result.flagged_tool_names(), vec!["write_file"]);
    }

    #[test]
    fn test_detect_tool_addition() {
        let mut known = HashMap::new();
        known.insert("read_file".to_string(), ToolAnnotations::default());

        let response = json!({
            "result": {
                "tools": [
                    {"name": "read_file"},
                    {"name": "exec_shell"},
                ]
            }
        });
        let result = detect_rug_pull(&response, &known, false);

        assert!(result.changed_tools.is_empty());
        assert_eq!(result.new_tools, vec!["exec_shell"]);
        assert!(result.removed_tools.is_empty());
        assert_eq!(result.flagged_tool_names(), vec!["exec_shell"]);
    }

    #[test]
    fn test_detect_tool_removal() {
        let mut known = HashMap::new();
        known.insert("read_file".to_string(), ToolAnnotations::default());
        known.insert("write_file".to_string(), ToolAnnotations::default());

        let response = json!({
            "result": {
                "tools": [
                    {"name": "read_file"},
                ]
            }
        });
        let result = detect_rug_pull(&response, &known, false);

        assert!(result.changed_tools.is_empty());
        assert!(result.new_tools.is_empty());
        assert_eq!(result.removed_tools, vec!["write_file"]);
        assert!(result.has_detections());
        // Removed tools are NOT flagged (they're gone), only changed/new are
        assert!(result.flagged_tool_names().is_empty());
    }

    #[test]
    fn test_detect_no_tools_in_response() {
        let response = json!({"result": {}});
        let known = HashMap::new();
        let result = detect_rug_pull(&response, &known, true);

        assert!(!result.has_detections());
        assert_eq!(result.tool_count, 0);
    }

    #[test]
    fn test_detect_combined_attacks() {
        let mut known = HashMap::new();
        known.insert(
            "safe_tool".to_string(),
            ToolAnnotations {
                read_only_hint: true,
                ..Default::default()
            },
        );
        known.insert("vanishing_tool".to_string(), ToolAnnotations::default());

        let response = json!({
            "result": {
                "tools": [
                    {"name": "safe_tool", "annotations": {"readOnlyHint": false}},
                    {"name": "new_evil_tool"},
                ]
            }
        });
        let result = detect_rug_pull(&response, &known, false);

        assert_eq!(result.changed_tools, vec!["safe_tool"]);
        assert_eq!(result.new_tools, vec!["new_evil_tool"]);
        assert_eq!(result.removed_tools, vec!["vanishing_tool"]);
        assert!(result.has_detections());

        let flagged: Vec<&str> = result.flagged_tool_names();
        assert!(flagged.contains(&"safe_tool"));
        assert!(flagged.contains(&"new_evil_tool"));
        assert!(!flagged.contains(&"vanishing_tool"));
    }

    // --- Phase 4C: Schema change detection tests ---

    #[test]
    fn test_schema_change_detected() {
        // First tools/list: tool has an inputSchema
        let response1 = json!({
            "result": {
                "tools": [{
                    "name": "run_query",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"}
                        }
                    },
                    "annotations": {"readOnlyHint": true}
                }]
            }
        });
        let known = HashMap::new();
        let result1 = detect_rug_pull(&response1, &known, true);
        assert!(!result1.has_detections());

        // Verify the schema hash was stored
        let ann = result1
            .updated_known
            .get("run_query")
            .expect("tool should be in known");
        assert!(ann.input_schema_hash.is_some(), "Schema hash should be set");

        // Second tools/list: same tool but different inputSchema (rug-pull!)
        let response2 = json!({
            "result": {
                "tools": [{
                    "name": "run_query",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "target_url": {"type": "string"}
                        }
                    },
                    "annotations": {"readOnlyHint": true}
                }]
            }
        });
        let result2 = detect_rug_pull(&response2, &result1.updated_known, false);

        assert!(result2.has_detections(), "Schema change should be detected");
        assert_eq!(result2.changed_tools, vec!["run_query"]);
    }

    #[test]
    fn test_same_schema_not_flagged() {
        // First tools/list
        let response = json!({
            "result": {
                "tools": [{
                    "name": "run_query",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"}
                        }
                    },
                    "annotations": {"readOnlyHint": true}
                }]
            }
        });
        let known = HashMap::new();
        let result1 = detect_rug_pull(&response, &known, true);
        assert!(!result1.has_detections());

        // Second tools/list: identical schema and annotations
        let result2 = detect_rug_pull(&response, &result1.updated_known, false);
        assert!(
            !result2.has_detections(),
            "Identical schema should not be flagged"
        );
        assert!(result2.changed_tools.is_empty());
    }

    #[test]
    fn test_schema_hash_computation_correct() {
        let schema1 = json!({"type": "object", "properties": {"query": {"type": "string"}}});
        let schema2 = json!({"type": "object", "properties": {"query": {"type": "string"}}});
        let schema3 = json!({"type": "object", "properties": {"url": {"type": "string"}}});

        let hash1 = compute_schema_hash(&schema1);
        let hash2 = compute_schema_hash(&schema2);
        let hash3 = compute_schema_hash(&schema3);

        // Same schema should produce same hash (deterministic)
        assert_eq!(
            hash1, hash2,
            "Identical schemas should produce the same hash"
        );

        // Different schema should produce different hash
        assert_ne!(
            hash1, hash3,
            "Different schemas should produce different hashes"
        );

        // Null schema should return None
        let null_hash = compute_schema_hash(&serde_json::Value::Null);
        assert!(null_hash.is_none(), "Null schema should return None");

        // Hash should be a hex string
        let h = hash1.expect("hash should be Some");
        assert_eq!(h.len(), 64, "SHA-256 hex string should be 64 chars");
        assert!(
            h.chars().all(|c| c.is_ascii_hexdigit()),
            "Hash should be hex"
        );
    }

    // --- Unicode normalization tests ---

    #[test]
    fn test_zero_width_char_tool_name_normalized() {
        // First tools/list: "bash" (clean)
        let response1 = json!({
            "result": {
                "tools": [
                    {"name": "bash", "annotations": {"readOnlyHint": false}},
                ]
            }
        });
        let known = HashMap::new();
        let result1 = detect_rug_pull(&response1, &known, true);
        assert!(!result1.has_detections());
        assert!(result1.updated_known.contains_key("bash"));

        // Second tools/list: "bash\u{200B}" (zero-width space injected)
        // Should normalize to "bash" and NOT be detected as a new tool
        let response2 = json!({
            "result": {
                "tools": [
                    {"name": "bash\u{200B}", "annotations": {"readOnlyHint": false}},
                ]
            }
        });
        let result2 = detect_rug_pull(&response2, &result1.updated_known, false);
        assert!(
            !result2.has_detections(),
            "Zero-width char variant should normalize to same tool name"
        );
    }

    #[test]
    fn test_case_variant_tool_name_normalized() {
        // First tools/list: "ReadFile"
        let response1 = json!({
            "result": {
                "tools": [
                    {"name": "ReadFile", "annotations": {"readOnlyHint": true}},
                ]
            }
        });
        let known = HashMap::new();
        let result1 = detect_rug_pull(&response1, &known, true);
        assert!(!result1.has_detections());
        // Stored as normalized lowercase
        assert!(result1.updated_known.contains_key("readfile"));

        // Second tools/list: "readfile" (different case)
        // Should normalize to same key and NOT be detected as new
        let response2 = json!({
            "result": {
                "tools": [
                    {"name": "readfile", "annotations": {"readOnlyHint": true}},
                ]
            }
        });
        let result2 = detect_rug_pull(&response2, &result1.updated_known, false);
        assert!(
            !result2.has_detections(),
            "Case variant should normalize to same tool name"
        );
    }

    #[test]
    fn test_annotation_change_detected_after_normalization() {
        // First tools/list: "BASH" with readOnly=false
        let response1 = json!({
            "result": {
                "tools": [
                    {"name": "BASH", "annotations": {"readOnlyHint": false}},
                ]
            }
        });
        let known = HashMap::new();
        let result1 = detect_rug_pull(&response1, &known, true);

        // Second tools/list: "bash\u{200B}" with readOnly=true (rug-pull!)
        // Normalization should map to same name, and annotation change should be detected
        let response2 = json!({
            "result": {
                "tools": [
                    {"name": "bash\u{200B}", "annotations": {"readOnlyHint": true}},
                ]
            }
        });
        let result2 = detect_rug_pull(&response2, &result1.updated_known, false);
        assert!(
            result2.has_detections(),
            "Annotation change should be detected despite Unicode variant"
        );
        assert_eq!(result2.changed_tools, vec!["bash"]);
    }

    #[test]
    fn test_flagged_names_are_normalized() {
        let mut known = HashMap::new();
        known.insert("bash".to_string(), ToolAnnotations::default());

        // New tool with zero-width chars should be flagged with normalized name
        let response = json!({
            "result": {
                "tools": [
                    {"name": "bash"},
                    {"name": "Evil\u{200B}Tool"},
                ]
            }
        });
        let result = detect_rug_pull(&response, &known, false);
        let flagged = result.flagged_tool_names();
        // The flagged name should be normalized (lowercase, no zero-width)
        assert!(
            flagged.contains(&"evil\u{200b}tool") || flagged.contains(&"eviltool"),
            "Flagged name should be normalized: {:?}",
            flagged
        );
    }
}
