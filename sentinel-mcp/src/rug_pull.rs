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
    }
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
        let name = match tool.get("name").and_then(|n| n.as_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        current_tool_names.insert(name.clone());

        let annotations = if let Some(ann) = tool.get("annotations") {
            parse_annotations(ann)
        } else {
            ToolAnnotations::default()
        };

        // Annotation change detection
        if let Some(prev) = known.get(&name) {
            if *prev != annotations {
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
}
