//! Shared rug-pull and tool squatting detection logic for MCP proxies.
//!
//! Rug-pull attacks manipulate tool annotations or tool lists between
//! `tools/list` responses. This module provides a unified detection
//! algorithm used by both the stdio and HTTP proxy implementations.
//!
//! Four attack types are detected:
//! 1. **Annotation changes** — tool claims different capabilities than before
//! 2. **Tool additions** — new tools appear after the initial `tools/list`
//! 3. **Tool removals** — known tools disappear from `tools/list`
//! 4. **Tool squatting** — tool names similar to known tools (Levenshtein/homoglyph)

use sentinel_audit::AuditLogger;
use sentinel_types::{Action, Verdict};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

// ── Tool Squatting Detection Types ─────────────────────

/// Kind of tool squatting detected.
#[derive(Debug, Clone, PartialEq)]
pub enum SquattingKind {
    /// Tool name is within Levenshtein edit distance of a known tool.
    Levenshtein,
    /// Tool name matches a known tool after homoglyph normalization.
    Homoglyph,
}

/// Alert for a suspected squatting tool.
#[derive(Debug, Clone)]
pub struct SquattingAlert {
    /// The suspicious tool name (as received).
    pub suspicious_tool: String,
    /// The known tool it resembles.
    pub similar_to: String,
    /// Edit distance (0 for homoglyph matches).
    pub distance: usize,
    /// Type of squatting detected.
    pub kind: SquattingKind,
}

/// Default well-known tool names to detect squatting against.
pub const DEFAULT_KNOWN_TOOLS: &[&str] = &[
    "read_file",
    "write_file",
    "edit_file",
    "list_files",
    "search_files",
    "bash",
    "execute",
    "run_command",
    "shell",
    "terminal",
    "read",
    "write",
    "delete",
    "create_file",
    "move_file",
    "copy_file",
    "http_request",
    "fetch",
    "curl",
    "download",
    "upload",
    "send_email",
    "database_query",
    "sql_query",
    "list_directory",
    "get_url",
    "post_url",
    "execute_command",
    "run_script",
    "eval",
];

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
    /// Updated map of tool name -> annotations (replaces the previous known state).
    pub updated_known: HashMap<String, ToolAnnotations>,
    /// Total number of tools in the current response.
    pub tool_count: usize,
    /// Tool squatting alerts detected during analysis.
    pub squatting_alerts: Vec<SquattingAlert>,
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

    /// Whether any rug-pull or squatting indicators were detected.
    pub fn has_detections(&self) -> bool {
        !self.changed_tools.is_empty()
            || !self.new_tools.is_empty()
            || !self.removed_tools.is_empty()
            || !self.squatting_alerts.is_empty()
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
/// - `response` -- the full JSON-RPC response (must have `result.tools` array)
/// - `known` -- previously known tool annotations (empty on first call)
/// - `is_first_list` -- whether this is the initial `tools/list` for this session
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
        // Without normalization, a server could use "bash" (Cyrillic 'a') to
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
            // New tool added after initial tools/list -- suspicious
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
/// tool additions, and squatting alerts. Each event is logged as a
/// `Verdict::Deny` with the `sentinel` tool namespace.
///
/// # Arguments
/// - `result` -- the detection result from [`detect_rug_pull`]
/// - `audit` -- the audit logger
/// - `source` -- identifier for the proxy type (e.g., `"proxy"` or `"http_proxy"`)
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

    if !result.squatting_alerts.is_empty() {
        let squatting_names: Vec<&str> = result
            .squatting_alerts
            .iter()
            .map(|a| a.suspicious_tool.as_str())
            .collect();
        let action = Action::new(
            "sentinel",
            "tool_squatting_detected",
            json!({
                "suspicious_tools": squatting_names,
                "alerts": result.squatting_alerts.iter().map(|a| {
                    json!({
                        "suspicious": &a.suspicious_tool,
                        "similar_to": &a.similar_to,
                        "distance": a.distance,
                        "kind": format!("{:?}", a.kind),
                    })
                }).collect::<Vec<_>>(),
            }),
        );
        let verdict = Verdict::Deny {
            reason: format!("Tool squatting detected: {}", squatting_names.join(", ")),
        };
        if let Err(e) = audit
            .log_entry(
                &action,
                &verdict,
                json!({"source": source, "event": "tool_squatting"}),
            )
            .await
        {
            tracing::warn!("Failed to audit tool squatting: {}", e);
        }
    }
}

// ── Tool Squatting Detection ─────────────────────

/// Compute Levenshtein edit distance between two strings.
fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();
    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0usize; b_len + 1];

    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1)
                .min(curr[j] + 1)
                .min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b_len]
}

/// Map common Unicode confusables to their ASCII equivalents.
/// Covers Cyrillic, Greek, and other common homoglyphs.
fn normalize_homoglyphs(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            // Cyrillic confusables
            '\u{0430}' => 'a', // Cyrillic a -> a
            '\u{0435}' => 'e', // Cyrillic ie -> e
            '\u{043E}' => 'o', // Cyrillic o -> o
            '\u{0440}' => 'p', // Cyrillic er -> p
            '\u{0441}' => 'c', // Cyrillic es -> c
            '\u{0443}' => 'y', // Cyrillic u -> y
            '\u{0445}' => 'x', // Cyrillic ha -> x
            '\u{0456}' => 'i', // Cyrillic i -> i
            '\u{0458}' => 'j', // Cyrillic je -> j
            '\u{04BB}' => 'h', // Cyrillic shha -> h
            '\u{0455}' => 's', // Cyrillic dze -> s
            '\u{0410}' => 'a', // Cyrillic A -> a (uppercase Cyrillic)
            '\u{0412}' => 'b', // Cyrillic Ve -> b
            '\u{0415}' => 'e', // Cyrillic Ie -> e
            '\u{041D}' => 'h', // Cyrillic En -> h
            '\u{041E}' => 'o', // Cyrillic O -> o
            '\u{0420}' => 'p', // Cyrillic Er -> p
            '\u{0421}' => 'c', // Cyrillic Es -> c
            '\u{0422}' => 't', // Cyrillic Te -> t
            '\u{0425}' => 'x', // Cyrillic Ha -> x
            // Greek confusables
            '\u{03B1}' => 'a', // alpha -> a
            '\u{03BF}' => 'o', // omicron -> o
            '\u{03C1}' => 'p', // rho -> p
            '\u{03B5}' => 'e', // epsilon -> e
            // Other common confusables
            '\u{0131}' => 'i', // dotless i -> i
            '\u{1D00}' => 'a', // small capital A -> a
            '\u{0261}' => 'g', // latin small letter script g -> g
            '\u{01C0}' => 'l', // latin letter dental click -> l
            other => other,
        })
        .collect()
}

/// Detect tool names suspiciously similar to known tools.
///
/// Checks for:
/// 1. **Levenshtein distance <= 2**: Tools within 2 edits of a known tool
/// 2. **Homoglyph collision**: Tools that match a known tool after Unicode normalization
///
/// Exact matches are NOT flagged (the tool IS the known tool).
pub fn detect_squatting(tool_name: &str, known_tools: &HashSet<String>) -> Vec<SquattingAlert> {
    let mut alerts = Vec::new();
    let normalized = crate::extractor::normalize_method(tool_name);

    // Skip if the tool IS a known tool (exact match after normalization)
    if known_tools.contains(&normalized) {
        return alerts;
    }

    // Check homoglyph normalization
    let homoglyph_normalized = normalize_homoglyphs(&normalized);
    for known in known_tools {
        if homoglyph_normalized == *known && normalized != *known {
            alerts.push(SquattingAlert {
                suspicious_tool: tool_name.to_string(),
                similar_to: known.clone(),
                distance: 0,
                kind: SquattingKind::Homoglyph,
            });
            // Don't also report Levenshtein for the same known tool
            continue;
        }
    }

    // Check Levenshtein distance
    // Skip very short names (<=2 chars) as too many false positives
    if normalized.len() > 2 {
        for known in known_tools {
            // Already reported as homoglyph
            if alerts.iter().any(|a| a.similar_to == *known) {
                continue;
            }
            // Quick length check to skip obvious non-matches
            let len_diff =
                (normalized.len() as isize - known.len() as isize).unsigned_abs();
            if len_diff > 2 {
                continue;
            }
            let dist = levenshtein(&normalized, known);
            if dist > 0 && dist <= 2 {
                alerts.push(SquattingAlert {
                    suspicious_tool: tool_name.to_string(),
                    similar_to: known.clone(),
                    distance: dist,
                    kind: SquattingKind::Levenshtein,
                });
            }
        }
    }

    alerts
}

/// Build the set of known tool names from defaults + config overrides.
pub fn build_known_tools(config_tools: &[String]) -> HashSet<String> {
    let mut tools: HashSet<String> = DEFAULT_KNOWN_TOOLS
        .iter()
        .map(|s| s.to_string())
        .collect();
    for t in config_tools {
        tools.insert(t.to_lowercase());
    }
    tools
}

/// Analyze a `tools/list` response for rug-pull AND squatting indicators.
///
/// Like [`detect_rug_pull`], but also checks tool names against known tools
/// for squatting detection.
pub fn detect_rug_pull_and_squatting(
    response: &serde_json::Value,
    known_annotations: &HashMap<String, ToolAnnotations>,
    is_first_list: bool,
    known_tools: &HashSet<String>,
) -> RugPullResult {
    let mut result = detect_rug_pull(response, known_annotations, is_first_list);

    // Run squatting detection on all tools in the response
    let tools = response
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array());

    if let Some(tools) = tools {
        for tool in tools {
            if let Some(name) = tool.get("name").and_then(|n| n.as_str()) {
                let squatting_alerts = detect_squatting(name, known_tools);
                for alert in &squatting_alerts {
                    tracing::warn!(
                        "SECURITY: Tool squatting detected: '{}' is suspicious \
                         -- similar to '{}' ({:?}, distance {})",
                        alert.suspicious_tool,
                        alert.similar_to,
                        alert.kind,
                        alert.distance
                    );
                }
                result.squatting_alerts.extend(squatting_alerts);
            }
        }
    }

    result
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

    // ── Tool Squatting Detection Tests ─────────────────────

    #[test]
    fn test_levenshtein_basic() {
        assert_eq!(super::levenshtein("kitten", "sitting"), 3);
        assert_eq!(super::levenshtein("", "abc"), 3);
        assert_eq!(super::levenshtein("abc", ""), 3);
        assert_eq!(super::levenshtein("abc", "abc"), 0);
        assert_eq!(super::levenshtein("read_file", "read_flie"), 2);
    }

    #[test]
    fn test_squatting_levenshtein_near_match() {
        let known = build_known_tools(&[]);
        let alerts = detect_squatting("read_flie", &known);
        assert!(!alerts.is_empty(), "read_flie should be flagged");
        assert!(alerts
            .iter()
            .any(|a| a.similar_to == "read_file" && a.kind == SquattingKind::Levenshtein));
    }

    #[test]
    fn test_squatting_levenshtein_far_enough() {
        let known = build_known_tools(&[]);
        let alerts = detect_squatting("completely_different_tool", &known);
        assert!(
            alerts.is_empty(),
            "Completely different name should not be flagged"
        );
    }

    #[test]
    fn test_squatting_homoglyph_cyrillic_a() {
        let known = build_known_tools(&[]);
        // "bash" with Cyrillic a (U+0430) instead of Latin a
        let alerts = detect_squatting("b\u{0430}sh", &known);
        assert!(
            !alerts.is_empty(),
            "Cyrillic 'a' in bash should be flagged"
        );
        assert!(alerts
            .iter()
            .any(|a| a.similar_to == "bash" && a.kind == SquattingKind::Homoglyph));
    }

    #[test]
    fn test_squatting_exact_match_not_flagged() {
        let known = build_known_tools(&[]);
        let alerts = detect_squatting("read_file", &known);
        assert!(alerts.is_empty(), "Exact match should NOT be flagged");
    }

    #[test]
    fn test_squatting_empty_known_tools_no_flags() {
        let known = HashSet::new();
        let alerts = detect_squatting("read_file", &known);
        assert!(alerts.is_empty(), "No known tools -> no flags");
    }

    #[test]
    fn test_squatting_case_normalized() {
        let known = build_known_tools(&[]);
        // "Read_File" normalizes to "read_file" which is an exact match -> not flagged
        let alerts = detect_squatting("Read_File", &known);
        assert!(
            alerts.is_empty(),
            "Case variant of known tool should not be flagged"
        );
    }

    #[test]
    fn test_squatting_combined_with_rug_pull() {
        let mut known_annotations = HashMap::new();
        known_annotations.insert("read_file".to_string(), ToolAnnotations::default());
        let known_tools = build_known_tools(&[]);

        let response = json!({
            "result": {
                "tools": [
                    {"name": "read_file", "annotations": {"readOnlyHint": false}},
                    {"name": "read_flie"},
                ]
            }
        });

        let result =
            detect_rug_pull_and_squatting(&response, &known_annotations, false, &known_tools);
        // Should detect both annotation change AND squatting
        assert!(result.has_detections());
        assert!(!result.changed_tools.is_empty() || !result.new_tools.is_empty());
        assert!(!result.squatting_alerts.is_empty());
    }

    #[test]
    fn test_squatting_custom_known_tools() {
        let known = build_known_tools(&["my_custom_tool".to_string()]);
        let alerts = detect_squatting("my_custum_tool", &known);
        assert!(
            !alerts.is_empty(),
            "Near match to custom tool should be flagged"
        );
    }

    #[test]
    fn test_squatting_short_names_not_flagged() {
        let known = build_known_tools(&[]);
        // Very short names (<=2 chars) should not trigger Levenshtein false positives
        let alerts = detect_squatting("ab", &known);
        assert!(
            alerts.is_empty(),
            "Very short names should not be flagged via Levenshtein"
        );
    }

    #[test]
    fn test_homoglyph_normalization() {
        // Cyrillic confusables
        assert_eq!(super::normalize_homoglyphs("b\u{0430}sh"), "bash");
        assert_eq!(super::normalize_homoglyphs("\u{0435}xec"), "exec");
        // Already ASCII stays the same
        assert_eq!(super::normalize_homoglyphs("bash"), "bash");
    }
}
