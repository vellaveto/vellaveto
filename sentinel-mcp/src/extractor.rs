//! Extract [`Action`] from MCP JSON-RPC tool call messages.
//!
//! MCP `tools/call` messages have this shape:
//! ```json
//! {
//!     "jsonrpc": "2.0",
//!     "id": 1,
//!     "method": "tools/call",
//!     "params": {
//!         "name": "read_file",
//!         "arguments": { "path": "/etc/passwd" }
//!     }
//! }
//! ```
//!
//! This module classifies messages and extracts the tool name + arguments
//! into a [`sentinel_types::Action`] for policy evaluation.

use sentinel_types::Action;
use serde_json::Value;

/// Classification of an MCP JSON-RPC message.
#[derive(Debug, Clone, PartialEq)]
pub enum MessageType {
    /// A `tools/call` request that should be policy-checked.
    ToolCall {
        id: Value,
        tool_name: String,
        arguments: Value,
    },
    /// A `resources/read` request that should be policy-checked.
    ResourceRead { id: Value, uri: String },
    /// An invalid request that should be rejected with an error response.
    Invalid { id: Value, reason: String },
    /// Any other message (notifications, responses, other methods).
    PassThrough,
}

/// Classify a JSON-RPC message.
///
/// Returns `ToolCall` for `"method": "tools/call"` requests with valid params.
/// Returns `ResourceRead` for `"method": "resources/read"` requests with a URI.
/// Returns `PassThrough` for everything else.
pub fn classify_message(msg: &Value) -> MessageType {
    let method = msg.get("method").and_then(|v| v.as_str());
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let params = msg.get("params");

    match method {
        Some("tools/call") => {
            let tool_name = params.and_then(|p| p.get("name")).and_then(|n| n.as_str());

            match tool_name {
                Some(name) if !name.is_empty() => {
                    let arguments = params
                        .and_then(|p| p.get("arguments"))
                        .cloned()
                        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));

                    MessageType::ToolCall {
                        id,
                        tool_name: name.to_string(),
                        arguments,
                    }
                }
                _ => MessageType::Invalid {
                    id,
                    reason: "tools/call missing or empty tool name".to_string(),
                },
            }
        }
        Some("resources/read") => {
            let uri = params
                .and_then(|p| p.get("uri"))
                .and_then(|u| u.as_str())
                .unwrap_or("")
                .to_string();

            MessageType::ResourceRead { id, uri }
        }
        _ => MessageType::PassThrough,
    }
}

/// Extract an [`Action`] from a classified tool call.
///
/// The `tool` field is set to the MCP tool name.
/// The `function` field is set to `"*"` (MCP tools don't have sub-functions).
/// The `parameters` field is the tool's arguments object.
pub fn extract_action(tool_name: &str, arguments: &Value) -> Action {
    Action {
        tool: tool_name.to_string(),
        function: "*".to_string(),
        parameters: arguments.clone(),
    }
}

/// Extract an [`Action`] from a `resources/read` URI.
///
/// The `tool` field is `"resources"`, `function` is `"read"`.
/// The `parameters` field contains:
/// - `uri`: the raw URI string
/// - `path`: extracted file path for `file://` URIs (for path constraint evaluation)
/// - `url`: the full URI for `http://`/`https://` URIs (for domain constraint evaluation)
pub fn extract_resource_action(uri: &str) -> Action {
    let mut params = serde_json::Map::new();
    params.insert("uri".to_string(), Value::String(uri.to_string()));

    if let Some(path) = uri.strip_prefix("file://") {
        // file:///etc/passwd → /etc/passwd
        // file://localhost/etc/passwd → /etc/passwd (strip optional host)
        let file_path = if let Some(rest) = path.strip_prefix("localhost") {
            rest
        } else if path.starts_with('/') {
            path
        } else {
            // file://host/path — extract path after host
            path.find('/').map(|i| &path[i..]).unwrap_or(path)
        };
        params.insert("path".to_string(), Value::String(file_path.to_string()));
    } else if uri.starts_with("http://") || uri.starts_with("https://") {
        params.insert("url".to_string(), Value::String(uri.to_string()));
    }

    Action {
        tool: "resources".to_string(),
        function: "read".to_string(),
        parameters: Value::Object(params),
    }
}

/// Build a JSON-RPC error response for an invalid request.
pub fn make_invalid_response(id: &Value, reason: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32600,
            "message": format!("Invalid request: {}", reason)
        }
    })
}

/// Build a JSON-RPC error response for a denied tool call.
///
/// Uses custom application error code -32001 (policy denial).
/// Per JSON-RPC 2.0, -32000 to -32099 are reserved for application-defined errors.
pub fn make_denial_response(id: &Value, reason: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32001,
            "message": format!("Denied by policy: {}", reason)
        }
    })
}

/// Build a JSON-RPC error response for a tool call that requires approval.
///
/// Uses custom application error code -32002 (approval required).
pub fn make_approval_response(id: &Value, reason: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32002,
            "message": format!("Approval required: {}", reason)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_classify_tool_call() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/etc/passwd"}
            }
        });
        let mt = classify_message(&msg);
        match mt {
            MessageType::ToolCall {
                id,
                tool_name,
                arguments,
            } => {
                assert_eq!(id, json!(1));
                assert_eq!(tool_name, "read_file");
                assert_eq!(arguments["path"], "/etc/passwd");
            }
            _ => panic!("Expected ToolCall"),
        }
    }

    #[test]
    fn test_classify_non_tool_call() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/list",
            "params": {}
        });
        assert_eq!(classify_message(&msg), MessageType::PassThrough);
    }

    #[test]
    fn test_classify_response() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"content": []}
        });
        assert_eq!(classify_message(&msg), MessageType::PassThrough);
    }

    #[test]
    fn test_classify_notification() {
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"token": "abc"}
        });
        assert_eq!(classify_message(&msg), MessageType::PassThrough);
    }

    #[test]
    fn test_classify_tool_call_missing_params_returns_invalid() {
        // Fix #5: Missing tool name must return Invalid, not ToolCall with empty name
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call"
        });
        let mt = classify_message(&msg);
        match mt {
            MessageType::Invalid { id, reason } => {
                assert_eq!(id, json!(4));
                assert!(reason.contains("missing or empty tool name"));
            }
            _ => panic!("Expected Invalid, got {:?}", mt),
        }
    }

    #[test]
    fn test_classify_tool_call_empty_name_returns_invalid() {
        // Fix #5: Empty string tool name must also return Invalid
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "", "arguments": {}}
        });
        let mt = classify_message(&msg);
        assert!(matches!(mt, MessageType::Invalid { .. }));
    }

    #[test]
    fn test_classify_tool_call_non_string_name_returns_invalid() {
        // Fix #5: Non-string name (e.g., integer) must return Invalid
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": 42, "arguments": {}}
        });
        let mt = classify_message(&msg);
        assert!(matches!(mt, MessageType::Invalid { .. }));
    }

    #[test]
    fn test_extract_action() {
        let args = json!({"path": "/tmp/file.txt", "encoding": "utf-8"});
        let action = extract_action("read_file", &args);
        assert_eq!(action.tool, "read_file");
        assert_eq!(action.function, "*");
        assert_eq!(action.parameters["path"], "/tmp/file.txt");
    }

    #[test]
    fn test_make_denial_response() {
        let resp = make_denial_response(&json!(5), "blocked by policy");
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 5);
        assert_eq!(resp["error"]["code"], -32001);
        assert!(resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Denied by policy"));
    }

    #[test]
    fn test_make_approval_response() {
        let resp = make_approval_response(&json!(6), "needs review");
        assert_eq!(resp["error"]["code"], -32002);
        assert!(resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Approval required"));
    }

    // --- resources/read classification tests ---

    #[test]
    fn test_classify_resource_read() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "resources/read",
            "params": {
                "uri": "file:///etc/passwd"
            }
        });
        let mt = classify_message(&msg);
        match mt {
            MessageType::ResourceRead { id, uri } => {
                assert_eq!(id, json!(10));
                assert_eq!(uri, "file:///etc/passwd");
            }
            _ => panic!("Expected ResourceRead, got {:?}", mt),
        }
    }

    #[test]
    fn test_classify_resource_read_http_uri() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "resources/read",
            "params": {
                "uri": "https://evil.com/exfil"
            }
        });
        let mt = classify_message(&msg);
        match mt {
            MessageType::ResourceRead { id, uri } => {
                assert_eq!(id, json!(11));
                assert_eq!(uri, "https://evil.com/exfil");
            }
            _ => panic!("Expected ResourceRead"),
        }
    }

    #[test]
    fn test_classify_resource_read_missing_params() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "resources/read"
        });
        let mt = classify_message(&msg);
        match mt {
            MessageType::ResourceRead { uri, .. } => {
                assert_eq!(uri, "");
            }
            _ => panic!("Expected ResourceRead"),
        }
    }

    #[test]
    fn test_classify_resources_list_is_passthrough() {
        // resources/list is NOT intercepted (only resources/read)
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "resources/list",
            "params": {}
        });
        assert_eq!(classify_message(&msg), MessageType::PassThrough);
    }

    // --- extract_resource_action tests ---

    #[test]
    fn test_extract_resource_action_file_uri() {
        let action = extract_resource_action("file:///etc/shadow");
        assert_eq!(action.tool, "resources");
        assert_eq!(action.function, "read");
        assert_eq!(action.parameters["uri"], "file:///etc/shadow");
        assert_eq!(action.parameters["path"], "/etc/shadow");
        // No url field for file:// URIs
        assert!(action.parameters.get("url").is_none());
    }

    #[test]
    fn test_extract_resource_action_file_uri_with_localhost() {
        let action = extract_resource_action("file://localhost/home/user/.ssh/id_rsa");
        assert_eq!(action.parameters["path"], "/home/user/.ssh/id_rsa");
    }

    #[test]
    fn test_extract_resource_action_http_uri() {
        let action = extract_resource_action("https://evil.com/data");
        assert_eq!(action.tool, "resources");
        assert_eq!(action.function, "read");
        assert_eq!(action.parameters["uri"], "https://evil.com/data");
        assert_eq!(action.parameters["url"], "https://evil.com/data");
        // No path field for http URIs
        assert!(action.parameters.get("path").is_none());
    }

    #[test]
    fn test_extract_resource_action_unknown_scheme() {
        // Unknown schemes get uri only, no path or url extraction
        let action = extract_resource_action("custom://something");
        assert_eq!(action.parameters["uri"], "custom://something");
        assert!(action.parameters.get("path").is_none());
        assert!(action.parameters.get("url").is_none());
    }
}
