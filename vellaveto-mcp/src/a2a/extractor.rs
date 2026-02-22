//! Extract [`Action`] from A2A JSON-RPC messages for policy evaluation.
//!
//! A2A messages are converted to Vellaveto Actions using the following mapping:
//!
//! | A2A Method        | Tool       | Function          |
//! |-------------------|------------|-------------------|
//! | message/send      | a2a        | message_send      |
//! | message/stream    | a2a        | message_stream    |
//! | tasks/get         | a2a        | task_get          |
//! | tasks/cancel      | a2a        | task_cancel       |
//! | tasks/resubscribe | a2a        | task_resubscribe  |

use serde_json::{json, Value};
use vellaveto_types::Action;

use super::message::A2aMessageType;

/// Tool name for all A2A actions.
pub const A2A_TOOL: &str = "a2a";

/// Extract an [`Action`] from an A2A message type for policy evaluation.
///
/// Returns `Some(Action)` for message types that should be policy-checked,
/// `None` for passthrough messages.
///
/// # Example
///
/// ```rust,ignore
/// use vellaveto_mcp::a2a::{classify_a2a_message, extract_a2a_action};
/// use serde_json::json;
///
/// let msg = json!({
///     "jsonrpc": "2.0",
///     "id": 1,
///     "method": "message/send",
///     "params": {
///         "message": {"role": "user", "parts": [{"type": "text", "text": "Hello"}]}
///     }
/// });
///
/// let msg_type = classify_a2a_message(&msg);
/// if let Some(action) = extract_a2a_action(&msg_type) {
///     // action.tool == "a2a"
///     // action.function == "message_send"
/// }
/// ```
pub fn extract_a2a_action(msg_type: &A2aMessageType) -> Option<Action> {
    match msg_type {
        A2aMessageType::MessageSend {
            message, task_id, ..
        } => Some(Action::new(
            A2A_TOOL.to_string(),
            "message_send".to_string(),
            json!({
                "task_id": task_id,
                "message": message,
            }),
        )),
        A2aMessageType::MessageStream {
            message, task_id, ..
        } => Some(Action::new(
            A2A_TOOL.to_string(),
            "message_stream".to_string(),
            json!({
                "task_id": task_id,
                "message": message,
            }),
        )),
        A2aMessageType::TaskGet { task_id, .. } => Some(Action::new(
            A2A_TOOL.to_string(),
            "task_get".to_string(),
            json!({ "task_id": task_id }),
        )),
        A2aMessageType::TaskCancel { task_id, .. } => Some(Action::new(
            A2A_TOOL.to_string(),
            "task_cancel".to_string(),
            json!({ "task_id": task_id }),
        )),
        A2aMessageType::TaskResubscribe { task_id, .. } => Some(Action::new(
            A2A_TOOL.to_string(),
            "task_resubscribe".to_string(),
            json!({ "task_id": task_id }),
        )),
        A2aMessageType::Batch => None,
        A2aMessageType::Invalid { .. } => None,
        A2aMessageType::PassThrough => None,
    }
}

/// Get the JSON-RPC request ID from an A2A message type.
///
/// Returns `Value::Null` for message types without an ID.
pub fn get_request_id(msg_type: &A2aMessageType) -> Value {
    match msg_type {
        A2aMessageType::MessageSend { id, .. } => id.clone(),
        A2aMessageType::MessageStream { id, .. } => id.clone(),
        A2aMessageType::TaskGet { id, .. } => id.clone(),
        A2aMessageType::TaskCancel { id, .. } => id.clone(),
        A2aMessageType::TaskResubscribe { id, .. } => id.clone(),
        A2aMessageType::Invalid { id, .. } => id.clone(),
        A2aMessageType::Batch => Value::Null,
        A2aMessageType::PassThrough => Value::Null,
    }
}

/// Create a JSON-RPC error response for A2A.
///
/// Follows the JSON-RPC 2.0 specification for error responses.
pub fn make_a2a_error_response(id: &Value, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
}

/// Create a JSON-RPC denial response for A2A policy denial.
///
/// Uses [`vellaveto_types::json_rpc::VALIDATION_ERROR`] with the denial reason.
pub fn make_a2a_denial_response(id: &Value, reason: &str) -> Value {
    use vellaveto_types::json_rpc;
    // SECURITY (FIND-R176-010): Sanitize reason to prevent control char propagation
    // into client-visible error messages and audit logs.
    let sanitized = vellaveto_types::sanitize_for_log(reason, 256);
    make_a2a_error_response(
        id,
        json_rpc::VALIDATION_ERROR as i32,
        &format!("Policy denied: {}", sanitized),
    )
}

/// Create a JSON-RPC success response for A2A.
pub fn make_a2a_success_response(id: &Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

/// Check if an A2A message type requires policy evaluation.
///
/// Returns `true` for message types that should be policy-checked before
/// forwarding to the upstream server.
pub fn requires_policy_check(msg_type: &A2aMessageType) -> bool {
    matches!(
        msg_type,
        A2aMessageType::MessageSend { .. }
            | A2aMessageType::MessageStream { .. }
            | A2aMessageType::TaskGet { .. }
            | A2aMessageType::TaskCancel { .. }
            | A2aMessageType::TaskResubscribe { .. }
    )
}

/// Get the A2A method name from a message type.
///
/// Returns the original A2A method name (e.g., "message/send") or None
/// for message types without a specific method.
pub fn get_method_name(msg_type: &A2aMessageType) -> Option<&'static str> {
    match msg_type {
        A2aMessageType::MessageSend { .. } => Some("message/send"),
        A2aMessageType::MessageStream { .. } => Some("message/stream"),
        A2aMessageType::TaskGet { .. } => Some("tasks/get"),
        A2aMessageType::TaskCancel { .. } => Some("tasks/cancel"),
        A2aMessageType::TaskResubscribe { .. } => Some("tasks/resubscribe"),
        A2aMessageType::Batch => None,
        A2aMessageType::Invalid { .. } => None,
        A2aMessageType::PassThrough => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a2a::message::classify_a2a_message;

    #[test]
    fn test_extract_message_send() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "Hello"}]
                }
            }
        });

        let msg_type = classify_a2a_message(&msg);
        let action = extract_a2a_action(&msg_type).unwrap();

        assert_eq!(action.tool, "a2a");
        assert_eq!(action.function, "message_send");
        assert!(action.parameters.get("message").is_some());
    }

    #[test]
    fn test_extract_message_send_with_task_id() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {
                "id": "task-123",
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "Continue"}]
                }
            }
        });

        let msg_type = classify_a2a_message(&msg);
        let action = extract_a2a_action(&msg_type).unwrap();

        assert_eq!(
            action.parameters.get("task_id").unwrap().as_str(),
            Some("task-123")
        );
    }

    #[test]
    fn test_extract_message_stream() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/stream",
            "params": {
                "message": {"role": "user", "parts": []}
            }
        });

        let msg_type = classify_a2a_message(&msg);
        let action = extract_a2a_action(&msg_type).unwrap();

        assert_eq!(action.tool, "a2a");
        assert_eq!(action.function, "message_stream");
    }

    #[test]
    fn test_extract_task_get() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/get",
            "params": {"id": "task-456"}
        });

        let msg_type = classify_a2a_message(&msg);
        let action = extract_a2a_action(&msg_type).unwrap();

        assert_eq!(action.tool, "a2a");
        assert_eq!(action.function, "task_get");
        assert_eq!(
            action.parameters.get("task_id").unwrap().as_str(),
            Some("task-456")
        );
    }

    #[test]
    fn test_extract_task_cancel() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/cancel",
            "params": {"id": "task-789"}
        });

        let msg_type = classify_a2a_message(&msg);
        let action = extract_a2a_action(&msg_type).unwrap();

        assert_eq!(action.tool, "a2a");
        assert_eq!(action.function, "task_cancel");
    }

    #[test]
    fn test_extract_task_resubscribe() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/resubscribe",
            "params": {"id": "task-abc"}
        });

        let msg_type = classify_a2a_message(&msg);
        let action = extract_a2a_action(&msg_type).unwrap();

        assert_eq!(action.tool, "a2a");
        assert_eq!(action.function, "task_resubscribe");
    }

    #[test]
    fn test_extract_batch_returns_none() {
        let msg = json!([{"jsonrpc": "2.0", "id": 1, "method": "message/send"}]);
        let msg_type = classify_a2a_message(&msg);
        assert!(extract_a2a_action(&msg_type).is_none());
    }

    #[test]
    fn test_extract_passthrough_returns_none() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {}
        });
        let msg_type = classify_a2a_message(&msg);
        assert!(extract_a2a_action(&msg_type).is_none());
    }

    #[test]
    fn test_make_error_response() {
        let response = make_a2a_error_response(&json!(1), -32600, "Invalid request");

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert_eq!(response["error"]["code"], -32600);
        assert_eq!(response["error"]["message"], "Invalid request");
    }

    #[test]
    fn test_make_denial_response() {
        let response = make_a2a_denial_response(&json!(1), "Action not allowed");

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert_eq!(response["error"]["code"], -32003);
        assert!(response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Policy denied"));
    }

    #[test]
    fn test_make_success_response() {
        let response = make_a2a_success_response(&json!(1), json!({"status": "ok"}));

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["status"], "ok");
    }

    #[test]
    fn test_requires_policy_check() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {"message": {"role": "user", "parts": []}}
        });
        let msg_type = classify_a2a_message(&msg);
        assert!(requires_policy_check(&msg_type));

        let response = json!({"jsonrpc": "2.0", "id": 1, "result": {}});
        let msg_type = classify_a2a_message(&response);
        assert!(!requires_policy_check(&msg_type));
    }

    #[test]
    fn test_get_method_name() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {"message": {"role": "user", "parts": []}}
        });
        let msg_type = classify_a2a_message(&msg);
        assert_eq!(get_method_name(&msg_type), Some("message/send"));

        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/cancel",
            "params": {"id": "task-123"}
        });
        let msg_type = classify_a2a_message(&msg);
        assert_eq!(get_method_name(&msg_type), Some("tasks/cancel"));
    }

    #[test]
    fn test_get_request_id() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": "req-123",
            "method": "message/send",
            "params": {"message": {"role": "user", "parts": []}}
        });
        let msg_type = classify_a2a_message(&msg);
        assert_eq!(get_request_id(&msg_type), json!("req-123"));
    }
}
