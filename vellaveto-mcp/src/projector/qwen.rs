use serde_json::{json, Value};
use vellaveto_types::{CanonicalToolCall, CanonicalToolResponse, CanonicalToolSchema, ModelFamily};

use super::error::ProjectorError;
use super::ModelProjection;

/// Maximum description length in characters for Qwen's tokenizer efficiency.
const MAX_DESCRIPTION_CHARS: usize = 200;

pub struct QwenProjection;

fn truncate_description(desc: &str) -> String {
    let trimmed = desc.trim();
    if trimmed.len() <= MAX_DESCRIPTION_CHARS {
        return trimmed.to_string();
    }
    // Truncate at char boundary and add ellipsis
    let mut end = MAX_DESCRIPTION_CHARS;
    while !trimmed.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    format!("{}...", &trimmed[..end])
}

impl ModelProjection for QwenProjection {
    fn model_family(&self) -> ModelFamily {
        ModelFamily::Qwen
    }

    fn project_schema(&self, canonical: &CanonicalToolSchema) -> Result<Value, ProjectorError> {
        let desc = truncate_description(&canonical.description);
        Ok(json!({
            "type": "function",
            "function": {
                "name": canonical.name,
                "description": desc,
                "parameters": canonical.input_schema,
            }
        }))
    }

    fn parse_call(&self, raw: &Value) -> Result<CanonicalToolCall, ProjectorError> {
        let obj = raw
            .as_object()
            .ok_or_else(|| ProjectorError::ParseError("expected JSON object".to_string()))?;

        let function = obj
            .get("function")
            .and_then(|v| v.as_object())
            .ok_or_else(|| ProjectorError::ParseError("missing 'function' object".to_string()))?;

        let name = function
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ProjectorError::ParseError("missing 'function.name'".to_string()))?;

        let arguments = match function.get("arguments") {
            Some(Value::String(s)) => serde_json::from_str(s).map_err(|e| {
                ProjectorError::ParseError(format!("failed to parse 'function.arguments': {}", e))
            })?,
            Some(v) => v.clone(),
            None => Value::Object(serde_json::Map::new()),
        };

        let call_id = obj.get("id").and_then(|v| v.as_str()).map(String::from);

        Ok(CanonicalToolCall {
            tool_name: name.to_string(),
            arguments,
            call_id,
        })
    }

    fn format_response(&self, canonical: &CanonicalToolResponse) -> Result<Value, ProjectorError> {
        let content_str = match &canonical.content {
            Value::String(s) => s.clone(),
            other => serde_json::to_string(other)
                .map_err(|e| ProjectorError::Serialization(e.to_string()))?,
        };

        let mut result = json!({
            "role": "tool",
            "content": content_str,
        });

        if let Some(ref id) = canonical.call_id {
            result
                .as_object_mut()
                .ok_or_else(|| ProjectorError::Serialization("failed to build result".to_string()))?
                .insert("tool_call_id".to_string(), Value::String(id.clone()));
        }

        Ok(result)
    }

    fn estimate_tokens(&self, schema: &CanonicalToolSchema) -> usize {
        // SECURITY (FIND-R131-001): Fail-closed on serialization failure.
        let json_str = match serde_json::to_string(schema) {
            Ok(s) => s,
            Err(_) => return super::FAILSAFE_TOKEN_ESTIMATE,
        };
        // Qwen: CJK-aware tokenizer, ~3 chars per token
        (json_str.len() as f64 / 3.0).ceil() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_schema() -> CanonicalToolSchema {
        CanonicalToolSchema {
            name: "translate".to_string(),
            description: "Translate text between languages".to_string(),
            input_schema: json!({"type": "object", "properties": {"text": {"type": "string"}, "target_lang": {"type": "string"}}}),
            output_schema: None,
        }
    }

    #[test]
    fn test_qwen_model_family() {
        let p = QwenProjection;
        assert_eq!(p.model_family(), ModelFamily::Qwen);
    }

    #[test]
    fn test_qwen_project_schema() {
        let p = QwenProjection;
        let result = p.project_schema(&sample_schema()).unwrap();
        assert_eq!(result["type"], "function");
        assert_eq!(result["function"]["name"], "translate");
        assert_eq!(
            result["function"]["description"],
            "Translate text between languages"
        );
        assert!(result["function"]["parameters"].is_object());
    }

    #[test]
    fn test_qwen_project_schema_truncates_long_description() {
        let p = QwenProjection;
        let long_desc = "A ".repeat(200); // 400 chars
        let schema = CanonicalToolSchema {
            name: "tool".to_string(),
            description: long_desc,
            input_schema: json!({}),
            output_schema: None,
        };
        let result = p.project_schema(&schema).unwrap();
        let desc = result["function"]["description"].as_str().unwrap();
        assert!(desc.len() <= MAX_DESCRIPTION_CHARS + 3); // +3 for "..."
        assert!(desc.ends_with("..."));
    }

    #[test]
    fn test_qwen_project_schema_short_description_unchanged() {
        let p = QwenProjection;
        let schema = CanonicalToolSchema {
            name: "t".to_string(),
            description: "Short desc".to_string(),
            input_schema: json!({}),
            output_schema: None,
        };
        let result = p.project_schema(&schema).unwrap();
        assert_eq!(result["function"]["description"], "Short desc");
    }

    #[test]
    fn test_qwen_parse_call_valid() {
        let p = QwenProjection;
        let raw = json!({
            "id": "call_q1",
            "type": "function",
            "function": {
                "name": "translate",
                "arguments": {"text": "hello", "target_lang": "zh"}
            }
        });
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.tool_name, "translate");
        assert_eq!(call.arguments["text"], "hello");
        assert_eq!(call.call_id, Some("call_q1".to_string()));
    }

    #[test]
    fn test_qwen_parse_call_string_arguments() {
        let p = QwenProjection;
        let raw = json!({
            "id": "call_q2",
            "function": {
                "name": "translate",
                "arguments": "{\"text\": \"hi\"}"
            }
        });
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.arguments["text"], "hi");
    }

    #[test]
    fn test_qwen_parse_call_missing_function() {
        let p = QwenProjection;
        let err = p.parse_call(&json!({"id": "x"})).unwrap_err();
        assert!(err.to_string().contains("function"));
    }

    #[test]
    fn test_qwen_parse_call_missing_name() {
        let p = QwenProjection;
        let raw = json!({
            "function": {"arguments": "{}"}
        });
        let err = p.parse_call(&raw).unwrap_err();
        assert!(err.to_string().contains("name"));
    }

    #[test]
    fn test_qwen_parse_call_not_object() {
        let p = QwenProjection;
        let err = p.parse_call(&json!([1, 2, 3])).unwrap_err();
        assert!(err.to_string().contains("object"));
    }

    #[test]
    fn test_qwen_format_response_with_id() {
        let p = QwenProjection;
        let resp = CanonicalToolResponse {
            call_id: Some("call_q1".to_string()),
            content: json!("translated text"),
            is_error: false,
        };
        let result = p.format_response(&resp).unwrap();
        assert_eq!(result["role"], "tool");
        assert_eq!(result["tool_call_id"], "call_q1");
        assert_eq!(result["content"], "translated text");
    }

    #[test]
    fn test_qwen_format_response_no_id() {
        let p = QwenProjection;
        let resp = CanonicalToolResponse {
            call_id: None,
            content: json!("ok"),
            is_error: false,
        };
        let result = p.format_response(&resp).unwrap();
        assert!(result.get("tool_call_id").is_none());
    }

    #[test]
    fn test_qwen_format_response_json_content() {
        let p = QwenProjection;
        let resp = CanonicalToolResponse {
            call_id: None,
            content: json!({"result": "ok", "count": 5}),
            is_error: false,
        };
        let result = p.format_response(&resp).unwrap();
        let s = result["content"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(s).unwrap();
        assert_eq!(parsed["count"], 5);
    }

    #[test]
    fn test_qwen_estimate_tokens() {
        let p = QwenProjection;
        let tokens = p.estimate_tokens(&sample_schema());
        assert!(tokens > 0);
    }

    #[test]
    fn test_truncate_description_empty() {
        assert_eq!(truncate_description(""), "");
    }

    #[test]
    fn test_truncate_description_exact_limit() {
        let desc = "a".repeat(MAX_DESCRIPTION_CHARS);
        assert_eq!(truncate_description(&desc), desc);
    }
}
