use serde_json::{json, Value};
use vellaveto_types::{CanonicalToolCall, CanonicalToolResponse, CanonicalToolSchema, ModelFamily};

use super::error::ProjectorError;
use super::ModelProjection;

pub struct ClaudeProjection;

impl ModelProjection for ClaudeProjection {
    fn model_family(&self) -> ModelFamily {
        ModelFamily::Claude
    }

    fn project_schema(&self, canonical: &CanonicalToolSchema) -> Result<Value, ProjectorError> {
        let mut tool = json!({
            "name": canonical.name,
            "description": canonical.description,
            "input_schema": canonical.input_schema,
            "cache_control": {"type": "ephemeral"},
        });
        if let Some(ref output) = canonical.output_schema {
            tool.as_object_mut()
                .ok_or_else(|| {
                    ProjectorError::Serialization("failed to build tool object".to_string())
                })?
                .insert("output_schema".to_string(), output.clone());
        }
        Ok(tool)
    }

    fn parse_call(&self, raw: &Value) -> Result<CanonicalToolCall, ProjectorError> {
        let obj = raw
            .as_object()
            .ok_or_else(|| ProjectorError::ParseError("expected JSON object".to_string()))?;

        let call_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if call_type != "tool_use" {
            return Err(ProjectorError::ParseError(format!(
                "expected type 'tool_use', got '{}'",
                call_type
            )));
        }

        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ProjectorError::ParseError("missing 'name' field".to_string()))?;

        let input = obj
            .get("input")
            .cloned()
            .unwrap_or(Value::Object(serde_json::Map::new()));

        let call_id = obj.get("id").and_then(|v| v.as_str()).map(String::from);

        Ok(CanonicalToolCall {
            tool_name: name.to_string(),
            arguments: input,
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
            "type": "tool_result",
            "content": [{"type": "text", "text": content_str}],
        });

        if let Some(ref id) = canonical.call_id {
            result
                .as_object_mut()
                .ok_or_else(|| {
                    ProjectorError::Serialization("failed to build result object".to_string())
                })?
                .insert("tool_use_id".to_string(), Value::String(id.clone()));
        }

        if canonical.is_error {
            result
                .as_object_mut()
                .ok_or_else(|| {
                    ProjectorError::Serialization("failed to build result object".to_string())
                })?
                .insert("is_error".to_string(), Value::Bool(true));
        }

        Ok(result)
    }

    fn estimate_tokens(&self, schema: &CanonicalToolSchema) -> usize {
        let json_str = serde_json::to_string(schema).unwrap_or_default();
        let chars = json_str.len();
        // Claude's tokenizer is more efficient: ~3.5 chars per token
        (chars as f64 / 3.5).ceil() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_schema() -> CanonicalToolSchema {
        CanonicalToolSchema {
            name: "read_file".to_string(),
            description: "Read a file from disk".to_string(),
            input_schema: json!({"type": "object", "properties": {"path": {"type": "string"}}}),
            output_schema: Some(json!({"type": "string"})),
        }
    }

    #[test]
    fn test_claude_model_family() {
        let p = ClaudeProjection;
        assert_eq!(p.model_family(), ModelFamily::Claude);
    }

    #[test]
    fn test_claude_project_schema() {
        let p = ClaudeProjection;
        let result = p.project_schema(&sample_schema()).unwrap();
        assert_eq!(result["name"], "read_file");
        assert_eq!(result["description"], "Read a file from disk");
        assert!(result["input_schema"].is_object());
        assert!(result["cache_control"].is_object());
        assert!(result["output_schema"].is_object());
    }

    #[test]
    fn test_claude_project_schema_no_output() {
        let p = ClaudeProjection;
        let mut schema = sample_schema();
        schema.output_schema = None;
        let result = p.project_schema(&schema).unwrap();
        assert!(result.get("output_schema").is_none());
    }

    #[test]
    fn test_claude_parse_call_valid() {
        let p = ClaudeProjection;
        let raw = json!({
            "type": "tool_use",
            "id": "toolu_123",
            "name": "read_file",
            "input": {"path": "/tmp/test.txt"}
        });
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.tool_name, "read_file");
        assert_eq!(call.arguments["path"], "/tmp/test.txt");
        assert_eq!(call.call_id, Some("toolu_123".to_string()));
    }

    #[test]
    fn test_claude_parse_call_missing_type() {
        let p = ClaudeProjection;
        let raw = json!({"name": "read_file", "input": {}});
        let err = p.parse_call(&raw).unwrap_err();
        assert!(err.to_string().contains("tool_use"));
    }

    #[test]
    fn test_claude_parse_call_wrong_type() {
        let p = ClaudeProjection;
        let raw = json!({"type": "text", "name": "read_file", "input": {}});
        let err = p.parse_call(&raw).unwrap_err();
        assert!(err.to_string().contains("tool_use"));
    }

    #[test]
    fn test_claude_parse_call_missing_name() {
        let p = ClaudeProjection;
        let raw = json!({"type": "tool_use", "input": {}});
        let err = p.parse_call(&raw).unwrap_err();
        assert!(err.to_string().contains("name"));
    }

    #[test]
    fn test_claude_parse_call_no_input() {
        let p = ClaudeProjection;
        let raw = json!({"type": "tool_use", "id": "x", "name": "exec"});
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.arguments, json!({}));
    }

    #[test]
    fn test_claude_parse_call_not_object() {
        let p = ClaudeProjection;
        let raw = json!("not an object");
        let err = p.parse_call(&raw).unwrap_err();
        assert!(err.to_string().contains("object"));
    }

    #[test]
    fn test_claude_format_response_success() {
        let p = ClaudeProjection;
        let resp = CanonicalToolResponse {
            call_id: Some("toolu_123".to_string()),
            content: json!("file contents here"),
            is_error: false,
        };
        let result = p.format_response(&resp).unwrap();
        assert_eq!(result["type"], "tool_result");
        assert_eq!(result["tool_use_id"], "toolu_123");
        assert_eq!(result["content"][0]["type"], "text");
        assert_eq!(result["content"][0]["text"], "file contents here");
        assert!(result.get("is_error").is_none());
    }

    #[test]
    fn test_claude_format_response_error() {
        let p = ClaudeProjection;
        let resp = CanonicalToolResponse {
            call_id: Some("toolu_456".to_string()),
            content: json!("something broke"),
            is_error: true,
        };
        let result = p.format_response(&resp).unwrap();
        assert_eq!(result["is_error"], true);
    }

    #[test]
    fn test_claude_format_response_no_call_id() {
        let p = ClaudeProjection;
        let resp = CanonicalToolResponse {
            call_id: None,
            content: json!({"key": "value"}),
            is_error: false,
        };
        let result = p.format_response(&resp).unwrap();
        assert!(result.get("tool_use_id").is_none());
    }

    #[test]
    fn test_claude_format_response_json_content() {
        let p = ClaudeProjection;
        let resp = CanonicalToolResponse {
            call_id: None,
            content: json!({"data": [1, 2, 3]}),
            is_error: false,
        };
        let result = p.format_response(&resp).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["data"], json!([1, 2, 3]));
    }

    #[test]
    fn test_claude_estimate_tokens() {
        let p = ClaudeProjection;
        let tokens = p.estimate_tokens(&sample_schema());
        assert!(tokens > 0);
        assert!(tokens < 1000);
    }

    #[test]
    fn test_claude_estimate_tokens_larger_schema() {
        let p = ClaudeProjection;
        let schema = CanonicalToolSchema {
            name: "complex".to_string(),
            description: "A ".repeat(1000),
            input_schema: json!({"type": "object"}),
            output_schema: None,
        };
        let tokens = p.estimate_tokens(&schema);
        assert!(tokens > 100);
    }
}
