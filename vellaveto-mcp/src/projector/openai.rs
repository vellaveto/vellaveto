use serde_json::{json, Value};
use vellaveto_types::{CanonicalToolCall, CanonicalToolResponse, CanonicalToolSchema, ModelFamily};

use super::error::ProjectorError;
use super::ModelProjection;

pub struct OpenAiProjection;

impl ModelProjection for OpenAiProjection {
    fn model_family(&self) -> ModelFamily {
        ModelFamily::OpenAi
    }

    fn project_schema(&self, canonical: &CanonicalToolSchema) -> Result<Value, ProjectorError> {
        Ok(json!({
            "type": "function",
            "function": {
                "name": canonical.name,
                "description": canonical.description,
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
                ProjectorError::ParseError(format!(
                    "failed to parse 'function.arguments' as JSON: {}",
                    e
                ))
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
        let json_str = serde_json::to_string(schema).unwrap_or_default();
        // OpenAI: ~4 chars per token
        json_str.len() / 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_schema() -> CanonicalToolSchema {
        CanonicalToolSchema {
            name: "get_weather".to_string(),
            description: "Get the current weather for a location".to_string(),
            input_schema: json!({"type": "object", "properties": {"location": {"type": "string"}}}),
            output_schema: None,
        }
    }

    #[test]
    fn test_openai_model_family() {
        let p = OpenAiProjection;
        assert_eq!(p.model_family(), ModelFamily::OpenAi);
    }

    #[test]
    fn test_openai_project_schema() {
        let p = OpenAiProjection;
        let result = p.project_schema(&sample_schema()).unwrap();
        assert_eq!(result["type"], "function");
        assert_eq!(result["function"]["name"], "get_weather");
        assert_eq!(
            result["function"]["description"],
            "Get the current weather for a location"
        );
        assert!(result["function"]["parameters"].is_object());
    }

    #[test]
    fn test_openai_parse_call_json_arguments() {
        let p = OpenAiProjection;
        let raw = json!({
            "id": "call_abc",
            "type": "function",
            "function": {
                "name": "get_weather",
                "arguments": {"location": "Paris"}
            }
        });
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.tool_name, "get_weather");
        assert_eq!(call.arguments["location"], "Paris");
        assert_eq!(call.call_id, Some("call_abc".to_string()));
    }

    #[test]
    fn test_openai_parse_call_string_arguments() {
        let p = OpenAiProjection;
        let raw = json!({
            "id": "call_xyz",
            "type": "function",
            "function": {
                "name": "get_weather",
                "arguments": "{\"location\": \"London\"}"
            }
        });
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.tool_name, "get_weather");
        assert_eq!(call.arguments["location"], "London");
    }

    #[test]
    fn test_openai_parse_call_invalid_string_arguments() {
        let p = OpenAiProjection;
        let raw = json!({
            "id": "call_xyz",
            "type": "function",
            "function": {
                "name": "get_weather",
                "arguments": "not valid json {{"
            }
        });
        let err = p.parse_call(&raw).unwrap_err();
        assert!(err.to_string().contains("parse"));
    }

    #[test]
    fn test_openai_parse_call_missing_function() {
        let p = OpenAiProjection;
        let raw = json!({"id": "call_1", "type": "function"});
        let err = p.parse_call(&raw).unwrap_err();
        assert!(err.to_string().contains("function"));
    }

    #[test]
    fn test_openai_parse_call_missing_name() {
        let p = OpenAiProjection;
        let raw = json!({
            "id": "call_1",
            "type": "function",
            "function": {"arguments": "{}"}
        });
        let err = p.parse_call(&raw).unwrap_err();
        assert!(err.to_string().contains("name"));
    }

    #[test]
    fn test_openai_parse_call_no_arguments() {
        let p = OpenAiProjection;
        let raw = json!({
            "id": "call_1",
            "type": "function",
            "function": {"name": "noop"}
        });
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.arguments, json!({}));
    }

    #[test]
    fn test_openai_parse_call_not_object() {
        let p = OpenAiProjection;
        let err = p.parse_call(&json!(42)).unwrap_err();
        assert!(err.to_string().contains("object"));
    }

    #[test]
    fn test_openai_format_response_with_id() {
        let p = OpenAiProjection;
        let resp = CanonicalToolResponse {
            call_id: Some("call_abc".to_string()),
            content: json!("sunny, 22C"),
            is_error: false,
        };
        let result = p.format_response(&resp).unwrap();
        assert_eq!(result["role"], "tool");
        assert_eq!(result["tool_call_id"], "call_abc");
        assert_eq!(result["content"], "sunny, 22C");
    }

    #[test]
    fn test_openai_format_response_no_id() {
        let p = OpenAiProjection;
        let resp = CanonicalToolResponse {
            call_id: None,
            content: json!("result"),
            is_error: false,
        };
        let result = p.format_response(&resp).unwrap();
        assert!(result.get("tool_call_id").is_none());
    }

    #[test]
    fn test_openai_format_response_json_content() {
        let p = OpenAiProjection;
        let resp = CanonicalToolResponse {
            call_id: None,
            content: json!({"temp": 22, "unit": "C"}),
            is_error: false,
        };
        let result = p.format_response(&resp).unwrap();
        let content_str = result["content"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(content_str).unwrap();
        assert_eq!(parsed["temp"], 22);
    }

    #[test]
    fn test_openai_estimate_tokens() {
        let p = OpenAiProjection;
        let tokens = p.estimate_tokens(&sample_schema());
        assert!(tokens > 0);
        assert!(tokens < 1000);
    }

    #[test]
    fn test_openai_estimate_tokens_empty() {
        let p = OpenAiProjection;
        let schema = CanonicalToolSchema {
            name: "x".to_string(),
            description: "".to_string(),
            input_schema: json!({}),
            output_schema: None,
        };
        let tokens = p.estimate_tokens(&schema);
        assert!(tokens > 0);
    }

    #[test]
    fn test_openai_parse_call_roundtrip() {
        let p = OpenAiProjection;
        let schema = sample_schema();
        let projected = p.project_schema(&schema).unwrap();
        assert_eq!(projected["function"]["name"], schema.name);
    }
}
