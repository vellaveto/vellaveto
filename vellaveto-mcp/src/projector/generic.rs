// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

use serde_json::{json, Value};
use vellaveto_types::{CanonicalToolCall, CanonicalToolResponse, CanonicalToolSchema, ModelFamily};

use super::error::ProjectorError;
use super::ModelProjection;

pub struct GenericProjection;

impl ModelProjection for GenericProjection {
    fn model_family(&self) -> ModelFamily {
        ModelFamily::Generic
    }

    fn project_schema(&self, canonical: &CanonicalToolSchema) -> Result<Value, ProjectorError> {
        let mut result = json!({
            "name": canonical.name,
            "description": canonical.description,
            "input_schema": canonical.input_schema,
        });
        if let Some(ref output) = canonical.output_schema {
            result
                .as_object_mut()
                .ok_or_else(|| ProjectorError::Serialization("failed to build schema".to_string()))?
                .insert("output_schema".to_string(), output.clone());
        }
        Ok(result)
    }

    fn parse_call(&self, raw: &Value) -> Result<CanonicalToolCall, ProjectorError> {
        let obj = raw
            .as_object()
            .ok_or_else(|| ProjectorError::ParseError("expected JSON object".to_string()))?;

        // Accept both "tool_name" and "name"
        let name = obj
            .get("tool_name")
            .or_else(|| obj.get("name"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ProjectorError::ParseError("missing 'tool_name' or 'name' field".to_string())
            })?;

        // Accept both "arguments" and "parameters"
        let arguments = obj
            .get("arguments")
            .or_else(|| obj.get("parameters"))
            .cloned()
            .unwrap_or(Value::Object(serde_json::Map::new()));

        let call_id = obj
            .get("call_id")
            .or_else(|| obj.get("id"))
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(CanonicalToolCall {
            tool_name: name.to_string(),
            arguments,
            call_id,
        })
    }

    fn format_response(&self, canonical: &CanonicalToolResponse) -> Result<Value, ProjectorError> {
        serde_json::to_value(canonical).map_err(|e| ProjectorError::Serialization(e.to_string()))
    }

    fn estimate_tokens(&self, schema: &CanonicalToolSchema) -> usize {
        // SECURITY (FIND-R131-001): Fail-closed on serialization failure.
        let json_str = match serde_json::to_string(schema) {
            Ok(s) => s,
            Err(_) => return super::FAILSAFE_TOKEN_ESTIMATE,
        };
        // Generic: ~4 chars per token
        json_str.len() / 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_schema() -> CanonicalToolSchema {
        CanonicalToolSchema {
            name: "list_files".to_string(),
            description: "List files in a directory".to_string(),
            input_schema: json!({"type": "object", "properties": {"path": {"type": "string"}}}),
            output_schema: Some(json!({"type": "array"})),
        }
    }

    #[test]
    fn test_generic_model_family() {
        let p = GenericProjection;
        assert_eq!(p.model_family(), ModelFamily::Generic);
    }

    #[test]
    fn test_generic_project_schema() {
        let p = GenericProjection;
        let result = p.project_schema(&sample_schema()).unwrap();
        assert_eq!(result["name"], "list_files");
        assert_eq!(result["description"], "List files in a directory");
        assert!(result["input_schema"].is_object());
        assert!(result["output_schema"].is_object());
    }

    #[test]
    fn test_generic_project_schema_no_output() {
        let p = GenericProjection;
        let mut schema = sample_schema();
        schema.output_schema = None;
        let result = p.project_schema(&schema).unwrap();
        assert!(result.get("output_schema").is_none());
    }

    #[test]
    fn test_generic_parse_call_tool_name() {
        let p = GenericProjection;
        let raw = json!({
            "tool_name": "list_files",
            "arguments": {"path": "/tmp"},
            "call_id": "gen_1"
        });
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.tool_name, "list_files");
        assert_eq!(call.arguments["path"], "/tmp");
        assert_eq!(call.call_id, Some("gen_1".to_string()));
    }

    #[test]
    fn test_generic_parse_call_name_fallback() {
        let p = GenericProjection;
        let raw = json!({
            "name": "list_files",
            "parameters": {"path": "/home"}
        });
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.tool_name, "list_files");
        assert_eq!(call.arguments["path"], "/home");
    }

    #[test]
    fn test_generic_parse_call_id_fallback() {
        let p = GenericProjection;
        let raw = json!({
            "name": "test",
            "id": "fallback_id"
        });
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.call_id, Some("fallback_id".to_string()));
    }

    #[test]
    fn test_generic_parse_call_missing_name() {
        let p = GenericProjection;
        let raw = json!({"arguments": {"x": 1}});
        let err = p.parse_call(&raw).unwrap_err();
        assert!(err.to_string().contains("name"));
    }

    #[test]
    fn test_generic_parse_call_no_arguments() {
        let p = GenericProjection;
        let raw = json!({"name": "noop"});
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.arguments, json!({}));
    }

    #[test]
    fn test_generic_parse_call_not_object() {
        let p = GenericProjection;
        let err = p.parse_call(&json!("string")).unwrap_err();
        assert!(err.to_string().contains("object"));
    }

    #[test]
    fn test_generic_format_response() {
        let p = GenericProjection;
        let resp = CanonicalToolResponse {
            call_id: Some("gen_1".to_string()),
            content: json!(["file1.txt", "file2.txt"]),
            is_error: false,
        };
        let result = p.format_response(&resp).unwrap();
        assert_eq!(result["call_id"], "gen_1");
        assert_eq!(result["is_error"], false);
    }

    #[test]
    fn test_generic_format_response_error() {
        let p = GenericProjection;
        let resp = CanonicalToolResponse {
            call_id: None,
            content: json!("error occurred"),
            is_error: true,
        };
        let result = p.format_response(&resp).unwrap();
        assert_eq!(result["is_error"], true);
        assert!(result["call_id"].is_null());
    }

    #[test]
    fn test_generic_format_response_roundtrip() {
        let p = GenericProjection;
        let original = CanonicalToolResponse {
            call_id: Some("rt_1".to_string()),
            content: json!({"data": "value"}),
            is_error: false,
        };
        let formatted = p.format_response(&original).unwrap();
        let roundtripped: CanonicalToolResponse = serde_json::from_value(formatted).unwrap();
        assert_eq!(original, roundtripped);
    }

    #[test]
    fn test_generic_estimate_tokens() {
        let p = GenericProjection;
        let tokens = p.estimate_tokens(&sample_schema());
        assert!(tokens > 0);
        assert!(tokens < 1000);
    }

    #[test]
    fn test_generic_estimate_tokens_empty() {
        let p = GenericProjection;
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
    fn test_generic_parse_call_prefers_tool_name_over_name() {
        let p = GenericProjection;
        let raw = json!({
            "tool_name": "preferred",
            "name": "fallback"
        });
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.tool_name, "preferred");
    }

    #[test]
    fn test_generic_parse_call_prefers_arguments_over_parameters() {
        let p = GenericProjection;
        let raw = json!({
            "name": "t",
            "arguments": {"a": 1},
            "parameters": {"p": 2}
        });
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.arguments["a"], 1);
    }
}
