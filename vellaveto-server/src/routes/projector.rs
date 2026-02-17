//! Projector route handlers (Phase 35.3).
//!
//! Endpoints:
//! - `GET /api/projector/models` — list supported model families
//! - `POST /api/projector/transform` — project a canonical schema for a given model family

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::json;
use vellaveto_types::{CanonicalToolSchema, ModelFamily};

use crate::routes::ErrorResponse;
use crate::AppState;

/// Maximum length of the model_family string in transform requests.
const MAX_MODEL_FAMILY_LENGTH: usize = 128;

/// Maximum length of the schema name field.
const MAX_SCHEMA_NAME_LENGTH: usize = 256;

/// Maximum length of the schema description field.
const MAX_SCHEMA_DESCRIPTION_LENGTH: usize = 4096;

/// SECURITY (FIND-R46-005): Maximum JSON nesting depth for schema objects.
/// Deeply nested schemas can cause stack overflow or excessive processing time.
const MAX_SCHEMA_DEPTH: usize = 32;

/// SECURITY (FIND-R46-005): Measure JSON value nesting depth.
fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => {
            1 + map.values().map(json_depth).max().unwrap_or(0)
        }
        serde_json::Value::Array(arr) => {
            1 + arr.iter().map(json_depth).max().unwrap_or(0)
        }
        _ => 1,
    }
}

/// GET /api/projector/models
///
/// List all supported model families in the projector registry.
/// Returns 404 when the projector is not enabled.
pub async fn projector_models(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let registry = state.projector_registry.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Model projector is not enabled".to_string(),
            }),
        )
    })?;

    let families = registry.families().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to list model families: {}", e),
            }),
        )
    })?;

    let family_strings: Vec<String> = families
        .iter()
        .map(|f| match f {
            ModelFamily::Claude => "claude".to_string(),
            ModelFamily::OpenAi => "openai".to_string(),
            ModelFamily::DeepSeek => "deepseek".to_string(),
            ModelFamily::Qwen => "qwen".to_string(),
            ModelFamily::Generic => "generic".to_string(),
            ModelFamily::Custom(name) => format!("custom:{}", name),
        })
        .collect();

    Ok(Json(json!({
        "model_families": family_strings,
    })))
}

/// Request body for `POST /api/projector/transform`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectorTransformRequest {
    /// The canonical tool schema to project.
    pub schema: CanonicalToolSchema,
    /// Target model family (e.g., "claude", "openai", "deepseek", "qwen", "generic").
    pub model_family: String,
}

/// Parse a model family string into a `ModelFamily` enum.
fn parse_model_family(s: &str) -> ModelFamily {
    match s {
        "claude" => ModelFamily::Claude,
        "openai" => ModelFamily::OpenAi,
        "deepseek" => ModelFamily::DeepSeek,
        "qwen" => ModelFamily::Qwen,
        "generic" => ModelFamily::Generic,
        other if other.starts_with("custom:") => {
            ModelFamily::Custom(other[7..].to_string())
        }
        other => ModelFamily::Custom(other.to_string()),
    }
}

/// POST /api/projector/transform
///
/// Project a canonical tool schema to a model-specific format.
/// Returns the projected schema and an estimated token count.
/// Returns 404 when the projector is not enabled.
pub async fn projector_transform(
    State(state): State<AppState>,
    Json(body): Json<ProjectorTransformRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let registry = state.projector_registry.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Model projector is not enabled".to_string(),
            }),
        )
    })?;

    // Validate model_family length
    if body.model_family.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "model_family must not be empty".to_string(),
            }),
        ));
    }
    if body.model_family.len() > MAX_MODEL_FAMILY_LENGTH {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "model_family length {} exceeds max {}",
                    body.model_family.len(),
                    MAX_MODEL_FAMILY_LENGTH
                ),
            }),
        ));
    }
    if body.model_family.chars().any(|c| c.is_control()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "model_family contains control characters".to_string(),
            }),
        ));
    }

    // Validate schema name
    if body.schema.name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "schema.name must not be empty".to_string(),
            }),
        ));
    }
    if body.schema.name.len() > MAX_SCHEMA_NAME_LENGTH {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "schema.name length {} exceeds max {}",
                    body.schema.name.len(),
                    MAX_SCHEMA_NAME_LENGTH
                ),
            }),
        ));
    }
    if body.schema.name.chars().any(|c| c.is_control()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "schema.name contains control characters".to_string(),
            }),
        ));
    }

    // Validate schema description
    if body.schema.description.len() > MAX_SCHEMA_DESCRIPTION_LENGTH {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "schema.description length {} exceeds max {}",
                    body.schema.description.len(),
                    MAX_SCHEMA_DESCRIPTION_LENGTH
                ),
            }),
        ));
    }

    // SECURITY (FIND-R46-005): Validate JSON nesting depth of input_schema and output_schema
    // to prevent stack overflow or excessive processing from deeply nested payloads.
    let input_depth = json_depth(&body.schema.input_schema);
    if input_depth > MAX_SCHEMA_DEPTH {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "schema.input_schema nesting depth {} exceeds max {}",
                    input_depth, MAX_SCHEMA_DEPTH
                ),
            }),
        ));
    }
    if let Some(ref output) = body.schema.output_schema {
        let output_depth = json_depth(output);
        if output_depth > MAX_SCHEMA_DEPTH {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "schema.output_schema nesting depth {} exceeds max {}",
                        output_depth, MAX_SCHEMA_DEPTH
                    ),
                }),
            ));
        }
    }

    let family = parse_model_family(&body.model_family);

    let projection = registry.get(&family).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Unsupported model family '{}': {}", body.model_family, e),
            }),
        )
    })?;

    let projected = projection.project_schema(&body.schema).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Schema projection failed: {}", e),
            }),
        )
    })?;

    let token_estimate = projection.estimate_tokens(&body.schema);

    Ok(Json(json!({
        "projected_schema": projected,
        "token_estimate": token_estimate,
        "model_family": body.model_family,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_model_family_known() {
        assert_eq!(parse_model_family("claude"), ModelFamily::Claude);
        assert_eq!(parse_model_family("openai"), ModelFamily::OpenAi);
        assert_eq!(parse_model_family("deepseek"), ModelFamily::DeepSeek);
        assert_eq!(parse_model_family("qwen"), ModelFamily::Qwen);
        assert_eq!(parse_model_family("generic"), ModelFamily::Generic);
    }

    #[test]
    fn test_parse_model_family_custom_prefix() {
        let result = parse_model_family("custom:my-model");
        assert_eq!(result, ModelFamily::Custom("my-model".to_string()));
    }

    #[test]
    fn test_parse_model_family_unknown_becomes_custom() {
        let result = parse_model_family("unknown-model");
        assert_eq!(result, ModelFamily::Custom("unknown-model".to_string()));
    }

    #[test]
    fn test_transform_request_deserialize() {
        let json = r#"{
            "schema": {
                "name": "test_tool",
                "description": "A test tool",
                "input_schema": {"type": "object"},
                "output_schema": null
            },
            "model_family": "claude"
        }"#;
        let req: ProjectorTransformRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.schema.name, "test_tool");
        assert_eq!(req.model_family, "claude");
    }

    #[test]
    fn test_json_depth_flat() {
        let v = serde_json::json!({"a": 1, "b": "hello"});
        assert_eq!(json_depth(&v), 2); // object + scalar
    }

    #[test]
    fn test_json_depth_nested() {
        let v = serde_json::json!({"a": {"b": {"c": 1}}});
        assert_eq!(json_depth(&v), 4);
    }

    #[test]
    fn test_json_depth_array() {
        let v = serde_json::json!([[[1]]]);
        assert_eq!(json_depth(&v), 4);
    }

    #[test]
    fn test_json_depth_scalar() {
        assert_eq!(json_depth(&serde_json::json!(42)), 1);
        assert_eq!(json_depth(&serde_json::json!(null)), 1);
    }

    #[test]
    fn test_transform_request_deserialize_with_output_schema() {
        let json = r#"{
            "schema": {
                "name": "tool_a",
                "description": "Tool A",
                "input_schema": {"type": "object", "properties": {}},
                "output_schema": {"type": "string"}
            },
            "model_family": "openai"
        }"#;
        let req: ProjectorTransformRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.schema.name, "tool_a");
        assert_eq!(req.model_family, "openai");
        assert!(req.schema.output_schema.is_some());
    }
}
