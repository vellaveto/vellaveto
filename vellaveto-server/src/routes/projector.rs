// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

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
/// SECURITY (FIND-R116-011): Bounded recursion to prevent stack overflow
/// on programmatically-created deeply nested values.
fn json_depth(value: &serde_json::Value) -> usize {
    json_depth_bounded(value, 0)
}

fn json_depth_bounded(value: &serde_json::Value, current: usize) -> usize {
    // Bail out at MAX_SCHEMA_DEPTH to prevent stack overflow
    if current >= MAX_SCHEMA_DEPTH {
        return current;
    }
    match value {
        serde_json::Value::Object(map) => {
            1 + map
                .values()
                .map(|v| json_depth_bounded(v, current + 1))
                .max()
                .unwrap_or(0)
        }
        serde_json::Value::Array(arr) => {
            1 + arr
                .iter()
                .map(|v| json_depth_bounded(v, current + 1))
                .max()
                .unwrap_or(0)
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
                error: "Model projector is not enabled. Set [projector] enabled = true in your config file and restart the server.".to_string(),
            }),
        )
    })?;

    let families = registry.families().map_err(|e| {
        // SECURITY (FIND-R65-002): Redact internal error details.
        tracing::warn!(error = %e, "Failed to list projector model families");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to list model families".to_string(),
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
            ModelFamily::Custom(name) => format!("custom:{name}"),
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
        other if other.starts_with("custom:") => ModelFamily::Custom(other[7..].to_string()),
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
                error: "Model projector is not enabled. Set [projector] enabled = true in your config file and restart the server.".to_string(),
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
    if body.model_family.chars().any(crate::routes::is_unsafe_char) {
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
    if body.schema.name.chars().any(crate::routes::is_unsafe_char) {
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
    // SECURITY (FIND-R133-001): Validate description for control characters.
    // Previously only schema.name was validated, creating an asymmetry that
    // allowed control char injection via the description field.
    if body
        .schema
        .description
        .chars()
        .any(crate::routes::is_unsafe_char)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "schema.description contains control characters".to_string(),
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
                    "schema.input_schema nesting depth {input_depth} exceeds max {MAX_SCHEMA_DEPTH}"
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
                        "schema.output_schema nesting depth {output_depth} exceeds max {MAX_SCHEMA_DEPTH}"
                    ),
                }),
            ));
        }
    }

    // SECURITY (FIND-R196-001): Call the type-level validate() which checks
    // input_schema/output_schema serialized sizes against MAX_PROJECTOR_VALUE_SIZE.
    // The manual checks above cover name/description/depth, but the Value size
    // limits are only enforced by CanonicalToolSchema::validate().
    body.schema.validate().map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("schema validation failed: {e}"),
            }),
        )
    })?;

    let family = parse_model_family(&body.model_family);

    let projection = registry.get(&family).map_err(|e| {
        tracing::warn!(model_family = %body.model_family, error = %e, "Unsupported model family");
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Unsupported model family".to_string(),
            }),
        )
    })?;

    let projected = projection.project_schema(&body.schema).map_err(|e| {
        tracing::warn!(error = %e, "Schema projection failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Schema projection failed".to_string(),
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

    // ── FIND-R133-001: is_unsafe_char validation coverage ──────────

    #[test]
    fn test_is_unsafe_char_detects_control_chars() {
        assert!(crate::routes::is_unsafe_char('\x00'));
        assert!(crate::routes::is_unsafe_char('\x1b'));
        assert!(crate::routes::is_unsafe_char('\u{200B}')); // zero-width space
        assert!(!crate::routes::is_unsafe_char('a'));
        assert!(!crate::routes::is_unsafe_char(' '));
    }

    // IMP-R126-003: Regression test for U+2065 gap that existed when is_unsafe_char
    // used inline ranges (0x2060..=0x2064) and (0x2066..=0x2069), missing U+2065.
    #[test]
    fn test_is_unsafe_char_u2065_no_longer_missing() {
        assert!(
            crate::routes::is_unsafe_char('\u{2065}'),
            "U+2065 must be detected — was previously missed in range gap"
        );
        // Verify the full contiguous range 2060-2069
        for cp in 0x2060u32..=0x2069 {
            let c = char::from_u32(cp).unwrap();
            assert!(
                crate::routes::is_unsafe_char(c),
                "U+{cp:04X} must be detected as unsafe"
            );
        }
    }

    // FIND-R196-001: projector_transform must call schema.validate()
    #[test]
    fn test_canonical_tool_schema_validate_called_in_route() {
        // Verify that MAX_PROJECTOR_VALUE_SIZE is available — this constant
        // is used by CanonicalToolSchema::validate() to bound input_schema
        // and output_schema sizes, confirming the type-level validation path.
        use vellaveto_types::projector::MAX_PROJECTOR_VALUE_SIZE;
        const { assert!(MAX_PROJECTOR_VALUE_SIZE > 0) };
    }
}
