//! Federation API route handlers (Phase 39).
//!
//! Endpoints:
//! - `GET /api/federation/status` -- federation status including per-anchor info
//! - `GET /api/federation/trust-anchors` -- list configured trust anchors with optional org_id filter

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;

use crate::routes::ErrorResponse;
use crate::AppState;

/// Query parameters for trust anchors listing.
#[derive(Debug, Deserialize)]
pub struct FederationAnchorsQuery {
    /// Optional filter by org_id.
    #[serde(default)]
    pub org_id: Option<String>,
}

/// GET /api/federation/status
///
/// Returns federation status including per-anchor JWKS cache info.
/// Returns 404 if federation is not enabled.
pub async fn federation_status(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let resolver = state.federation_resolver.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "federation not enabled".to_string(),
            }),
        )
    })?;

    let status = resolver.status();
    Ok(Json(serde_json::json!({
        "enabled": status.enabled,
        "trust_anchor_count": status.trust_anchor_count,
        "anchors": status.anchors.iter().map(|a| serde_json::json!({
            "org_id": a.org_id,
            "display_name": a.display_name,
            "issuer_pattern": a.issuer_pattern,
            "trust_level": a.trust_level,
            "has_jwks_uri": a.has_jwks_uri,
            "identity_mapping_count": a.identity_mapping_count,
            "successful_validations": a.successful_validations,
            "failed_validations": a.failed_validations,
        })).collect::<Vec<_>>(),
    })))
}

/// GET /api/federation/trust-anchors
///
/// Returns list of configured trust anchors. Supports ?org_id= filter.
pub async fn federation_trust_anchors(
    State(state): State<AppState>,
    Query(params): Query<FederationAnchorsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let resolver = state.federation_resolver.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "federation not enabled".to_string(),
            }),
        )
    })?;

    // Validate org_id parameter if provided
    if let Some(ref org_id) = params.org_id {
        if org_id.len() > 128 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "org_id exceeds max length (128)".to_string(),
                }),
            ));
        }
        if org_id.chars().any(|c| c.is_control()) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "org_id contains control characters".to_string(),
                }),
            ));
        }
    }

    let config = resolver.config();
    let anchors: Vec<serde_json::Value> = config
        .trust_anchors
        .iter()
        .filter(|a| {
            params
                .org_id
                .as_ref()
                .is_none_or(|filter| a.org_id == *filter)
        })
        .map(|a| {
            serde_json::json!({
                "org_id": a.org_id,
                "display_name": a.display_name,
                "issuer_pattern": a.issuer_pattern,
                "trust_level": a.trust_level,
                "has_jwks_uri": a.jwks_uri.is_some(),
                "identity_mapping_count": a.identity_mappings.len(),
            })
        })
        .collect();

    let total = anchors.len();
    Ok(Json(serde_json::json!({
        "anchors": anchors,
        "total": total,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_federation_anchors_query_default() {
        let q: FederationAnchorsQuery = serde_json::from_str("{}").unwrap();
        assert!(q.org_id.is_none());
    }

    #[test]
    fn test_federation_anchors_query_with_org_id() {
        let q: FederationAnchorsQuery =
            serde_json::from_str(r#"{"org_id": "acme-corp"}"#).unwrap();
        assert_eq!(q.org_id.as_deref(), Some("acme-corp"));
    }

    #[test]
    fn test_error_response_serializes() {
        let err = ErrorResponse {
            error: "test error".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("test error"));
    }
}
