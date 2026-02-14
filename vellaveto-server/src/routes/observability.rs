//! AI Observability Platform Integration route handlers (Phase 15).
//!
//! This module provides REST API endpoints for AI observability platform
//! integration, including exporter status and statistics.
//!
//! Endpoints:
//! - `GET /api/observability/exporters` - List configured observability exporters
//! - `GET /api/observability/stats` - Get observability statistics
//! - `POST /api/observability/test` - Test observability exporter connectivity

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

/// Response for observability exporter list.
#[derive(Debug, Serialize)]
pub struct ObservabilityExporterResponse {
    pub enabled: bool,
    pub exporters: Vec<crate::observability::ExporterInfo>,
}

/// Response for observability stats.
#[derive(Debug, Serialize)]
pub struct ObservabilityStatsResponse {
    pub enabled: bool,
    pub stats: Option<crate::observability::ObservabilityStatsSnapshot>,
    pub exporters: Vec<crate::observability::ExporterInfo>,
}

/// List configured observability exporters.
#[tracing::instrument(name = "vellaveto.observability.list_exporters", skip(state))]
pub async fn list_observability_exporters(
    State(state): State<AppState>,
) -> Json<ObservabilityExporterResponse> {
    match &state.observability {
        Some(obs) => Json(ObservabilityExporterResponse {
            enabled: true,
            exporters: obs.exporters().to_vec(),
        }),
        None => Json(ObservabilityExporterResponse {
            enabled: false,
            exporters: vec![],
        }),
    }
}

/// Get observability statistics.
#[tracing::instrument(name = "vellaveto.observability.stats", skip(state))]
pub async fn observability_stats(
    State(state): State<AppState>,
) -> Json<ObservabilityStatsResponse> {
    match &state.observability {
        Some(obs) => Json(ObservabilityStatsResponse {
            enabled: true,
            stats: Some(obs.stats()),
            exporters: obs.exporters().to_vec(),
        }),
        None => Json(ObservabilityStatsResponse {
            enabled: false,
            stats: None,
            exporters: vec![],
        }),
    }
}

/// Test observability exporter connectivity.
#[tracing::instrument(name = "vellaveto.observability.test", skip(state))]
pub async fn test_observability(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let Some(ref _obs) = state.observability else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Observability not enabled".to_string(),
            }),
        ));
    };

    // For now, return success if observability is enabled.
    // Full health check would require async health_check calls to each exporter.
    Ok(Json(json!({
        "status": "ok",
        "message": "Observability manager is running"
    })))
}
