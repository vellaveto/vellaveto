//! Deployment info route handler (Phase 27).
//!
//! Endpoint:
//! - `GET /api/deployment/info` — returns deployment metadata

use axum::{extract::State, Json};
use vellaveto_types::DeploymentInfo;

use crate::AppState;

/// GET /api/deployment/info
///
/// Returns deployment metadata: instance ID, leader status, discovered
/// endpoint count, uptime, and deployment mode.
pub async fn deployment_info(State(state): State<AppState>) -> Json<DeploymentInfo> {
    let instance_id = state.deployment_config.effective_instance_id();

    let leader_status = match state.leader_election.as_ref() {
        Some(le) => le.current_status(),
        None => vellaveto_types::LeaderStatus::Unknown,
    };

    let discovered_endpoints = match state.service_discovery.as_ref() {
        Some(sd) => sd.discover().await.map(|eps| eps.len()).unwrap_or(0),
        None => 0,
    };

    let uptime_secs = state.start_time.elapsed().as_secs();

    let mode = format!("{:?}", state.deployment_config.mode);

    Json(DeploymentInfo {
        instance_id,
        leader_status,
        discovered_endpoints,
        uptime_secs,
        mode,
    })
}
