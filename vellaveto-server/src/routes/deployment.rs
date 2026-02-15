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
    // SECURITY (FIND-P27-002): Use cached values — never call discover() from request handlers.
    let instance_id = state.cached_instance_id.as_ref().clone();

    let leader_status = match state.leader_election.as_ref() {
        Some(le) => le.current_status(),
        None => vellaveto_types::LeaderStatus::Unknown,
    };

    let discovered_endpoints = state
        .cached_discovered_endpoints
        .load(std::sync::atomic::Ordering::Relaxed) as usize;

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
