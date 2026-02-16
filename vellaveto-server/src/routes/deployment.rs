//! Deployment info route handler (Phase 27).
//!
//! Endpoint:
//! - `GET /api/deployment/info` -- returns deployment metadata
//!
//! SECURITY (FIND-R44-015): This endpoint is behind auth middleware when
//! authentication is configured. In anonymous mode (api_key is None),
//! sensitive topology fields are redacted to prevent information leakage.

use axum::{extract::State, Json};
use vellaveto_types::DeploymentInfo;

use crate::AppState;

/// GET /api/deployment/info
///
/// Returns deployment metadata: instance ID, leader status, discovered
/// endpoint count, uptime, and deployment mode.
///
/// SECURITY (FIND-R44-015): When running in anonymous mode (no api_key
/// configured), sensitive topology fields (instance_id, leader_status,
/// discovered_endpoints) are redacted to prevent information leakage.
/// Only `mode` and `uptime_secs` are returned.
pub async fn deployment_info(State(state): State<AppState>) -> Json<DeploymentInfo> {
    // SECURITY (FIND-P27-002): Use cached values -- never call discover() from request handlers.
    let uptime_secs = state.start_time.elapsed().as_secs();
    let mode = format!("{:?}", state.deployment_config.mode);

    // SECURITY (FIND-R44-015): Check if anonymous mode is active.
    // Anonymous mode = api_key is None (no authentication configured).
    let is_anonymous = state.api_key.is_none();

    if is_anonymous {
        // Redact sensitive topology information in anonymous mode.
        Json(DeploymentInfo {
            instance_id: None,
            leader_status: None,
            discovered_endpoints: None,
            uptime_secs,
            mode,
        })
    } else {
        let instance_id = state.cached_instance_id.as_ref().clone();

        let leader_status = match state.leader_election.as_ref() {
            Some(le) => le.current_status(),
            None => vellaveto_types::LeaderStatus::Unknown,
        };

        let discovered_endpoints = state
            .cached_discovered_endpoints
            .load(std::sync::atomic::Ordering::Relaxed) as usize;

        Json(DeploymentInfo {
            instance_id: Some(instance_id),
            leader_status: Some(leader_status),
            discovered_endpoints: Some(discovered_endpoints),
            uptime_secs,
            mode,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deployment_info_anonymous_redacts_topology() {
        // Verify that when fields are None, they are omitted from JSON.
        let info = DeploymentInfo {
            instance_id: None,
            leader_status: None,
            discovered_endpoints: None,
            uptime_secs: 100,
            mode: "Standalone".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("instance_id"));
        assert!(!json.contains("leader_status"));
        assert!(!json.contains("discovered_endpoints"));
        assert!(json.contains("uptime_secs"));
        assert!(json.contains("mode"));
    }

    #[test]
    fn test_deployment_info_authenticated_includes_topology() {
        let info = DeploymentInfo {
            instance_id: Some("vellaveto-0".to_string()),
            leader_status: Some(vellaveto_types::LeaderStatus::Unknown),
            discovered_endpoints: Some(5),
            uptime_secs: 200,
            mode: "Kubernetes".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("instance_id"));
        assert!(json.contains("leader_status"));
        assert!(json.contains("discovered_endpoints"));
        assert!(json.contains("uptime_secs"));
        assert!(json.contains("mode"));
    }
}
