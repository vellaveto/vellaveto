//! MCP Gateway Router — multi-backend tool routing with health tracking (Phase 20).
//!
//! The gateway routes tool calls to different upstream MCP servers based on
//! tool name prefix matching. It maintains per-backend health state with
//! configurable failure/success thresholds and supports session affinity.
//!
//! # Design Decisions
//!
//! - **Fail-closed**: When all matching backends are unhealthy, `route()` returns
//!   `None` and the caller must deny the request.
//! - **Longest prefix match**: Tool names are matched against prefixes sorted by
//!   length descending, so `file_system_` beats `file_`.
//! - **No rewrite of forwarding**: The router only resolves "which URL" — the
//!   existing `forward_to_upstream()` function handles the actual HTTP request.

use std::collections::HashMap;
use std::sync::RwLock;
use vellaveto_config::GatewayConfig;
use vellaveto_types::{BackendHealth, RoutingDecision, ToolConflict};

/// Maximum tool name length considered for routing.
/// Tool names longer than this are truncated before prefix matching.
const MAX_TOOL_NAME_LEN: usize = 256;

/// Internal health state for a single backend.
#[derive(Debug)]
struct BackendState {
    url: String,
    health: BackendHealth,
    consecutive_failures: u32,
    consecutive_successes: u32,
}

/// MCP Gateway Router.
///
/// Routes tool calls to upstream backends based on tool name prefix matching,
/// with health-aware failover and session affinity support.
impl std::fmt::Debug for GatewayRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayRouter")
            .field("prefix_table_len", &self.prefix_table.len())
            .field("default_backend_id", &self.default_backend_id)
            .field("unhealthy_threshold", &self.unhealthy_threshold)
            .field("healthy_threshold", &self.healthy_threshold)
            .finish()
    }
}

pub struct GatewayRouter {
    /// Per-backend mutable health state, keyed by backend ID.
    states: RwLock<HashMap<String, BackendState>>,
    /// Prefix→backend_id routing table, sorted longest-first for greedy matching.
    prefix_table: Vec<(String, String)>,
    /// Backend ID of the default (catch-all) backend, if any.
    default_backend_id: Option<String>,
    /// Number of consecutive failures before marking a backend unhealthy.
    unhealthy_threshold: u32,
    /// Number of consecutive successes before restoring a backend to healthy.
    healthy_threshold: u32,
}

impl GatewayRouter {
    /// Build a router from gateway configuration.
    ///
    /// Returns an error if the configuration is structurally invalid
    /// (duplicate IDs, empty backends, etc.).
    pub fn from_config(config: &GatewayConfig) -> Result<Self, String> {
        if config.backends.is_empty() {
            return Err("gateway requires at least one backend".to_string());
        }

        let mut states = HashMap::new();
        let mut prefix_table = Vec::new();
        let mut default_backend_id = None;
        let mut seen_ids = std::collections::HashSet::new();

        for backend in &config.backends {
            if !seen_ids.insert(&backend.id) {
                return Err(format!("duplicate backend id '{}'", backend.id));
            }

            states.insert(
                backend.id.clone(),
                BackendState {
                    url: backend.url.clone(),
                    health: BackendHealth::Healthy,
                    consecutive_failures: 0,
                    consecutive_successes: 0,
                },
            );

            if backend.tool_prefixes.is_empty() {
                if default_backend_id.is_some() {
                    return Err(
                        "multiple default backends (empty tool_prefixes); at most one allowed"
                            .to_string(),
                    );
                }
                default_backend_id = Some(backend.id.clone());
            } else {
                for prefix in &backend.tool_prefixes {
                    prefix_table.push((prefix.clone(), backend.id.clone()));
                }
            }
        }

        // Sort by prefix length descending for longest-prefix-first matching
        prefix_table.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        Ok(Self {
            states: RwLock::new(states),
            prefix_table,
            default_backend_id,
            unhealthy_threshold: config.unhealthy_threshold,
            healthy_threshold: config.healthy_threshold,
        })
    }

    /// Route a tool call to the appropriate backend.
    ///
    /// Returns `None` when no healthy backend matches (fail-closed).
    pub fn route(&self, tool_name: &str) -> Option<RoutingDecision> {
        // Truncate excessively long tool names
        let tool_name = if tool_name.len() > MAX_TOOL_NAME_LEN {
            &tool_name[..MAX_TOOL_NAME_LEN]
        } else {
            tool_name
        };

        let states = self.states.read().unwrap_or_else(|e| e.into_inner());

        // Try longest-prefix match first
        for (prefix, backend_id) in &self.prefix_table {
            if tool_name.starts_with(prefix.as_str()) {
                if let Some(state) = states.get(backend_id) {
                    if state.health != BackendHealth::Unhealthy {
                        return Some(RoutingDecision {
                            backend_id: backend_id.clone(),
                            upstream_url: state.url.clone(),
                        });
                    }
                }
            }
        }

        // Fall back to default backend
        if let Some(ref default_id) = self.default_backend_id {
            if let Some(state) = states.get(default_id) {
                if state.health != BackendHealth::Unhealthy {
                    return Some(RoutingDecision {
                        backend_id: default_id.clone(),
                        upstream_url: state.url.clone(),
                    });
                }
            }
        }

        None // fail-closed
    }

    /// Route with session affinity — prefer a previously used backend if healthy.
    ///
    /// `session_affinities` maps tool_name → backend_id from prior routing decisions.
    pub fn route_with_affinity(
        &self,
        tool_name: &str,
        session_affinities: &HashMap<String, String>,
    ) -> Option<RoutingDecision> {
        // Check if there's a session-affine backend for this tool
        if let Some(affine_id) = session_affinities.get(tool_name) {
            let states = self.states.read().unwrap_or_else(|e| e.into_inner());
            if let Some(state) = states.get(affine_id.as_str()) {
                if state.health != BackendHealth::Unhealthy {
                    return Some(RoutingDecision {
                        backend_id: affine_id.clone(),
                        upstream_url: state.url.clone(),
                    });
                }
            }
            // Affine backend is unhealthy — fall through to normal routing
        }

        self.route(tool_name)
    }

    /// Record a successful response from a backend.
    ///
    /// Transitions: Unhealthy→Degraded (after 1 success), Degraded→Healthy
    /// (after `healthy_threshold` consecutive successes).
    pub fn record_success(&self, backend_id: &str) {
        let mut states = self.states.write().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = states.get_mut(backend_id) {
            state.consecutive_failures = 0;
            state.consecutive_successes += 1;

            match state.health {
                BackendHealth::Unhealthy => {
                    state.health = BackendHealth::Degraded;
                    state.consecutive_successes = 1;
                    tracing::info!(
                        backend = %backend_id,
                        "Gateway backend transitioning: unhealthy → degraded"
                    );
                }
                BackendHealth::Degraded => {
                    if state.consecutive_successes >= self.healthy_threshold {
                        state.health = BackendHealth::Healthy;
                        state.consecutive_successes = 0;
                        tracing::info!(
                            backend = %backend_id,
                            "Gateway backend transitioning: degraded → healthy"
                        );
                    }
                }
                BackendHealth::Healthy => {}
            }
        }
    }

    /// Record a failed response from a backend.
    ///
    /// Marks the backend as Unhealthy after `unhealthy_threshold` consecutive failures.
    pub fn record_failure(&self, backend_id: &str) {
        let mut states = self.states.write().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = states.get_mut(backend_id) {
            state.consecutive_successes = 0;
            state.consecutive_failures += 1;

            if state.consecutive_failures >= self.unhealthy_threshold
                && state.health != BackendHealth::Unhealthy
            {
                tracing::warn!(
                    backend = %backend_id,
                    failures = state.consecutive_failures,
                    "Gateway backend transitioning: {} → unhealthy",
                    match state.health {
                        BackendHealth::Healthy => "healthy",
                        BackendHealth::Degraded => "degraded",
                        BackendHealth::Unhealthy => "unhealthy",
                    }
                );
                state.health = BackendHealth::Unhealthy;
            }
        }
    }

    /// Return a snapshot of all backend health states.
    pub fn backend_health(&self) -> Vec<(String, String, BackendHealth)> {
        let states = self.states.read().unwrap_or_else(|e| e.into_inner());
        states
            .iter()
            .map(|(id, state)| (id.clone(), state.url.clone(), state.health))
            .collect()
    }

    /// Number of configured backends.
    pub fn backend_count(&self) -> usize {
        let states = self.states.read().unwrap_or_else(|e| e.into_inner());
        states.len()
    }
}

/// Data about tools discovered from a single backend.
pub struct DiscoveredTools {
    pub backend_id: String,
    pub tool_names: Vec<String>,
}

/// Detect tool name conflicts across multiple backends.
///
/// Returns a list of tool names that are advertised by more than one backend.
pub fn detect_conflicts(discovered: &[DiscoveredTools]) -> Vec<ToolConflict> {
    let mut tool_map: HashMap<&str, Vec<&str>> = HashMap::new();
    for dt in discovered {
        for name in &dt.tool_names {
            tool_map
                .entry(name.as_str())
                .or_default()
                .push(dt.backend_id.as_str());
        }
    }
    tool_map
        .into_iter()
        .filter(|(_, backends)| backends.len() > 1)
        .map(|(tool_name, backends)| ToolConflict {
            tool_name: tool_name.to_string(),
            backends: backends.into_iter().map(String::from).collect(),
        })
        .collect()
}

/// Spawn a background health checker that periodically pings backends.
///
/// Sends a JSON-RPC `ping` request to each backend URL and records
/// success/failure based on the response status.
pub fn spawn_health_checker(
    gateway: std::sync::Arc<GatewayRouter>,
    client: reqwest::Client,
    interval_secs: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        // Skip the first immediate tick
        interval.tick().await;

        loop {
            interval.tick().await;

            let backends: Vec<(String, String)> = {
                let states = gateway.states.read().unwrap_or_else(|e| e.into_inner());
                states
                    .iter()
                    .map(|(id, state)| (id.clone(), state.url.clone()))
                    .collect()
            };

            for (backend_id, url) in &backends {
                let ping_body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "health",
                    "method": "ping"
                });

                let result = client
                    .post(url)
                    .header("content-type", "application/json")
                    .json(&ping_body)
                    .timeout(std::time::Duration::from_secs(5))
                    .send()
                    .await;

                match result {
                    Ok(resp) if resp.status().is_success() || resp.status().is_client_error() => {
                        // 2xx or 4xx = server is alive (even if it rejects the ping method)
                        gateway.record_success(backend_id);
                    }
                    Ok(resp) => {
                        tracing::debug!(
                            backend = %backend_id,
                            status = %resp.status(),
                            "Gateway health check: server error"
                        );
                        gateway.record_failure(backend_id);
                    }
                    Err(e) => {
                        tracing::debug!(
                            backend = %backend_id,
                            error = %e,
                            "Gateway health check: connection failed"
                        );
                        gateway.record_failure(backend_id);
                    }
                }
            }

            // Update metrics
            let health = gateway.backend_health();
            let total = health.len();
            let healthy_count = health
                .iter()
                .filter(|(_, _, h)| *h == BackendHealth::Healthy)
                .count();

            metrics::gauge!("vellaveto_gateway_backends_total").set(total as f64);
            metrics::gauge!("vellaveto_gateway_backends_healthy").set(healthy_count as f64);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vellaveto_config::{BackendConfig, GatewayConfig};

    fn test_config(backends: Vec<BackendConfig>) -> GatewayConfig {
        GatewayConfig {
            enabled: true,
            backends,
            health_check_interval_secs: 15,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        }
    }

    fn backend(id: &str, url: &str, prefixes: &[&str]) -> BackendConfig {
        BackendConfig {
            id: id.to_string(),
            url: url.to_string(),
            tool_prefixes: prefixes.iter().map(|s| s.to_string()).collect(),
            weight: 100,
        }
    }

    fn default_backend(id: &str, url: &str) -> BackendConfig {
        BackendConfig {
            id: id.to_string(),
            url: url.to_string(),
            tool_prefixes: vec![],
            weight: 100,
        }
    }

    #[test]
    fn test_router_from_config_valid() {
        let config = test_config(vec![
            backend("fs", "http://fs:8000", &["fs_", "file_"]),
            default_backend("default", "http://default:8000"),
        ]);
        let router = GatewayRouter::from_config(&config).unwrap();
        assert_eq!(router.backend_count(), 2);
        assert_eq!(router.prefix_table.len(), 2);
        assert_eq!(router.default_backend_id, Some("default".to_string()));
    }

    #[test]
    fn test_router_from_config_empty_backends() {
        let config = test_config(vec![]);
        let err = GatewayRouter::from_config(&config).unwrap_err();
        assert!(err.contains("at least one backend"), "got: {}", err);
    }

    #[test]
    fn test_router_from_config_duplicate_ids() {
        let config = test_config(vec![
            backend("dup", "http://a:8000", &["a_"]),
            backend("dup", "http://b:8000", &["b_"]),
        ]);
        let err = GatewayRouter::from_config(&config).unwrap_err();
        assert!(err.contains("duplicate backend id"), "got: {}", err);
    }

    #[test]
    fn test_router_from_config_multiple_defaults() {
        let config = test_config(vec![
            default_backend("d1", "http://a:8000"),
            default_backend("d2", "http://b:8000"),
        ]);
        let err = GatewayRouter::from_config(&config).unwrap_err();
        assert!(err.contains("multiple default backends"), "got: {}", err);
    }

    #[test]
    fn test_route_prefix_match() {
        let config = test_config(vec![
            backend("fs", "http://fs:8000", &["fs_"]),
            default_backend("default", "http://default:8000"),
        ]);
        let router = GatewayRouter::from_config(&config).unwrap();

        let decision = router.route("fs_read_file").unwrap();
        assert_eq!(decision.backend_id, "fs");
        assert_eq!(decision.upstream_url, "http://fs:8000");
    }

    #[test]
    fn test_route_longest_prefix_wins() {
        let config = test_config(vec![
            backend("short", "http://short:8000", &["fs_"]),
            backend("long", "http://long:8000", &["fs_read_"]),
        ]);
        let router = GatewayRouter::from_config(&config).unwrap();

        // "fs_read_file" matches both "fs_" and "fs_read_", longest wins
        let decision = router.route("fs_read_file").unwrap();
        assert_eq!(decision.backend_id, "long");

        // "fs_write_file" only matches "fs_"
        let decision = router.route("fs_write_file").unwrap();
        assert_eq!(decision.backend_id, "short");
    }

    #[test]
    fn test_route_default_fallback() {
        let config = test_config(vec![
            backend("fs", "http://fs:8000", &["fs_"]),
            default_backend("default", "http://default:8000"),
        ]);
        let router = GatewayRouter::from_config(&config).unwrap();

        let decision = router.route("unknown_tool").unwrap();
        assert_eq!(decision.backend_id, "default");
    }

    #[test]
    fn test_route_no_match_no_default_returns_none() {
        let config = test_config(vec![backend("fs", "http://fs:8000", &["fs_"])]);
        let router = GatewayRouter::from_config(&config).unwrap();

        assert!(router.route("unknown_tool").is_none());
    }

    #[test]
    fn test_route_unhealthy_backend_skipped() {
        let config = test_config(vec![
            backend("fs", "http://fs:8000", &["fs_"]),
            default_backend("default", "http://default:8000"),
        ]);
        let router = GatewayRouter::from_config(&config).unwrap();

        // Mark fs as unhealthy
        for _ in 0..3 {
            router.record_failure("fs");
        }

        // Should fall through to default
        let decision = router.route("fs_read_file").unwrap();
        assert_eq!(decision.backend_id, "default");
    }

    #[test]
    fn test_route_degraded_backend_included() {
        let config = GatewayConfig {
            unhealthy_threshold: 5, // higher so we don't cross it
            ..test_config(vec![backend("fs", "http://fs:8000", &["fs_"])])
        };
        let router = GatewayRouter::from_config(&config).unwrap();

        // Record some failures but not enough to be unhealthy
        router.record_failure("fs");
        router.record_failure("fs");

        // Should still route (degraded but not unhealthy since threshold is 5)
        let decision = router.route("fs_read_file").unwrap();
        assert_eq!(decision.backend_id, "fs");
    }

    #[test]
    fn test_record_failure_marks_unhealthy() {
        let config = test_config(vec![backend("fs", "http://fs:8000", &["fs_"])]);
        let router = GatewayRouter::from_config(&config).unwrap();

        // threshold is 3
        router.record_failure("fs");
        router.record_failure("fs");
        assert!(router.route("fs_tool").is_some()); // still healthy

        router.record_failure("fs");
        assert!(router.route("fs_tool").is_none()); // now unhealthy
    }

    #[test]
    fn test_record_success_restores_from_degraded() {
        let config = test_config(vec![backend("fs", "http://fs:8000", &["fs_"])]);
        let router = GatewayRouter::from_config(&config).unwrap();

        // Make unhealthy
        for _ in 0..3 {
            router.record_failure("fs");
        }
        assert!(router.route("fs_tool").is_none());

        // One success transitions to degraded
        router.record_success("fs");
        assert!(router.route("fs_tool").is_some()); // degraded is routable

        // Another success restores to healthy (healthy_threshold = 2)
        router.record_success("fs");
        let health = router.backend_health();
        let fs_health = health.iter().find(|(id, _, _)| id == "fs").unwrap();
        assert_eq!(fs_health.2, BackendHealth::Healthy);
    }

    #[test]
    fn test_record_failure_resets_success_count() {
        let config = test_config(vec![backend("fs", "http://fs:8000", &["fs_"])]);
        let router = GatewayRouter::from_config(&config).unwrap();

        // Make unhealthy, then start recovering
        for _ in 0..3 {
            router.record_failure("fs");
        }
        router.record_success("fs"); // degraded now, success_count = 1

        // Failure resets success counter
        router.record_failure("fs");

        // Need healthy_threshold (2) more successes to restore
        router.record_success("fs");
        let health = router.backend_health();
        let fs_health = health.iter().find(|(id, _, _)| id == "fs").unwrap();
        assert_eq!(fs_health.2, BackendHealth::Degraded); // still degraded
    }

    #[test]
    fn test_health_transition_unhealthy_to_degraded() {
        let config = test_config(vec![backend("b", "http://b:8000", &["b_"])]);
        let router = GatewayRouter::from_config(&config).unwrap();

        for _ in 0..3 {
            router.record_failure("b");
        }

        let health = router.backend_health();
        assert_eq!(health[0].2, BackendHealth::Unhealthy);

        router.record_success("b");
        let health = router.backend_health();
        assert_eq!(health[0].2, BackendHealth::Degraded);
    }

    #[test]
    fn test_health_transition_degraded_to_healthy() {
        let config = test_config(vec![backend("b", "http://b:8000", &["b_"])]);
        let router = GatewayRouter::from_config(&config).unwrap();

        for _ in 0..3 {
            router.record_failure("b");
        }
        router.record_success("b"); // degraded
        router.record_success("b"); // healthy (threshold = 2)

        let health = router.backend_health();
        assert_eq!(health[0].2, BackendHealth::Healthy);
    }

    #[test]
    fn test_backend_health_returns_all() {
        let config = test_config(vec![
            backend("a", "http://a:8000", &["a_"]),
            backend("b", "http://b:8000", &["b_"]),
        ]);
        let router = GatewayRouter::from_config(&config).unwrap();

        let health = router.backend_health();
        assert_eq!(health.len(), 2);
    }

    #[test]
    fn test_backend_count() {
        let config = test_config(vec![
            backend("a", "http://a:8000", &["a_"]),
            backend("b", "http://b:8000", &["b_"]),
            backend("c", "http://c:8000", &["c_"]),
        ]);
        let router = GatewayRouter::from_config(&config).unwrap();
        assert_eq!(router.backend_count(), 3);
    }

    #[test]
    fn test_detect_conflicts_none() {
        let discovered = vec![
            DiscoveredTools {
                backend_id: "a".to_string(),
                tool_names: vec!["tool_a".to_string()],
            },
            DiscoveredTools {
                backend_id: "b".to_string(),
                tool_names: vec!["tool_b".to_string()],
            },
        ];
        let conflicts = detect_conflicts(&discovered);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_detect_conflicts_found() {
        let discovered = vec![
            DiscoveredTools {
                backend_id: "a".to_string(),
                tool_names: vec!["read_file".to_string(), "unique_a".to_string()],
            },
            DiscoveredTools {
                backend_id: "b".to_string(),
                tool_names: vec!["read_file".to_string(), "unique_b".to_string()],
            },
        ];
        let conflicts = detect_conflicts(&discovered);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].tool_name, "read_file");
        assert_eq!(conflicts[0].backends.len(), 2);
    }

    #[test]
    fn test_route_with_affinity_prefers_known() {
        let config = test_config(vec![
            backend("a", "http://a:8000", &["fs_"]),
            backend("b", "http://b:8000", &["fs_"]),
            default_backend("default", "http://default:8000"),
        ]);
        let router = GatewayRouter::from_config(&config).unwrap();

        let mut affinities = HashMap::new();
        affinities.insert("fs_read".to_string(), "b".to_string());

        let decision = router.route_with_affinity("fs_read", &affinities).unwrap();
        assert_eq!(decision.backend_id, "b");
    }

    #[test]
    fn test_route_with_affinity_falls_back_on_unhealthy() {
        let config = test_config(vec![
            backend("a", "http://a:8000", &["fs_"]),
            default_backend("default", "http://default:8000"),
        ]);
        let router = GatewayRouter::from_config(&config).unwrap();

        // Make "a" unhealthy
        for _ in 0..3 {
            router.record_failure("a");
        }

        let mut affinities = HashMap::new();
        affinities.insert("fs_read".to_string(), "a".to_string());

        // Should fall back to default since "a" is unhealthy
        let decision = router.route_with_affinity("fs_read", &affinities).unwrap();
        assert_eq!(decision.backend_id, "default");
    }

    #[test]
    fn test_route_with_affinity_empty_affinities() {
        let config = test_config(vec![
            backend("fs", "http://fs:8000", &["fs_"]),
            default_backend("default", "http://default:8000"),
        ]);
        let router = GatewayRouter::from_config(&config).unwrap();

        let affinities = HashMap::new();
        let decision = router.route_with_affinity("fs_read", &affinities).unwrap();
        assert_eq!(decision.backend_id, "fs");
    }

    #[test]
    fn test_route_truncates_long_tool_name() {
        let config = test_config(vec![default_backend("default", "http://default:8000")]);
        let router = GatewayRouter::from_config(&config).unwrap();

        let long_name = "x".repeat(1000);
        let decision = router.route(&long_name).unwrap();
        assert_eq!(decision.backend_id, "default");
    }

    #[test]
    fn test_route_empty_tool_name_uses_default() {
        let config = test_config(vec![
            backend("fs", "http://fs:8000", &["fs_"]),
            default_backend("default", "http://default:8000"),
        ]);
        let router = GatewayRouter::from_config(&config).unwrap();

        let decision = router.route("").unwrap();
        assert_eq!(decision.backend_id, "default");
    }

    #[test]
    fn test_gateway_config_validate_valid() {
        let config = test_config(vec![
            backend("a", "http://a:8000", &["a_"]),
            default_backend("default", "http://default:8000"),
        ]);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_gateway_config_validate_empty_id() {
        let config = test_config(vec![BackendConfig {
            id: String::new(),
            url: "http://a:8000".to_string(),
            tool_prefixes: vec![],
            weight: 100,
        }]);
        let err = config.validate().unwrap_err();
        assert!(err.contains("id must not be empty"), "got: {}", err);
    }

    #[test]
    fn test_gateway_config_validate_zero_weight() {
        let config = test_config(vec![BackendConfig {
            id: "b".to_string(),
            url: "http://a:8000".to_string(),
            tool_prefixes: vec![],
            weight: 0,
        }]);
        let err = config.validate().unwrap_err();
        assert!(err.contains("weight must be >= 1"), "got: {}", err);
    }

    #[test]
    fn test_gateway_config_validate_interval_bounds() {
        let mut config = test_config(vec![default_backend("d", "http://d:8000")]);
        config.health_check_interval_secs = 1;
        assert!(config.validate().unwrap_err().contains("[5, 300]"));

        config.health_check_interval_secs = 500;
        assert!(config.validate().unwrap_err().contains("[5, 300]"));
    }

    #[test]
    fn test_gateway_config_disabled_skips_validation() {
        let config = GatewayConfig {
            enabled: false,
            backends: vec![],
            health_check_interval_secs: 0,
            unhealthy_threshold: 0,
            healthy_threshold: 0,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_gateway_config_serde_roundtrip() {
        let config = test_config(vec![
            backend("a", "http://a:8000", &["prefix_"]),
            default_backend("default", "http://d:8000"),
        ]);
        let json_str = serde_json::to_string(&config).unwrap();
        let deserialized: GatewayConfig = serde_json::from_str(&json_str).unwrap();
        assert_eq!(config, deserialized);
    }
}
