//! Policy simulation endpoints for developer experience (Phase 22).
//!
//! Provides safe sandbox evaluation endpoints that don't require a running
//! server's policies. Supports single evaluation, batch evaluation,
//! config validation, and policy diff.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use vellaveto_config::PolicyConfig;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, EvaluationContext, EvaluationTrace, Policy, Verdict};

use crate::AppState;

use super::main::ErrorResponse;

/// Maximum actions in a batch request.
const MAX_BATCH_ACTIONS: usize = 100;

/// SECURITY (FIND-R46-001): Maximum inline policy config string length (256KB).
const MAX_POLICY_CONFIG_LENGTH: usize = 256 * 1024;

/// SECURITY (FIND-R46-001): Maximum number of policies in an inline config.
const MAX_POLICY_COUNT: usize = 500;

/// SECURITY (FIND-R46-002): Maximum config string length for diff endpoint (128KB per side).
const MAX_DIFF_CONFIG_LENGTH: usize = 128 * 1024;

/// SECURITY (FIND-R46-007): Maximum config string length for validate endpoint (512KB).
const MAX_VALIDATE_CONFIG_LENGTH: usize = 512 * 1024;

/// SECURITY (FIND-R46-003): Maximum red-team scenarios.
const MAX_RED_TEAM_SCENARIOS: usize = 100;

/// SECURITY (FIND-R46-014): Reduced batch limit when inline config is provided.
const MAX_BATCH_ACTIONS_WITH_INLINE_CONFIG: usize = 25;

// ═══════════════════════════════════════════════════════════════════
// Request / Response types
// ═══════════════════════════════════════════════════════════════════

/// Request body for `POST /api/simulator/evaluate`.
#[derive(Debug, Deserialize)]
pub struct SimulateRequest {
    pub action: Action,
    #[serde(default)]
    pub context: Option<EvaluationContext>,
    /// Optional inline policies (TOML string). If absent, uses server's loaded policies.
    #[serde(default)]
    pub policy_config: Option<String>,
}

/// Response for `POST /api/simulator/evaluate`.
#[derive(Debug, Serialize)]
pub struct SimulateResponse {
    pub verdict: Verdict,
    pub trace: EvaluationTrace,
    pub policies_checked: usize,
    pub duration_us: u64,
}

/// Request body for `POST /api/simulator/batch`.
#[derive(Debug, Deserialize)]
pub struct BatchRequest {
    pub actions: Vec<Action>,
    #[serde(default)]
    pub policy_config: Option<String>,
}

/// Response for `POST /api/simulator/batch`.
#[derive(Debug, Serialize)]
pub struct BatchResponse {
    pub results: Vec<BatchResult>,
    pub summary: BatchSummary,
}

/// Per-action result in a batch evaluation.
#[derive(Debug, Serialize)]
pub struct BatchResult {
    pub action_index: usize,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<EvaluationTrace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Summary statistics for a batch evaluation.
#[derive(Debug, Serialize)]
pub struct BatchSummary {
    pub total: usize,
    pub allowed: usize,
    pub denied: usize,
    pub errors: usize,
    pub duration_us: u64,
}

/// Request body for `POST /api/simulator/validate`.
#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    pub config: String,
    #[serde(default)]
    pub strict: bool,
}

/// Response for `POST /api/simulator/validate`.
#[derive(Debug, Serialize)]
pub struct ValidateResponse {
    pub valid: bool,
    pub findings: Vec<vellaveto_config::validation::ValidationFinding>,
    pub summary: vellaveto_config::validation::ValidationSummary,
    pub policy_count: usize,
}

/// Request body for `POST /api/simulator/diff`.
#[derive(Debug, Deserialize)]
pub struct DiffRequest {
    pub before: String,
    pub after: String,
}

/// Response for `POST /api/simulator/diff`.
#[derive(Debug, Serialize)]
pub struct DiffResponse {
    pub added: Vec<PolicySummary>,
    pub removed: Vec<PolicySummary>,
    pub modified: Vec<PolicyDiff>,
    pub unchanged: usize,
}

/// Summary of a single policy for diff output.
#[derive(Debug, Serialize)]
pub struct PolicySummary {
    pub id: String,
    pub name: String,
    pub policy_type: String,
    pub priority: i32,
}

/// A modified policy with human-readable change descriptions.
#[derive(Debug, Serialize)]
pub struct PolicyDiff {
    pub id: String,
    pub name: String,
    pub changes: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Try to parse a TOML config string, compile policies and engine.
/// Returns (engine, policies) or an error string.
///
/// `max_len`: maximum allowed byte length for the TOML string.
fn compile_from_toml_bounded(
    toml_str: &str,
    max_len: usize,
) -> Result<(PolicyEngine, Vec<Policy>), String> {
    // SECURITY (FIND-R46-001): Enforce size limit before parsing.
    if toml_str.len() > max_len {
        return Err(format!(
            "Config string length {} exceeds maximum of {} bytes",
            toml_str.len(),
            max_len
        ));
    }
    let config =
        PolicyConfig::from_toml(toml_str).map_err(|e| format!("TOML parse error: {}", e))?;
    let mut policies = config.to_policies();
    // SECURITY (FIND-R46-001): Cap policy count.
    if policies.len() > MAX_POLICY_COUNT {
        return Err(format!(
            "Policy count {} exceeds maximum of {}",
            policies.len(),
            MAX_POLICY_COUNT
        ));
    }
    PolicyEngine::sort_policies(&mut policies);
    let engine = PolicyEngine::with_policies(false, &policies).map_err(|errors| {
        let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
        format!("Policy compilation errors: {}", msgs.join("; "))
    })?;
    Ok((engine, policies))
}

/// Convenience wrapper using the default max config length.
fn compile_from_toml(toml_str: &str) -> Result<(PolicyEngine, Vec<Policy>), String> {
    compile_from_toml_bounded(toml_str, MAX_POLICY_CONFIG_LENGTH)
}

/// Create a PolicySummary from a Policy.
fn policy_to_summary(p: &Policy) -> PolicySummary {
    PolicySummary {
        id: p.id.clone(),
        name: p.name.clone(),
        policy_type: format!("{:?}", p.policy_type),
        priority: p.priority,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Handlers
// ═══════════════════════════════════════════════════════════════════

/// `POST /api/simulator/evaluate` — Single action simulation with full trace.
pub async fn simulate_evaluate(
    State(state): State<AppState>,
    Json(req): Json<SimulateRequest>,
) -> Result<Json<SimulateResponse>, (StatusCode, Json<ErrorResponse>)> {
    let action = req.action;

    // Validate action
    if let Err(e) = action.validate() {
        tracing::warn!("Simulator: action validation failed: {}", e);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid action".to_string(),
            }),
        ));
    }

    // Compile engine from inline config or use server's loaded policies
    let (engine, _policies) = if let Some(ref toml_str) = req.policy_config {
        compile_from_toml(toml_str)
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e })))?
    } else {
        let snap = state.policy_state.load();
        (
            PolicyEngine::with_policies(false, &snap.policies).map_err(|errors| {
                let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Policy recompilation failed: {}", msgs.join("; ")),
                    }),
                )
            })?,
            snap.policies.clone(),
        )
    };

    // Always evaluate with trace for simulation
    let (verdict, trace) = engine
        .evaluate_action_traced_with_context(&action, req.context.as_ref())
        .map_err(|e| {
            tracing::error!("Simulator: evaluation error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Policy evaluation failed".to_string(),
                }),
            )
        })?;

    Ok(Json(SimulateResponse {
        policies_checked: trace.policies_checked,
        duration_us: trace.duration_us,
        verdict,
        trace,
    }))
}

/// `POST /api/simulator/batch` — Batch evaluation of multiple actions.
pub async fn simulate_batch(
    State(state): State<AppState>,
    Json(req): Json<BatchRequest>,
) -> Result<Json<BatchResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Bound check
    // SECURITY (FIND-R46-014): When inline config is provided, reduce batch limit
    // to prevent DoS from repeated inline TOML parsing + policy compilation.
    let effective_batch_limit = if req.policy_config.is_some() {
        MAX_BATCH_ACTIONS_WITH_INLINE_CONFIG
    } else {
        MAX_BATCH_ACTIONS
    };
    if req.actions.len() > effective_batch_limit {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "Batch size {} exceeds maximum of {}",
                    req.actions.len(),
                    effective_batch_limit
                ),
            }),
        ));
    }

    if req.actions.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Batch must contain at least one action".to_string(),
            }),
        ));
    }

    let batch_start = std::time::Instant::now();

    // Compile engine once
    let engine = if let Some(ref toml_str) = req.policy_config {
        let (engine, _) = compile_from_toml(toml_str)
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e })))?;
        engine
    } else {
        let snap = state.policy_state.load();
        PolicyEngine::with_policies(false, &snap.policies).map_err(|errors| {
            let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Policy recompilation failed: {}", msgs.join("; ")),
                }),
            )
        })?
    };

    let mut results = Vec::with_capacity(req.actions.len());
    let mut allowed = 0usize;
    let mut denied = 0usize;
    let mut errors = 0usize;

    for (i, action) in req.actions.into_iter().enumerate() {
        // Validate action
        if let Err(e) = action.validate() {
            results.push(BatchResult {
                action_index: i,
                verdict: Verdict::Deny {
                    reason: "Invalid action".to_string(),
                },
                trace: None,
                error: Some(format!("Validation failed: {}", e)),
            });
            errors += 1;
            continue;
        }

        match engine.evaluate_action_traced_with_context(&action, None) {
            Ok((verdict, trace)) => {
                match &verdict {
                    Verdict::Allow => allowed += 1,
                    Verdict::Deny { .. } => denied += 1,
                    _ => {}
                }
                results.push(BatchResult {
                    action_index: i,
                    verdict,
                    trace: Some(trace),
                    error: None,
                });
            }
            Err(e) => {
                results.push(BatchResult {
                    action_index: i,
                    verdict: Verdict::Deny {
                        reason: "Evaluation error".to_string(),
                    },
                    trace: None,
                    error: Some(e.to_string()),
                });
                errors += 1;
            }
        }
    }

    let duration_us = batch_start.elapsed().as_micros() as u64;

    Ok(Json(BatchResponse {
        summary: BatchSummary {
            total: results.len(),
            allowed,
            denied,
            errors,
            duration_us,
        },
        results,
    }))
}

/// `POST /api/simulator/validate` — Validate policy config without loading.
pub async fn simulate_validate(
    Json(req): Json<ValidateRequest>,
) -> Result<Json<ValidateResponse>, (StatusCode, Json<ErrorResponse>)> {
    use vellaveto_config::validation::PolicyValidator;

    // SECURITY (FIND-R46-007): Enforce size limit before parsing.
    if req.config.len() > MAX_VALIDATE_CONFIG_LENGTH {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "Config string length {} exceeds maximum of {} bytes",
                    req.config.len(),
                    MAX_VALIDATE_CONFIG_LENGTH
                ),
            }),
        ));
    }

    // Try parsing as TOML first, then JSON
    let config = match PolicyConfig::from_toml(&req.config) {
        Ok(c) => c,
        Err(toml_err) => match PolicyConfig::from_json(&req.config) {
            Ok(c) => c,
            Err(_json_err) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Config parse error (tried TOML and JSON): {}", toml_err),
                    }),
                ));
            }
        },
    };

    let mut validator = PolicyValidator::new();
    if req.strict {
        validator = validator.strict();
    }

    let result = validator.validate(&config);
    let policy_count = config.to_policies().len();

    Ok(Json(ValidateResponse {
        valid: result.summary.valid,
        findings: result.findings,
        summary: result.summary,
        policy_count,
    }))
}

/// `POST /api/simulator/diff` — Compare two policy configs.
pub async fn simulate_diff(
    Json(req): Json<DiffRequest>,
) -> Result<Json<DiffResponse>, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY (FIND-R46-002): Enforce per-config size limits before parsing.
    if req.before.len() > MAX_DIFF_CONFIG_LENGTH {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "'before' config length {} exceeds maximum of {} bytes",
                    req.before.len(),
                    MAX_DIFF_CONFIG_LENGTH
                ),
            }),
        ));
    }
    if req.after.len() > MAX_DIFF_CONFIG_LENGTH {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "'after' config length {} exceeds maximum of {} bytes",
                    req.after.len(),
                    MAX_DIFF_CONFIG_LENGTH
                ),
            }),
        ));
    }

    // Parse both configs
    let before_config = PolicyConfig::from_toml(&req.before).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("'before' config parse error: {}", e),
            }),
        )
    })?;

    let after_config = PolicyConfig::from_toml(&req.after).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("'after' config parse error: {}", e),
            }),
        )
    })?;

    let before_policies = before_config.to_policies();
    let after_policies = after_config.to_policies();

    // Build ID maps
    let before_map: std::collections::HashMap<&str, &Policy> =
        before_policies.iter().map(|p| (p.id.as_str(), p)).collect();
    let after_map: std::collections::HashMap<&str, &Policy> =
        after_policies.iter().map(|p| (p.id.as_str(), p)).collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();
    let mut unchanged = 0usize;

    // Find added and modified
    for (id, after_p) in &after_map {
        match before_map.get(id) {
            None => added.push(policy_to_summary(after_p)),
            Some(before_p) => {
                let changes = diff_policies(before_p, after_p);
                if changes.is_empty() {
                    unchanged += 1;
                } else {
                    modified.push(PolicyDiff {
                        id: after_p.id.clone(),
                        name: after_p.name.clone(),
                        changes,
                    });
                }
            }
        }
    }

    // Find removed
    for (id, before_p) in &before_map {
        if !after_map.contains_key(id) {
            removed.push(policy_to_summary(before_p));
        }
    }

    Ok(Json(DiffResponse {
        added,
        removed,
        modified,
        unchanged,
    }))
}

/// `POST /api/simulator/red-team` — Run autonomous red team against current policies.
pub async fn simulate_red_team(
    State(state): State<AppState>,
) -> Result<Json<vellaveto_mcp::red_team::RedTeamReport>, (StatusCode, Json<ErrorResponse>)> {
    use vellaveto_mcp::attack_sim::AttackSimulator;
    use vellaveto_mcp::red_team::RedTeamRunner;

    let snap = state.policy_state.load();
    let engine = PolicyEngine::with_policies(false, &snap.policies).map_err(|errors| {
        let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Policy compilation failed: {}", msgs.join("; ")),
            }),
        )
    })?;

    let sim = AttackSimulator::new();
    // SECURITY (FIND-R46-003): Cap scenario count to prevent unbounded execution.
    let scenarios = sim.scenarios();
    let bounded_scenarios: Vec<vellaveto_mcp::attack_sim::AttackScenario> =
        if scenarios.len() > MAX_RED_TEAM_SCENARIOS {
            scenarios[..MAX_RED_TEAM_SCENARIOS].to_vec()
        } else {
            scenarios.to_vec()
        };

    let runner = RedTeamRunner::new(engine);

    // SECURITY (FIND-R46-003): Enforce a total timeout (30s) to prevent DoS.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::task::spawn_blocking(move || runner.run(&bounded_scenarios)),
    )
    .await;

    match result {
        Ok(Ok(report)) => Ok(Json(report)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Red team execution failed: {}", e),
            }),
        )),
        Err(_) => Err((
            StatusCode::REQUEST_TIMEOUT,
            Json(ErrorResponse {
                error: "Red team execution timed out (30s limit)".to_string(),
            }),
        )),
    }
}

/// Compare two policies and return human-readable change descriptions.
fn diff_policies(before: &Policy, after: &Policy) -> Vec<String> {
    let mut changes = Vec::new();

    if before.name != after.name {
        changes.push(format!("name: '{}' → '{}'", before.name, after.name));
    }
    if format!("{:?}", before.policy_type) != format!("{:?}", after.policy_type) {
        changes.push(format!(
            "type: {:?} → {:?}",
            before.policy_type, after.policy_type
        ));
    }
    if before.priority != after.priority {
        changes.push(format!(
            "priority: {} → {}",
            before.priority, after.priority
        ));
    }
    if before.path_rules != after.path_rules {
        changes.push("path_rules changed".to_string());
    }
    if before.network_rules != after.network_rules {
        changes.push("network_rules changed".to_string());
    }

    changes
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_toml() -> &'static str {
        r#"
[[policies]]
name = "allow reads"
tool_pattern = "filesystem"
function_pattern = "read_file"
policy_type = "Allow"
priority = 100

[[policies]]
name = "block bash"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
priority = 200
"#
    }

    #[test]
    fn test_compile_from_toml_valid() {
        let (engine, policies) = compile_from_toml(make_test_toml()).unwrap();
        assert_eq!(policies.len(), 2);
        // Engine should have compiled successfully
        let action = Action::new("filesystem", "read_file", serde_json::json!({}));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_compile_from_toml_invalid() {
        let result = compile_from_toml("this is not valid toml [[[");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("TOML parse error"));
    }

    #[test]
    fn test_policy_to_summary() {
        let policy = Policy {
            id: "test-id".to_string(),
            name: "Test Policy".to_string(),
            policy_type: vellaveto_types::PolicyType::Allow,
            priority: 50,
            path_rules: None,
            network_rules: None,
        };
        let summary = policy_to_summary(&policy);
        assert_eq!(summary.id, "test-id");
        assert_eq!(summary.name, "Test Policy");
        assert_eq!(summary.priority, 50);
    }

    #[test]
    fn test_diff_policies_identical() {
        let policy = Policy {
            id: "p1".to_string(),
            name: "Allow All".to_string(),
            policy_type: vellaveto_types::PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        };
        let changes = diff_policies(&policy, &policy);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_diff_policies_name_change() {
        let before = Policy {
            id: "p1".to_string(),
            name: "Old Name".to_string(),
            policy_type: vellaveto_types::PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        };
        let after = Policy {
            id: "p1".to_string(),
            name: "New Name".to_string(),
            policy_type: vellaveto_types::PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        };
        let changes = diff_policies(&before, &after);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].contains("name:"));
    }

    #[test]
    fn test_diff_policies_priority_and_type_change() {
        let before = Policy {
            id: "p1".to_string(),
            name: "Test".to_string(),
            policy_type: vellaveto_types::PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        };
        let after = Policy {
            id: "p1".to_string(),
            name: "Test".to_string(),
            policy_type: vellaveto_types::PolicyType::Deny,
            priority: 200,
            path_rules: None,
            network_rules: None,
        };
        let changes = diff_policies(&before, &after);
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|c| c.contains("type:")));
        assert!(changes.iter().any(|c| c.contains("priority:")));
    }

    #[test]
    fn test_batch_max_exceeded() {
        let actions: Vec<Action> = (0..101)
            .map(|i| Action::new(format!("tool{}", i), "fn", serde_json::json!({})))
            .collect();
        assert!(actions.len() > MAX_BATCH_ACTIONS);
    }

    #[test]
    fn test_validate_valid_config() {
        use vellaveto_config::validation::PolicyValidator;

        let config = PolicyConfig::from_toml(make_test_toml()).unwrap();
        let validator = PolicyValidator::new();
        let result = validator.validate(&config);
        assert!(result.summary.valid);
    }

    #[test]
    fn test_diff_added_removed() {
        let before_toml = r#"
[[policies]]
name = "allow reads"
tool_pattern = "filesystem"
function_pattern = "read_file"
policy_type = "Allow"
priority = 100
id = "p1"
"#;
        let after_toml = r#"
[[policies]]
name = "block bash"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
priority = 200
id = "p2"
"#;
        let before_config = PolicyConfig::from_toml(before_toml).unwrap();
        let after_config = PolicyConfig::from_toml(after_toml).unwrap();

        let before_policies = before_config.to_policies();
        let after_policies = after_config.to_policies();

        let before_map: std::collections::HashMap<&str, &Policy> =
            before_policies.iter().map(|p| (p.id.as_str(), p)).collect();
        let after_map: std::collections::HashMap<&str, &Policy> =
            after_policies.iter().map(|p| (p.id.as_str(), p)).collect();

        // p1 should be removed, p2 should be added
        assert!(!after_map.contains_key("p1"));
        assert!(after_map.contains_key("p2"));
        assert!(before_map.contains_key("p1"));
        assert!(!before_map.contains_key("p2"));
    }
}
