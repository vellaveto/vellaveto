//! HTTP client that sends attack payloads to the gateway under test.

use crate::attacks::{self, AttackTest};
use crate::{AttackResult, GatewayConfig};
use std::time::Instant;

/// Send an evaluate request to the gateway and return the parsed response.
async fn send_evaluate(
    client: &reqwest::Client,
    config: &GatewayConfig,
    payload: &serde_json::Value,
    timeout_secs: u64,
) -> Result<EvaluateResponse, String> {
    let url = format!("{}{}", config.base_url, config.evaluate_path);

    let mut req = client
        .post(&url)
        .header("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .json(payload);

    if let Some(ref auth) = config.auth_header {
        req = req.header("Authorization", format!("Bearer {auth}"));
    }

    let resp = req.send().await.map_err(|e| format!("Request failed: {e}"))?;

    let status = resp.status().as_u16();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("Failed to read response body: {e}"))?;

    let json: serde_json::Value =
        serde_json::from_str(&body).unwrap_or(serde_json::json!({"raw": body}));

    Ok(EvaluateResponse { status, body: json })
}

/// Parsed response from the gateway's evaluate endpoint.
struct EvaluateResponse {
    status: u16,
    body: serde_json::Value,
}

/// Run all attack tests against the gateway.
pub async fn run_all(config: &GatewayConfig, timeout_secs: u64) -> Vec<AttackResult> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .build()
        .expect("Failed to build HTTP client");

    let all_tests = attacks::all_tests();
    let mut results = Vec::with_capacity(all_tests.len());

    for test in &all_tests {
        let start = Instant::now();
        let passed = run_single_test(&client, config, test, timeout_secs).await;
        let latency_ns = start.elapsed().as_nanos() as u64;

        results.push(AttackResult {
            attack_id: test.id.to_string(),
            name: test.name.to_string(),
            class: test.class.to_string(),
            passed,
            latency_ns,
            details: if passed {
                "Gateway correctly handled the attack".to_string()
            } else {
                "Gateway did not detect or block the attack".to_string()
            },
        });
    }

    results
}

/// Run a single attack test and return whether the gateway passed.
async fn run_single_test(
    client: &reqwest::Client,
    config: &GatewayConfig,
    test: &AttackTest,
    timeout_secs: u64,
) -> bool {
    let result = send_evaluate(client, config, &test.payload, timeout_secs).await;

    match result {
        Ok(resp) => (test.check_fn)(&resp.body, resp.status),
        Err(_) => false,
    }
}
