// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! HTTP client that sends attack payloads to the gateway under test.

use crate::attacks::{self, AttackTest};
use crate::{AttackResult, GatewayConfig};
use std::sync::Arc;
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

    let resp = req
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

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

/// Run all attack tests against the gateway sequentially.
pub async fn run_all(config: &GatewayConfig, timeout_secs: u64) -> Vec<AttackResult> {
    let all_tests = attacks::all_tests();
    run_tests(&all_tests, config, timeout_secs, 1).await
}

/// Filter tests by class prefixes (e.g., ["A1", "A4", "A9"]).
/// Returns all tests whose ID starts with any of the given prefixes.
pub fn filter_tests_by_class(
    tests: Vec<attacks::AttackTest>,
    classes: &[String],
) -> Vec<attacks::AttackTest> {
    if classes.is_empty() {
        return tests;
    }
    tests
        .into_iter()
        .filter(|t| {
            let prefix = t.id.split('.').next().unwrap_or(t.id);
            classes.iter().any(|c| c.eq_ignore_ascii_case(prefix))
        })
        .collect()
}

/// Run the given attack tests against the gateway with configurable concurrency.
///
/// When `concurrency` is 1, tests run sequentially (preserving ordering for
/// stateful tests like rate limiting and cross-call DLP). Higher values use
/// a semaphore to bound parallel requests, which is faster but may cause
/// stateful tests (A10.4, A13.*) to produce unreliable results.
pub async fn run_tests(
    all_tests: &[attacks::AttackTest],
    config: &GatewayConfig,
    timeout_secs: u64,
    concurrency: usize,
) -> Vec<AttackResult> {
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            let details = format!("HTTP client initialization failed: {e}");
            return all_tests
                .iter()
                .map(|test| AttackResult {
                    attack_id: test.id.to_string(),
                    name: test.name.to_string(),
                    class: test.class.to_string(),
                    passed: false,
                    latency_ns: 0,
                    details: details.clone(),
                })
                .collect();
        }
    };

    let concurrency = concurrency.max(1);

    if concurrency == 1 {
        // Sequential: preserves ordering for stateful tests.
        let mut results = Vec::with_capacity(all_tests.len());
        for test in all_tests {
            results.push(run_and_record(&client, config, test, timeout_secs).await);
        }
        results
    } else {
        // Concurrent: use a semaphore to bound parallel requests.
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let client = Arc::new(client);
        let config = Arc::new(config.clone());

        let mut handles = Vec::with_capacity(all_tests.len());
        for test in all_tests {
            let sem = Arc::clone(&semaphore);
            let cl = Arc::clone(&client);
            let cfg = Arc::clone(&config);
            let owned = OwnedTest {
                id: test.id.to_string(),
                name: test.name.to_string(),
                class: test.class.to_string(),
                payload: test.payload.clone(),
                check_fn: test.check_fn,
            };
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.expect("semaphore closed unexpectedly");
                run_single_owned(&cl, &cfg, &owned, timeout_secs).await
            }));
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(AttackResult {
                    attack_id: "unknown".to_string(),
                    name: "Task join error".to_string(),
                    class: "Internal".to_string(),
                    passed: false,
                    latency_ns: 0,
                    details: format!("Task panicked: {e}"),
                }),
            }
        }
        results
    }
}

/// Execute a single test and build an AttackResult.
async fn run_and_record(
    client: &reqwest::Client,
    config: &GatewayConfig,
    test: &AttackTest,
    timeout_secs: u64,
) -> AttackResult {
    let start = Instant::now();
    let (passed, details) = run_single_test(client, config, test, timeout_secs).await;
    let latency_ns = start.elapsed().as_nanos() as u64;

    AttackResult {
        attack_id: test.id.to_string(),
        name: test.name.to_string(),
        class: test.class.to_string(),
        passed,
        latency_ns,
        details,
    }
}

/// Run a single attack test and return (passed, details).
async fn run_single_test(
    client: &reqwest::Client,
    config: &GatewayConfig,
    test: &AttackTest,
    timeout_secs: u64,
) -> (bool, String) {
    // Handle rapid-fire tests: if the payload contains `_test_rapid_requests`,
    // send that many requests and check if any later ones trigger rate limiting.
    if let Some(count) = test
        .payload
        .get("_test_rapid_requests")
        .and_then(|v| v.as_u64())
    {
        // Build a clean payload without the _test_rapid_requests meta field
        let mut clean_payload = test.payload.clone();
        if let Some(obj) = clean_payload.as_object_mut() {
            obj.remove("_test_rapid_requests");
        }

        for i in 0..count {
            let result = send_evaluate(client, config, &clean_payload, timeout_secs).await;
            if let Ok(resp) = result {
                if (test.check_fn)(&resp.body, resp.status) {
                    return (
                        true,
                        format!(
                            "Rate limiting triggered after {i} requests (status {})",
                            resp.status
                        ),
                    );
                }
            }
        }
        return (
            false,
            format!("Sent {count} rapid requests but rate limiting was not triggered"),
        );
    }

    let result = send_evaluate(client, config, &test.payload, timeout_secs).await;

    match result {
        Ok(resp) => {
            let passed = (test.check_fn)(&resp.body, resp.status);
            let details = if passed {
                format!(
                    "Gateway correctly handled the attack (status {})",
                    resp.status
                )
            } else {
                // Include a truncated response snippet for debugging.
                let snippet = resp.body.to_string();
                let truncated = if snippet.len() > 200 {
                    format!("{}...", &snippet[..200])
                } else {
                    snippet
                };
                format!(
                    "Gateway did not detect or block the attack (status {}, response: {truncated})",
                    resp.status
                )
            };
            (passed, details)
        }
        Err(e) => (false, format!("Request error: {e}")),
    }
}

/// Owned test data for concurrent execution (avoids lifetime issues with spawned tasks).
struct OwnedTest {
    id: String,
    name: String,
    class: String,
    payload: serde_json::Value,
    check_fn: fn(&serde_json::Value, u16) -> bool,
}

/// Run a single test from owned data (used by concurrent executor to avoid lifetime issues).
async fn run_single_owned(
    client: &reqwest::Client,
    config: &GatewayConfig,
    test: &OwnedTest,
    timeout_secs: u64,
) -> AttackResult {
    let OwnedTest {
        id,
        name,
        class,
        payload,
        check_fn,
    } = test;
    let start = Instant::now();

    let (passed, details) = if let Some(count) =
        payload.get("_test_rapid_requests").and_then(|v| v.as_u64())
    {
        let mut clean_payload = payload.clone();
        if let Some(obj) = clean_payload.as_object_mut() {
            obj.remove("_test_rapid_requests");
        }
        let mut result = (
            false,
            format!("Sent {count} rapid requests but rate limiting was not triggered"),
        );
        for i in 0..count {
            if let Ok(resp) = send_evaluate(client, config, &clean_payload, timeout_secs).await {
                if check_fn(&resp.body, resp.status) {
                    result = (
                        true,
                        format!(
                            "Rate limiting triggered after {i} requests (status {})",
                            resp.status
                        ),
                    );
                    break;
                }
            }
        }
        result
    } else {
        match send_evaluate(client, config, payload, timeout_secs).await {
            Ok(resp) => {
                let passed = check_fn(&resp.body, resp.status);
                let details = if passed {
                    format!(
                        "Gateway correctly handled the attack (status {})",
                        resp.status
                    )
                } else {
                    let snippet = resp.body.to_string();
                    let truncated = if snippet.len() > 200 {
                        format!("{}...", &snippet[..200])
                    } else {
                        snippet
                    };
                    format!(
                        "Gateway did not detect or block the attack (status {}, response: {truncated})",
                        resp.status
                    )
                };
                (passed, details)
            }
            Err(e) => (false, format!("Request error: {e}")),
        }
    };

    let latency_ns = start.elapsed().as_nanos() as u64;
    AttackResult {
        attack_id: id.clone(),
        name: name.clone(),
        class: class.clone(),
        passed,
        latency_ns,
        details,
    }
}
