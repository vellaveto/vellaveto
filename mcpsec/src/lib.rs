// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! MCPSEC: MCP Security Benchmark Framework
//!
//! Vendor-neutral security evaluation for MCP gateways.
//! Tests 10 security properties across 64 attack test cases.

pub mod attacks;
pub mod report;
pub mod runner;
pub mod scoring;

use serde::{Deserialize, Serialize};

/// Configuration for a benchmark run.
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Gateway configuration (URL, auth, paths).
    pub gateway: GatewayConfig,
    /// Output format.
    pub format: OutputFormat,
    /// Per-request timeout in seconds.
    pub timeout_secs: u64,
    /// Number of concurrent test requests.
    pub concurrency: usize,
}

/// Gateway connection configuration.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Base URL of the gateway (e.g., `http://localhost:3000`).
    pub base_url: String,
    /// Path to the evaluate endpoint (e.g., `/api/evaluate`).
    pub evaluate_path: String,
    /// Optional Bearer token for authentication.
    pub auth_header: Option<String>,
}

/// Output format for benchmark results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Markdown,
}

/// Result of a single attack test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    /// Attack identifier (e.g., "A1.1").
    pub attack_id: String,
    /// Human-readable name.
    pub name: String,
    /// Attack class (e.g., "Prompt Injection Evasion").
    pub class: String,
    /// Whether the gateway correctly blocked/detected the attack.
    pub passed: bool,
    /// Request latency in nanoseconds.
    pub latency_ns: u64,
    /// Details about the test outcome.
    pub details: String,
}

/// Score for a single security property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyScore {
    /// Property identifier (e.g., "P1").
    pub property_id: String,
    /// Property name.
    pub name: String,
    /// Score as percentage (0-100).
    pub score: f64,
    /// Number of tests that passed.
    pub tests_passed: usize,
    /// Total number of tests.
    pub tests_total: usize,
}

/// Complete benchmark result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Framework identifier.
    pub framework: String,
    /// Framework version.
    pub version: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Gateway name.
    pub gateway: String,
    /// Gateway version (if reported).
    pub gateway_version: String,
    /// Overall score (0-100).
    pub overall_score: f64,
    /// Tier (0-5).
    pub tier: u8,
    /// Tier name.
    pub tier_name: String,
    /// Per-property scores.
    pub properties: Vec<PropertyScore>,
    /// Individual attack results.
    pub attacks: Vec<AttackResult>,
    /// Summary statistics.
    pub summary: BenchmarkSummary,
}

/// Summary statistics for a benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSummary {
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
}

/// Run the full benchmark suite against a gateway.
pub async fn run_benchmark(config: &BenchmarkConfig) -> BenchmarkResult {
    let attack_results = runner::run_all(&config.gateway, config.timeout_secs).await;
    let properties = scoring::calculate_property_scores(&attack_results);
    let overall_score = scoring::calculate_overall_score(&properties);
    let tier = scoring::score_to_tier(overall_score);
    let tier_name = scoring::tier_name(tier);

    let passed = attack_results.iter().filter(|r| r.passed).count();
    let total = attack_results.len();

    BenchmarkResult {
        framework: "MCPSEC".to_string(),
        version: "1.0.0".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        gateway: config.gateway.base_url.clone(),
        gateway_version: String::new(),
        overall_score,
        tier,
        tier_name: tier_name.to_string(),
        properties,
        attacks: attack_results,
        summary: BenchmarkSummary {
            total_tests: total,
            passed,
            failed: total - passed,
            skipped: 0,
        },
    }
}
