// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! A16: Circuit Breaker Evasion — 4 tests
//!
//! Tests the gateway's cascading failure protection via circuit breakers.
//! A secure gateway must trip circuit breakers on repeated failures and
//! prevent continued forwarding to failing tools.

use super::AttackTest;
use serde_json::json;

pub fn tests() -> Vec<AttackTest> {
    vec![
        AttackTest {
            id: "A16.1",
            name: "Circuit breaker trips after repeated failures",
            class: "Circuit Breaker Evasion",
            payload: json!({
                "tool": "vellaveto", "function": "circuit_breaker_check",
                "parameters": {
                    "tool_name": "failing_tool",
                    "consecutive_failures": 10,
                    "threshold": 5,
                    "description": "Tool has failed 10 consecutive times; circuit should be open"
                }
            }),
            // Gateway should deny (circuit open) after exceeding failure threshold
            check_fn: |body: &serde_json::Value, status: u16| -> bool {
                // 503 = circuit open (service unavailable)
                // 429 = rate limited (also acceptable)
                if status == 503 || status == 429 {
                    return true;
                }
                // Check for circuit breaker state in response
                if let Some(state) = body.get("circuit_state").and_then(|s| s.as_str()) {
                    return state == "Open" || state == "open";
                }
                // Deny verdict also acceptable
                super::is_deny(body, status)
            },
        },
        AttackTest {
            id: "A16.2",
            name: "Circuit breaker resets after cooldown",
            class: "Circuit Breaker Evasion",
            payload: json!({
                "tool": "vellaveto", "function": "circuit_breaker_check",
                "parameters": {
                    "tool_name": "recovered_tool",
                    "consecutive_failures": 10,
                    "recovery_time_secs": 60,
                    "time_since_last_failure_secs": 120,
                    "description": "Tool failed before but cooldown has elapsed; circuit should be half-open"
                }
            }),
            // Gateway should allow a probe request through (half-open state)
            check_fn: |body: &serde_json::Value, status: u16| -> bool {
                if status == 200 {
                    // Half-open or closed state allows requests
                    if let Some(state) = body.get("circuit_state").and_then(|s| s.as_str()) {
                        return state == "HalfOpen" || state == "half_open" || state == "Closed";
                    }
                    return true;
                }
                false
            },
        },
        AttackTest {
            id: "A16.3",
            name: "Circuit breaker prevents cascade to downstream",
            class: "Circuit Breaker Evasion",
            payload: json!({
                "tool": "vellaveto", "function": "cascading_failure_check",
                "parameters": {
                    "upstream_tool": "database",
                    "downstream_tools": ["cache", "search", "analytics"],
                    "upstream_state": "Open",
                    "description": "Upstream tool circuit is open; downstream dependents should also be protected"
                }
            }),
            // Gateway should prevent cascade (deny or return circuit-open for dependents)
            check_fn: |body: &serde_json::Value, status: u16| -> bool {
                if status == 503 || status == 429 {
                    return true;
                }
                // Check if cascading protection is active
                if body.get("cascade_protection") == Some(&json!(true)) {
                    return true;
                }
                super::is_deny(body, status)
            },
        },
        AttackTest {
            id: "A16.4",
            name: "Circuit breaker counters resist overflow",
            class: "Circuit Breaker Evasion",
            payload: json!({
                "tool": "vellaveto", "function": "circuit_breaker_check",
                "parameters": {
                    "tool_name": "overflow_test",
                    "failure_count": u64::MAX,
                    "description": "Attempt to overflow failure counter (should use saturating arithmetic)"
                }
            }),
            // Gateway should handle max values without overflow or panic
            check_fn: |_body: &serde_json::Value, status: u16| -> bool {
                // Any non-500 response means no overflow/panic
                status != 500
            },
        },
    ]
}
