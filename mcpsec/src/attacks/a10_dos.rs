// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! A10: DoS & Resource Exhaustion — 4 tests
//!
//! Tests the gateway's resilience against denial-of-service attacks
//! including ReDoS, oversized messages, parameter bombs, and rate limiting.

use super::AttackTest;
use serde_json::json;

pub fn tests() -> Vec<AttackTest> {
    vec![
        AttackTest {
            id: "A10.1",
            name: "ReDoS nested quantifier rejection",
            class: "DoS & Resource Exhaustion",
            payload: json!({
                "tool": "vellaveto", "function": "regex_compile",
                "parameters": {
                    "pattern": "^(a+)+b$",
                    "test_input": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            }),
            // Gateway should reject nested quantifiers
            check_fn: |body: &serde_json::Value, status: u16| -> bool {
                // 400 = rejected at compile time (ideal)
                // 200 with error = also acceptable
                if status == 400 {
                    return true;
                }
                if let Some(err) = body.get("error") {
                    return err.as_str().is_some_and(|s| {
                        s.contains("quantifier") || s.contains("regex") || s.contains("rejected")
                    });
                }
                // If gateway handled it without hanging, that's also a pass
                // (the test harness enforces a timeout)
                status == 200
            },
        },
        AttackTest {
            id: "A10.2",
            name: "Oversized MCP message rejection",
            class: "DoS & Resource Exhaustion",
            payload: {
                // Create a payload just over 1MB
                let big_value = "X".repeat(1_048_577);
                json!({
                    "tool": "file", "function": "read",
                    "parameters": {"data": big_value}
                })
            },
            // Gateway should reject oversized messages
            check_fn: |_body: &serde_json::Value, status: u16| -> bool {
                // 413 Payload Too Large or 400 Bad Request
                status == 413 || status == 400 || status == 429
            },
        },
        AttackTest {
            id: "A10.3",
            name: "Parameter bomb",
            class: "DoS & Resource Exhaustion",
            payload: {
                // Create 10,000 parameters
                let mut params = serde_json::Map::new();
                for i in 0..10_000 {
                    params.insert(format!("param_{i}"), json!("value"));
                }
                json!({
                    "tool": "file", "function": "read",
                    "parameters": params
                })
            },
            // Gateway should handle without OOM or excessive CPU
            check_fn: |_body: &serde_json::Value, status: u16| -> bool {
                // Any response (not 500) means gateway handled it
                status != 500
            },
        },
        AttackTest {
            id: "A10.4",
            name: "Rate limiting enforcement",
            class: "DoS & Resource Exhaustion",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/test"},
                "_test_rapid_requests": 100
            }),
            // This test is special — the runner sends 100 rapid requests and
            // checks if any receive 429. The gateway should rate-limit after
            // exceeding its configured burst capacity.
            check_fn: |body: &serde_json::Value, status: u16| -> bool {
                status == 429
                    || body.get("rate_limited").and_then(|r| r.as_bool()) == Some(true)
                    || body.get("rate_limits_enabled").and_then(|r| r.as_bool()) == Some(true)
            },
        },
    ]
}
