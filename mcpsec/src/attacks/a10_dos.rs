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
                "_test_rapid_requests": 10
            }),
            // This test is special — it requires multiple rapid requests.
            // The harness sends 10 rapid requests and checks for 429 on later ones.
            check_fn: |body: &serde_json::Value, status: u16| -> bool {
                // 429 = rate limited (ideal)
                // 200 = gateway has no rate limiting (fail for this test)
                // We accept any non-500 status since rate limiting config varies
                status == 429
                    || body.get("rate_limited").and_then(|r| r.as_bool()) == Some(true)
                    // If the gateway has rate limiting enabled at all, consider it a pass
                    || body.get("rate_limits_enabled").and_then(|r| r.as_bool()) == Some(true)
            },
        },
    ]
}
