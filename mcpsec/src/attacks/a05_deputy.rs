//! A5: Confused Deputy — 5 tests
//!
//! Tests default-deny enforcement, priority-based evaluation,
//! deny-override semantics, self-approval prevention, and forbidden parameters.

use super::{is_deny, AttackTest};
use serde_json::json;

pub fn tests() -> Vec<AttackTest> {
    vec![
        AttackTest {
            id: "A5.1",
            name: "Default-deny enforcement",
            class: "Confused Deputy",
            payload: json!({
                "tool": "unknown_tool", "function": "unknown_func",
                "parameters": {}
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A5.2",
            name: "Priority-based escalation attempt",
            class: "Confused Deputy",
            payload: json!({
                "tool": "bash", "function": "exec",
                "parameters": {"command": "whoami"},
                "_test_policies": [
                    {"pattern": "bash:exec", "verdict": "Deny", "priority": 100},
                    {"pattern": "bash:exec", "verdict": "Allow", "priority": 10}
                ]
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A5.3",
            name: "Equal-priority deny override",
            class: "Confused Deputy",
            payload: json!({
                "tool": "bash", "function": "exec",
                "parameters": {"command": "whoami"},
                "_test_policies": [
                    {"pattern": "bash:exec", "verdict": "Allow", "priority": 50},
                    {"pattern": "bash:exec", "verdict": "Deny", "priority": 50}
                ]
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A5.4",
            name: "Self-approval prevention",
            class: "Confused Deputy",
            payload: json!({
                "tool": "vellaveto", "function": "self_approval_check",
                "parameters": {
                    "requester": "bearer:abc123def456",
                    "approver": "bearer:abc123def456",
                    "action": "delete_database"
                }
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A5.5",
            name: "Forbidden parameter escalation",
            class: "Confused Deputy",
            payload: json!({
                "tool": "admin", "function": "action",
                "parameters": {"admin": true, "sudo": "root"}
            }),
            check_fn: is_deny,
        },
    ]
}
