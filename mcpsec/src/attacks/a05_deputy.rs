// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! A5: Confused Deputy — 10 tests
//!
//! Tests default-deny enforcement, priority-based evaluation,
//! deny-override semantics, self-approval prevention, forbidden parameters,
//! priority cascade, delegation chain limits, circular delegation,
//! delegation attenuation, and re-delegation.

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
        // A5.6: Three-level priority cascade — highest-priority Deny must win
        // even when two lower-priority Allow policies exist.
        AttackTest {
            id: "A5.6",
            name: "Three-level priority cascade",
            class: "Confused Deputy",
            payload: json!({
                "tool": "bash", "function": "exec",
                "parameters": {"command": "ls"},
                "_test_policies": [
                    {"pattern": "bash:exec", "verdict": "Allow", "priority": 1},
                    {"pattern": "bash:exec", "verdict": "Allow", "priority": 50},
                    {"pattern": "bash:exec", "verdict": "Deny", "priority": 99}
                ]
            }),
            check_fn: is_deny,
        },
        // A5.7: Delegation chain depth limit — a delegation chain deeper than
        // the maximum allowed depth (3) must be rejected.
        AttackTest {
            id: "A5.7",
            name: "Delegation chain depth limit",
            class: "Confused Deputy",
            payload: json!({
                "tool": "vellaveto", "function": "delegation_check",
                "parameters": {
                    "delegation_chain": [
                        {"from": "root", "to": "admin"},
                        {"from": "admin", "to": "manager"},
                        {"from": "manager", "to": "user"},
                        {"from": "user", "to": "agent"}
                    ],
                    "max_depth": 3
                }
            }),
            check_fn: is_deny,
        },
        // A5.8: Circular delegation detection — A delegates to B, B delegates
        // back to A. Must be detected and rejected.
        AttackTest {
            id: "A5.8",
            name: "Circular delegation detection",
            class: "Confused Deputy",
            payload: json!({
                "tool": "vellaveto", "function": "delegation_check",
                "parameters": {
                    "delegation_chain": [
                        {"from": "alice", "to": "bob"},
                        {"from": "bob", "to": "charlie"},
                        {"from": "charlie", "to": "alice"}
                    ]
                }
            }),
            check_fn: is_deny,
        },
        // A5.9: Delegation attenuation — delegated permissions must be a subset
        // of the delegator's permissions. Escalation must be denied.
        AttackTest {
            id: "A5.9",
            name: "Delegation attenuation violation",
            class: "Confused Deputy",
            payload: json!({
                "tool": "vellaveto", "function": "delegation_check",
                "parameters": {
                    "delegator_permissions": ["read"],
                    "delegated_permissions": ["read", "write", "admin"],
                    "action": "create_admin_token"
                }
            }),
            check_fn: is_deny,
        },
        // A5.10: Re-delegation without authority — agent B, who received
        // delegated read-only access from A, tries to re-delegate write access
        // to agent C. Must be rejected.
        AttackTest {
            id: "A5.10",
            name: "Unauthorized re-delegation",
            class: "Confused Deputy",
            payload: json!({
                "tool": "vellaveto", "function": "delegation_check",
                "parameters": {
                    "original_grant": {"from": "admin", "to": "agent_b", "permissions": ["read"]},
                    "re_delegation": {"from": "agent_b", "to": "agent_c", "permissions": ["read", "write"]},
                    "re_delegation_allowed": false
                }
            }),
            check_fn: is_deny,
        },
    ]
}
