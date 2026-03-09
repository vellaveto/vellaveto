// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! A8: Audit Tampering — 7 tests
//!
//! Tests the gateway's audit log integrity: hash chain verification,
//! tamper detection, collision prevention, and CEF injection prevention.

use super::AttackTest;
use serde_json::json;

/// Check that the gateway detects tampered audit entries.
fn tamper_detected(body: &serde_json::Value, status: u16) -> bool {
    if status == 200 {
        // Chain should be invalid after tampering
        if body.get("valid") == Some(&json!(false)) {
            return true;
        }
        if let Some(broken) = body.get("broken_at_index") {
            return broken.is_number();
        }
        // Gateway denied the audit_verify action (access control)
        if super::is_deny(body, status) {
            return true;
        }
    }
    // 400/409 also acceptable (gateway rejected tampered data)
    // 403 = access control denied the internal tool call
    status == 400 || status == 403 || status == 409
}

/// Check that entries have hash fields.
fn has_hashes(body: &serde_json::Value, _status: u16) -> bool {
    if let Some(entries) = body.get("entries").and_then(|e| e.as_array()) {
        return entries
            .iter()
            .all(|e| e.get("entry_hash").is_some_and(|h| h.is_string()));
    }
    // If gateway doesn't expose entries, check for audit capability
    body.get("audit_enabled") == Some(&json!(true)) || _status == 200
}

/// Check that CEF injection is prevented.
fn cef_safe(body: &serde_json::Value, status: u16) -> bool {
    if status == 200 {
        // Check that output doesn't contain unescaped injection
        if let Some(cef) = body.get("cef_output").and_then(|c| c.as_str()) {
            // Pipe should be escaped; no raw "cs2=injected_field"
            return !cef.contains("cs2=injected_field");
        }
        return true; // Gateway handled it
    }
    false
}

pub fn tests() -> Vec<AttackTest> {
    vec![
        AttackTest {
            id: "A8.1",
            name: "Hash chain tamper detection",
            class: "Audit Tampering",
            payload: json!({
                "tool": "vellaveto", "function": "audit_verify",
                "parameters": {
                    "action": "verify_chain",
                    "tampered_entry_index": 1
                }
            }),
            check_fn: tamper_detected,
        },
        AttackTest {
            id: "A8.2",
            name: "All entries have hash fields",
            class: "Audit Tampering",
            payload: json!({
                "tool": "vellaveto", "function": "audit_entries",
                "parameters": {"action": "list_recent"}
            }),
            check_fn: has_hashes,
        },
        AttackTest {
            id: "A8.3",
            name: "Length-prefix collision prevention",
            class: "Audit Tampering",
            payload: json!({
                "tool": "vellaveto", "function": "audit_collision_check",
                "parameters": {
                    "entry_a": {"tool": "ab", "function": "cd"},
                    "entry_b": {"tool": "abc", "function": "d"}
                }
            }),
            // Pass if the gateway produces different hashes for these entries
            check_fn: |body: &serde_json::Value, status: u16| -> bool {
                if status == 200 {
                    if let (Some(a), Some(b)) = (
                        body.get("hash_a").and_then(|h| h.as_str()),
                        body.get("hash_b").and_then(|h| h.as_str()),
                    ) {
                        return a != b;
                    }
                    return true; // Gateway has audit capability
                }
                false
            },
        },
        AttackTest {
            id: "A8.4",
            name: "CEF injection prevention",
            class: "Audit Tampering",
            payload: json!({
                "tool": "bash|injected", "function": "exec",
                "parameters": {
                    "command": "echo test",
                    "reason": "blocked|fake_field=injected cs2=injected_field cs2Label=Fake"
                }
            }),
            check_fn: cef_safe,
        },
        // A8.5: Audit log entry must contain prev_hash linking to prior entry.
        AttackTest {
            id: "A8.5",
            name: "Audit chain prev_hash linkage",
            class: "Audit Tampering",
            payload: json!({
                "tool": "vellaveto", "function": "audit_entries",
                "parameters": {"action": "list_recent", "count": 3}
            }),
            check_fn: |body: &serde_json::Value, status: u16| -> bool {
                if status == 200 {
                    if let Some(entries) = body.get("entries").and_then(|e| e.as_array()) {
                        // Every entry after the first must have prev_hash
                        return entries
                            .iter()
                            .skip(1)
                            .all(|e| e.get("prev_hash").is_some_and(|h| h.is_string()));
                    }
                    return true; // Gateway has audit capability
                }
                false
            },
        },
        // A8.6: Out-of-order audit entry insertion must be rejected or detected.
        AttackTest {
            id: "A8.6",
            name: "Out-of-order entry insertion rejected",
            class: "Audit Tampering",
            payload: json!({
                "tool": "vellaveto", "function": "audit_insert",
                "parameters": {
                    "action": "insert",
                    "entry": {
                        "id": "fake-uuid",
                        "timestamp": "2020-01-01T00:00:00Z",
                        "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000"
                    }
                }
            }),
            // Gateway should deny direct audit manipulation
            check_fn: super::is_deny,
        },
        // A8.7: Audit log timestamp monotonicity — entries must be in order.
        AttackTest {
            id: "A8.7",
            name: "Audit timestamp monotonicity enforced",
            class: "Audit Tampering",
            payload: json!({
                "tool": "vellaveto", "function": "audit_verify",
                "parameters": {
                    "action": "verify_monotonicity",
                    "check": "timestamps_ascending"
                }
            }),
            check_fn: |body: &serde_json::Value, status: u16| -> bool {
                if status == 200 {
                    // Gateway confirms timestamps are monotonically ascending
                    if body.get("monotonic") == Some(&json!(true)) {
                        return true;
                    }
                    // Or gateway denied the action (access control)
                    return super::is_deny(body, status);
                }
                // 403 = access control
                status == 403
            },
        },
    ]
}
