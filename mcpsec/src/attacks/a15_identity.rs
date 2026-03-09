// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! A15: Agent Identity Spoofing — 5 tests
//!
//! Tests the gateway's ability to enforce agent identity in policy evaluation,
//! detect identity spoofing attempts, and prevent context-aware policy bypass.

use super::{is_deny, AttackTest};
use serde_json::json;

pub fn tests() -> Vec<AttackTest> {
    vec![
        AttackTest {
            id: "A15.1",
            name: "Unauthenticated agent denied by ABAC policy",
            class: "Agent Identity Spoofing",
            payload: json!({
                "tool": "admin", "function": "manage_users",
                "parameters": {},
                "_test_context": {
                    "agent_identity": null,
                    "abac_requires": "agent_id != null"
                }
            }),
            // Gateway should deny when ABAC policy requires agent identity
            // and the request has no agent identity
            check_fn: is_deny,
        },
        AttackTest {
            id: "A15.2",
            name: "Agent ID with control characters rejected",
            class: "Agent Identity Spoofing",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/test"},
                "_test_context": {
                    "agent_identity": "agent\u{0000}admin",
                    "description": "Null byte injection in agent identity"
                }
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A15.3",
            name: "Agent ID with Unicode format chars rejected",
            class: "Agent Identity Spoofing",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/test"},
                "_test_context": {
                    // Zero-width joiner + bidi override in agent ID
                    "agent_identity": "trusted\u{200D}\u{202E}agent",
                    "description": "Unicode format characters in agent identity"
                }
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A15.4",
            name: "Agent ID exceeding max length rejected",
            class: "Agent Identity Spoofing",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/test"},
                "_test_context": {
                    "agent_identity": "a".repeat(1024),
                    "description": "Oversized agent identity (1024 chars, limit should be 512)"
                }
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A15.5",
            name: "Agent Homoglyph spoofing (Cyrillic agent ID)",
            class: "Agent Identity Spoofing",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/test"},
                "_test_context": {
                    // Cyrillic 'а' (U+0430) instead of Latin 'a' in "admin-agent"
                    "agent_identity": "\u{0430}dmin-agent",
                    "known_agents": ["admin-agent", "reader-agent"],
                    "description": "Homoglyph spoofing of known agent identity"
                }
            }),
            check_fn: is_deny,
        },
    ]
}
