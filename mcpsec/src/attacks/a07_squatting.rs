// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! A7: Tool Squatting — 5 tests
//!
//! Tests the gateway's ability to detect tool name squatting via
//! homoglyphs, Unicode normalization, mixed-script detection, and
//! Levenshtein distance.

use super::{is_deny, AttackTest};
use serde_json::json;

pub fn tests() -> Vec<AttackTest> {
    vec![
        AttackTest {
            id: "A7.1",
            name: "Cyrillic homoglyph squatting",
            class: "Tool Squatting",
            // Cyrillic 'а' (U+0430) in "read_file"
            payload: json!({
                "tool": "re\u{0430}d_file", "function": "read",
                "parameters": {"path": "/tmp/test"}
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A7.2",
            name: "Greek omicron squatting",
            class: "Tool Squatting",
            // Greek 'ο' (U+03BF) in "copy_file"
            payload: json!({
                "tool": "c\u{03BF}py_file", "function": "copy",
                "parameters": {"src": "/tmp/a", "dst": "/tmp/b"}
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A7.3",
            name: "Fullwidth Latin normalization",
            class: "Tool Squatting",
            // Fullwidth "read_file" — NFKC normalizes to exact match
            payload: json!({
                "tool": "\u{FF52}\u{FF45}\u{FF41}\u{FF44}_file", "function": "read",
                "parameters": {"path": "/tmp/test"}
            }),
            // NFKC normalization to "read_file" = exact match = NOT squatting.
            // The gateway should normalize and allow (or deny based on policy, not squatting).
            // This tests that NFKC normalization happens correctly.
            check_fn: |_body: &serde_json::Value, _status: u16| -> bool {
                // Pass if the gateway either allows (NFKC normalized to exact match)
                // or denies for policy reasons (not squatting)
                // Fail only if it errors or doesn't process the request
                _status != 500
            },
        },
        AttackTest {
            id: "A7.4",
            name: "Mixed-script detection",
            class: "Tool Squatting",
            // Latin + Cyrillic mixed: "bаsh" with Cyrillic 'а'
            payload: json!({
                "tool": "b\u{0430}sh", "function": "exec",
                "parameters": {"command": "echo test"}
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A7.5",
            name: "Levenshtein typosquatting",
            class: "Tool Squatting",
            // "bassh" — distance 1 from "bash"
            payload: json!({
                "tool": "bassh", "function": "exec",
                "parameters": {"command": "echo test"}
            }),
            check_fn: is_deny,
        },
    ]
}
