// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! A9: SSRF & Domain Bypass — 6 tests
//!
//! Tests the gateway's ability to correctly extract and evaluate
//! domains from URLs, including bypass techniques.

use super::{is_deny, AttackTest};
use serde_json::json;

pub fn tests() -> Vec<AttackTest> {
    vec![
        AttackTest {
            id: "A9.1",
            name: "Cloud metadata SSRF",
            class: "SSRF & Domain Bypass",
            payload: json!({
                "tool": "http", "function": "request",
                "parameters": {"url": "http://169.254.169.254/latest/meta-data/"}
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A9.2",
            name: "Userinfo bypass",
            class: "SSRF & Domain Bypass",
            payload: json!({
                "tool": "http", "function": "request",
                "parameters": {"url": "http://allowed.com@169.254.169.254/path"}
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A9.3",
            name: "Percent-encoded userinfo bypass",
            class: "SSRF & Domain Bypass",
            payload: json!({
                "tool": "http", "function": "request",
                "parameters": {"url": "http://allowed%2Ecom%40169.254.169.254@evil.com/"}
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A9.4",
            name: "Trailing dot bypass",
            class: "SSRF & Domain Bypass",
            payload: json!({
                "tool": "http", "function": "request",
                "parameters": {"url": "https://evil.com./path"}
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A9.5",
            name: "IPv6 loopback",
            class: "SSRF & Domain Bypass",
            payload: json!({
                "tool": "http", "function": "request",
                "parameters": {"url": "http://[::1]/admin"}
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A9.6",
            name: "Port smuggling",
            class: "SSRF & Domain Bypass",
            payload: json!({
                "tool": "http", "function": "request",
                "parameters": {"url": "https://evil.com:8080/exfiltrate"}
            }),
            check_fn: is_deny,
        },
    ]
}
