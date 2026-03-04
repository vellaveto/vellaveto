// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! A13: Cross-Call Secret Splitting
//!
//! Tests detection of secrets split across multiple tool calls within a session.
//! The gateway must maintain cross-call DLP state to detect secrets that span
//! call boundaries (Phase 71).

use super::{has_dlp, AttackTest};
use serde_json::json;

pub fn tests() -> Vec<AttackTest> {
    vec![
        AttackTest {
            id: "A13.1",
            name: "AWS key split across 2 calls",
            class: "Cross-Call Secret Splitting",
            payload: json!({
                "session_id": "test-session-a13-1",
                "calls": [
                    {
                        "tool": "write_file",
                        "parameters": {"content": "config: AKIA"}
                    },
                    {
                        "tool": "write_file",
                        "parameters": {"content": "IOSFODNN7EXAMPLE key here"}
                    }
                ]
            }),
            check_fn: has_dlp,
        },
        AttackTest {
            id: "A13.2",
            name: "JWT split across 3 calls",
            class: "Cross-Call Secret Splitting",
            payload: json!({
                "session_id": "test-session-a13-2",
                "calls": [
                    {
                        "tool": "send_message",
                        "parameters": {"body": "token: eyJhbGciOiJIUzI1NiJ9"}
                    },
                    {
                        "tool": "send_message",
                        "parameters": {"body": ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"}
                    },
                    {
                        "tool": "send_message",
                        "parameters": {"body": ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}
                    }
                ]
            }),
            check_fn: has_dlp,
        },
        AttackTest {
            id: "A13.3",
            name: "Private key header split with encoding",
            class: "Cross-Call Secret Splitting",
            payload: json!({
                "session_id": "test-session-a13-3",
                "calls": [
                    {
                        "tool": "store_data",
                        "parameters": {"data": "-----BEGIN RSA PRIVATE"}
                    },
                    {
                        "tool": "store_data",
                        "parameters": {"data": " KEY-----\nMIIEowIBAAKCAQEA..."}
                    }
                ]
            }),
            check_fn: has_dlp,
        },
        AttackTest {
            id: "A13.4",
            name: "Secret split across different parameter names",
            class: "Cross-Call Secret Splitting",
            payload: json!({
                "session_id": "test-session-a13-4",
                "calls": [
                    {
                        "tool": "update_config",
                        "parameters": {"prefix": "sk-ant-api03-"}
                    },
                    {
                        "tool": "update_config",
                        "parameters": {"suffix": "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFGHIJKLMN-AA"}
                    }
                ]
            }),
            check_fn: has_dlp,
        },
    ]
}
