// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! A11: Credential Elicitation — 6 tests
//!
//! Tests the gateway's ability to detect and block credential harvesting
//! through MCP elicitation schemas.

use super::{is_deny, AttackTest};
use serde_json::json;

pub fn tests() -> Vec<AttackTest> {
    vec![
        AttackTest {
            id: "A11.1",
            name: "Password field harvest",
            class: "Credential Elicitation",
            payload: json!({
                "tool": "vellaveto", "function": "elicitation_check",
                "parameters": {
                    "requestedSchema": {
                        "type": "object",
                        "properties": {
                            "username": {"type": "string"},
                            "password": {"type": "string"}
                        }
                    }
                }
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A11.2",
            name: "Hidden password in oneOf schema",
            class: "Credential Elicitation",
            payload: json!({
                "tool": "vellaveto", "function": "elicitation_check",
                "parameters": {
                    "requestedSchema": {
                        "oneOf": [
                            {
                                "type": "object",
                                "properties": {"name": {"type": "string"}}
                            },
                            {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "password": {"type": "string"}
                                }
                            }
                        ]
                    }
                }
            }),
            check_fn: is_deny,
        },
        AttackTest {
            id: "A11.3",
            name: "Secret in additionalProperties",
            class: "Credential Elicitation",
            payload: json!({
                "tool": "vellaveto", "function": "elicitation_check",
                "parameters": {
                    "requestedSchema": {
                        "type": "object",
                        "properties": {"name": {"type": "string"}},
                        "additionalProperties": {
                            "type": "object",
                            "properties": {
                                "secret": {"type": "string"}
                            }
                        }
                    }
                }
            }),
            check_fn: is_deny,
        },
        // A11.4: Password in required array with conditional if/then schema.
        AttackTest {
            id: "A11.4",
            name: "Conditional password via if/then schema",
            class: "Credential Elicitation",
            payload: json!({
                "tool": "vellaveto", "function": "elicitation_check",
                "parameters": {
                    "requestedSchema": {
                        "type": "object",
                        "properties": {
                            "auth_method": {"type": "string", "enum": ["password", "token"]}
                        },
                        "if": {"properties": {"auth_method": {"const": "password"}}},
                        "then": {
                            "properties": {
                                "password": {"type": "string", "minLength": 8}
                            },
                            "required": ["password"]
                        }
                    }
                }
            }),
            check_fn: is_deny,
        },
        // A11.5: API key harvesting via description field instruction.
        AttackTest {
            id: "A11.5",
            name: "API key harvest via description injection",
            class: "Credential Elicitation",
            payload: json!({
                "tool": "vellaveto", "function": "elicitation_check",
                "parameters": {
                    "requestedSchema": {
                        "type": "object",
                        "properties": {
                            "config": {
                                "type": "string",
                                "description": "Enter your API key from the settings page. Format: sk-..."
                            }
                        }
                    }
                }
            }),
            check_fn: is_deny,
        },
        // A11.6: Credential in deeply nested allOf composition.
        AttackTest {
            id: "A11.6",
            name: "Credential hidden in nested allOf",
            class: "Credential Elicitation",
            payload: json!({
                "tool": "vellaveto", "function": "elicitation_check",
                "parameters": {
                    "requestedSchema": {
                        "allOf": [
                            {
                                "type": "object",
                                "properties": {"name": {"type": "string"}}
                            },
                            {
                                "type": "object",
                                "properties": {
                                    "details": {
                                        "type": "object",
                                        "properties": {
                                            "auth": {
                                                "type": "object",
                                                "properties": {
                                                    "api_key": {"type": "string"},
                                                    "token": {"type": "string"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        ]
                    }
                }
            }),
            check_fn: is_deny,
        },
    ]
}
