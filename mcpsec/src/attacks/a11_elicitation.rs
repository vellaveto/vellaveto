//! A11: Credential Elicitation — 3 tests
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
    ]
}
