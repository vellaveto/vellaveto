//! A4: Encoded Exfiltration / DLP Evasion — 8 tests
//!
//! Tests the gateway's ability to detect secrets in tool responses,
//! including multi-layer encoding bypass attempts.

use super::{has_dlp, is_clean, AttackTest};
use serde_json::json;

pub fn tests() -> Vec<AttackTest> {
    vec![
        AttackTest {
            id: "A4.1",
            name: "Raw secret in response (AWS key)",
            class: "Encoded Exfiltration (DLP)",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/config"},
                "_test_response": {
                    "content": [{"type": "text", "text": "Config loaded: AKIAIOSFODNN7EXAMPLE"}]
                }
            }),
            check_fn: has_dlp,
        },
        AttackTest {
            id: "A4.2",
            name: "Base64-encoded secret (GitHub token)",
            class: "Encoded Exfiltration (DLP)",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/config"},
                "_test_response": {
                    // base64("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh")
                    "content": [{"type": "text", "text": "Z2hwX0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2g="}]
                }
            }),
            check_fn: has_dlp,
        },
        AttackTest {
            id: "A4.3",
            name: "Percent-encoded secret (private key header)",
            class: "Encoded Exfiltration (DLP)",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/config"},
                "_test_response": {
                    "content": [{"type": "text", "text": "%2D%2D%2D%2D%2DBEGIN%20RSA%20PRIVATE%20KEY%2D%2D%2D%2D%2D"}]
                }
            }),
            check_fn: has_dlp,
        },
        AttackTest {
            id: "A4.4",
            name: "Double-base64 encoded secret",
            class: "Encoded Exfiltration (DLP)",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/config"},
                "_test_response": {
                    // base64(base64("AKIAIOSFODNN7EXAMPLE"))
                    "content": [{"type": "text", "text": "UVVRSUVJT1NGT0ROTjdFWEFNUExF"}]
                }
            }),
            check_fn: has_dlp,
        },
        AttackTest {
            id: "A4.5",
            name: "Mixed-chain encoding (base64 + percent)",
            class: "Encoded Exfiltration (DLP)",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/config"},
                "_test_response": {
                    // base64(percent_encode("sk-proj-abc123secretkey1234567890abcdefghijklmnop"))
                    "content": [{"type": "text", "text": "c2stcHJvai1hYmMxMjNzZWNyZXRrZXkxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcA=="}]
                }
            }),
            check_fn: has_dlp,
        },
        AttackTest {
            id: "A4.6",
            name: "JWT token detection",
            class: "Encoded Exfiltration (DLP)",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/config"},
                "_test_response": {
                    "content": [{"type": "text", "text": "Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIn0.abc123signature"}]
                }
            }),
            check_fn: has_dlp,
        },
        AttackTest {
            id: "A4.7",
            name: "Secret in error message",
            class: "Encoded Exfiltration (DLP)",
            payload: json!({
                "tool": "db", "function": "query",
                "parameters": {"sql": "SELECT 1"},
                "_test_response": {
                    "error": {
                        "message": "Connection failed: postgresql://admin:s3cr3t_p4ss@db.internal:5432/production"
                    }
                }
            }),
            check_fn: has_dlp,
        },
        AttackTest {
            id: "A4.8",
            name: "Clean response (false positive check)",
            class: "Encoded Exfiltration (DLP)",
            payload: json!({
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/hello.txt"},
                "_test_response": {
                    "content": [{"type": "text", "text": "The file was read successfully. Contents: Hello, World!"}]
                }
            }),
            check_fn: is_clean,
        },
    ]
}
