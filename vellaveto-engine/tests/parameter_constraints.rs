// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn make_engine() -> PolicyEngine {
    PolicyEngine::new(false)
}

fn make_strict_engine() -> PolicyEngine {
    PolicyEngine::new(true)
}

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

fn make_conditional_policy(
    id: &str,
    name: &str,
    priority: i32,
    conditions: serde_json::Value,
) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Conditional { conditions },
        priority,
        path_rules: None,
        network_rules: None,
    }
}

// === Path glob block/allow ===

#[test]
fn test_glob_blocks_aws_credentials() {
    let engine = make_engine();
    let action = make_action(
        "file_system",
        "read_file",
        json!({"path": "/home/user/.aws/credentials"}),
    );
    let policy = make_conditional_policy(
        "file_system:read_file",
        "Block credentials",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "glob", "pattern": "/home/*/.aws/**", "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_glob_allows_safe_path() {
    let engine = make_engine();
    let action = make_action(
        "file_system",
        "read_file",
        json!({"path": "/home/user/projects/readme.md"}),
    );
    let policy = make_conditional_policy(
        "file_system:read_file",
        "Block credentials",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "glob", "pattern": "/home/*/.aws/**", "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_glob_blocks_ssh_keys() {
    let engine = make_engine();
    let action = make_action(
        "file_system",
        "read_file",
        json!({"path": "/home/user/.ssh/id_rsa"}),
    );
    let policy = make_conditional_policy(
        "file_system:read_file",
        "Block SSH",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "glob", "pattern": "/home/*/.ssh/**", "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// === Path traversal after normalization ===

#[test]
fn test_path_traversal_normalized() {
    let engine = make_engine();
    // Attempt to escape via ../../
    let action = make_action(
        "file_system",
        "read_file",
        json!({"path": "/home/user/projects/../../user/.aws/credentials"}),
    );
    let policy = make_conditional_policy(
        "file_system:read_file",
        "Block credentials",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "glob", "pattern": "/home/*/.aws/**", "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_path_with_dot_segments_normalized() {
    let engine = make_engine();
    let action = make_action(
        "file_system",
        "read_file",
        json!({"path": "/home/user/./.aws/./credentials"}),
    );
    let policy = make_conditional_policy(
        "file_system:read_file",
        "Block credentials",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "glob", "pattern": "/home/*/.aws/**", "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// === Domain block/allowlist ===

#[test]
fn test_domain_not_in_blocks_unknown_domain() {
    let engine = make_engine();
    let action = make_action(
        "http_request",
        "post",
        json!({"url": "https://evil.com/exfil"}),
    );
    let policy = make_conditional_policy(
        "http_request:*",
        "Domain allowlist",
        200,
        json!({
            "parameter_constraints": [
                { "param": "url", "op": "domain_not_in", "patterns": ["*.example.com", "api.anthropic.com"], "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_domain_not_in_allows_listed_domain() {
    let engine = make_engine();
    let action = make_action(
        "http_request",
        "get",
        json!({"url": "https://api.example.com/data"}),
    );
    let policy = make_conditional_policy(
        "http_request:*",
        "Domain allowlist",
        200,
        json!({
            "parameter_constraints": [
                { "param": "url", "op": "domain_not_in", "patterns": ["*.example.com", "api.anthropic.com"], "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_domain_not_in_allows_exact_match() {
    let engine = make_engine();
    let action = make_action(
        "http_request",
        "get",
        json!({"url": "https://api.anthropic.com/v1/messages"}),
    );
    let policy = make_conditional_policy(
        "http_request:*",
        "Domain allowlist",
        200,
        json!({
            "parameter_constraints": [
                { "param": "url", "op": "domain_not_in", "patterns": ["*.example.com", "api.anthropic.com"], "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_domain_match_blocks_evil_subdomain() {
    let engine = make_engine();
    let action = make_action(
        "http_request",
        "post",
        json!({"url": "https://data.evil.com/collect"}),
    );
    let policy = make_conditional_policy(
        "http_request:*",
        "Block evil.com",
        200,
        json!({
            "parameter_constraints": [
                { "param": "url", "op": "domain_match", "pattern": "*.evil.com", "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// === Regex matching ===

#[test]
fn test_regex_blocks_rm_rf() {
    let engine = make_engine();
    let action = make_action(
        "bash",
        "execute",
        json!({"command": "rm -rf /important/data"}),
    );
    let policy = make_conditional_policy(
        "bash:execute",
        "Block rm -rf",
        200,
        json!({
            "parameter_constraints": [
                { "param": "command", "op": "regex", "pattern": "(?i)rm\\s+-rf", "on_match": "require_approval" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::RequireApproval { .. }));
}

#[test]
fn test_regex_allows_safe_command() {
    let engine = make_engine();
    let action = make_action("bash", "execute", json!({"command": "ls -la /tmp"}));
    let policy = make_conditional_policy(
        "bash:execute",
        "Block rm -rf",
        200,
        json!({
            "parameter_constraints": [
                { "param": "command", "op": "regex", "pattern": "(?i)rm\\s+-rf", "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

// === Missing parameter → deny (fail-closed) ===

#[test]
fn test_missing_parameter_denies_by_default() {
    let engine = make_engine();
    let action = make_action("file_system", "read_file", json!({})); // no "path" param
    let policy = make_conditional_policy(
        "file_system:read_file",
        "Need path",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "glob", "pattern": "/safe/**", "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// === on_missing: "skip" override ===

#[test]
fn test_on_missing_skip_all_constraints_skipped_denies() {
    // Exploit #2 fix: when ALL constraints skip because required params are missing,
    // the policy returns Deny (fail-closed), not Allow.
    let engine = make_engine();
    let action = make_action("file_system", "read_file", json!({})); // no "path" param
    let policy = make_conditional_policy(
        "file_system:read_file",
        "Optional path check",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "glob", "pattern": "/home/*/.aws/**", "on_match": "deny", "on_missing": "skip" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "All constraints skipped → fail-closed deny, got: {:?}",
        verdict
    );
}

// === Mixed with require_approval (approval takes precedence because it's checked first) ===

#[test]
fn test_require_approval_takes_precedence_over_constraints() {
    let engine = make_engine();
    let action = make_action(
        "file_system",
        "read_file",
        json!({"path": "/home/user/.aws/credentials"}),
    );
    let policy = make_conditional_policy(
        "file_system:read_file",
        "Approval first",
        200,
        json!({
            "require_approval": true,
            "parameter_constraints": [
                { "param": "path", "op": "glob", "pattern": "/home/*/.aws/**", "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    // require_approval is checked before parameter_constraints
    assert!(matches!(verdict, Verdict::RequireApproval { .. }));
}

// === Priority interaction with non-conditional policies ===

#[test]
fn test_higher_priority_deny_overrides_constraint_allow() {
    let engine = make_engine();
    let action = make_action(
        "file_system",
        "read_file",
        json!({"path": "/safe/file.txt"}),
    );

    let deny_policy = Policy {
        id: "file_system:*".to_string(),
        name: "Deny all files".to_string(),
        policy_type: PolicyType::Deny,
        priority: 300,
        path_rules: None,
        network_rules: None,
    };

    let constraint_policy = make_conditional_policy(
        "file_system:read_file",
        "Constraint check",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "glob", "pattern": "/home/*/.aws/**", "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine
        .evaluate_action(&action, &[constraint_policy, deny_policy])
        .unwrap();
    // Higher priority Deny should match first
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_lower_priority_constraint_not_reached() {
    let engine = make_engine();
    let action = make_action(
        "file_system",
        "read_file",
        json!({"path": "/home/user/.aws/credentials"}),
    );

    let allow_policy = Policy {
        id: "file_system:*".to_string(),
        name: "Allow all files".to_string(),
        policy_type: PolicyType::Allow,
        priority: 300,
        path_rules: None,
        network_rules: None,
    };

    let constraint_policy = make_conditional_policy(
        "file_system:read_file",
        "Block credentials",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "glob", "pattern": "/home/*/.aws/**", "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine
        .evaluate_action(&action, &[allow_policy, constraint_policy])
        .unwrap();
    // Higher priority Allow matches first, constraint never evaluated
    assert!(matches!(verdict, Verdict::Allow));
}

// === Invalid operator → error ===

#[test]
fn test_unknown_operator_errors() {
    let engine = make_engine();
    let action = make_action("file_system", "read_file", json!({"path": "/tmp/test"}));
    let policy = make_conditional_policy(
        "file_system:read_file",
        "Bad op",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "nonexistent_op", "pattern": "x", "on_match": "deny" }
            ]
        }),
    );

    let result = engine.evaluate_action(&action, &[policy]);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("Unknown constraint operator"));
}

// === Invalid glob/regex pattern → error ===

#[test]
fn test_invalid_glob_pattern_errors() {
    let engine = make_engine();
    let action = make_action("file_system", "read_file", json!({"path": "/tmp/test"}));
    let policy = make_conditional_policy(
        "file_system:read_file",
        "Bad glob",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "glob", "pattern": "[invalid", "on_match": "deny" }
            ]
        }),
    );

    let result = engine.evaluate_action(&action, &[policy]);
    assert!(result.is_err());
}

#[test]
fn test_invalid_regex_pattern_errors() {
    let engine = make_engine();
    let action = make_action("bash", "execute", json!({"command": "ls"}));
    let policy = make_conditional_policy(
        "bash:execute",
        "Bad regex",
        200,
        json!({
            "parameter_constraints": [
                { "param": "command", "op": "regex", "pattern": "[invalid(", "on_match": "deny" }
            ]
        }),
    );

    let result = engine.evaluate_action(&action, &[policy]);
    assert!(result.is_err());
}

// === Eq / Ne / One-of / None-of operators ===

#[test]
fn test_eq_matches() {
    let engine = make_engine();
    let action = make_action("tool", "fn", json!({"mode": "destructive"}));
    let policy = make_conditional_policy(
        "tool:fn",
        "Block destructive",
        200,
        json!({
            "parameter_constraints": [
                { "param": "mode", "op": "eq", "value": "destructive", "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_eq_no_match() {
    let engine = make_engine();
    let action = make_action("tool", "fn", json!({"mode": "safe"}));
    let policy = make_conditional_policy(
        "tool:fn",
        "Block destructive",
        200,
        json!({
            "parameter_constraints": [
                { "param": "mode", "op": "eq", "value": "destructive", "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_ne_fires_when_different() {
    let engine = make_engine();
    let action = make_action("tool", "fn", json!({"mode": "anything"}));
    let policy = make_conditional_policy(
        "tool:fn",
        "Only safe mode",
        200,
        json!({
            "parameter_constraints": [
                { "param": "mode", "op": "ne", "value": "safe", "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_one_of_matches() {
    let engine = make_engine();
    let action = make_action("tool", "fn", json!({"format": "csv"}));
    let policy = make_conditional_policy(
        "tool:fn",
        "Block certain formats",
        200,
        json!({
            "parameter_constraints": [
                { "param": "format", "op": "one_of", "values": ["csv", "tsv", "xlsx"], "on_match": "require_approval" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::RequireApproval { .. }));
}

#[test]
fn test_none_of_fires_when_not_in_set() {
    let engine = make_engine();
    let action = make_action("tool", "fn", json!({"format": "exe"}));
    let policy = make_conditional_policy(
        "tool:fn",
        "Only safe formats",
        200,
        json!({
            "parameter_constraints": [
                { "param": "format", "op": "none_of", "values": ["json", "txt", "md"], "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_none_of_does_not_fire_when_in_set() {
    let engine = make_engine();
    let action = make_action("tool", "fn", json!({"format": "json"}));
    let policy = make_conditional_policy(
        "tool:fn",
        "Only safe formats",
        200,
        json!({
            "parameter_constraints": [
                { "param": "format", "op": "none_of", "values": ["json", "txt", "md"], "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

// === Not-glob allowlist ===

#[test]
fn test_not_glob_blocks_outside_allowlist() {
    let engine = make_engine();
    let action = make_action("file_system", "write_file", json!({"path": "/etc/passwd"}));
    let policy = make_conditional_policy(
        "file_system:write_file",
        "Project dir only",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "not_glob", "patterns": ["/home/user/project/**", "/tmp/**"], "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_not_glob_allows_within_allowlist() {
    let engine = make_engine();
    let action = make_action(
        "file_system",
        "write_file",
        json!({"path": "/home/user/project/src/main.rs"}),
    );
    let policy = make_conditional_policy(
        "file_system:write_file",
        "Project dir only",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "not_glob", "patterns": ["/home/user/project/**", "/tmp/**"], "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

// === Non-string value on string operator ===

#[test]
fn test_non_string_on_glob_denies_in_non_strict() {
    let engine = make_engine();
    let action = make_action("file_system", "read_file", json!({"path": 42}));
    let policy = make_conditional_policy(
        "file_system:read_file",
        "Glob check",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "glob", "pattern": "/tmp/**", "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_non_string_on_glob_errors_in_strict() {
    let engine = make_strict_engine();
    let action = make_action("file_system", "read_file", json!({"path": 42}));
    let policy = make_conditional_policy(
        "file_system:read_file",
        "Glob check",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "glob", "pattern": "/tmp/**", "on_match": "deny" }
            ]
        }),
    );

    let result = engine.evaluate_action(&action, &[policy]);
    assert!(result.is_err());
}

// === Domain extraction edge cases ===

#[test]
fn test_domain_extraction_with_port() {
    let engine = make_engine();
    let action = make_action(
        "http_request",
        "get",
        json!({"url": "https://api.example.com:8443/path"}),
    );
    let policy = make_conditional_policy(
        "http_request:*",
        "Domain allowlist",
        200,
        json!({
            "parameter_constraints": [
                { "param": "url", "op": "domain_not_in", "patterns": ["*.example.com"], "on_match": "deny" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

// === Multiple constraints, first match wins ===

#[test]
fn test_multiple_constraints_first_match_wins() {
    let engine = make_engine();
    let action = make_action(
        "file_system",
        "read_file",
        json!({"path": "/home/user/.ssh/id_rsa"}),
    );
    let policy = make_conditional_policy(
        "file_system:read_file",
        "Multi-check",
        200,
        json!({
            "parameter_constraints": [
                { "param": "path", "op": "glob", "pattern": "/home/*/.aws/**", "on_match": "deny" },
                { "param": "path", "op": "glob", "pattern": "/home/*/.ssh/**", "on_match": "require_approval" }
            ]
        }),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    // First constraint doesn't match, second does
    assert!(matches!(verdict, Verdict::RequireApproval { .. }));
}
