// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Integration tests for P1: Path and Domain security scenarios.
//!
//! These tests demonstrate real-world attack scenarios that the Vellaveto
//! policy engine blocks using parameter constraints (glob, not_glob,
//! domain_match, domain_not_in, regex).

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

fn engine() -> PolicyEngine {
    PolicyEngine::new(false)
}

fn strict_engine() -> PolicyEngine {
    PolicyEngine::new(true)
}

fn action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

fn constraint_policy(
    id: &str,
    name: &str,
    priority: i32,
    constraints: serde_json::Value,
) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({ "parameter_constraints": constraints }),
        },
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn deny_policy(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn allow_policy(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Allow,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO: Credential exfiltration blocked
// ═══════════════════════════════════════════════════════════════

#[test]
fn scenario_block_aws_credential_read() {
    let eng = engine();
    let policies = vec![
        constraint_policy(
            "file_system:*",
            "Block sensitive paths",
            200,
            json!([
                { "param": "path", "op": "glob", "pattern": "/home/*/.aws/**", "on_match": "deny" },
                { "param": "path", "op": "glob", "pattern": "/home/*/.ssh/**", "on_match": "deny" },
                { "param": "path", "op": "glob", "pattern": "/etc/shadow", "on_match": "deny" },
            ]),
        ),
        allow_policy("file_system:*", "Allow file operations by default", 100),
    ];

    // Blocked: AWS credentials
    let v = eng
        .evaluate_action(
            &action(
                "file_system",
                "read_file",
                json!({"path": "/home/alice/.aws/credentials"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "AWS credentials should be blocked"
    );

    // Blocked: SSH private key
    let v = eng
        .evaluate_action(
            &action(
                "file_system",
                "read_file",
                json!({"path": "/home/alice/.ssh/id_rsa"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "SSH keys should be blocked"
    );

    // Blocked: /etc/shadow
    let v = eng
        .evaluate_action(
            &action("file_system", "read_file", json!({"path": "/etc/shadow"})),
            &policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "/etc/shadow should be blocked"
    );

    // Allowed: normal project file
    let v = eng
        .evaluate_action(
            &action(
                "file_system",
                "read_file",
                json!({"path": "/home/alice/project/src/main.rs"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Project files should be allowed"
    );
}

#[test]
fn scenario_traversal_bypasses_narrow_glob() {
    // IMPORTANT SECURITY LESSON: A narrow glob like /home/*/.aws/** requires a
    // username segment. Path traversal can collapse that segment:
    //   /home/alice/project/../../.aws/credentials → /home/.aws/credentials
    // which does NOT match /home/*/.aws/** because * requires a segment.
    //
    // Defense: Use **/.aws/** to catch .aws at any depth.
    let eng = engine();

    // Narrow pattern: can be bypassed by traversal
    let narrow_policies = vec![
        constraint_policy(
            "file_system:*",
            "Narrow block",
            200,
            json!([
                { "param": "path", "op": "glob", "pattern": "/home/*/.aws/**", "on_match": "deny" },
            ]),
        ),
        allow_policy("file_system:*", "Allow file ops", 100),
    ];

    // This traversal ESCAPES the narrow glob — demonstrating the risk
    let v = eng
        .evaluate_action(
            &action(
                "file_system",
                "read_file",
                json!({"path": "/home/alice/project/../../.aws/credentials"}),
            ),
            &narrow_policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Narrow glob misses collapsed traversal"
    );

    // CORRECT defense: use recursive glob **/.aws/**
    let broad_policies = vec![
        constraint_policy(
            "file_system:*",
            "Broad block",
            200,
            json!([
                { "param": "path", "op": "glob", "pattern": "**/.aws/**", "on_match": "deny" },
            ]),
        ),
        allow_policy("file_system:*", "Allow file ops", 100),
    ];

    let v = eng
        .evaluate_action(
            &action(
                "file_system",
                "read_file",
                json!({"path": "/home/alice/project/../../.aws/credentials"}),
            ),
            &broad_policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Recursive glob catches traversal"
    );
}

#[test]
fn scenario_allowlist_blocks_traversal_escape() {
    // Allowlist approach is inherently safe against traversal:
    // After normalization, the path either matches the allowed pattern or doesn't.
    let eng = engine();
    let policies = vec![
        constraint_policy(
            "file_system:*",
            "Only allow project dir",
            200,
            json!([
                {
                    "param": "path",
                    "op": "not_glob",
                    "patterns": ["/home/alice/project/**"],
                    "on_match": "deny"
                }
            ]),
        ),
        allow_policy("file_system:*", "Allow file ops", 100),
    ];

    // Traversal normalizes outside the allowed path → denied
    let v = eng
        .evaluate_action(
            &action(
                "file_system",
                "read_file",
                json!({"path": "/home/alice/project/../../.aws/credentials"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Allowlist blocks traversal escape"
    );
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO: Path allowlist enforcement
// ═══════════════════════════════════════════════════════════════

#[test]
fn scenario_path_allowlist_restricts_to_workspace() {
    let eng = engine();
    let policies = vec![
        constraint_policy(
            "file_system:*",
            "Only allow workspace paths",
            200,
            json!([
                {
                    "param": "path",
                    "op": "not_glob",
                    "patterns": ["/home/user/project/**", "/tmp/agent-workspace/**"],
                    "on_match": "deny"
                }
            ]),
        ),
        allow_policy("file_system:*", "Allow file ops", 100),
    ];

    // Allowed: project file
    let v = eng
        .evaluate_action(
            &action(
                "file_system",
                "write_file",
                json!({"path": "/home/user/project/output.json"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Allow));

    // Allowed: temp workspace
    let v = eng
        .evaluate_action(
            &action(
                "file_system",
                "write_file",
                json!({"path": "/tmp/agent-workspace/cache.db"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Allow));

    // Blocked: system files
    let v = eng
        .evaluate_action(
            &action("file_system", "write_file", json!({"path": "/etc/crontab"})),
            &policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "System files outside allowlist should be blocked"
    );

    // Blocked: another user's home
    let v = eng
        .evaluate_action(
            &action(
                "file_system",
                "write_file",
                json!({"path": "/home/admin/.bashrc"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Other user's files should be blocked"
    );
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO: Domain allowlist prevents data exfiltration
// ═══════════════════════════════════════════════════════════════

#[test]
fn scenario_domain_allowlist_blocks_exfiltration() {
    let eng = engine();
    let policies = vec![
        constraint_policy(
            "http:*",
            "Only allow known APIs",
            200,
            json!([
                {
                    "param": "url",
                    "op": "domain_not_in",
                    "patterns": ["api.anthropic.com", "*.github.com", "*.company.internal"],
                    "on_match": "deny"
                }
            ]),
        ),
        allow_policy("http:*", "Allow HTTP by default", 100),
    ];

    // Allowed: Anthropic API
    let v = eng
        .evaluate_action(
            &action(
                "http",
                "post",
                json!({"url": "https://api.anthropic.com/v1/messages"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Allow));

    // Allowed: GitHub API
    let v = eng
        .evaluate_action(
            &action(
                "http",
                "get",
                json!({"url": "https://api.github.com/repos/org/repo"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Allow));

    // Blocked: Pastebin (data exfiltration)
    let v = eng
        .evaluate_action(
            &action(
                "http",
                "post",
                json!({"url": "https://pastebin.com/api/post"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Pastebin should be blocked"
    );

    // Blocked: ngrok tunnel
    let v = eng
        .evaluate_action(
            &action(
                "http",
                "post",
                json!({"url": "https://abc123.ngrok.io/exfil"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Ngrok tunnels should be blocked"
    );

    // Blocked: random attacker domain
    let v = eng
        .evaluate_action(
            &action(
                "http",
                "post",
                json!({"url": "https://evil-server.xyz/collect"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Unknown domains should be blocked"
    );
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO: Domain blocklist for known-bad destinations
// ═══════════════════════════════════════════════════════════════

#[test]
fn scenario_domain_blocklist_known_bad() {
    let eng = engine();
    let policies = vec![
        constraint_policy(
            "http:*",
            "Block known exfil domains",
            200,
            json!([
                { "param": "url", "op": "domain_match", "pattern": "*.pastebin.com", "on_match": "deny" },
                { "param": "url", "op": "domain_match", "pattern": "*.ngrok.io", "on_match": "deny" },
                { "param": "url", "op": "domain_match", "pattern": "*.requestbin.com", "on_match": "deny" },
            ]),
        ),
        allow_policy("http:*", "Allow HTTP", 100),
    ];

    // Blocked: pastebin subdomain
    let v = eng
        .evaluate_action(
            &action(
                "http",
                "post",
                json!({"url": "https://data.pastebin.com/raw/abc"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));

    // Allowed: legitimate API
    let v = eng
        .evaluate_action(
            &action(
                "http",
                "get",
                json!({"url": "https://api.stripe.com/v1/charges"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Allow));
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO: SQL injection prevention via regex
// ═══════════════════════════════════════════════════════════════

#[test]
fn scenario_sql_injection_prevention() {
    let eng = engine();
    let policies = vec![
        constraint_policy(
            "database:*",
            "Block dangerous SQL",
            200,
            json!([
                { "param": "query", "op": "regex", "pattern": "(?i)drop\\s+table", "on_match": "deny" },
                { "param": "query", "op": "regex", "pattern": "(?i)truncate\\s+table", "on_match": "deny" },
                { "param": "query", "op": "regex", "pattern": "(?i)alter\\s+table.*drop", "on_match": "deny" },
                { "param": "query", "op": "regex", "pattern": "(?i)delete\\s+from", "on_match": "require_approval" },
            ]),
        ),
        allow_policy("database:*", "Allow DB operations", 100),
    ];

    // Blocked: DROP TABLE
    let v = eng
        .evaluate_action(
            &action("database", "execute", json!({"query": "DROP TABLE users;"})),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));

    // Blocked: case-insensitive
    let v = eng
        .evaluate_action(
            &action(
                "database",
                "execute",
                json!({"query": "drop  table  users;"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));

    // Requires approval: DELETE
    let v = eng
        .evaluate_action(
            &action(
                "database",
                "execute",
                json!({"query": "DELETE FROM orders WHERE id = 42"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::RequireApproval { .. }));

    // Allowed: normal SELECT
    let v = eng
        .evaluate_action(
            &action(
                "database",
                "execute",
                json!({"query": "SELECT * FROM users WHERE active = true"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Allow));
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO: Layered defense — path + domain + tool
// ═══════════════════════════════════════════════════════════════

#[test]
fn scenario_layered_defense() {
    let eng = engine();
    let policies = vec![
        // Layer 1: Block shell execution entirely
        deny_policy("shell:*", "Block all shell commands", 300),
        // Layer 2: Block sensitive paths
        constraint_policy(
            "file_system:*",
            "Block sensitive paths",
            200,
            json!([
                { "param": "path", "op": "glob", "pattern": "/home/*/.ssh/**", "on_match": "deny" },
                { "param": "path", "op": "glob", "pattern": "/home/*/.aws/**", "on_match": "deny" },
            ]),
        ),
        // Layer 3: Domain allowlist for HTTP
        constraint_policy(
            "http:*",
            "Domain allowlist",
            200,
            json!([
                {
                    "param": "url",
                    "op": "domain_not_in",
                    "patterns": ["api.anthropic.com", "*.github.com"],
                    "on_match": "deny"
                }
            ]),
        ),
        // Default: allow everything else
        allow_policy("*", "Default allow", 50),
    ];

    // Shell blocked by deny policy (layer 1)
    let v = eng
        .evaluate_action(
            &action("shell", "execute", json!({"command": "cat /etc/passwd"})),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));

    // SSH key blocked by path constraint (layer 2)
    let v = eng
        .evaluate_action(
            &action(
                "file_system",
                "read_file",
                json!({"path": "/home/user/.ssh/id_ed25519"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));

    // Unknown domain blocked by allowlist (layer 3)
    let v = eng
        .evaluate_action(
            &action("http", "post", json!({"url": "https://attacker.com/steal"})),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));

    // Normal file read allowed
    let v = eng
        .evaluate_action(
            &action(
                "file_system",
                "read_file",
                json!({"path": "/home/user/project/README.md"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Allow));

    // Allowed domain passes
    let v = eng
        .evaluate_action(
            &action(
                "http",
                "get",
                json!({"url": "https://api.anthropic.com/v1/models"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Allow));
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO: Priority interactions between constraints and tool policies
// ═══════════════════════════════════════════════════════════════

#[test]
fn scenario_deny_policy_overrides_lower_constraint_allow() {
    let eng = engine();
    let policies = vec![
        // High-priority deny for shell
        deny_policy("shell:*", "Block shell", 300),
        // Lower-priority constraint that would allow
        constraint_policy(
            "*",
            "Path check",
            100,
            json!([
                {
                    "param": "path",
                    "op": "not_glob",
                    "patterns": ["/safe/**"],
                    "on_match": "deny"
                }
            ]),
        ),
    ];

    // Shell is denied by higher priority, constraints irrelevant
    let v = eng
        .evaluate_action(
            &action("shell", "execute", json!({"path": "/safe/script.sh"})),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO: Fail-closed — missing parameters deny by default
// ═══════════════════════════════════════════════════════════════

#[test]
fn scenario_fail_closed_missing_path_parameter() {
    let eng = engine();
    let policies = vec![
        constraint_policy(
            "file_system:*",
            "Path check",
            200,
            json!([
                {
                    "param": "path",
                    "op": "not_glob",
                    "patterns": ["/safe/**"],
                    "on_match": "deny"
                }
            ]),
        ),
        allow_policy("file_system:*", "Allow file ops", 100),
    ];

    // Missing path parameter → fail-closed deny
    let v = eng
        .evaluate_action(&action("file_system", "read_file", json!({})), &policies)
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Missing path should fail-closed to deny"
    );
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO: Strict mode catches misconfigured policies
// ═══════════════════════════════════════════════════════════════

#[test]
fn scenario_strict_mode_rejects_non_string_on_path_ops() {
    let eng = strict_engine();
    let policies = vec![
        constraint_policy(
            "*",
            "Path check",
            200,
            json!([
                { "param": "path", "op": "glob", "pattern": "/etc/**", "on_match": "deny" }
            ]),
        ),
        allow_policy("*", "Allow", 100),
    ];

    // Non-string path value → error in strict mode
    let result = eng.evaluate_action(
        &action("file_system", "read_file", json!({"path": 42})),
        &policies,
    );
    assert!(
        result.is_err(),
        "Strict mode should error on non-string path"
    );
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO: Combined path blocklist and allowlist
// ═══════════════════════════════════════════════════════════════

#[test]
fn scenario_blocklist_takes_precedence_in_constraint_order() {
    let eng = engine();
    let policies = vec![
        constraint_policy(
            "file_system:*",
            "Security rules",
            200,
            json!([
                // Blocklist (checked first): always block .env files
                { "param": "path", "op": "glob", "pattern": "**/.env", "on_match": "deny" },
                { "param": "path", "op": "glob", "pattern": "**/.env.*", "on_match": "deny" },
                // Allowlist: restrict to project directory
                {
                    "param": "path",
                    "op": "not_glob",
                    "patterns": ["/home/user/project/**"],
                    "on_match": "deny"
                }
            ]),
        ),
        allow_policy("file_system:*", "Allow file ops", 100),
    ];

    // Blocked: .env file even within project
    let v = eng
        .evaluate_action(
            &action(
                "file_system",
                "read_file",
                json!({"path": "/home/user/project/.env"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        ".env should be blocked even in allowed directory"
    );

    // Blocked: outside project
    let v = eng
        .evaluate_action(
            &action("file_system", "read_file", json!({"path": "/etc/hosts"})),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));

    // Allowed: normal project file
    let v = eng
        .evaluate_action(
            &action(
                "file_system",
                "read_file",
                json!({"path": "/home/user/project/src/main.rs"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(matches!(v, Verdict::Allow));
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO: URL evasion attempts
// ═══════════════════════════════════════════════════════════════

#[test]
fn scenario_domain_evasion_with_port() {
    let eng = engine();
    let policies = vec![
        constraint_policy(
            "http:*",
            "Block evil.com",
            200,
            json!([
                { "param": "url", "op": "domain_match", "pattern": "evil.com", "on_match": "deny" }
            ]),
        ),
        allow_policy("http:*", "Allow HTTP", 100),
    ];

    // Blocked despite non-standard port
    let v = eng
        .evaluate_action(
            &action(
                "http",
                "post",
                json!({"url": "https://evil.com:9999/exfil"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Port evasion should be blocked"
    );
}

#[test]
fn scenario_domain_evasion_with_userinfo() {
    let eng = engine();
    let policies = vec![
        constraint_policy(
            "http:*",
            "Block evil.com",
            200,
            json!([
                { "param": "url", "op": "domain_match", "pattern": "evil.com", "on_match": "deny" }
            ]),
        ),
        allow_policy("http:*", "Allow HTTP", 100),
    ];

    // Blocked despite userinfo in URL
    let v = eng
        .evaluate_action(
            &action(
                "http",
                "post",
                json!({"url": "https://user:pass@evil.com/exfil"}),
            ),
            &policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Userinfo evasion should be blocked"
    );
}

#[test]
fn scenario_domain_evasion_with_case() {
    let eng = engine();
    let policies = vec![
        constraint_policy(
            "http:*",
            "Block evil.com",
            200,
            json!([
                { "param": "url", "op": "domain_match", "pattern": "evil.com", "on_match": "deny" }
            ]),
        ),
        allow_policy("http:*", "Allow HTTP", 100),
    ];

    // Blocked despite mixed case
    let v = eng
        .evaluate_action(
            &action("http", "post", json!({"url": "https://EVIL.COM/exfil"})),
            &policies,
        )
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Case evasion should be blocked"
    );
}
