//! Tests that exercise canonical policy presets through the actual PolicyEngine.
//! The vellaveto-canonical crate has unit tests for construction, but these test
//! whether the produced policies actually work as intended when evaluated.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

// We can't depend on vellaveto-canonical from vellaveto-integration (it's not
// in the Cargo.toml), so we recreate the canonical presets exactly as defined.
// This also serves as a compatibility check: if canonical changes its output,
// these tests document the expected engine behavior.

fn deny_all_policy() -> Policy {
    Policy {
        id: "*".to_string(),
        name: "Deny All Actions".to_string(),
        policy_type: PolicyType::Deny,
        priority: 1000,
        path_rules: None,
        network_rules: None,
    }
}

fn allow_all_policy() -> Policy {
    Policy {
        id: "*".to_string(),
        name: "Allow All Actions".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    }
}

fn block_dangerous_tools() -> Vec<Policy> {
    vec![
        Policy {
            id: "bash_block".to_string(),
            name: "Block Bash Commands".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "tool_pattern": "bash",
                    "require_approval": true
                }),
            },
            priority: 900,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "system_block".to_string(),
            name: "Block System Commands".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "tool_pattern": "system",
                    "forbidden_parameters": ["rm", "delete", "format"]
                }),
            },
            priority: 900,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "file_protection".to_string(),
            name: "File Operation Protection".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "tool_pattern": "file",
                    "function_pattern": "delete",
                    "require_approval": true
                }),
            },
            priority: 800,
            path_rules: None,
            network_rules: None,
        },
    ]
}

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

// ═══════════════════════════════════════════
// DENY ALL PRESET
// ═══════════════════════════════════════════

#[test]
fn deny_all_denies_any_action() {
    let engine = PolicyEngine::new(false);
    let policies = vec![deny_all_policy()];

    let actions = vec![
        make_action("bash", "exec", json!({})),
        make_action("file", "read", json!({})),
        make_action("network", "fetch", json!({"url": "http://example.com"})),
        make_action("", "", json!(null)),
    ];

    for action in &actions {
        match engine.evaluate_action(action, &policies).unwrap() {
            Verdict::Deny { .. } => {}
            other => panic!("deny_all should deny {:?}, got {:?}", action.tool, other),
        }
    }
}

// ═══════════════════════════════════════════
// ALLOW ALL PRESET
// ═══════════════════════════════════════════

#[test]
fn allow_all_allows_any_action() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow_all_policy()];

    let actions = vec![
        make_action("bash", "exec", json!({})),
        make_action("file", "delete", json!({})),
        make_action("anything", "whatever", json!({"key": "val"})),
    ];

    for action in &actions {
        assert_eq!(
            engine.evaluate_action(action, &policies).unwrap(),
            Verdict::Allow,
            "allow_all should allow {:?}",
            action.tool,
        );
    }
}

// ════════════════════════════════════════════
// DENY ALL OVERRIDES ALLOW ALL (priority 1000 > 1)
// ════════════════════════════════════════════

#[test]
fn deny_all_overrides_allow_all() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow_all_policy(), deny_all_policy()];

    let action = make_action("any", "thing", json!({}));
    match engine.evaluate_action(&action, &policies).unwrap() {
        Verdict::Deny { .. } => {}
        other => panic!(
            "deny_all(1000) should override allow_all(1), got {:?}",
            other
        ),
    }
}

// ═══════════════════════════════════════════
// BLOCK DANGEROUS TOOLS PRESET
// ═══════════════════════════════════════════

/// The bash_block policy has id "bash_block" which doesn't use colon notation.
/// So it matches tools named exactly "bash_block" via match_pattern, NOT "bash".
/// This is a subtle design choice — the canonical preset blocks by tool name
/// match on the policy ID, not by the tool_pattern condition field.
#[test]
fn bash_block_policy_id_matching_behavior() {
    let engine = PolicyEngine::new(false);
    let dangerous = block_dangerous_tools();

    // The policy id is "bash_block", not "bash:*".
    // So an action with tool="bash_block" matches the ID.
    let action = make_action("bash_block", "exec", json!({}));
    match engine.evaluate_action(&action, &dangerous).unwrap() {
        Verdict::RequireApproval { .. } => {}
        other => panic!(
            "bash_block ID should match tool 'bash_block', got {:?}",
            other
        ),
    }

    // An action with tool="bash" does NOT match id="bash_block" (no wildcard in ID)
    let action = make_action("bash", "exec", json!({}));
    match engine.evaluate_action(&action, &dangerous).unwrap() {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("No matching policy"),
                "Should fall through to default deny"
            );
        }
        other => panic!(
            "tool='bash' should NOT match id='bash_block', got {:?}",
            other
        ),
    }
}

/// system_block checks forbidden_parameters. An action with tool="system_block"
/// and a forbidden param like "rm" should be denied.
#[test]
fn system_block_forbidden_parameters() {
    let engine = PolicyEngine::new(false);
    let dangerous = block_dangerous_tools();

    // Tool matches id="system_block" exactly, has forbidden param "rm"
    let action = make_action("system_block", "run", json!({"rm": true}));
    match engine.evaluate_action(&action, &dangerous).unwrap() {
        Verdict::Deny { reason } => {
            assert!(reason.contains("rm"), "Should mention forbidden param 'rm'");
        }
        other => panic!("Expected Deny for forbidden param, got {:?}", other),
    }
}

/// system_block without forbidden params → Allow (conditions pass).
#[test]
fn system_block_without_forbidden_params_allows() {
    let engine = PolicyEngine::new(false);
    let dangerous = block_dangerous_tools();

    let action = make_action("system_block", "status", json!({"safe": true}));
    assert_eq!(
        engine.evaluate_action(&action, &dangerous).unwrap(),
        Verdict::Allow,
        "No forbidden params present, conditional should allow"
    );
}

/// file_protection has require_approval=true, so it should require approval
/// for any action matching id="file_protection".
#[test]
fn file_protection_requires_approval() {
    let engine = PolicyEngine::new(false);
    let dangerous = block_dangerous_tools();

    let action = make_action("file_protection", "anything", json!({}));
    match engine.evaluate_action(&action, &dangerous).unwrap() {
        Verdict::RequireApproval { .. } => {}
        other => panic!("file_protection should require approval, got {:?}", other),
    }
}

// ═══════════════════════════════════════════
// COMBINING DANGEROUS TOOLS WITH ALLOW-ALL FALLBACK
// ════════════════════════════════════════════

/// In a real deployment, you'd combine block_dangerous_tools with allow_all
/// as a low-priority fallback. Dangerous tools get their conditional check,
/// everything else gets allowed.
#[test]
fn dangerous_tools_with_allow_all_fallback() {
    let engine = PolicyEngine::new(false);
    let mut policies = block_dangerous_tools();
    policies.push(allow_all_policy()); // priority=1, lowest

    // Safe tool → allow_all matches (priority 1)
    let safe = make_action("git", "status", json!({}));
    assert_eq!(
        engine.evaluate_action(&safe, &policies).unwrap(),
        Verdict::Allow,
    );

    // "bash_block" tool → conditional (priority 900) matches first
    let bash = make_action("bash_block", "exec", json!({}));
    match engine.evaluate_action(&bash, &policies).unwrap() {
        Verdict::RequireApproval { .. } => {}
        other => panic!(
            "bash_block should require approval even with allow-all fallback, got {:?}",
            other
        ),
    }

    // "system_block" with forbidden param → deny (priority 900)
    let sys = make_action("system_block", "run", json!({"delete": true}));
    match engine.evaluate_action(&sys, &policies).unwrap() {
        Verdict::Deny { .. } => {}
        other => panic!(
            "system_block with forbidden param should deny, got {:?}",
            other
        ),
    }

    // "system_block" without forbidden param → allow (conditional passes through)
    let sys_safe = make_action("system_block", "info", json!({"query": "version"}));
    assert_eq!(
        engine.evaluate_action(&sys_safe, &policies).unwrap(),
        Verdict::Allow,
    );
}

// ═══════════════════════════════════════════
// CANONICAL POLICY SERIALIZATION COMPATIBILITY
// ═══════════════════════════════════════════

/// Canonical policies should survive JSON serialization roundtrip and still
/// produce the same verdicts when deserialized.
#[test]
fn canonical_policies_survive_serialization() {
    let engine = PolicyEngine::new(false);
    let original_policies = block_dangerous_tools();

    // Serialize and deserialize
    let json_str = serde_json::to_string(&original_policies).unwrap();
    let deserialized_policies: Vec<Policy> = serde_json::from_str(&json_str).unwrap();

    // Same verdicts for the same actions
    let test_actions = vec![
        make_action("bash_block", "exec", json!({})),
        make_action("system_block", "run", json!({"rm": true})),
        make_action("file_protection", "delete", json!({})),
        make_action("unknown", "thing", json!({})),
    ];

    for action in &test_actions {
        let v1 = engine.evaluate_action(action, &original_policies).unwrap();
        let v2 = engine
            .evaluate_action(action, &deserialized_policies)
            .unwrap();
        assert_eq!(
            v1, v2,
            "Verdict mismatch after roundtrip for action {:?}",
            action.tool
        );
    }
}
