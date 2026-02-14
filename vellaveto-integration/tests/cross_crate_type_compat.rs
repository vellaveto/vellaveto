//! Tests that types from vellaveto_types are correctly recognized and used
//! across all crate boundaries. Verifies that engine, audit, and MCP-style
//! flows all agree on type serialization formats.

use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;
use tempfile::TempDir;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

// ═══════════════════════════════════════════
// ACTION TYPE COMPATIBILITY
// ═══════════════════════════════════════════

/// An Action serialized by vellaveto-types can be deserialized and used by
/// the engine and audit logger without transformation.
#[test]
fn action_type_shared_across_crates() {
    let rt = runtime();
    rt.block_on(async {
        let action = Action::new(
            "compat_test".to_string(),
            "verify".to_string(),
            json!({"cross_crate": true}),
        );

        // Serialize (simulating network/IPC boundary)
        let json_str = serde_json::to_string(&action).unwrap();

        // Deserialize on "engine side"
        let engine_action: Action = serde_json::from_str(&json_str).unwrap();

        // Use in engine
        let engine = PolicyEngine::new(false);
        let policies = vec![Policy {
            id: "compat_test:verify".to_string(),
            name: "Compat test".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        }];
        let verdict = engine.evaluate_action(&engine_action, &policies).unwrap();
        assert_eq!(verdict, Verdict::Allow);

        // Deserialize on "audit side" (same bytes)
        let audit_action: Action = serde_json::from_str(&json_str).unwrap();

        // Use in audit logger
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        logger
            .log_entry(&audit_action, &verdict, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(
            entries[0].action, action,
            "Action should be identical across crate boundaries"
        );
    });
}

// ═══════════════════════════════════════════
// VERDICT TYPE COMPATIBILITY
// ═══════════════════════════════════════════

/// Verdicts produced by the engine can be directly consumed by the audit logger.
#[test]
fn verdict_flows_from_engine_to_audit() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let action = Action::new("file".to_string(), "read".to_string(), json!({}));

        // Test all three verdict types
        let policy_sets: Vec<(Vec<Policy>, &str)> = vec![
            (
                vec![Policy {
                    id: "file:read".to_string(),
                    name: "Allow".to_string(),
                    policy_type: PolicyType::Allow,
                    priority: 10,
                    path_rules: None,
                    network_rules: None,
                }],
                "Allow",
            ),
            (
                vec![Policy {
                    id: "file:read".to_string(),
                    name: "Deny".to_string(),
                    policy_type: PolicyType::Deny,
                    priority: 10,
                    path_rules: None,
                    network_rules: None,
                }],
                "Deny",
            ),
            (
                vec![Policy {
                    id: "file:read".to_string(),
                    name: "Conditional".to_string(),
                    policy_type: PolicyType::Conditional {
                        conditions: json!({"require_approval": true}),
                    },
                    priority: 10,
                    path_rules: None,
                    network_rules: None,
                }],
                "RequireApproval",
            ),
        ];

        for (policies, expected_type) in &policy_sets {
            let verdict = engine.evaluate_action(&action, policies).unwrap();
            // Engine verdict can be directly passed to audit
            logger
                .log_entry(&action, &verdict, json!({"test": expected_type}))
                .await
                .unwrap();
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 3);
        assert_eq!(report.allow_count, 1);
        assert_eq!(report.deny_count, 1);
        assert_eq!(report.require_approval_count, 1);
    });
}

// ═══════════════════════════════════════════
// POLICY SERIALIZATION CROSS-CRATE
// ═══════════════════════════════════════════

/// A Policy serialized as JSON (as MCP or config would send it) can be
/// deserialized and used by the engine.
#[test]
fn policy_json_consumed_by_engine() {
    let engine = PolicyEngine::new(false);

    // Simulate receiving policy as JSON (from MCP, config file, or API)
    let policy_json = json!({
        "id": "net:*",
        "name": "Block network",
        "policy_type": "Deny",
        "priority": 500
    });
    let policy: Policy = serde_json::from_value(policy_json).unwrap();

    let action = Action::new(
        "net".to_string(),
        "fetch".to_string(),
        json!({"url": "https://example.com"}),
    );

    match engine.evaluate_action(&action, &[policy]).unwrap() {
        Verdict::Deny { .. } => {}
        other => panic!("Expected Deny, got {:?}", other),
    }
}

/// Conditional policy with complex conditions survives JSON roundtrip.
#[test]
fn conditional_policy_json_roundtrip_preserves_behavior() {
    let engine = PolicyEngine::new(false);

    let original = Policy {
        id: "*".to_string(),
        name: "Complex conditional".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "forbidden_parameters": ["secret", "password", "token"],
                "required_parameters": ["user_id"],
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    };

    let json_str = serde_json::to_string(&original).unwrap();
    let roundtripped: Policy = serde_json::from_str(&json_str).unwrap();

    // Same behavior with original and roundtripped policy
    let test_cases: Vec<(Action, bool)> = vec![
        // Has required, no forbidden → Allow
        (
            Action::new(
                "api".to_string(),
                "call".to_string(),
                json!({"user_id": "123"}),
            ),
            true,
        ),
        // Missing required → Deny
        (
            Action::new("api".to_string(), "call".to_string(), json!({})),
            false,
        ),
        // Has forbidden  Deny
        (
            Action::new(
                "api".to_string(),
                "call".to_string(),
                json!({"user_id": "123", "secret": "s"}),
            ),
            false,
        ),
    ];

    for (action, should_allow) in &test_cases {
        let v1 = engine
            .evaluate_action(action, std::slice::from_ref(&original))
            .unwrap();
        let v2 = engine
            .evaluate_action(action, std::slice::from_ref(&roundtripped))
            .unwrap();
        assert_eq!(v1, v2, "Behavior should be identical after roundtrip");

        match (should_allow, &v1) {
            (true, Verdict::Allow) => {}
            (false, Verdict::Deny { .. }) => {}
            _ => panic!(
                "Expected allow={} for {:?}, got {:?}",
                should_allow, action.parameters, v1
            ),
        }
    }
}

// ═══════════════════════════════════════════
// AUDIT ENTRY PRESERVES ENGINE OUTPUT EXACTLY
// ═══════════════════════════════════════════

/// The verdict stored in an AuditEntry must be structurally identical
/// to what the engine produced.
#[test]
fn audit_entry_verdict_matches_engine_output_exactly() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let action = Action::new(
            "shell".to_string(),
            "exec".to_string(),
            json!({"cmd": "ls"}),
        );
        let policies = vec![Policy {
            id: "shell:*".to_string(),
            name: "Shell conditional".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 50,
            path_rules: None,
            network_rules: None,
        }];

        let engine_verdict = engine.evaluate_action(&action, &policies).unwrap();
        logger
            .log_entry(&action, &engine_verdict, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].verdict, engine_verdict,
            "Audit entry verdict must exactly match engine output"
        );
    });
}

// ═══════════════════════════════════════════
// PRIORITY I32 COMPATIBILITY
// ════════════════════════════════════════════

/// Verify that i32 priority values survive JSON serialization.
/// This catches if someone accidentally changes the type to u32.
#[test]
fn negative_priority_survives_json_roundtrip() {
    let policy = Policy {
        id: "*".to_string(),
        name: "Negative priority".to_string(),
        policy_type: PolicyType::Allow,
        priority: -42,
        path_rules: None,
        network_rules: None,
    };
    let json_str = serde_json::to_string(&policy).unwrap();
    let deserialized: Policy = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.priority, -42);
}

#[test]
fn extreme_priorities_survive_json_roundtrip() {
    for priority in [i32::MIN, i32::MAX, 0, -1, 1] {
        let policy = Policy {
            id: "*".to_string(),
            name: format!("pri-{}", priority),
            policy_type: PolicyType::Deny,
            priority,
            path_rules: None,
            network_rules: None,
        };
        let json_str = serde_json::to_string(&policy).unwrap();
        let deserialized: Policy = serde_json::from_str(&json_str).unwrap();
        assert_eq!(
            deserialized.priority, priority,
            "Priority {} should survive roundtrip",
            priority
        );
    }
}
