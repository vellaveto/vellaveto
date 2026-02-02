//! Tests that exercise the config → engine → audit pipeline.
//! Verifies that PolicyConfig-defined rules produce correct verdicts
//! and are properly recorded in the audit trail.

use sentinel_audit::AuditLogger;
use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;
use tempfile::TempDir;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

/// Convert a JSON policy definition (like what sentinel-config would parse)
/// into a Policy struct. This simulates the config → types pipeline.
fn _policy_from_json(value: serde_json::Value) -> Policy {
    serde_json::from_value(value).expect("failed to deserialize policy")
}

// ════════════════════════════════════════════════
// CONFIG-DRIVEN POLICY EVALUATION
// ════════════════════════════════════════════════

#[test]
fn json_config_driven_full_pipeline() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        // Simulate loading policies from a JSON config file
        let config_json = json!([
            {
                "id": "file:read",
                "name": "Allow file reads",
                "policy_type": "Allow",
                "priority": 100
            },
            {
                "id": "file:delete",
                "name": "Block deletes",
                "policy_type": "Deny",
                "priority": 200
            },
            {
                "id": "network:*",
                "name": "Network approval required",
                "policy_type": {"Conditional": {"conditions": {"require_approval": true}}},
                "priority": 150
            }
        ]);

        let policies: Vec<Policy> = serde_json::from_value(config_json).unwrap();
        assert_eq!(policies.len(), 3);

        // Evaluate and audit a series of actions
        let actions_and_expected: Vec<(Action, &str)> = vec![
            (
                Action {
                    tool: "file".into(),
                    function: "read".into(),
                    parameters: json!({}),
                },
                "allow",
            ),
            (
                Action {
                    tool: "file".into(),
                    function: "delete".into(),
                    parameters: json!({}),
                },
                "deny",
            ),
            (
                Action {
                    tool: "network".into(),
                    function: "http_get".into(),
                    parameters: json!({}),
                },
                "approval",
            ),
        ];

        for (action, expected_type) in &actions_and_expected {
            let verdict = engine.evaluate_action(action, &policies).unwrap();
            match *expected_type {
                "allow" => assert_eq!(verdict, Verdict::Allow),
                "deny" => assert!(matches!(verdict, Verdict::Deny { .. })),
                "approval" => assert!(matches!(verdict, Verdict::RequireApproval { .. })),
                _ => panic!("unknown expected type"),
            }
            logger
                .log_entry(action, &verdict, json!({"source": "config_test"}))
                .await
                .unwrap();
        }

        // Verify complete audit trail
        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 3);
        assert_eq!(report.allow_count, 1);
        assert_eq!(report.deny_count, 1);
        assert_eq!(report.require_approval_count, 1);

        // Verify entries contain metadata
        for entry in &report.entries {
            assert_eq!(entry.metadata["source"], "config_test");
        }
    });
}

#[test]
fn empty_config_means_fail_closed() {
    let engine = PolicyEngine::new(false);
    let policies: Vec<Policy> = serde_json::from_value(json!([])).unwrap();

    let action = Action {
        tool: "anything".into(),
        function: "anything".into(),
        parameters: json!({}),
    };

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Empty config must fail closed"
    );
}

#[test]
fn config_priority_ordering_matches_engine_behavior() {
    let engine = PolicyEngine::new(false);

    // Two conflicting policies from "config" — higher priority wins
    let policies: Vec<Policy> = serde_json::from_value(json!([
        {"id": "*", "name": "Low-pri allow", "policy_type": "Allow", "priority": 1},
        {"id": "bash:*", "name": "High-pri deny bash", "policy_type": "Deny", "priority": 500}
    ]))
    .unwrap();

    let bash_action = Action {
        tool: "bash".into(),
        function: "exec".into(),
        parameters: json!({}),
    };
    assert!(matches!(
        engine.evaluate_action(&bash_action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));

    // Non-bash action should still be allowed
    let safe_action = Action {
        tool: "git".into(),
        function: "status".into(),
        parameters: json!({}),
    };
    assert_eq!(
        engine.evaluate_action(&safe_action, &policies).unwrap(),
        Verdict::Allow
    );
}

// ═════════════════════════════════════════════════
// MULTIPLE AUDIT LOG FILES
// ═════════════════════════════════════════════════

#[test]
fn separate_audit_logs_for_different_contexts() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let engine = PolicyEngine::new(false);

        let prod_logger = AuditLogger::new(tmp.path().join("prod_audit.log"));
        let dev_logger = AuditLogger::new(tmp.path().join("dev_audit.log"));

        let prod_policies = vec![Policy {
            id: "*".into(),
            name: "Deny all in prod".into(),
            policy_type: PolicyType::Deny,
            priority: 1000,
        }];
        let dev_policies = vec![Policy {
            id: "*".into(),
            name: "Allow all in dev".into(),
            policy_type: PolicyType::Allow,
            priority: 1,
        }];

        let action = Action {
            tool: "bash".into(),
            function: "exec".into(),
            parameters: json!({}),
        };

        let prod_verdict = engine.evaluate_action(&action, &prod_policies).unwrap();
        let dev_verdict = engine.evaluate_action(&action, &dev_policies).unwrap();

        prod_logger
            .log_entry(&action, &prod_verdict, json!({"env": "prod"}))
            .await
            .unwrap();
        dev_logger
            .log_entry(&action, &dev_verdict, json!({"env": "dev"}))
            .await
            .unwrap();

        let prod_report = prod_logger.generate_report().await.unwrap();
        let dev_report = dev_logger.generate_report().await.unwrap();

        assert_eq!(prod_report.deny_count, 1);
        assert_eq!(prod_report.allow_count, 0);
        assert_eq!(dev_report.allow_count, 1);
        assert_eq!(dev_report.deny_count, 0);
    });
}
