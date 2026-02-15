//! Verifies that every verdict the engine produces is faithfully recorded
//! in the audit log, and that report statistics stay consistent under
//! various policy configurations.

use serde_json::json;
use tempfile::TempDir;
use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

fn setup_logger() -> (AuditLogger, TempDir) {
    let tmp = TempDir::new().unwrap();
    let logger = AuditLogger::new(tmp.path().join("audit.log"));
    (logger, tmp)
}

// ═════════════════════════════════════════════
// ENGINE VERDICTS ARE FAITHFULLY AUDITED
// ═════════════════════════════════════════════

#[test]
fn all_three_verdict_types_are_logged_and_counted() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let (logger, _tmp) = setup_logger();

        let policies = vec![
            Policy {
                id: "file:read".to_string(),
                name: "Allow reads".to_string(),
                policy_type: PolicyType::Allow,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "file:delete".to_string(),
                name: "Block deletes".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "shell:*".to_string(),
                name: "Approve shell".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({ "require_approval": true }),
                },
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
        ];

        let actions_and_expected: Vec<(Action, &str)> = vec![
            (make_action("file", "read", json!({})), "Allow"),
            (make_action("file", "delete", json!({})), "Deny"),
            (make_action("shell", "bash", json!({})), "RequireApproval"),
        ];

        for (action, expected_tag) in &actions_and_expected {
            let verdict = engine.evaluate_action(action, &policies).unwrap();
            // Verify verdict type matches expectation
            let tag = match &verdict {
                Verdict::Allow => "Allow",
                Verdict::Deny { .. } => "Deny",
                Verdict::RequireApproval { .. } => "RequireApproval",
                // Handle future variants
                _ => "Unknown",
            };
            assert_eq!(tag, *expected_tag, "Wrong verdict for {:?}", action);

            logger.log_entry(action, &verdict, json!({})).await.unwrap();
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 3);
        assert_eq!(report.allow_count, 1);
        assert_eq!(report.deny_count, 1);
        assert_eq!(report.require_approval_count, 1);
        assert_eq!(
            report.allow_count + report.deny_count + report.require_approval_count,
            report.total_entries
        );
    });
}

#[test]
fn bulk_allow_verdicts_counted_correctly() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let (logger, _tmp) = setup_logger();

        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 1,
            path_rules: None,
            network_rules: None,
        }];

        for i in 0..50 {
            let action = make_action("tool", &format!("func_{}", i), json!({}));
            let verdict = engine.evaluate_action(&action, &policies).unwrap();
            assert!(matches!(verdict, Verdict::Allow));
            logger
                .log_entry(&action, &verdict, json!({}))
                .await
                .unwrap();
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 50);
        assert_eq!(report.allow_count, 50);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 0);
    });
}

#[test]
fn bulk_deny_verdicts_from_empty_policies() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let (logger, _tmp) = setup_logger();

        // Empty policy set -> all denied
        let policies: Vec<Policy> = vec![];

        for i in 0..20 {
            let action = make_action("t", &format!("f_{}", i), json!({}));
            let verdict = engine.evaluate_action(&action, &policies).unwrap();
            assert!(matches!(verdict, Verdict::Deny { .. }));
            logger
                .log_entry(&action, &verdict, json!({}))
                .await
                .unwrap();
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 20);
        assert_eq!(report.deny_count, 20);
        assert_eq!(report.allow_count, 0);
    });
}

#[test]
fn metadata_survives_roundtrip_through_audit() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("file", "read", json!({"path": "/etc/passwd"}));

        let metadata = json!({
            "user": "admin",
            "session_id": "abc-123",
            "tags": ["sensitive", "audit-required"],
            "nested": {"depth": 1}
        });

        logger
            .log_entry(&action, &Verdict::Allow, metadata.clone())
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata, metadata);
        assert_eq!(entries[0].metadata["user"], "admin");
        assert_eq!(entries[0].metadata["tags"][0], "sensitive");
        assert_eq!(entries[0].metadata["nested"]["depth"], 1);
    });
}

#[test]
fn action_fields_survive_roundtrip_through_audit() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action(
            "file_system",
            "read_file",
            json!({"path": "/tmp/test.txt", "encoding": "utf-8"}),
        );

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.tool, "file_system");
        assert_eq!(entries[0].action.function, "read_file");
        assert_eq!(entries[0].action.parameters["path"], "/tmp/test.txt");
        assert_eq!(entries[0].action.parameters["encoding"], "utf-8");
    });
}

#[test]
fn verdict_reason_strings_survive_roundtrip() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("t", "f", json!({}));

        let deny_reason = "Denied by policy 'Block bash'";
        let approval_reason = "Approval required by policy 'Shell guard'";

        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: deny_reason.to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        logger
            .log_entry(
                &action,
                &Verdict::RequireApproval {
                    reason: approval_reason.to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 2);

        match &entries[0].verdict {
            Verdict::Deny { reason } => assert_eq!(reason, deny_reason),
            other => panic!("Expected Deny, got {:?}", other),
        }
        match &entries[1].verdict {
            Verdict::RequireApproval { reason } => assert_eq!(reason, approval_reason),
            other => panic!("Expected RequireApproval, got {:?}", other),
        }
    });
}

#[test]
fn report_invariant_counts_equal_entries_length() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let (logger, _tmp) = setup_logger();

        let policies = vec![
            Policy {
                id: "a:*".to_string(),
                name: "Allow A".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "b:*".to_string(),
                name: "Deny B".to_string(),
                policy_type: PolicyType::Deny,
                priority: 10,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "c:*".to_string(),
                name: "Approve C".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({ "require_approval": true }),
                },
                priority: 10,
                path_rules: None,
                network_rules: None,
            },
        ];

        // Log actions hitting each policy multiple times
        let combos: Vec<(&str, &str)> = vec![
            ("a", "x"),
            ("a", "y"),
            ("a", "z"),
            ("b", "x"),
            ("b", "y"),
            ("c", "x"),
            ("c", "y"),
            ("c", "z"),
            ("c", "w"),
        ];

        for (tool, func) in &combos {
            let action = make_action(tool, func, json!({}));
            let verdict = engine.evaluate_action(&action, &policies).unwrap();
            logger
                .log_entry(&action, &verdict, json!({}))
                .await
                .unwrap();
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, combos.len());
        assert_eq!(
            report.allow_count + report.deny_count + report.require_approval_count,
            report.total_entries,
            "Sum of verdict counts must equal total_entries"
        );
        assert_eq!(report.allow_count, 3); // a:x, a:y, a:z
        assert_eq!(report.deny_count, 2); // b:x, b:y
        assert_eq!(report.require_approval_count, 4); // c:x, c:y, c:z, c:w
        assert_eq!(report.entries.len(), report.total_entries);
    });
}
