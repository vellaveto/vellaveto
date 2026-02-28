// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests the complete pipeline from JSON config → Policy deserialization
//! → engine evaluation → audit logging → report generation.
//! Simulates what a real deployment would do without needing vellaveto-config
//! as a direct dependency.

use serde_json::json;
use tempfile::TempDir;
use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, Verdict};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

/// Deserialize policies from a JSON array, exactly as vellaveto-config would.
fn policies_from_json(json_val: serde_json::Value) -> Vec<Policy> {
    serde_json::from_value(json_val).expect("policy deserialization failed")
}

// ═══════════════════════════════════════════
// BASIC CONFIG → ENGINE → AUDIT PIPELINE
// ═══════════════════════════════════════════

#[test]
fn basic_config_to_audit_pipeline() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let config = json!([
            {"id": "file:read", "name": "Allow reads", "policy_type": "Allow", "priority": 10},
            {"id": "file:write", "name": "Allow writes", "policy_type": "Allow", "priority": 10},
            {"id": "file:delete", "name": "Block deletes", "policy_type": "Deny", "priority": 100},
            {"id": "*", "name": "Default deny", "policy_type": "Deny", "priority": -1}
        ]);
        let policies = policies_from_json(config);

        let scenarios = vec![
            (make_action("file", "read", json!({})), true), // allowed
            (make_action("file", "write", json!({})), true), // allowed
            (make_action("file", "delete", json!({})), false), // denied
            (make_action("network", "fetch", json!({})), false), // default deny
        ];

        for (action, should_allow) in &scenarios {
            let verdict = engine.evaluate_action(action, &policies).unwrap();
            logger.log_entry(action, &verdict, json!({})).await.unwrap();

            match (&verdict, should_allow) {
                (Verdict::Allow, true) => {}
                (Verdict::Deny { .. }, false) => {}
                _ => panic!(
                    "Action {}:{} expected allow={}, got {:?}",
                    action.tool, action.function, should_allow, verdict
                ),
            }
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 4);
        assert_eq!(report.allow_count, 2);
        assert_eq!(report.deny_count, 2);
        assert_eq!(report.require_approval_count, 0);
    });
}

// ═══════════════════════════════════════════
// CONDITIONAL CONFIG PIPELINE
// ════════════════════════════════════════════

#[test]
fn conditional_config_pipeline() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let config = json!([
            {
                "id": "*",
                "name": "Require approval for dangerous ops",
                "policy_type": {
                    "Conditional": {
                        "conditions": {
                            "forbidden_parameters": ["force", "no_verify"],
                            "require_approval": false
                        }
                    }
                },
                "priority": 50
            },
            {
                "id": "*",
                "name": "Default allow",
                "policy_type": "Allow",
                "priority": 1
            }
        ]);
        let policies = policies_from_json(config);

        // Safe action → conditional allows (no forbidden params), then Allow
        let safe = make_action("deploy", "run", json!({"env": "staging"}));
        let v = engine.evaluate_action(&safe, &policies).unwrap();
        logger.log_entry(&safe, &v, json!({})).await.unwrap();
        assert_eq!(v, Verdict::Allow);

        // Dangerous action → conditional denies (has "force" param)
        let dangerous = make_action("deploy", "run", json!({"force": true}));
        let v = engine.evaluate_action(&dangerous, &policies).unwrap();
        logger.log_entry(&dangerous, &v, json!({})).await.unwrap();
        match &v {
            Verdict::Deny { reason } => {
                assert!(reason.contains("force"), "Should mention forbidden param");
            }
            other => panic!("Expected Deny for 'force' param, got {:?}", other),
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 2);
        assert_eq!(report.allow_count, 1);
        assert_eq!(report.deny_count, 1);
    });
}

// ═══════════════════════════════════════════
// MULTIPLE CONDITIONAL POLICIES FROM CONFIG
// ═══════════════════════════════════════════

#[test]
fn layered_conditional_config() {
    let engine = PolicyEngine::new(false);

    let config = json!([
        {
            "id": "shell:*",
            "name": "Shell needs approval",
            "policy_type": {"Conditional": {"conditions": {"require_approval": true}}},
            "priority": 100
        },
        {
            "id": "file:delete",
            "name": "Block file delete",
            "policy_type": "Deny",
            "priority": 90
        },
        {
            "id": "file:*",
            "name": "Allow file ops",
            "policy_type": "Allow",
            "priority": 50
        },
        {
            "id": "*",
            "name": "Default deny",
            "policy_type": "Deny",
            "priority": 0
        }
    ]);
    let policies = policies_from_json(config);

    // shell:exec → RequireApproval (priority 100)
    match engine
        .evaluate_action(&make_action("shell", "exec", json!({})), &policies)
        .unwrap()
    {
        Verdict::RequireApproval { .. } => {}
        other => panic!("shell:exec should require approval, got {:?}", other),
    }

    // file:read → Allow (priority 50, "file:*" matches)
    assert_eq!(
        engine
            .evaluate_action(&make_action("file", "read", json!({})), &policies,)
            .unwrap(),
        Verdict::Allow,
    );

    // file:delete  Deny (priority 90 beats Allow at 50)
    match engine
        .evaluate_action(&make_action("file", "delete", json!({})), &policies)
        .unwrap()
    {
        Verdict::Deny { .. } => {}
        other => panic!("file:delete should be denied, got {:?}", other),
    }

    // network:fetch  Default deny (priority 0)
    match engine
        .evaluate_action(&make_action("network", "fetch", json!({})), &policies)
        .unwrap()
    {
        Verdict::Deny { .. } => {}
        other => panic!("network:fetch should hit default deny, got {:?}", other),
    }
}

// ═══════════════════════════════════════════
// CONFIG WITH NEGATIVE PRIORITIES
// ═══════════════════════════════════════════

#[test]
fn config_with_negative_priorities() {
    let engine = PolicyEngine::new(false);

    let config = json!([
        {"id": "*", "name": "Absolute fallback allow", "policy_type": "Allow", "priority": -1000},
        {"id": "file:*", "name": "File deny", "policy_type": "Deny", "priority": -500},
        {"id": "file:read", "name": "Allow reads specifically", "policy_type": "Allow", "priority": -100}
    ]);
    let policies = policies_from_json(config);

    // file:read matches both "file:read"(-100) and "file:*"(-500) and "*"(-1000)
    // -100 > -500 > -1000, so Allow wins
    assert_eq!(
        engine
            .evaluate_action(&make_action("file", "read", json!({})), &policies,)
            .unwrap(),
        Verdict::Allow,
    );

    // file:write matches "file:*"(-500) and "*"(-1000)
    // -500 > -1000, so Deny wins
    match engine
        .evaluate_action(&make_action("file", "write", json!({})), &policies)
        .unwrap()
    {
        Verdict::Deny { .. } => {}
        other => panic!(
            "file:write should be denied at priority -500, got {:?}",
            other
        ),
    }

    // network:fetch matches only "*"(-1000) → Allow
    assert_eq!(
        engine
            .evaluate_action(&make_action("network", "fetch", json!({})), &policies,)
            .unwrap(),
        Verdict::Allow,
    );
}

// ═══════════════════════════════════════════
// MALFORMED CONFIG: DESERIALIZATION FAILURES
// ════════════════════════════════════════════

#[test]
fn config_missing_required_fields_fails() {
    // Missing "id" field
    let bad_config = json!([
        {"name": "No ID", "policy_type": "Allow", "priority": 10}
    ]);
    let result: Result<Vec<Policy>, _> = serde_json::from_value(bad_config);
    assert!(result.is_err());
}

#[test]
fn config_wrong_priority_type_fails() {
    // Priority as string instead of i32
    let bad_config = json!([
        {"id": "*", "name": "Bad priority", "policy_type": "Allow", "priority": "high"}
    ]);
    let result: Result<Vec<Policy>, _> = serde_json::from_value(bad_config);
    assert!(result.is_err());
}

#[test]
fn config_invalid_policy_type_fails() {
    let bad_config = json!([
        {"id": "*", "name": "Bad type", "policy_type": "Reject", "priority": 10}
    ]);
    let result: Result<Vec<Policy>, _> = serde_json::from_value(bad_config);
    assert!(result.is_err());
}

#[test]
fn config_empty_array_produces_no_policies() {
    let config = json!([]);
    let policies: Vec<Policy> = serde_json::from_value(config).unwrap();
    assert!(policies.is_empty());

    // Empty policies → engine returns Deny
    let engine = PolicyEngine::new(false);
    let action = make_action("any", "thing", json!({}));
    match engine.evaluate_action(&action, &policies).unwrap() {
        Verdict::Deny { reason } => {
            assert!(reason.contains("No policies"), "Should mention no policies");
        }
        other => panic!("Expected Deny for empty policies, got {:?}", other),
    }
}
