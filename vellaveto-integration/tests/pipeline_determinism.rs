// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests that the full pipeline (engine + audit) produces deterministic,
//! reproducible results when given the same inputs.

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

fn build_policy_set() -> Vec<Policy> {
    vec![
        Policy {
            id: "file:read".to_string(),
            name: "Allow file reads".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "file:delete".to_string(),
            name: "Block file deletes".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "shell:*".to_string(),
            name: "Shell requires approval".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "api:*".to_string(),
            name: "API needs auth".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"required_parameters": ["auth_token"]}),
            },
            priority: 30,
            path_rules: None,
            network_rules: None,
        },
    ]
}

fn build_test_actions() -> Vec<Action> {
    vec![
        make_action("file", "read", json!({"path": "/tmp/data.txt"})),
        make_action("file", "delete", json!({"path": "/etc/passwd"})),
        make_action("shell", "exec", json!({"cmd": "ls"})),
        make_action("api", "call", json!({"auth_token": "abc"})),
        make_action("api", "call", json!({"endpoint": "/data"})),
        make_action("unknown", "something", json!({})),
    ]
}

// ════════════════════════════════════════════
// DETERMINISM
// ════════════════════════════════════════════

#[test]
fn engine_produces_same_verdict_on_repeated_calls() {
    let engine = PolicyEngine::new(false);
    let policies = build_policy_set();
    let actions = build_test_actions();

    for action in &actions {
        let v1 = engine.evaluate_action(action, &policies).unwrap();
        let v2 = engine.evaluate_action(action, &policies).unwrap();
        assert_eq!(v1, v2, "engine must be deterministic for action {action:?}");
    }
}

#[test]
fn policy_order_in_input_does_not_affect_verdict() {
    let engine = PolicyEngine::new(false);
    let mut policies = build_policy_set();
    let actions = build_test_actions();

    // Collect verdicts with original order
    let verdicts_original: Vec<Verdict> = actions
        .iter()
        .map(|a| engine.evaluate_action(a, &policies).unwrap())
        .collect();

    // Reverse the policy order
    policies.reverse();

    let verdicts_reversed: Vec<Verdict> = actions
        .iter()
        .map(|a| engine.evaluate_action(a, &policies).unwrap())
        .collect();

    assert_eq!(
        verdicts_original, verdicts_reversed,
        "policy input order must not affect verdicts (engine sorts by priority)"
    );
}

#[test]
fn strict_mode_flag_does_not_change_basic_verdicts() {
    // strict_mode is stored but not used to change basic evaluation logic
    let engine_lax = PolicyEngine::new(false);
    let engine_strict = PolicyEngine::new(true);
    let policies = build_policy_set();
    let actions = build_test_actions();

    for action in &actions {
        let v_lax = engine_lax.evaluate_action(action, &policies).unwrap();
        let v_strict = engine_strict.evaluate_action(action, &policies).unwrap();
        assert_eq!(
            v_lax, v_strict,
            "strict_mode should not change basic verdict for {action:?}"
        );
    }
}

// ════════════════════════════════════════════
// AUDIT PIPELINE DETERMINISM
// ═══════════════════════════════════════════

#[test]
fn audit_entries_match_engine_verdicts() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let policies = build_policy_set();
        let actions = build_test_actions();
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let mut expected_verdicts = Vec::new();
        for action in &actions {
            let verdict = engine.evaluate_action(action, &policies).unwrap();
            logger.log_entry(action, &verdict, json!({})).await.unwrap();
            expected_verdicts.push(verdict);
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), expected_verdicts.len());

        for (entry, expected) in entries.iter().zip(expected_verdicts.iter()) {
            assert_eq!(
                &entry.verdict, expected,
                "audit entry verdict must match engine output"
            );
        }
    });
}

#[test]
fn audit_report_consistent_with_engine_output() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let policies = build_policy_set();
        let actions = build_test_actions();
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let mut allow_count = 0;
        let mut deny_count = 0;
        let mut approval_count = 0;

        for action in &actions {
            let verdict = engine.evaluate_action(action, &policies).unwrap();
            match &verdict {
                Verdict::Allow => allow_count += 1,
                Verdict::Deny { .. } => deny_count += 1,
                Verdict::RequireApproval { .. } => approval_count += 1,
                // Handle future variants - count as deny
                _ => deny_count += 1,
            }
            logger.log_entry(action, &verdict, json!({})).await.unwrap();
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, actions.len());
        assert_eq!(report.allow_count, allow_count);
        assert_eq!(report.deny_count, deny_count);
        assert_eq!(report.require_approval_count, approval_count);
    });
}

// ═══════════════════════════════════════════
// INDEPENDENT LOGGER INSTANCES
// ═══════════════════════════════════════════

#[test]
fn two_loggers_same_file_see_each_others_entries() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("shared.log");
        let logger1 = AuditLogger::new(path.clone());
        let logger2 = AuditLogger::new(path);
        let action = make_action("t", "f", json!({}));

        logger1
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger2
            .log_entry(&action, &Verdict::Deny { reason: "r".into() }, json!({}))
            .await
            .unwrap();

        // Both should see 2 entries
        let entries1 = logger1.load_entries().await.unwrap();
        let entries2 = logger2.load_entries().await.unwrap();
        assert_eq!(entries1.len(), 2);
        assert_eq!(entries2.len(), 2);
    });
}
