// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Integration tests: evaluate canonical policies through the engine
//! and verify the full pipeline from policy definition → verdict → audit.

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

fn conditional_policy(
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

// ═════════════════════════════════════════════════
// CANONICAL DENY-ALL / ALLOW-ALL
// ═════════════════════════════════════════════════

#[test]
fn deny_all_blocks_every_action() {
    let engine = PolicyEngine::new(false);
    let deny_all = deny_policy("*", "Deny All", 1000);

    let actions = vec![
        make_action("bash", "execute", json!({"cmd": "ls"})),
        make_action("file", "read", json!({"path": "/etc/passwd"})),
        make_action("network", "fetch", json!({"url": "https://example.com"})),
        make_action("database", "query", json!({"sql": "SELECT 1"})),
    ];

    for action in &actions {
        let verdict = engine
            .evaluate_action(action, std::slice::from_ref(&deny_all))
            .unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "deny-all should block {:?}, got {:?}",
            action.tool,
            verdict
        );
    }
}

#[test]
fn allow_all_permits_every_action() {
    let engine = PolicyEngine::new(false);
    let allow_all = allow_policy("*", "Allow All", 1);

    let actions = vec![
        make_action("bash", "execute", json!({})),
        make_action("file", "write", json!({})),
        make_action("network", "post", json!({})),
    ];

    for action in &actions {
        let verdict = engine
            .evaluate_action(action, std::slice::from_ref(&allow_all))
            .unwrap();
        assert_eq!(
            verdict,
            Verdict::Allow,
            "allow-all should permit {:?}",
            action.tool
        );
    }
}

// ════════════════════════════════════════════════
// LAYERED POLICY: deny-all base + selective allow
// ════════════════════════════════════════════════

#[test]
fn selective_allow_overrides_lower_priority_deny() {
    let engine = PolicyEngine::new(false);
    let policies = vec![
        deny_policy("*", "Deny All", 1),
        allow_policy("file:read", "Allow file reads", 100),
    ];

    // file:read should be allowed (priority 100 > 1)
    let read = make_action("file", "read", json!({}));
    assert_eq!(
        engine.evaluate_action(&read, &policies).unwrap(),
        Verdict::Allow
    );

    // file:write should be denied (only wildcard matches, priority 1)
    let write = make_action("file", "write", json!({}));
    assert!(matches!(
        engine.evaluate_action(&write, &policies).unwrap(),
        Verdict::Deny { .. }
    ));
}

#[test]
fn deny_overrides_allow_at_higher_priority() {
    let engine = PolicyEngine::new(false);
    let policies = vec![
        allow_policy("*", "Allow All", 1),
        deny_policy("bash:*", "Block bash", 500),
    ];

    let bash_action = make_action("bash", "execute", json!({}));
    assert!(matches!(
        engine.evaluate_action(&bash_action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));

    let file_action = make_action("file", "read", json!({}));
    assert_eq!(
        engine.evaluate_action(&file_action, &policies).unwrap(),
        Verdict::Allow
    );
}

// ═════════════════════════════════════════════════
// CONDITIONAL + AUDIT PIPELINE
// ════════════════════════════════════════════════

#[test]
fn conditional_forbidden_param_through_full_pipeline() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let policies = vec![
            conditional_policy(
                "bash:*",
                "Dangerous bash",
                100,
                json!({
                    "forbidden_parameters": ["force", "recursive"]
                }),
            ),
            allow_policy("*", "Default allow", 1),
        ];

        // Action with forbidden param → Deny
        let dangerous = make_action("bash", "execute", json!({"force": true, "cmd": "rm"}));
        let verdict = engine.evaluate_action(&dangerous, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
        logger
            .log_entry(&dangerous, &verdict, json!({"test": "forbidden_param"}))
            .await
            .unwrap();

        // Action without forbidden param → Allow (conditional doesn't trigger)
        let safe = make_action("bash", "execute", json!({"cmd": "ls"}));
        let verdict = engine.evaluate_action(&safe, &policies).unwrap();
        assert_eq!(verdict, Verdict::Allow);
        logger
            .log_entry(&safe, &verdict, json!({"test": "safe_param"}))
            .await
            .unwrap();

        // Verify audit trail
        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 2);
        assert_eq!(report.deny_count, 1);
        assert_eq!(report.allow_count, 1);
    });
}

#[test]
fn require_approval_logged_correctly() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let policies = vec![conditional_policy(
            "network:*",
            "Network needs approval",
            200,
            json!({"require_approval": true}),
        )];

        let action = make_action("network", "fetch", json!({"url": "https://evil.com"}));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::RequireApproval { .. }));

        logger
            .log_entry(&action, &verdict, json!({}))
            .await
            .unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.require_approval_count, 1);
        assert_eq!(report.total_entries, 1);
    });
}

// ═════════════════════════════════════════════════
// EQUAL-PRIORITY DENY-OVERRIDES BEHAVIOR
// ════════════════════════════════════════════════

#[test]
fn equal_priority_deny_wins_over_allow() {
    let engine = PolicyEngine::new(false);
    let policies = vec![
        allow_policy("*", "Allow all", 50),
        deny_policy("*", "Deny all", 50),
    ];

    let action = make_action("anything", "anything", json!({}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    // The engine sorts deny before allow at equal priority
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "At equal priority, deny should override allow"
    );
}

// ═════════════════════════════════════════════════
// MULTI-LAYER COMPLEX SCENARIO
// ═════════════════════════════════════════════════

#[test]
fn complex_layered_policy_scenario() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        // Layered policies simulating a real deployment:
        // 1. Base: deny everything (priority 1)
        // 2. Allow safe dev tools (priority 100)
        // 3. Require approval for network (priority 200)
        // 4. Hard-deny system commands (priority 900)
        let policies = vec![
            deny_policy("*", "Default deny", 1),
            allow_policy("file:read", "Allow reads", 100),
            allow_policy("git:*", "Allow git", 100),
            conditional_policy(
                "network:*",
                "Network approval",
                200,
                json!({"require_approval": true}),
            ),
            deny_policy("system:*", "Block system", 900),
        ];

        #[allow(clippy::type_complexity)]
        let test_cases: Vec<(&str, &str, Box<dyn Fn(&Verdict) -> bool>)> = vec![
            ("file", "read", Box::new(|v| *v == Verdict::Allow)),
            (
                "file",
                "write",
                Box::new(|v| matches!(v, Verdict::Deny { .. })),
            ),
            ("git", "commit", Box::new(|v| *v == Verdict::Allow)),
            ("git", "push", Box::new(|v| *v == Verdict::Allow)),
            (
                "network",
                "fetch",
                Box::new(|v| matches!(v, Verdict::RequireApproval { .. })),
            ),
            (
                "system",
                "exec",
                Box::new(|v| matches!(v, Verdict::Deny { .. })),
            ),
            (
                "unknown",
                "thing",
                Box::new(|v| matches!(v, Verdict::Deny { .. })),
            ),
        ];

        for (tool, func, check) in &test_cases {
            let action = make_action(tool, func, json!({}));
            let verdict = engine.evaluate_action(&action, &policies).unwrap();
            assert!(
                check(&verdict),
                "{}:{} produced unexpected verdict: {:?}",
                tool,
                func,
                verdict
            );
            logger
                .log_entry(&action, &verdict, json!({"tool": tool, "func": func}))
                .await
                .unwrap();
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 7);
        // file:read + git:commit + git:push = 3 allows
        assert_eq!(report.allow_count, 3);
        // file:write + system:exec + unknown:thing = 3 denies
        assert_eq!(report.deny_count, 3);
        // network:fetch = 1 require_approval
        assert_eq!(report.require_approval_count, 1);
    });
}
