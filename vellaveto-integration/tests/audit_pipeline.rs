// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Audit-focused integration tests.
//! Tests AuditLogger with realistic engine outputs.

use serde_json::json;
use tempfile::TempDir;
use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn make_action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
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

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

// ═════════════════════════════════════════════════
// AUDIT HAPPY PATH
// ═════════════════════════════════════════════════

#[test]
fn test_log_and_load_single_entry() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action("file", "read");
        let verdict = Verdict::Allow;

        logger
            .log_entry(&action, &verdict, json!({}))
            .await
            .unwrap();
        let entries = logger.load_entries().await.unwrap();

        assert_eq!(entries.len(), 1, "should have exactly one entry");
    });
}

#[test]
fn test_log_mixed_verdicts() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        for i in 0..10 {
            let action = make_action("tool", &format!("func_{}", i));
            let verdict = if i % 2 == 0 {
                Verdict::Allow
            } else {
                Verdict::Deny {
                    reason: format!("denied action {}", i),
                }
            };
            logger
                .log_entry(&action, &verdict, json!({}))
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 10, "should have 10 entries");
    });
}

#[test]
fn test_report_generation_with_mixed_verdicts() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let policies = vec![
            allow_policy("file:read", "Allow reads", 0),
            deny_policy("file:delete", "Deny deletes", 10),
        ];

        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let actions = vec![
            make_action("file", "read"),
            make_action("file", "delete"),
            make_action("file", "read"),
            make_action("file", "delete"),
        ];

        for action in &actions {
            let verdict = engine.evaluate_action(action, &policies).unwrap();
            logger.log_entry(action, &verdict, json!({})).await.unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 4);

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 4, "report should have 4 entries");
    });
}

#[test]
fn test_log_entry_with_metadata() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action("database", "query");
        let verdict = Verdict::Allow;

        let metadata = json!({
            "engine_mode": "non-strict",
            "policy_count": 3,
            "source": "integration_test",
        });

        logger.log_entry(&action, &verdict, metadata).await.unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
    });
}

// ═════════════════════════════════════════════════
// AUDIT EDGE CASES
// ═════════════════════════════════════════════════

#[test]
fn test_load_entries_from_empty_log() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 0, "fresh logger should have zero entries");
    });
}

#[test]
fn test_report_on_empty_log() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let report = logger.generate_report().await.unwrap();
        assert_eq!(
            report.total_entries, 0,
            "empty log should have zero entries"
        );
    });
}

#[test]
fn test_separate_loggers_independent() {
    let rt = runtime();
    rt.block_on(async {
        let tmp1 = TempDir::new().unwrap();
        let tmp2 = TempDir::new().unwrap();
        let logger1 = AuditLogger::new(tmp1.path().join("audit.log"));
        let logger2 = AuditLogger::new(tmp2.path().join("audit.log"));

        let action = make_action("file", "read");
        let verdict = Verdict::Allow;

        logger1
            .log_entry(&action, &verdict, json!({}))
            .await
            .unwrap();
        logger1
            .log_entry(&action, &verdict, json!({}))
            .await
            .unwrap();
        logger2
            .log_entry(&action, &verdict, json!({}))
            .await
            .unwrap();

        let entries1 = logger1.load_entries().await.unwrap();
        let entries2 = logger2.load_entries().await.unwrap();

        assert_eq!(entries1.len(), 2, "logger1 should have 2 entries");
        assert_eq!(entries2.len(), 1, "logger2 should have 1 entry");
    });
}
