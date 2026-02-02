//! Full pipeline integration tests against the REAL workspace API.
//! Uses manual tokio runtime to avoid needing tokio/macros.

use sentinel_engine::PolicyEngine;
use sentinel_audit::AuditLogger;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use tempfile::TempDir;
use serde_json::json;

fn make_action(tool: &str, function: &str) -> Action {
    Action {
        tool: tool.to_string(),
        function: function.to_string(),
        parameters: json!({}),
    }
}

fn allow_policy(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Allow,
        priority,
    }
}

fn deny_policy(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Deny,
        priority,
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

// ════════════════════════════════════════════════
// PIPELINE: EVALUATE → LOG → LOAD → VERIFY
// ═════════════════════════════════════════════════

#[test]
fn test_allow_pipeline() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let action = make_action("file", "read");
        let policies = vec![allow_policy("file:read", "Allow reads", 0)];

        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));

        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        logger.log_entry(&action, &verdict, json!({})).await.unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
    });
}

#[test]
fn test_deny_pipeline() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let action = make_action("file", "delete");
        let policies = vec![deny_policy("file:delete", "Block deletes", 0)];

        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));

        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        logger.log_entry(&action, &verdict, json!({})).await.unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
    });
}

#[test]
fn test_deny_overrides_allow_pipeline() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let action = make_action("file", "write");
        let policies = vec![
            allow_policy("file:write", "Allow writes", 0),
            deny_policy("file:write", "Deny writes", 0),
        ];

        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "deny should override allow, got {:?}", verdict
        );

        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        logger.log_entry(&action, &verdict, json!({})).await.unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
    });
}

#[test]
fn test_strict_mode_unmatched_denies_and_audits() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(true);
        let action = make_action("network", "connect");
        let policies = vec![allow_policy("file:read", "Only file reads", 0)];

        let result = engine.evaluate_action(&action, &policies);

        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        match result {
            Ok(verdict) => {
                assert!(
                    !matches!(verdict, Verdict::Allow),
                    "strict mode must not allow unmatched actions"
                );
                logger.log_entry(&action, &verdict, json!({})).await.unwrap();
            }
            Err(e) => {
                let deny = Verdict::Deny { reason: format!("engine error: {}", e) };
                logger.log_entry(&action, &deny, json!({})).await.unwrap();
            }
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
    });
}

#[test]
fn test_full_pipeline_report_generation() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let policies = vec![
            allow_policy("file:read", "Allow reads", 0),
            deny_policy("file:delete", "Deny deletes", 10),
        ];

        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let test_actions = vec![
            ("file", "read"),
            ("file", "delete"),
            ("file", "read"),
            ("file", "read"),
            ("file", "delete"),
        ];

        for (tool, func) in &test_actions {
            let action = make_action(tool, func);
            let verdict = engine.evaluate_action(&action, &policies).unwrap();
            logger.log_entry(&action, &verdict, json!({})).await.unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 5);

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 5, "report should have 5 entries");
        assert!(report.allow_count > 0, "should have some allows");
        assert!(report.deny_count > 0, "should have some denies");
    });
}

// ════════════════════════════════════════════════
// ADVERSARIAL: TRY TO BREAK THE PIPELINE
// ═════════════════════════════════════════════════

#[test]
fn test_pipeline_with_empty_policies() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let action = make_action("any", "thing");

        let result = engine.evaluate_action(&action, &[]);
        assert!(result.is_ok(), "empty policies should not error");

        let verdict = result.unwrap();
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        logger.log_entry(&action, &verdict, json!({})).await.unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1, "default verdict should be loggable");
    });
}

#[test]
fn test_pipeline_concurrent_evaluations_and_logging() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let policies = vec![allow_policy("file:read", "Allow", 0)];
        let tmp = TempDir::new().unwrap();
        let logger = std::sync::Arc::new(AuditLogger::new(tmp.path().join("audit.log")));

        let mut handles = vec![];
        for i in 0..20 {
            let logger_clone = logger.clone();
            let policies_clone = policies.clone();
            handles.push(tokio::spawn(async move {
                let engine = PolicyEngine::new(false);
                let action = make_action("file", &format!("read_{}", i));
                let verdict = engine.evaluate_action(&action, &policies_clone).unwrap();
                logger_clone.log_entry(&action, &verdict, json!({})).await.unwrap();
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 20, "all 20 concurrent entries should persist");
    });
}
