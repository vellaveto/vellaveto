//! End-to-end integration tests for the parameter constraints pipeline.
//!
//! Tests the full flow: TOML config → PolicyConfig → Policy vec → PolicyEngine
//! → evaluate_action with parameter_constraints → AuditLogger → verify_chain.

use vellaveto_audit::AuditLogger;
use vellaveto_config::PolicyConfig;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Verdict};
use serde_json::json;
use tempfile::TempDir;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

const TEST_POLICY_TOML: &str = include_str!("fixtures/test-policy.toml");

// ═══════════════════════════════════════
// CONFIG LOADING
// ═══════════════════════════════════════

#[test]
fn config_loads_from_toml_with_parameter_constraints() {
    let config = PolicyConfig::from_toml(TEST_POLICY_TOML).expect("test-policy.toml should parse");
    assert_eq!(config.policies.len(), 3);

    let policies = config.to_policies();
    assert_eq!(policies.len(), 3);

    // Verify the credential-blocking policy has parameter_constraints
    let creds = &policies[0];
    assert_eq!(creds.id, "file_system:read_file");
    assert_eq!(creds.priority, 200);
}

#[test]
fn config_loads_from_file_path() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("policy.toml");
    std::fs::write(&path, TEST_POLICY_TOML).unwrap();

    let config = PolicyConfig::load_file(path.to_str().unwrap()).expect("load_file should succeed");
    let policies = config.to_policies();
    assert_eq!(policies.len(), 3);
}

// ═══════════════════════════════════════
// PATH CONSTRAINT EVALUATION
// ═══════════════════════════════════════

#[test]
fn denies_aws_credential_access() {
    let config = PolicyConfig::from_toml(TEST_POLICY_TOML).unwrap();
    let policies = config.to_policies();
    let engine = PolicyEngine::new(false);

    let action = Action::new(
        "file_system",
        "read_file",
        json!({ "path": "/home/user/.aws/credentials" }),
    );

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Should deny AWS credential access, got: {:?}",
        verdict
    );
}

#[test]
fn denies_ssh_key_access() {
    let config = PolicyConfig::from_toml(TEST_POLICY_TOML).unwrap();
    let policies = config.to_policies();
    let engine = PolicyEngine::new(false);

    let action = Action::new(
        "file_system",
        "read_file",
        json!({ "path": "/home/user/.ssh/id_rsa" }),
    );

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Should deny SSH key access, got: {:?}",
        verdict
    );
}

#[test]
fn denies_etc_shadow_access() {
    let config = PolicyConfig::from_toml(TEST_POLICY_TOML).unwrap();
    let policies = config.to_policies();
    let engine = PolicyEngine::new(false);

    let action = Action::new("file_system", "read_file", json!({ "path": "/etc/shadow" }));

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Should deny /etc/shadow access, got: {:?}",
        verdict
    );
}

#[test]
fn allows_safe_file_read() {
    let config = PolicyConfig::from_toml(TEST_POLICY_TOML).unwrap();
    let policies = config.to_policies();
    let engine = PolicyEngine::new(false);

    let action = Action::new(
        "file_system",
        "read_file",
        json!({ "path": "/home/user/project/src/main.rs" }),
    );

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(verdict, Verdict::Allow, "Should allow safe path read");
}

#[test]
fn path_traversal_caught_after_config_load() {
    let config = PolicyConfig::from_toml(TEST_POLICY_TOML).unwrap();
    let policies = config.to_policies();
    let engine = PolicyEngine::new(false);

    // Attempt traversal to reach .aws from a different starting point
    let action = Action::new(
        "file_system",
        "read_file",
        json!({ "path": "/home/user/project/../../user/.aws/credentials" }),
    );

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Path traversal to .aws should be caught, got: {:?}",
        verdict
    );
}

// ═══════════════════════════════════════
// PATH ALLOWLIST (not_glob)
// ═══════════════════════════════════════

#[test]
fn write_to_allowed_path_succeeds() {
    let config = PolicyConfig::from_toml(TEST_POLICY_TOML).unwrap();
    let policies = config.to_policies();
    let engine = PolicyEngine::new(false);

    let action = Action::new(
        "file_system",
        "write_file",
        json!({ "path": "/home/user/project/output.txt" }),
    );

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        verdict,
        Verdict::Allow,
        "Write to allowed path should succeed"
    );
}

#[test]
fn write_to_disallowed_path_denied() {
    let config = PolicyConfig::from_toml(TEST_POLICY_TOML).unwrap();
    let policies = config.to_policies();
    let engine = PolicyEngine::new(false);

    let action = Action::new(
        "file_system",
        "write_file",
        json!({ "path": "/etc/passwd" }),
    );

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Write outside allowlist should be denied, got: {:?}",
        verdict
    );
}

// ═══════════════════════════════════════
// DOMAIN CONSTRAINT EVALUATION
// ═══════════════════════════════════════

#[test]
fn denies_unlisted_domain() {
    let config = PolicyConfig::from_toml(TEST_POLICY_TOML).unwrap();
    let policies = config.to_policies();
    let engine = PolicyEngine::new(false);

    let action = Action::new(
        "http_request",
        "get",
        json!({ "url": "https://evil.com/exfiltrate" }),
    );

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Request to unlisted domain should be denied, got: {:?}",
        verdict
    );
}

#[test]
fn allows_listed_domain() {
    let config = PolicyConfig::from_toml(TEST_POLICY_TOML).unwrap();
    let policies = config.to_policies();
    let engine = PolicyEngine::new(false);

    let action = Action::new(
        "http_request",
        "get",
        json!({ "url": "https://api.example.com/data" }),
    );

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        verdict,
        Verdict::Allow,
        "Request to listed domain should be allowed"
    );
}

#[test]
fn allows_wildcard_subdomain() {
    let config = PolicyConfig::from_toml(TEST_POLICY_TOML).unwrap();
    let policies = config.to_policies();
    let engine = PolicyEngine::new(false);

    let action = Action::new(
        "http_request",
        "post",
        json!({ "url": "https://staging.internal.dev/api" }),
    );

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        verdict,
        Verdict::Allow,
        "Request to wildcard-matched domain should be allowed"
    );
}

// ═══════════════════════════════════════
// AUDIT CHAIN INTEGRITY
// ═══════════════════════════════════════

#[test]
fn full_pipeline_with_audit_chain_verification() {
    let rt = runtime();
    rt.block_on(async {
        let config = PolicyConfig::from_toml(TEST_POLICY_TOML).unwrap();
        let policies = config.to_policies();
        let engine = PolicyEngine::new(false);

        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.jsonl"));

        // Evaluate several actions and log each verdict
        let test_cases = [
            (
                "file_system",
                "read_file",
                json!({"path": "/home/user/.aws/credentials"}),
            ),
            (
                "file_system",
                "read_file",
                json!({"path": "/home/user/project/main.rs"}),
            ),
            (
                "http_request",
                "get",
                json!({"url": "https://evil.com/steal"}),
            ),
            (
                "http_request",
                "get",
                json!({"url": "https://api.example.com/ok"}),
            ),
            (
                "file_system",
                "write_file",
                json!({"path": "/tmp/scratch.txt"}),
            ),
            (
                "file_system",
                "write_file",
                json!({"path": "/root/.bashrc"}),
            ),
        ];

        for (tool, function, params) in &test_cases {
            let action = Action::new(tool.to_string(), function.to_string(), params.clone());
            let verdict = engine.evaluate_action(&action, &policies).unwrap();
            logger
                .log_entry(&action, &verdict, json!({"test": true}))
                .await
                .unwrap();
        }

        // Verify audit chain integrity
        let verification = logger.verify_chain().await.unwrap();
        assert!(
            verification.valid,
            "Audit chain should be valid after logging"
        );
        assert_eq!(verification.entries_checked, 6);

        // Verify entry count and verdict distribution
        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 6);
        // Expected: deny, allow, deny, allow, allow, deny → 3 deny, 3 allow
        assert_eq!(report.allow_count, 3);
        assert_eq!(report.deny_count, 3);
    });
}

#[test]
fn audit_chain_survives_logger_restart() {
    let rt = runtime();
    rt.block_on(async {
        let config = PolicyConfig::from_toml(TEST_POLICY_TOML).unwrap();
        let policies = config.to_policies();
        let engine = PolicyEngine::new(false);

        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.jsonl");

        // First logger session: log 3 entries
        {
            let logger = AuditLogger::new(log_path.clone());
            for path in [
                "/home/user/project/a.rs",
                "/home/user/project/b.rs",
                "/tmp/c.txt",
            ] {
                let action = Action::new("file_system", "read_file", json!({"path": path}));
                let verdict = engine.evaluate_action(&action, &policies).unwrap();
                logger
                    .log_entry(&action, &verdict, json!({}))
                    .await
                    .unwrap();
            }
        }

        // Second logger session: resume chain and log more
        {
            let logger = AuditLogger::new(log_path.clone());
            logger.initialize_chain().await.unwrap();

            let action = Action::new(
                "file_system",
                "read_file",
                json!({"path": "/home/user/project/d.rs"}),
            );
            let verdict = engine.evaluate_action(&action, &policies).unwrap();
            logger
                .log_entry(&action, &verdict, json!({}))
                .await
                .unwrap();

            // Full chain (all 4 entries) should verify
            let verification = logger.verify_chain().await.unwrap();
            assert!(verification.valid, "Chain should be valid after restart");
            assert_eq!(verification.entries_checked, 4);
        }
    });
}

// ═══════════════════════════════════════
// MISSING PARAMETERS (fail-closed)
// ═══════════════════════════════════════

#[test]
fn missing_path_parameter_defaults_to_deny() {
    let config = PolicyConfig::from_toml(TEST_POLICY_TOML).unwrap();
    let policies = config.to_policies();
    let engine = PolicyEngine::new(false);

    // Action matches file_system:read_file but has no "path" parameter
    let action = Action::new("file_system", "read_file", json!({}));

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Missing path parameter should fail-closed to deny, got: {:?}",
        verdict
    );
}

#[test]
fn missing_url_parameter_defaults_to_deny() {
    let config = PolicyConfig::from_toml(TEST_POLICY_TOML).unwrap();
    let policies = config.to_policies();
    let engine = PolicyEngine::new(false);

    let action = Action::new("http_request", "get", json!({"headers": {}}));

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Missing url parameter should fail-closed to deny, got: {:?}",
        verdict
    );
}
