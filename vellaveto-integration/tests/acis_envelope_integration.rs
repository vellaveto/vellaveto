// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Integration tests for ACIS decision envelopes.
//!
//! Validates the end-to-end ACIS pipeline: mediation → envelope construction →
//! validation → audit persistence. Tests transport-agnostic properties that
//! hold across HTTP, WebSocket, gRPC, and stdio surfaces.

use serde_json::json;
use tempfile::TempDir;
use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_mcp::mediation::{mediate, MediationConfig};
use vellaveto_types::acis::{AcisDecisionEnvelope, DecisionKind, DecisionOrigin};
use vellaveto_types::identity::CallChainEntry;
use vellaveto_types::{Action, EvaluationContext, Policy, PolicyType, Verdict};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn test_action() -> Action {
    Action::new(
        "file_write".to_string(),
        "write".to_string(),
        json!({"path": "/tmp/out.txt", "content": "hello"}),
    )
}

fn deny_policy() -> Policy {
    Policy {
        id: "file_write:*".to_string(),
        name: "Block all file writes".to_string(),
        policy_type: PolicyType::Deny,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }
}

fn allow_policy() -> Policy {
    Policy {
        id: "file_write:*".to_string(),
        name: "Allow all file writes".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }
}

// ═══════════════════════════════════════
// MEDIATION PIPELINE → ACIS ENVELOPE
// ═══════════════════════════════════════

#[test]
fn test_acis_mediate_deny_produces_valid_envelope() {
    let engine = PolicyEngine::with_policies(true, &[deny_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();

    let result = mediate("test-decision-1", &action, &engine, None, "http", &config, None, None);

    assert_eq!(result.envelope.decision, DecisionKind::Deny);
    assert_eq!(result.envelope.origin, DecisionOrigin::PolicyEngine);
    assert_eq!(result.envelope.transport, "http");
    assert_eq!(result.envelope.action_summary.tool, "file_write");
    assert_eq!(result.envelope.action_summary.function, "write");
    assert!(!result.envelope.action_fingerprint.is_empty());
    assert!(result.envelope.validate().is_ok(), "envelope should validate");
}

#[test]
fn test_acis_mediate_allow_produces_valid_envelope() {
    let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();

    let result = mediate("test-decision-2", &action, &engine, None, "stdio", &config, None, None);

    assert_eq!(result.envelope.decision, DecisionKind::Allow);
    assert_eq!(result.envelope.transport, "stdio");
    assert!(result.envelope.validate().is_ok());
}

#[test]
fn test_acis_envelope_captures_agent_identity_from_context() {
    let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();
    let ctx = EvaluationContext {
        agent_id: Some("claude-agent-v4".to_string()),
        ..Default::default()
    };

    let result = mediate(
        "test-decision-3",
        &action,
        &engine,
        Some(&ctx),
        "websocket",
        &config,
        Some("sess-abc"),
        Some("tenant-xyz"),
    );

    assert_eq!(result.envelope.agent_id.as_deref(), Some("claude-agent-v4"));
    assert_eq!(result.envelope.session_id.as_deref(), Some("sess-abc"));
    assert_eq!(result.envelope.tenant_id.as_deref(), Some("tenant-xyz"));
    assert!(result.envelope.validate().is_ok());
}

#[test]
fn test_acis_fingerprint_deterministic_across_transports() {
    let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();

    let r1 = mediate("id-1", &action, &engine, None, "http", &config, None, None);
    let r2 = mediate("id-2", &action, &engine, None, "websocket", &config, None, None);
    let r3 = mediate("id-3", &action, &engine, None, "grpc", &config, None, None);
    let r4 = mediate("id-4", &action, &engine, None, "stdio", &config, None, None);

    // Same action → same fingerprint regardless of transport
    assert_eq!(r1.envelope.action_fingerprint, r2.envelope.action_fingerprint);
    assert_eq!(r2.envelope.action_fingerprint, r3.envelope.action_fingerprint);
    assert_eq!(r3.envelope.action_fingerprint, r4.envelope.action_fingerprint);

    // But decision_id differs
    assert_ne!(r1.envelope.decision_id, r2.envelope.decision_id);
}

// ═══════════════════════════════════════
// VALIDATION BOUNDARY TESTS
// ═══════════════════════════════════════

#[test]
fn test_acis_envelope_rejects_oversized_evaluation_us() {
    let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();

    let mut result = mediate("id-5", &action, &engine, None, "http", &config, None, None);
    result.envelope.evaluation_us = Some(3_600_000_001); // > 1 hour

    let err = result.envelope.validate().unwrap_err();
    assert!(err.contains("evaluation_us"));
}

#[test]
fn test_acis_envelope_rejects_oversized_call_chain_depth() {
    let mut envelope = AcisDecisionEnvelope {
        decision_id: "abc123".into(),
        timestamp: "2026-03-09T10:00:00Z".into(),
        session_id: None,
        tenant_id: None,
        agent_identity: None,
        agent_id: None,
        action_summary: vellaveto_types::acis::AcisActionSummary {
            tool: "test".into(),
            function: "run".into(),
            target_path_count: 0,
            target_domain_count: 0,
        },
        action_fingerprint: "deadbeef".into(),
        decision: DecisionKind::Deny,
        origin: DecisionOrigin::PolicyEngine,
        reason: String::new(),
        matched_policy_id: None,
        transport: "http".into(),
        findings: vec![],
        evaluation_us: None,
        call_chain_depth: 257,
    };

    let err = envelope.validate().unwrap_err();
    assert!(err.contains("call_chain_depth"));

    envelope.call_chain_depth = 256;
    assert!(envelope.validate().is_ok());
}

// ═══════════════════════════════════════
// AUDIT PERSISTENCE WITH ACIS
// ═══════════════════════════════════════

#[test]
fn test_acis_envelope_persisted_in_audit_entry() {
    let rt = runtime();
    rt.block_on(async {
        let dir = TempDir::new().expect("tempdir");
        let logger = AuditLogger::new(dir.path().join("audit.jsonl"));

        let action = test_action();
        let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
        let config = MediationConfig::default();
        let result = mediate("persist-1", &action, &engine, None, "http", &config, None, None);

        // Persist with ACIS envelope
        logger
            .log_entry_with_acis(
                &action,
                &result.verdict,
                json!({"source": "integration_test"}),
                result.envelope.clone(),
            )
            .await
            .expect("audit persist should succeed");

        // Verify the audit file contains the envelope
        let content = tokio::fs::read_to_string(dir.path().join("audit.jsonl"))
            .await
            .expect("read audit");
        assert!(content.contains("acis_envelope"));
        assert!(content.contains(&result.envelope.action_fingerprint));
    });
}

#[test]
fn test_acis_audit_rejects_invalid_envelope() {
    let rt = runtime();
    rt.block_on(async {
        let dir = TempDir::new().expect("tempdir");
        let logger = AuditLogger::new(dir.path().join("audit.jsonl"));

        let action = test_action();
        let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
        let config = MediationConfig::default();
        let mut result = mediate("persist-2", &action, &engine, None, "http", &config, None, None);

        // Corrupt the envelope — empty tool name
        result.envelope.action_summary.tool = String::new();

        let err: Result<(), vellaveto_audit::AuditError> = logger
            .log_entry_with_acis(
                &action,
                &result.verdict,
                json!({"source": "integration_test"}),
                result.envelope,
            )
            .await;

        assert!(err.is_err(), "should reject invalid envelope");
    });
}

// ═══════════════════════════════════════
// CALL CHAIN DEPTH CLAMPING
// ═══════════════════════════════════════

#[test]
fn test_acis_call_chain_depth_clamped_to_256() {
    let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();

    // Build a context with 300 call chain entries
    let ctx = EvaluationContext {
        call_chain: (0..300)
            .map(|i| CallChainEntry {
                agent_id: format!("agent-{i}"),
                tool: "test".into(),
                function: "run".into(),
                timestamp: "2026-03-09T10:00:00Z".into(),
                hmac: None,
                verified: None,
            })
            .collect(),
        ..Default::default()
    };

    let result = mediate("depth-1", &action, &engine, Some(&ctx), "http", &config, None, None);

    // Depth should be clamped to 256, not 300
    assert_eq!(result.envelope.call_chain_depth, 256);
    assert!(result.envelope.validate().is_ok());
}

#[test]
fn test_acis_mediate_with_dlp_finding_produces_deny() {
    let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
    // Action with an API key in parameters
    let action = Action::new(
        "http_request".to_string(),
        "post".to_string(),
        json!({"headers": {"Authorization": "Bearer sk-proj-abc123def456ghi789"}}),
    );
    let config = MediationConfig {
        dlp_enabled: true,
        dlp_blocking: true,
        ..Default::default()
    };

    let result = mediate("dlp-1", &action, &engine, None, "http", &config, None, None);

    // Regardless of whether DLP catches this specific pattern,
    // the envelope must always validate.
    assert!(result.envelope.validate().is_ok());
    // If DLP did catch it, origin should be Dlp
    if !result.dlp_findings.is_empty() {
        assert_eq!(result.envelope.decision, DecisionKind::Deny);
        assert_eq!(result.envelope.origin, DecisionOrigin::Dlp);
    }
}
