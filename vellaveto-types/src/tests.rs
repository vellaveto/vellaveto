use super::*;
use proptest::prelude::*;
use serde_json::json;
use std::collections::HashMap;

#[test]
fn test_action_serialization_roundtrip() {
    let action = Action::new("file_system", "read_file", json!({"path": "/tmp/test.txt"}));
    let json_str = serde_json::to_string(&action).unwrap();
    let deserialized: Action = serde_json::from_str(&json_str).unwrap();
    assert_eq!(action, deserialized);
}

#[test]
fn test_verdict_all_variants() {
    let variants = vec![
        Verdict::Allow,
        Verdict::Deny {
            reason: "blocked".to_string(),
        },
        Verdict::RequireApproval {
            reason: "needs review".to_string(),
        },
    ];
    for v in variants {
        let json_str = serde_json::to_string(&v).unwrap();
        let deserialized: Verdict = serde_json::from_str(&json_str).unwrap();
        assert_eq!(v, deserialized);
    }
}

#[test]
fn test_policy_type_conditional_with_value() {
    let pt = PolicyType::Conditional {
        conditions: json!({"tool_pattern": "bash", "forbidden_parameters": ["force"]}),
    };
    let json_str = serde_json::to_string(&pt).unwrap();
    let deserialized: PolicyType = serde_json::from_str(&json_str).unwrap();
    assert_eq!(pt, deserialized);
}

#[test]
fn test_policy_serialization() {
    let policy = Policy {
        id: "bash:*".to_string(),
        name: "Block bash".to_string(),
        policy_type: PolicyType::Deny,
        priority: 100,
        path_rules: None,
        network_rules: None,
    };
    let json_str = serde_json::to_string(&policy).unwrap();
    let deserialized: Policy = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.id, "bash:*");
    assert_eq!(deserialized.priority, 100);
}

// --- Action validation tests (M2) ---

#[test]
fn test_validated_accepts_valid_input() {
    let action = Action::validated("read_file", "execute", json!({}));
    assert!(action.is_ok());
    let action = action.unwrap();
    assert_eq!(action.tool, "read_file");
    assert_eq!(action.function, "execute");
}

#[test]
fn test_validated_rejects_empty_tool() {
    let result = Action::validated("", "execute", json!({}));
    assert!(matches!(
        result,
        Err(ValidationError::EmptyField { field: "tool" })
    ));
}

#[test]
fn test_validated_rejects_empty_function() {
    let result = Action::validated("read_file", "", json!({}));
    assert!(matches!(
        result,
        Err(ValidationError::EmptyField { field: "function" })
    ));
}

#[test]
fn test_validated_rejects_null_bytes_in_tool() {
    let result = Action::validated("read\0file", "execute", json!({}));
    assert!(matches!(
        result,
        Err(ValidationError::NullByte { field: "tool" })
    ));
}

#[test]
fn test_validated_rejects_null_bytes_in_function() {
    let result = Action::validated("read_file", "exec\0ute", json!({}));
    assert!(matches!(
        result,
        Err(ValidationError::NullByte { field: "function" })
    ));
}

#[test]
fn test_validated_rejects_too_long_tool() {
    let long_name = "a".repeat(257);
    let result = Action::validated(long_name, "execute", json!({}));
    assert!(matches!(
        result,
        Err(ValidationError::TooLong { field: "tool", .. })
    ));
}

#[test]
fn test_validated_accepts_max_length_tool() {
    let name = "a".repeat(256);
    let result = Action::validated(name, "execute", json!({}));
    assert!(result.is_ok());
}

#[test]
fn test_validate_existing_action() {
    let action = Action::new("read_file", "execute", json!({}));
    assert!(action.validate().is_ok());

    let bad = Action::new("", "execute", json!({}));
    assert!(bad.validate().is_err());
}

#[test]
fn test_new_still_works_without_validation() {
    // Backward compatibility: new() doesn't validate
    let action = Action::new("", "", json!({}));
    assert_eq!(action.tool, "");
    assert_eq!(action.function, "");
}

#[test]
fn test_validation_error_display() {
    let e = ValidationError::EmptyField { field: "tool" };
    assert!(e.to_string().contains("tool"));
    assert!(e.to_string().contains("empty"));
}

#[test]
fn test_validated_rejects_control_chars_with_correct_variant() {
    // Tab character should produce ControlCharacter, not NullByte
    let result = Action::validated("read\tfile", "execute", json!({}));
    assert!(
        matches!(
            result,
            Err(ValidationError::ControlCharacter { field: "tool" })
        ),
        "Tab should produce ControlCharacter variant, got: {:?}",
        result
    );

    // Newline in function
    let result = Action::validated("tool", "exec\nute", json!({}));
    assert!(
        matches!(
            result,
            Err(ValidationError::ControlCharacter { field: "function" })
        ),
        "Newline should produce ControlCharacter variant, got: {:?}",
        result
    );
}

#[test]
fn test_control_character_error_display() {
    let e = ValidationError::ControlCharacter { field: "tool" };
    let msg = e.to_string();
    assert!(
        msg.contains("control character"),
        "Error message should say 'control character', got: {}",
        msg
    );
    assert!(!msg.contains("null byte"), "Should NOT mention null byte");
}

// --- Target validation tests ---

#[test]
fn test_validate_rejects_null_byte_in_target_path() {
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = vec!["/tmp/foo\0bar".to_string()];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TargetNullByte {
            field: "target_paths",
            index: 0
        })
    ));
}

#[test]
fn test_validate_rejects_null_byte_in_target_domain() {
    let mut action = Action::new("tool", "func", json!({}));
    action.target_domains = vec!["evil\0.com".to_string()];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TargetNullByte {
            field: "target_domains",
            index: 0
        })
    ));
}

#[test]
fn test_validate_rejects_too_long_target_path() {
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = vec!["a".repeat(4097)];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TargetTooLong {
            field: "target_paths",
            index: 0,
            ..
        })
    ));
}

#[test]
fn test_validate_accepts_max_length_target_path() {
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = vec!["a".repeat(4096)];
    assert!(action.validate().is_ok());
}

#[test]
fn test_validate_rejects_too_many_targets() {
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = (0..200).map(|i| format!("/path/{}", i)).collect();
    action.target_domains = (0..100).map(|i| format!("d{}.com", i)).collect();
    // 200 + 100 = 300 > 256
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TooManyTargets {
            count: 300,
            max: 256
        })
    ));
}

#[test]
fn test_validate_accepts_max_targets() {
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = (0..128).map(|i| format!("/path/{}", i)).collect();
    action.target_domains = (0..128).map(|i| format!("d{}.com", i)).collect();
    // 128 + 128 = 256 == MAX_TARGETS
    assert!(action.validate().is_ok());
}

#[test]
fn test_validate_rejects_too_many_resolved_ips_r39_eng_4() {
    // R39-ENG-4: resolved_ips must be counted in total_targets.
    // 300 resolved_ips alone should exceed MAX_TARGETS=256.
    let mut action = Action::new("tool", "func", json!({}));
    action.resolved_ips = (0..300)
        .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
        .collect();
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TooManyTargets {
            count: 300,
            max: 256
        })
    ));
}

#[test]
fn test_validate_resolved_ips_combined_with_paths_domains_r39_eng_4() {
    // R39-ENG-4: Combination of paths + domains + IPs exceeding MAX_TARGETS
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = (0..100).map(|i| format!("/path/{}", i)).collect();
    action.target_domains = (0..100).map(|i| format!("d{}.com", i)).collect();
    action.resolved_ips = (0..57).map(|i| format!("10.0.0.{}", i)).collect();
    // 100 + 100 + 57 = 257 > 256
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TooManyTargets {
            count: 257,
            max: 256
        })
    ));
}

#[test]
fn test_validate_resolved_ips_at_boundary_r39_eng_4() {
    // R39-ENG-4: paths + domains + IPs exactly at MAX_TARGETS should pass
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = (0..85).map(|i| format!("/path/{}", i)).collect();
    action.target_domains = (0..85).map(|i| format!("d{}.com", i)).collect();
    action.resolved_ips = (0..86).map(|i| format!("10.0.0.{}", i)).collect();
    // 85 + 85 + 86 = 256 == MAX_TARGETS
    assert!(action.validate().is_ok());
}

// --- R42-TYPES-1: resolved_ips content validation tests ---

#[test]
fn test_r42_types_1_resolved_ips_null_byte_rejected() {
    // R42-TYPES-1: resolved_ips with null byte must be rejected
    let mut action = Action::new("tool", "func", json!({}));
    action.resolved_ips = vec!["10.0.0.1".to_string(), "10.0.\0.2".to_string()];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TargetNullByte {
            field: "resolved_ips",
            index: 1
        })
    ));
}

#[test]
fn test_r42_types_1_resolved_ips_oversized_rejected() {
    // R42-TYPES-1: resolved_ips with oversized string must be rejected
    let mut action = Action::new("tool", "func", json!({}));
    let oversized = "A".repeat(4097); // MAX_TARGET_LEN is 4096
    action.resolved_ips = vec![oversized];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TargetTooLong {
            field: "resolved_ips",
            index: 0,
            len: 4097,
            max: 4096
        })
    ));
}

#[test]
fn test_r42_types_1_resolved_ips_valid_entries_pass() {
    // R42-TYPES-1: Valid resolved_ips should pass validation
    let mut action = Action::new("tool", "func", json!({}));
    action.resolved_ips = vec![
        "10.0.0.1".to_string(),
        "192.168.1.1".to_string(),
        "::1".to_string(),
    ];
    assert!(action.validate().is_ok());
}

#[test]
fn test_r42_types_1_resolved_ips_null_byte_first_entry() {
    // R42-TYPES-1: null byte at index 0
    let mut action = Action::new("tool", "func", json!({}));
    action.resolved_ips = vec!["\0".to_string()];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TargetNullByte {
            field: "resolved_ips",
            index: 0
        })
    ));
}

#[test]
fn test_validate_null_byte_second_target() {
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = vec!["/ok".to_string(), "/bad\0path".to_string()];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TargetNullByte {
            field: "target_paths",
            index: 1
        })
    ));
}

#[test]
fn test_target_validation_error_display() {
    let e = ValidationError::TooManyTargets {
        count: 500,
        max: 256,
    };
    assert!(e.to_string().contains("500"));
    assert!(e.to_string().contains("256"));

    let e = ValidationError::TargetNullByte {
        field: "target_paths",
        index: 3,
    };
    assert!(e.to_string().contains("target_paths[3]"));
    assert!(e.to_string().contains("null byte"));

    let e = ValidationError::TargetTooLong {
        field: "target_domains",
        index: 0,
        len: 5000,
        max: 4096,
    };
    assert!(e.to_string().contains("5000"));
    assert!(e.to_string().contains("4096"));
}

// ═══════════════════════════════════════════════════
// PROPERTY-BASED TESTS: Action Validation
// ═══════════════════════════════════════════════════

proptest! {
    // PROPERTY: validated() succeeds iff validate() succeeds on the same inputs
    #[test]
    fn validated_ok_iff_validate_ok(
        tool in "[a-z_]{0,260}",
        function in "[a-z_]{0,260}",
    ) {
        let validated_result = Action::validated(&tool, &function, json!({}));
        let new_action = Action::new(&tool, &function, json!({}));
        let validate_result = new_action.validate();

        prop_assert_eq!(
            validated_result.is_ok(),
            validate_result.is_ok(),
            "validated() and validate() must agree for tool={:?} function={:?}\n\
             validated: {:?}\n\
             validate:  {:?}",
            tool, function, validated_result, validate_result
        );
    }

    // PROPERTY: Any name containing a null byte is always rejected
    #[test]
    fn null_byte_always_rejected(
        prefix in "[a-z]{1,10}",
        suffix in "[a-z]{1,10}",
    ) {
        let tool_with_null = format!("{}\0{}", prefix, suffix);

        // Null in tool
        let result = Action::validated(&tool_with_null, "func", json!({}));
        prop_assert!(
            matches!(result, Err(ValidationError::NullByte { field: "tool" })),
            "Null byte in tool must be rejected. Got: {:?}", result
        );

        // Null in function
        let result = Action::validated("tool", &tool_with_null, json!({}));
        prop_assert!(
            matches!(result, Err(ValidationError::NullByte { field: "function" })),
            "Null byte in function must be rejected. Got: {:?}", result
        );
    }

    // PROPERTY: Empty tool or function name is always rejected
    #[test]
    fn empty_name_always_rejected(
        other in "[a-z]{1,10}",
    ) {
        let result = Action::validated("", &other, json!({}));
        prop_assert!(
            matches!(result, Err(ValidationError::EmptyField { field: "tool" })),
            "Empty tool must be rejected. Got: {:?}", result
        );

        let result = Action::validated(&other, "", json!({}));
        prop_assert!(
            matches!(result, Err(ValidationError::EmptyField { field: "function" })),
            "Empty function must be rejected. Got: {:?}", result
        );
    }

    // PROPERTY: 256-byte name is accepted, 257-byte name is rejected
    #[test]
    fn max_length_boundary(
        ch in "[a-z]",
    ) {
        let at_max = ch.repeat(256);
        let over_max = ch.repeat(257);

        let ok_result = Action::validated(&at_max, "func", json!({}));
        prop_assert!(ok_result.is_ok(),
            "256-byte name must be accepted. Got: {:?}", ok_result);

        let err_result = Action::validated(&over_max, "func", json!({}));
        prop_assert!(
            matches!(err_result, Err(ValidationError::TooLong { field: "tool", .. })),
            "257-byte name must be rejected. Got: {:?}", err_result
        );
    }

    // PROPERTY: Valid actions roundtrip through serde unchanged
    #[test]
    fn valid_names_roundtrip_serde(
        tool in "[a-z_]{1,20}",
        function in "[a-z_]{1,20}",
    ) {
        let action = Action::validated(&tool, &function, json!({"key": "value"})).unwrap();
        let serialized = serde_json::to_string(&action).unwrap();
        let deserialized: Action = serde_json::from_str(&serialized).unwrap();
        prop_assert_eq!(&action, &deserialized,
            "Valid action must roundtrip through serde unchanged");
    }
}

// SECURITY (R16-TYPES-2): EvaluationContext.has_any_meaningful_fields()
// must include timestamp so time-window policies fail-closed.
#[test]
fn test_context_timestamp_only_is_meaningful() {
    let ctx = EvaluationContext {
        timestamp: Some("2024-01-01T00:00:00Z".to_string()),
        ..Default::default()
    };
    assert!(
        ctx.has_any_meaningful_fields(),
        "Context with only timestamp should be meaningful"
    );
}

#[test]
fn test_context_empty_is_not_meaningful() {
    let ctx = EvaluationContext::default();
    assert!(
        !ctx.has_any_meaningful_fields(),
        "Default context should not be meaningful"
    );
}

// --- Call chain tests (OWASP ASI08) ---

#[test]
fn test_call_chain_entry_serialization() {
    let entry = CallChainEntry {
        agent_id: "agent-a".to_string(),
        tool: "read_file".to_string(),
        function: "execute".to_string(),
        timestamp: "2026-01-01T12:00:00Z".to_string(),
        hmac: None,
        verified: None,
    };
    let json_str = serde_json::to_string(&entry).unwrap();
    let deserialized: CallChainEntry = serde_json::from_str(&json_str).unwrap();
    assert_eq!(entry, deserialized);
}

#[test]
fn test_context_call_chain_is_meaningful() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-a".to_string(),
            tool: "read_file".to_string(),
            function: "execute".to_string(),
            timestamp: "2026-01-01T12:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    assert!(
        ctx.has_any_meaningful_fields(),
        "Context with call_chain should be meaningful"
    );
}

#[test]
fn test_call_chain_depth() {
    let empty_ctx = EvaluationContext::default();
    assert_eq!(empty_ctx.call_chain_depth(), 0);

    let single_hop_ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-a".to_string(),
            tool: "tool1".to_string(),
            function: "func1".to_string(),
            timestamp: "2026-01-01T12:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    assert_eq!(single_hop_ctx.call_chain_depth(), 1);

    let multi_hop_ctx = EvaluationContext {
        call_chain: vec![
            CallChainEntry {
                agent_id: "agent-a".to_string(),
                tool: "tool1".to_string(),
                function: "func1".to_string(),
                timestamp: "2026-01-01T12:00:00Z".to_string(),
                hmac: None,
                verified: None,
            },
            CallChainEntry {
                agent_id: "agent-b".to_string(),
                tool: "tool2".to_string(),
                function: "func2".to_string(),
                timestamp: "2026-01-01T12:00:01Z".to_string(),
                hmac: None,
                verified: None,
            },
        ],
        ..Default::default()
    };
    assert_eq!(multi_hop_ctx.call_chain_depth(), 2);
}

#[test]
fn test_originating_agent() {
    let empty_ctx = EvaluationContext::default();
    assert!(empty_ctx.originating_agent().is_none());

    let ctx = EvaluationContext {
        call_chain: vec![
            CallChainEntry {
                agent_id: "origin-agent".to_string(),
                tool: "tool1".to_string(),
                function: "func1".to_string(),
                timestamp: "2026-01-01T12:00:00Z".to_string(),
                hmac: None,
                verified: None,
            },
            CallChainEntry {
                agent_id: "proxy-agent".to_string(),
                tool: "tool2".to_string(),
                function: "func2".to_string(),
                timestamp: "2026-01-01T12:00:01Z".to_string(),
                hmac: None,
                verified: None,
            },
        ],
        ..Default::default()
    };
    assert_eq!(ctx.originating_agent(), Some("origin-agent"));
}

// --- AgentIdentity tests (OWASP ASI07) ---

#[test]
fn test_agent_identity_serialization_roundtrip() {
    let mut claims = HashMap::new();
    claims.insert("role".to_string(), json!("admin"));
    claims.insert("permissions".to_string(), json!(["read", "write"]));

    let identity = AgentIdentity {
        issuer: Some("https://auth.example.com".to_string()),
        subject: Some("agent-123".to_string()),
        audience: vec!["mcp-server".to_string()],
        claims,
    };

    let json_str = serde_json::to_string(&identity).unwrap();
    let deserialized: AgentIdentity = serde_json::from_str(&json_str).unwrap();
    assert_eq!(identity, deserialized);
}

#[test]
fn test_agent_identity_is_populated() {
    let empty = AgentIdentity::default();
    assert!(!empty.is_populated());

    let with_issuer = AgentIdentity {
        issuer: Some("https://auth.example.com".to_string()),
        ..Default::default()
    };
    assert!(with_issuer.is_populated());

    let with_subject = AgentIdentity {
        subject: Some("agent-123".to_string()),
        ..Default::default()
    };
    assert!(with_subject.is_populated());

    let with_audience = AgentIdentity {
        audience: vec!["server".to_string()],
        ..Default::default()
    };
    assert!(with_audience.is_populated());

    let mut claims = HashMap::new();
    claims.insert("role".to_string(), json!("admin"));
    let with_claims = AgentIdentity {
        claims,
        ..Default::default()
    };
    assert!(with_claims.is_populated());
}

#[test]
fn test_agent_identity_claim_str() {
    let mut claims = HashMap::new();
    claims.insert("role".to_string(), json!("admin"));
    claims.insert("count".to_string(), json!(42));

    let identity = AgentIdentity {
        claims,
        ..Default::default()
    };

    assert_eq!(identity.claim_str("role"), Some("admin"));
    assert_eq!(identity.claim_str("count"), None); // Not a string
    assert_eq!(identity.claim_str("missing"), None);
}

#[test]
fn test_agent_identity_claim_str_array() {
    let mut claims = HashMap::new();
    claims.insert("permissions".to_string(), json!(["read", "write"]));
    claims.insert("role".to_string(), json!("admin")); // Not an array
    claims.insert("mixed".to_string(), json!(["str", 42])); // Mixed types

    let identity = AgentIdentity {
        claims,
        ..Default::default()
    };

    assert_eq!(
        identity.claim_str_array("permissions"),
        Some(vec!["read", "write"])
    );
    assert_eq!(identity.claim_str_array("role"), None); // Not an array
                                                        // Mixed array should only contain strings
    assert_eq!(identity.claim_str_array("mixed"), Some(vec!["str"]));
    assert_eq!(identity.claim_str_array("missing"), None);
}

#[test]
fn test_context_with_agent_identity_is_meaningful() {
    let identity = AgentIdentity {
        subject: Some("agent-123".to_string()),
        ..Default::default()
    };
    let ctx = EvaluationContext {
        agent_identity: Some(identity),
        ..Default::default()
    };
    assert!(
        ctx.has_any_meaningful_fields(),
        "Context with agent_identity should be meaningful"
    );
}

#[test]
fn test_context_with_empty_agent_identity_is_not_meaningful() {
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity::default()),
        ..Default::default()
    };
    assert!(
        !ctx.has_any_meaningful_fields(),
        "Context with empty agent_identity should not be meaningful"
    );
}

// ═══════════════════════════════════════════════════
// MCP 2025-11-25 TYPES TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_task_status_serialization() {
    let statuses = vec![
        TaskStatus::Pending,
        TaskStatus::Running,
        TaskStatus::Completed,
        TaskStatus::Failed {
            reason: "timeout".to_string(),
        },
        TaskStatus::Cancelled,
        TaskStatus::Expired,
    ];
    for status in statuses {
        let json_str = serde_json::to_string(&status).unwrap();
        let deserialized: TaskStatus = serde_json::from_str(&json_str).unwrap();
        assert_eq!(status, deserialized);
    }
}

#[test]
fn test_task_status_display() {
    assert_eq!(TaskStatus::Pending.to_string(), "pending");
    assert_eq!(TaskStatus::Running.to_string(), "running");
    assert_eq!(TaskStatus::Completed.to_string(), "completed");
    assert_eq!(
        TaskStatus::Failed {
            reason: "error".to_string()
        }
        .to_string(),
        "failed: error"
    );
    assert_eq!(TaskStatus::Cancelled.to_string(), "cancelled");
    assert_eq!(TaskStatus::Expired.to_string(), "expired");
}

#[test]
fn test_tracked_task_terminal_states() {
    let pending = TrackedTask {
        task_id: "1".to_string(),
        tool: "tool".to_string(),
        function: "func".to_string(),
        status: TaskStatus::Pending,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        created_by: None,
        session_id: None,
    };
    assert!(!pending.is_terminal());
    assert!(pending.is_active());

    let running = TrackedTask {
        status: TaskStatus::Running,
        ..pending.clone()
    };
    assert!(!running.is_terminal());
    assert!(running.is_active());

    let completed = TrackedTask {
        status: TaskStatus::Completed,
        ..pending.clone()
    };
    assert!(completed.is_terminal());
    assert!(!completed.is_active());

    let failed = TrackedTask {
        status: TaskStatus::Failed {
            reason: "error".to_string(),
        },
        ..pending.clone()
    };
    assert!(failed.is_terminal());
    assert!(!failed.is_active());

    let cancelled = TrackedTask {
        status: TaskStatus::Cancelled,
        ..pending.clone()
    };
    assert!(cancelled.is_terminal());
    assert!(!cancelled.is_active());

    let expired = TrackedTask {
        status: TaskStatus::Expired,
        ..pending
    };
    assert!(expired.is_terminal());
    assert!(!expired.is_active());
}

#[test]
fn test_tracked_task_serialization() {
    let task = TrackedTask {
        task_id: "task-123".to_string(),
        tool: "background_job".to_string(),
        function: "execute".to_string(),
        status: TaskStatus::Running,
        created_at: "2026-01-01T12:00:00Z".to_string(),
        expires_at: Some("2026-01-01T13:00:00Z".to_string()),
        created_by: Some("agent-1".to_string()),
        session_id: Some("session-abc".to_string()),
    };
    let json_str = serde_json::to_string(&task).unwrap();
    let deserialized: TrackedTask = serde_json::from_str(&json_str).unwrap();
    assert_eq!(task, deserialized);
}

#[test]
fn test_auth_level_ordering() {
    assert!(AuthLevel::None < AuthLevel::Basic);
    assert!(AuthLevel::Basic < AuthLevel::OAuth);
    assert!(AuthLevel::OAuth < AuthLevel::OAuthMfa);
    assert!(AuthLevel::OAuthMfa < AuthLevel::HardwareKey);
}

#[test]
fn test_auth_level_satisfies() {
    assert!(AuthLevel::HardwareKey.satisfies(AuthLevel::None));
    assert!(AuthLevel::HardwareKey.satisfies(AuthLevel::Basic));
    assert!(AuthLevel::HardwareKey.satisfies(AuthLevel::OAuth));
    assert!(AuthLevel::HardwareKey.satisfies(AuthLevel::OAuthMfa));
    assert!(AuthLevel::HardwareKey.satisfies(AuthLevel::HardwareKey));

    assert!(!AuthLevel::None.satisfies(AuthLevel::Basic));
    assert!(!AuthLevel::OAuth.satisfies(AuthLevel::OAuthMfa));
}

#[test]
fn test_auth_level_from_u8() {
    assert_eq!(AuthLevel::from_u8(0), AuthLevel::None);
    assert_eq!(AuthLevel::from_u8(1), AuthLevel::Basic);
    assert_eq!(AuthLevel::from_u8(2), AuthLevel::OAuth);
    assert_eq!(AuthLevel::from_u8(3), AuthLevel::OAuthMfa);
    assert_eq!(AuthLevel::from_u8(4), AuthLevel::HardwareKey);
    assert_eq!(AuthLevel::from_u8(255), AuthLevel::None); // Unknown defaults to None
}

#[test]
fn test_auth_level_display() {
    assert_eq!(AuthLevel::None.to_string(), "none");
    assert_eq!(AuthLevel::Basic.to_string(), "basic");
    assert_eq!(AuthLevel::OAuth.to_string(), "oauth");
    assert_eq!(AuthLevel::OAuthMfa.to_string(), "oauth_mfa");
    assert_eq!(AuthLevel::HardwareKey.to_string(), "hardware_key");
}

#[test]
fn test_mcp_capability_new() {
    let cap = McpCapability::new("tools");
    assert_eq!(cap.name, "tools");
    assert!(cap.version.is_none());
    assert!(cap.sub_capabilities.is_empty());
}

#[test]
fn test_mcp_capability_with_version() {
    let cap = McpCapability::with_version("sampling", "1.0");
    assert_eq!(cap.name, "sampling");
    assert_eq!(cap.version, Some("1.0".to_string()));
}

#[test]
fn test_mcp_capability_has_sub() {
    let mut cap = McpCapability::new("tools");
    cap.sub_capabilities = vec!["read".to_string(), "write".to_string()];

    assert!(cap.has_sub("read"));
    assert!(cap.has_sub("write"));
    assert!(!cap.has_sub("execute"));
}

#[test]
fn test_mcp_capability_serialization() {
    let cap = McpCapability {
        name: "resources".to_string(),
        version: Some("2.0".to_string()),
        sub_capabilities: vec!["list".to_string(), "read".to_string()],
    };
    let json_str = serde_json::to_string(&cap).unwrap();
    let deserialized: McpCapability = serde_json::from_str(&json_str).unwrap();
    assert_eq!(cap, deserialized);
}

// ═══════════════════════════════════════════════════
// PHASE 2: ADVANCED THREAT DETECTION TYPES TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_circuit_state_display() {
    assert_eq!(CircuitState::Closed.to_string(), "closed");
    assert_eq!(CircuitState::Open.to_string(), "open");
    assert_eq!(CircuitState::HalfOpen.to_string(), "half_open");
}

#[test]
fn test_circuit_state_serialization() {
    let states = vec![
        CircuitState::Closed,
        CircuitState::Open,
        CircuitState::HalfOpen,
    ];
    for state in states {
        let json_str = serde_json::to_string(&state).unwrap();
        let deserialized: CircuitState = serde_json::from_str(&json_str).unwrap();
        assert_eq!(state, deserialized);
    }
}

#[test]
fn test_circuit_stats_default() {
    let stats = CircuitStats::default();
    assert_eq!(stats.state, CircuitState::Closed);
    assert_eq!(stats.failure_count, 0);
    assert_eq!(stats.success_count, 0);
    assert!(stats.last_failure.is_none());
}

#[test]
fn test_circuit_stats_serialization() {
    let stats = CircuitStats {
        state: CircuitState::Open,
        failure_count: 5,
        success_count: 0,
        last_failure: Some(1_704_067_200),
        last_state_change: 1_704_067_200,
        trip_count: 0,
    };
    let json_str = serde_json::to_string(&stats).unwrap();
    let deserialized: CircuitStats = serde_json::from_str(&json_str).unwrap();
    assert_eq!(stats, deserialized);
}

#[test]
fn test_agent_fingerprint_is_populated() {
    let empty = AgentFingerprint::default();
    assert!(!empty.is_populated());

    let with_sub = AgentFingerprint {
        jwt_sub: Some("agent-123".to_string()),
        ..Default::default()
    };
    assert!(with_sub.is_populated());

    let with_iss = AgentFingerprint {
        jwt_iss: Some("https://auth.example.com".to_string()),
        ..Default::default()
    };
    assert!(with_iss.is_populated());
}

#[test]
fn test_agent_fingerprint_summary() {
    let empty = AgentFingerprint::default();
    assert_eq!(empty.summary(), "empty");

    let fp = AgentFingerprint {
        jwt_sub: Some("agent-123".to_string()),
        jwt_iss: Some("https://auth.example.com".to_string()),
        client_id: Some("client-456".to_string()),
        ip_hash: Some("abc123".to_string()),
    };
    let summary = fp.summary();
    assert!(summary.contains("sub:agent-123"));
    assert!(summary.contains("iss:"));
    assert!(summary.contains("cid:client-456"));
    assert!(summary.contains("ip:*"));
}

#[test]
fn test_agent_fingerprint_serialization() {
    let fp = AgentFingerprint {
        jwt_sub: Some("sub".to_string()),
        jwt_iss: Some("iss".to_string()),
        client_id: Some("cid".to_string()),
        ip_hash: Some("hash".to_string()),
    };
    let json_str = serde_json::to_string(&fp).unwrap();
    let deserialized: AgentFingerprint = serde_json::from_str(&json_str).unwrap();
    assert_eq!(fp, deserialized);
}

#[test]
fn test_trust_level_ordering() {
    assert!(TrustLevel::Unknown < TrustLevel::Low);
    assert!(TrustLevel::Low < TrustLevel::Medium);
    assert!(TrustLevel::Medium < TrustLevel::High);
    assert!(TrustLevel::High < TrustLevel::Verified);
}

#[test]
fn test_trust_level_from_u8() {
    assert_eq!(TrustLevel::from_u8(0), TrustLevel::Unknown);
    assert_eq!(TrustLevel::from_u8(1), TrustLevel::Low);
    assert_eq!(TrustLevel::from_u8(2), TrustLevel::Medium);
    assert_eq!(TrustLevel::from_u8(3), TrustLevel::High);
    assert_eq!(TrustLevel::from_u8(4), TrustLevel::Verified);
    assert_eq!(TrustLevel::from_u8(255), TrustLevel::Unknown);
}

#[test]
fn test_trust_level_display() {
    assert_eq!(TrustLevel::Unknown.to_string(), "unknown");
    assert_eq!(TrustLevel::Low.to_string(), "low");
    assert_eq!(TrustLevel::Medium.to_string(), "medium");
    assert_eq!(TrustLevel::High.to_string(), "high");
    assert_eq!(TrustLevel::Verified.to_string(), "verified");
}

#[test]
fn test_schema_record_new() {
    let record = SchemaRecord::new("my_tool", "abc123", 1_704_067_200);
    assert_eq!(record.tool_name, "my_tool");
    assert_eq!(record.schema_hash, "abc123");
    assert_eq!(record.first_seen, 1_704_067_200);
    assert_eq!(record.last_seen, 1_704_067_200);
    assert!(record.version_history.is_empty());
    assert_eq!(record.trust_score, 0.0);
}

#[test]
fn test_schema_record_version_count() {
    let mut record = SchemaRecord::new("tool", "hash1", 1000);
    assert_eq!(record.version_count(), 1);

    record.version_history.push("hash0".to_string());
    assert_eq!(record.version_count(), 2);

    record.version_history.push("hash_prev".to_string());
    assert_eq!(record.version_count(), 3);
}

#[test]
fn test_schema_record_is_stable() {
    let record = SchemaRecord::new("tool", "hash", 1000);
    assert!(record.is_stable()); // No history = stable

    let mut record_same = record.clone();
    record_same.version_history.push("hash".to_string());
    assert!(record_same.is_stable()); // Same hash in history = stable

    let mut record_diff = record.clone();
    record_diff
        .version_history
        .push("different_hash".to_string());
    assert!(!record_diff.is_stable()); // Different hash in history = unstable
}

#[test]
fn test_schema_record_serialization() {
    let record = SchemaRecord {
        tool_name: "my_tool".to_string(),
        schema_hash: "hash123".to_string(),
        first_seen: 1000,
        last_seen: 2000,
        version_history: vec!["hash0".to_string(), "hash1".to_string()],
        trust_score: 0.75,
        schema_content: Some(serde_json::json!({"type": "object"})),
    };
    let json_str = serde_json::to_string(&record).unwrap();
    let deserialized: SchemaRecord = serde_json::from_str(&json_str).unwrap();
    assert_eq!(record, deserialized);
}

#[test]
fn test_schema_record_new_with_content() {
    let schema = serde_json::json!({"type": "object", "properties": {"name": {"type": "string"}}});
    let record = SchemaRecord::new_with_content("test_tool", "hash123", &schema, 1000);
    assert_eq!(record.tool_name, "test_tool");
    assert_eq!(record.schema_hash, "hash123");
    assert_eq!(record.schema_content, Some(schema));
}

#[test]
fn test_schema_record_large_schema_not_stored() {
    // Create a schema larger than MAX_SCHEMA_SIZE
    let large_value = "x".repeat(SchemaRecord::MAX_SCHEMA_SIZE + 1000);
    let schema = serde_json::json!({"data": large_value});
    let record = SchemaRecord::new_with_content("test_tool", "hash123", &schema, 1000);
    // Schema content should be None because it's too large
    assert!(record.schema_content.is_none());
}

#[test]
fn test_principal_context_direct() {
    let ctx = PrincipalContext::direct("user-123");
    assert_eq!(ctx.original_principal, "user-123");
    assert!(!ctx.is_delegated());
    assert_eq!(ctx.delegation_depth, 0);
}

#[test]
fn test_principal_context_is_delegated() {
    let direct = PrincipalContext::direct("user");
    assert!(!direct.is_delegated());

    let delegated = PrincipalContext {
        original_principal: "user".to_string(),
        delegated_to: Some("agent".to_string()),
        delegation_depth: 1,
        allowed_tools: vec!["read_file".to_string()],
        delegation_expires: None,
    };
    assert!(delegated.is_delegated());
}

#[test]
fn test_principal_context_is_expired() {
    let no_expiry = PrincipalContext::direct("user");
    assert!(!no_expiry.is_expired(1000));

    let not_expired = PrincipalContext {
        delegation_expires: Some(2000),
        ..PrincipalContext::direct("user")
    };
    assert!(!not_expired.is_expired(1000));

    let expired = PrincipalContext {
        delegation_expires: Some(1000),
        ..PrincipalContext::direct("user")
    };
    assert!(expired.is_expired(1000));
    assert!(expired.is_expired(2000));
}

#[test]
fn test_principal_context_serialization() {
    let ctx = PrincipalContext {
        original_principal: "user".to_string(),
        delegated_to: Some("agent".to_string()),
        delegation_depth: 2,
        allowed_tools: vec!["tool1".to_string(), "tool2".to_string()],
        delegation_expires: Some(1_704_067_200),
    };
    let json_str = serde_json::to_string(&ctx).unwrap();
    let deserialized: PrincipalContext = serde_json::from_str(&json_str).unwrap();
    assert_eq!(ctx, deserialized);
}

#[test]
fn test_sampling_stats_new() {
    let stats = SamplingStats::new(1000);
    assert_eq!(stats.request_count, 0);
    assert_eq!(stats.last_request, 1000);
    assert_eq!(stats.window_start, 1000);
    assert!(stats.flagged_patterns.is_empty());
}

#[test]
fn test_sampling_stats_record_request() {
    let mut stats = SamplingStats::new(1000);
    assert_eq!(stats.record_request(1001), 1);
    assert_eq!(stats.record_request(1002), 2);
    assert_eq!(stats.last_request, 1002);
    assert_eq!(stats.request_count, 2);
}

#[test]
fn test_sampling_stats_reset_window() {
    let mut stats = SamplingStats::new(1000);
    stats.record_request(1001);
    stats.record_request(1002);
    stats.flagged_patterns.push("pattern1".to_string());

    stats.reset_window(2000);
    assert_eq!(stats.request_count, 0);
    assert_eq!(stats.window_start, 2000);
    // Flagged patterns are preserved
    assert!(!stats.flagged_patterns.is_empty());
}

#[test]
fn test_sampling_stats_serialization() {
    let stats = SamplingStats {
        request_count: 5,
        last_request: 1005,
        window_start: 1000,
        flagged_patterns: vec!["sensitive".to_string()],
    };
    let json_str = serde_json::to_string(&stats).unwrap();
    let deserialized: SamplingStats = serde_json::from_str(&json_str).unwrap();
    assert_eq!(stats, deserialized);
}

// ═══════════════════════════════════════════════════
// ETDI (Enhanced Tool Definition Interface) TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_signature_algorithm_display() {
    assert_eq!(SignatureAlgorithm::Ed25519.to_string(), "ed25519");
    assert_eq!(SignatureAlgorithm::EcdsaP256.to_string(), "ecdsa_p256");
}

#[test]
fn test_signature_algorithm_default() {
    assert_eq!(SignatureAlgorithm::default(), SignatureAlgorithm::Ed25519);
}

#[test]
fn test_signature_algorithm_serialization() {
    for alg in [SignatureAlgorithm::Ed25519, SignatureAlgorithm::EcdsaP256] {
        let json_str = serde_json::to_string(&alg).unwrap();
        let deserialized: SignatureAlgorithm = serde_json::from_str(&json_str).unwrap();
        assert_eq!(alg, deserialized);
    }
}

#[test]
fn test_tool_signature_serialization_roundtrip() {
    let sig = ToolSignature {
        signature_id: "sig-123".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "cafe0123".to_string(),
        key_fingerprint: Some("fp:abc".to_string()),
        signed_at: "2026-01-15T12:00:00Z".to_string(),
        expires_at: Some("2027-01-15T12:00:00Z".to_string()),
        signer_spiffe_id: Some("spiffe://example.org/agent".to_string()),
        rekor_entry: None,
    };
    let json_str = serde_json::to_string(&sig).unwrap();
    let deserialized: ToolSignature = serde_json::from_str(&json_str).unwrap();
    assert_eq!(sig, deserialized);
}

#[test]
fn test_tool_signature_is_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "abc".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "key".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2026-06-01T00:00:00Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };

    // Before expiry
    assert!(!sig.is_expired("2026-05-01T00:00:00Z"));
    // At expiry
    assert!(sig.is_expired("2026-06-01T00:00:00Z"));
    // After expiry
    assert!(sig.is_expired("2026-12-01T00:00:00Z"));
}

#[test]
fn test_tool_signature_no_expiry_never_expires() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "abc".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "key".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(!sig.is_expired("2099-12-31T23:59:59Z"));
}

#[test]
fn test_signature_verification_is_fully_verified() {
    let valid_and_trusted = SignatureVerification {
        valid: true,
        signer_trusted: true,
        expired: false,
        message: "OK".to_string(),
    };
    assert!(valid_and_trusted.is_fully_verified());

    let invalid = SignatureVerification {
        valid: false,
        signer_trusted: true,
        expired: false,
        message: "bad sig".to_string(),
    };
    assert!(!invalid.is_fully_verified());

    let untrusted = SignatureVerification {
        valid: true,
        signer_trusted: false,
        expired: false,
        message: "unknown signer".to_string(),
    };
    assert!(!untrusted.is_fully_verified());

    let expired = SignatureVerification {
        valid: true,
        signer_trusted: true,
        expired: true,
        message: "expired".to_string(),
    };
    assert!(!expired.is_fully_verified());
}

#[test]
fn test_signature_verification_serialization() {
    let verification = SignatureVerification {
        valid: true,
        signer_trusted: true,
        expired: false,
        message: "Verified successfully".to_string(),
    };
    let json_str = serde_json::to_string(&verification).unwrap();
    let deserialized: SignatureVerification = serde_json::from_str(&json_str).unwrap();
    assert_eq!(verification, deserialized);
}

#[test]
fn test_tool_attestation_is_initial() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "abc".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "key".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        signer_spiffe_id: None,
        rekor_entry: None,
    };

    let initial = ToolAttestation {
        attestation_id: "att-1".to_string(),
        attestation_type: "initial".to_string(),
        attester: "admin".to_string(),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        tool_hash: "hash123".to_string(),
        previous_attestation: None,
        signature: sig.clone(),
        transparency_log_entry: None,
    };
    assert!(initial.is_initial());

    let chained = ToolAttestation {
        attestation_id: "att-2".to_string(),
        attestation_type: "version_update".to_string(),
        attester: "admin".to_string(),
        timestamp: "2026-02-01T00:00:00Z".to_string(),
        tool_hash: "hash456".to_string(),
        previous_attestation: Some("att-1".to_string()),
        signature: sig,
        transparency_log_entry: Some("log-entry-123".to_string()),
    };
    assert!(!chained.is_initial());
}

#[test]
fn test_tool_attestation_serialization() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "abc".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "key".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    let attestation = ToolAttestation {
        attestation_id: "att-1".to_string(),
        attestation_type: "initial".to_string(),
        attester: "admin".to_string(),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        tool_hash: "hash123".to_string(),
        previous_attestation: None,
        signature: sig,
        transparency_log_entry: None,
    };
    let json_str = serde_json::to_string(&attestation).unwrap();
    let deserialized: ToolAttestation = serde_json::from_str(&json_str).unwrap();
    assert_eq!(attestation, deserialized);
}

#[test]
fn test_tool_version_pin_exact_vs_constraint() {
    let exact = ToolVersionPin {
        tool_name: "my_tool".to_string(),
        pinned_version: Some("1.2.3".to_string()),
        version_constraint: None,
        definition_hash: "hash123".to_string(),
        pinned_at: "2026-01-01T00:00:00Z".to_string(),
        pinned_by: "admin".to_string(),
    };
    assert!(exact.is_exact());
    assert!(!exact.is_constraint());

    let constraint = ToolVersionPin {
        tool_name: "my_tool".to_string(),
        pinned_version: None,
        version_constraint: Some("^1.2.0".to_string()),
        definition_hash: "hash456".to_string(),
        pinned_at: "2026-01-01T00:00:00Z".to_string(),
        pinned_by: "admin".to_string(),
    };
    assert!(!constraint.is_exact());
    assert!(constraint.is_constraint());
}

#[test]
fn test_tool_version_pin_serialization() {
    let pin = ToolVersionPin {
        tool_name: "tool".to_string(),
        pinned_version: Some("1.0.0".to_string()),
        version_constraint: None,
        definition_hash: "hash".to_string(),
        pinned_at: "2026-01-01T00:00:00Z".to_string(),
        pinned_by: "admin".to_string(),
    };
    let json_str = serde_json::to_string(&pin).unwrap();
    let deserialized: ToolVersionPin = serde_json::from_str(&json_str).unwrap();
    assert_eq!(pin, deserialized);
}

#[test]
fn test_version_drift_alert_version_mismatch() {
    let alert = VersionDriftAlert::version_mismatch(
        "my_tool",
        "1.0.0",
        "1.1.0",
        true,
        "2026-02-01T00:00:00Z",
    );
    assert_eq!(alert.tool, "my_tool");
    assert_eq!(alert.expected_version, "1.0.0");
    assert_eq!(alert.actual_version, "1.1.0");
    assert_eq!(alert.drift_type, "version_mismatch");
    assert!(alert.blocking);
}

#[test]
fn test_version_drift_alert_hash_mismatch() {
    let alert = VersionDriftAlert::hash_mismatch(
        "my_tool",
        "abc123",
        "def456",
        false,
        "2026-02-01T00:00:00Z",
    );
    assert_eq!(alert.drift_type, "hash_mismatch");
    assert!(!alert.blocking);
}

#[test]
fn test_version_drift_alert_serialization() {
    let alert = VersionDriftAlert {
        tool: "tool".to_string(),
        expected_version: "1.0".to_string(),
        actual_version: "2.0".to_string(),
        drift_type: "version_mismatch".to_string(),
        blocking: true,
        detected_at: "2026-01-01T00:00:00Z".to_string(),
    };
    let json_str = serde_json::to_string(&alert).unwrap();
    let deserialized: VersionDriftAlert = serde_json::from_str(&json_str).unwrap();
    assert_eq!(alert, deserialized);
}

// ═══════════════════════════════════════════════════
// PHASE 10: NHI LIFECYCLE TYPES TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_nhi_attestation_type_serialization() {
    let types = vec![
        NhiAttestationType::Jwt,
        NhiAttestationType::Mtls,
        NhiAttestationType::Spiffe,
        NhiAttestationType::DPoP,
        NhiAttestationType::ApiKey,
    ];
    for atype in types {
        let json_str = serde_json::to_string(&atype).unwrap();
        let deserialized: NhiAttestationType = serde_json::from_str(&json_str).unwrap();
        assert_eq!(atype, deserialized);
    }
}

#[test]
fn test_nhi_attestation_type_display() {
    assert_eq!(NhiAttestationType::Jwt.to_string(), "jwt");
    assert_eq!(NhiAttestationType::Mtls.to_string(), "mtls");
    assert_eq!(NhiAttestationType::Spiffe.to_string(), "spiffe");
    assert_eq!(NhiAttestationType::DPoP.to_string(), "dpop");
    assert_eq!(NhiAttestationType::ApiKey.to_string(), "api_key");
}

#[test]
fn test_nhi_identity_status_serialization() {
    let statuses = vec![
        NhiIdentityStatus::Active,
        NhiIdentityStatus::Suspended,
        NhiIdentityStatus::Revoked,
        NhiIdentityStatus::Expired,
        NhiIdentityStatus::Probationary,
    ];
    for status in statuses {
        let json_str = serde_json::to_string(&status).unwrap();
        let deserialized: NhiIdentityStatus = serde_json::from_str(&json_str).unwrap();
        assert_eq!(status, deserialized);
    }
}

#[test]
fn test_nhi_identity_status_display() {
    assert_eq!(NhiIdentityStatus::Active.to_string(), "active");
    assert_eq!(NhiIdentityStatus::Suspended.to_string(), "suspended");
    assert_eq!(NhiIdentityStatus::Revoked.to_string(), "revoked");
    assert_eq!(NhiIdentityStatus::Expired.to_string(), "expired");
    assert_eq!(NhiIdentityStatus::Probationary.to_string(), "probationary");
}

#[test]
fn test_nhi_agent_identity_serialization() {
    let identity = NhiAgentIdentity {
        id: "agent-123".to_string(),
        name: "Test Agent".to_string(),
        attestation_type: NhiAttestationType::Spiffe,
        status: NhiIdentityStatus::Active,
        spiffe_id: Some("spiffe://example.org/agent/test".to_string()),
        public_key: Some("abc123".to_string()),
        key_algorithm: Some("Ed25519".to_string()),
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        last_rotation: Some("2026-06-01T00:00:00Z".to_string()),
        auth_count: 42,
        last_auth: Some("2026-02-01T12:00:00Z".to_string()),
        tags: vec!["production".to_string(), "internal".to_string()],
        metadata: {
            let mut m = HashMap::new();
            m.insert("team".to_string(), "platform".to_string());
            m
        },
        verification_tier: VerificationTier::DidVerified,
        did_plc: Some("did:plc:ewvi7nxsareczkwkx5pz6q6e".to_string()),
        attestations: vec![],
    };
    let json_str = serde_json::to_string(&identity).unwrap();
    let deserialized: NhiAgentIdentity = serde_json::from_str(&json_str).unwrap();
    assert_eq!(identity, deserialized);
}

#[test]
fn test_nhi_behavioral_baseline_serialization() {
    let baseline = NhiBehavioralBaseline {
        agent_id: "agent-123".to_string(),
        tool_call_patterns: {
            let mut m = HashMap::new();
            m.insert("file:read".to_string(), 10.5);
            m.insert("http:get".to_string(), 5.2);
            m
        },
        avg_request_interval_secs: 2.5,
        request_interval_stddev: 0.8,
        typical_session_duration_secs: 3600.0,
        observation_count: 1000,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        last_updated: "2026-02-01T00:00:00Z".to_string(),
        confidence: 0.95,
        typical_source_ips: vec!["10.0.0.0/8".to_string()],
        active_hours: vec![9, 10, 11, 12, 13, 14, 15, 16, 17],
    };
    let json_str = serde_json::to_string(&baseline).unwrap();
    let deserialized: NhiBehavioralBaseline = serde_json::from_str(&json_str).unwrap();
    assert_eq!(baseline, deserialized);
}

#[test]
fn test_nhi_behavioral_recommendation_display() {
    assert_eq!(NhiBehavioralRecommendation::Allow.to_string(), "allow");
    assert_eq!(
        NhiBehavioralRecommendation::AllowWithLogging.to_string(),
        "allow_with_logging"
    );
    assert_eq!(
        NhiBehavioralRecommendation::StepUpAuth.to_string(),
        "step_up_auth"
    );
    assert_eq!(NhiBehavioralRecommendation::Suspend.to_string(), "suspend");
    assert_eq!(NhiBehavioralRecommendation::Revoke.to_string(), "revoke");
}

#[test]
fn test_nhi_delegation_chain_depth() {
    let chain = NhiDelegationChain {
        chain: vec![
            NhiDelegationLink {
                from_agent: "agent-a".to_string(),
                to_agent: "agent-b".to_string(),
                permissions: vec!["read".to_string()],
                scope_constraints: vec!["tools:file_*".to_string()],
                created_at: "2026-01-01T00:00:00Z".to_string(),
                expires_at: "2026-02-01T00:00:00Z".to_string(),
                active: true,
                reason: Some("Temporary delegation".to_string()),
            },
            NhiDelegationLink {
                from_agent: "agent-b".to_string(),
                to_agent: "agent-c".to_string(),
                permissions: vec!["read".to_string()],
                scope_constraints: vec![],
                created_at: "2026-01-01T00:00:00Z".to_string(),
                expires_at: "2026-02-01T00:00:00Z".to_string(),
                active: true,
                reason: None,
            },
        ],
        max_depth: 5,
        resolved_at: "2026-01-15T00:00:00Z".to_string(),
    };
    assert_eq!(chain.depth(), 2);
    assert!(!chain.exceeds_max_depth());
    assert_eq!(chain.origin(), Some("agent-a"));
    assert_eq!(chain.terminus(), Some("agent-c"));
}

#[test]
fn test_nhi_delegation_chain_exceeds_max() {
    let chain = NhiDelegationChain {
        chain: vec![NhiDelegationLink {
            from_agent: "a".to_string(),
            to_agent: "b".to_string(),
            permissions: vec![],
            scope_constraints: vec![],
            created_at: "".to_string(),
            expires_at: "".to_string(),
            active: true,
            reason: None,
        }],
        max_depth: 0, // Max depth of 0 means no delegation allowed
        resolved_at: "".to_string(),
    };
    assert!(chain.exceeds_max_depth());
}

#[test]
fn test_nhi_dpop_proof_serialization() {
    let proof = NhiDpopProof {
        proof: "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0...".to_string(),
        htm: "POST".to_string(),
        htu: "https://api.example.com/resource".to_string(),
        ath: Some("fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo".to_string()),
        nonce: Some("server-nonce-123".to_string()),
        iat: "2026-02-01T12:00:00Z".to_string(),
        jti: "unique-id-456".to_string(),
    };
    let json_str = serde_json::to_string(&proof).unwrap();
    let deserialized: NhiDpopProof = serde_json::from_str(&json_str).unwrap();
    assert_eq!(proof, deserialized);
}

#[test]
fn test_nhi_stats_default() {
    let stats = NhiStats::default();
    assert_eq!(stats.total_identities, 0);
    assert_eq!(stats.active_identities, 0);
    assert_eq!(stats.active_delegations, 0);
}

#[test]
fn test_nhi_credential_rotation_serialization() {
    let rotation = NhiCredentialRotation {
        agent_id: "agent-123".to_string(),
        previous_thumbprint: Some("old-thumb".to_string()),
        new_thumbprint: "new-thumb".to_string(),
        rotated_at: "2026-02-01T00:00:00Z".to_string(),
        trigger: "scheduled".to_string(),
        new_expires_at: "2027-02-01T00:00:00Z".to_string(),
    };
    let json_str = serde_json::to_string(&rotation).unwrap();
    let deserialized: NhiCredentialRotation = serde_json::from_str(&json_str).unwrap();
    assert_eq!(rotation, deserialized);
}

#[test]
fn test_evaluation_context_builder() {
    // Test basic builder usage
    let ctx = EvaluationContext::builder()
        .agent_id("agent-123")
        .tenant_id("tenant-abc")
        .build();
    assert_eq!(ctx.agent_id, Some("agent-123".to_string()));
    assert_eq!(ctx.tenant_id, Some("tenant-abc".to_string()));
    assert!(ctx.call_counts.is_empty());
    assert!(ctx.previous_actions.is_empty());
}

#[test]
fn test_evaluation_context_builder_call_counts() {
    let ctx = EvaluationContext::builder()
        .call_count("read_file", 5)
        .call_count("write_file", 3)
        .build();
    assert_eq!(ctx.call_counts.get("read_file"), Some(&5));
    assert_eq!(ctx.call_counts.get("write_file"), Some(&3));
}

#[test]
fn test_evaluation_context_builder_previous_actions() {
    let ctx = EvaluationContext::builder()
        .previous_action("read_file")
        .previous_action("process_data")
        .previous_action("write_file")
        .build();
    assert_eq!(ctx.previous_actions.len(), 3);
    assert_eq!(ctx.previous_actions[0], "read_file");
    assert_eq!(ctx.previous_actions[2], "write_file");
}

#[test]
fn test_evaluation_context_builder_has_meaningful_fields() {
    // Empty builder produces context with no meaningful fields
    let empty_ctx = EvaluationContext::builder().build();
    assert!(!empty_ctx.has_any_meaningful_fields());

    // Context with agent_id has meaningful fields
    let ctx_with_agent = EvaluationContext::builder().agent_id("agent-1").build();
    assert!(ctx_with_agent.has_any_meaningful_fields());

    // Context with timestamp has meaningful fields
    let ctx_with_timestamp = EvaluationContext::builder()
        .timestamp("2025-01-15T10:00:00Z")
        .build();
    assert!(ctx_with_timestamp.has_any_meaningful_fields());
}

// --- Extension types tests ---

#[test]
fn test_extension_descriptor_serde_roundtrip() {
    let desc = ExtensionDescriptor {
        id: "vellaveto-audit".to_string(),
        name: "Audit Query Extension".to_string(),
        version: "1.0.0".to_string(),
        capabilities: vec!["read".to_string()],
        methods: vec!["x-vellaveto-audit/stats".to_string()],
        signature: None,
        public_key: None,
    };
    let json_str = serde_json::to_string(&desc).unwrap();
    let deserialized: ExtensionDescriptor = serde_json::from_str(&json_str).unwrap();
    assert_eq!(desc, deserialized);
}

#[test]
fn test_extension_descriptor_validate_valid() {
    let desc = ExtensionDescriptor {
        id: "my-ext".to_string(),
        name: "My Extension".to_string(),
        version: "0.1.0".to_string(),
        capabilities: vec![],
        methods: vec!["x-my-ext/do-thing".to_string()],
        signature: None,
        public_key: None,
    };
    assert!(desc.validate().is_ok());
}

#[test]
fn test_extension_descriptor_validate_empty_id() {
    let desc = ExtensionDescriptor {
        id: "".to_string(),
        name: "My Extension".to_string(),
        version: "0.1.0".to_string(),
        capabilities: vec![],
        methods: vec![],
        signature: None,
        public_key: None,
    };
    let err = desc.validate().unwrap_err();
    assert!(err.to_string().contains("id must not be empty"));
}

#[test]
fn test_extension_descriptor_validate_empty_name() {
    let desc = ExtensionDescriptor {
        id: "my-ext".to_string(),
        name: "".to_string(),
        version: "0.1.0".to_string(),
        capabilities: vec![],
        methods: vec![],
        signature: None,
        public_key: None,
    };
    let err = desc.validate().unwrap_err();
    assert!(err.to_string().contains("name must not be empty"));
}

#[test]
fn test_extension_resource_limits_defaults() {
    let limits = ExtensionResourceLimits::default();
    assert_eq!(limits.max_concurrent_requests, 10);
    assert_eq!(limits.max_requests_per_sec, 100);
}

#[test]
fn test_extension_negotiation_result_serde() {
    let result = ExtensionNegotiationResult {
        accepted: vec!["ext-a".to_string()],
        rejected: vec![("ext-b".to_string(), "blocked".to_string())],
    };
    let json_str = serde_json::to_string(&result).unwrap();
    let deserialized: ExtensionNegotiationResult = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.accepted, vec!["ext-a"]);
    assert_eq!(deserialized.rejected.len(), 1);
    assert_eq!(deserialized.rejected[0].0, "ext-b");
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 18: Transport & SDK Tier types
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_transport_protocol_ordering() {
    // gRPC > WebSocket > HTTP > stdio
    assert!(TransportProtocol::Grpc < TransportProtocol::WebSocket);
    assert!(TransportProtocol::WebSocket < TransportProtocol::Http);
    assert!(TransportProtocol::Http < TransportProtocol::Stdio);
}

#[test]
fn test_sdk_tier_ordering() {
    assert!(SdkTier::Core < SdkTier::Standard);
    assert!(SdkTier::Standard < SdkTier::Extended);
    assert!(SdkTier::Extended < SdkTier::Full);
}

#[test]
fn test_transport_endpoint_serde_roundtrip() {
    let endpoint = TransportEndpoint {
        protocol: TransportProtocol::WebSocket,
        url: "ws://localhost:3001/mcp/ws".to_string(),
        available: true,
        protocol_versions: vec!["2026-06".to_string(), "2025-11-25".to_string()],
    };
    let json_str = serde_json::to_string(&endpoint).unwrap();
    let deserialized: TransportEndpoint = serde_json::from_str(&json_str).unwrap();
    assert_eq!(endpoint, deserialized);
    // Verify lowercase rename
    assert!(json_str.contains("\"websocket\""));
}

#[test]
fn test_sdk_capabilities_serde_roundtrip() {
    let caps = SdkCapabilities {
        tier: SdkTier::Extended,
        capabilities: vec!["policy-evaluation".to_string(), "dlp-scanning".to_string()],
        supported_versions: vec!["2026-06".to_string()],
    };
    let json_str = serde_json::to_string(&caps).unwrap();
    let deserialized: SdkCapabilities = serde_json::from_str(&json_str).unwrap();
    assert_eq!(caps, deserialized);
    assert!(json_str.contains("\"extended\""));
}

// ═══════════════════════════════════════════════════
// PHASE 29: TRANSPORT FALLBACK TYPES TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_transport_attempt_serde_roundtrip_success() {
    let attempt = TransportAttempt {
        protocol: TransportProtocol::Grpc,
        endpoint_url: "http://localhost:50051".to_string(),
        succeeded: true,
        duration_ms: 12,
        error: None,
    };
    let json_str = serde_json::to_string(&attempt).unwrap();
    let deserialized: TransportAttempt = serde_json::from_str(&json_str).unwrap();
    assert_eq!(attempt, deserialized);
    assert!(json_str.contains("\"grpc\""));
}

#[test]
fn test_transport_attempt_serde_roundtrip_failure() {
    let attempt = TransportAttempt {
        protocol: TransportProtocol::WebSocket,
        endpoint_url: "ws://localhost:3001/mcp/ws".to_string(),
        succeeded: false,
        duration_ms: 5000,
        error: Some("connection refused".to_string()),
    };
    let json_str = serde_json::to_string(&attempt).unwrap();
    let deserialized: TransportAttempt = serde_json::from_str(&json_str).unwrap();
    assert_eq!(attempt, deserialized);
    assert!(json_str.contains("connection refused"));
}

#[test]
fn test_fallback_negotiation_history_serde_roundtrip() {
    let history = FallbackNegotiationHistory {
        attempts: vec![
            TransportAttempt {
                protocol: TransportProtocol::Grpc,
                endpoint_url: "http://localhost:50051".to_string(),
                succeeded: false,
                duration_ms: 30,
                error: Some("circuit open".to_string()),
            },
            TransportAttempt {
                protocol: TransportProtocol::Http,
                endpoint_url: "http://localhost:3001/mcp".to_string(),
                succeeded: true,
                duration_ms: 15,
                error: None,
            },
        ],
        successful_transport: Some(TransportProtocol::Http),
        total_duration_ms: 45,
    };
    let json_str = serde_json::to_string(&history).unwrap();
    let deserialized: FallbackNegotiationHistory = serde_json::from_str(&json_str).unwrap();
    assert_eq!(history, deserialized);
}

#[test]
fn test_fallback_negotiation_history_all_failed() {
    let history = FallbackNegotiationHistory {
        attempts: vec![TransportAttempt {
            protocol: TransportProtocol::Http,
            endpoint_url: "http://localhost:3001/mcp".to_string(),
            succeeded: false,
            duration_ms: 5000,
            error: Some("timeout".to_string()),
        }],
        successful_transport: None,
        total_duration_ms: 5000,
    };
    assert!(history.successful_transport.is_none());
    assert_eq!(history.attempts.len(), 1);
}

#[test]
fn test_fallback_negotiation_history_empty_attempts() {
    let history = FallbackNegotiationHistory {
        attempts: Vec::new(),
        successful_transport: None,
        total_duration_ms: 0,
    };
    let json_str = serde_json::to_string(&history).unwrap();
    let deserialized: FallbackNegotiationHistory = serde_json::from_str(&json_str).unwrap();
    assert_eq!(history, deserialized);
    assert!(deserialized.attempts.is_empty());
}

#[test]
fn test_transport_attempt_zero_duration() {
    let attempt = TransportAttempt {
        protocol: TransportProtocol::Stdio,
        endpoint_url: "stdio://local".to_string(),
        succeeded: true,
        duration_ms: 0,
        error: None,
    };
    let json_str = serde_json::to_string(&attempt).unwrap();
    assert!(json_str.contains("\"stdio\""));
    let deserialized: TransportAttempt = serde_json::from_str(&json_str).unwrap();
    assert_eq!(attempt, deserialized);
}

// ═══════════════════════════════════════════════════
// PHASE 20: GATEWAY TYPES TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_backend_health_serde_roundtrip() {
    for health in [
        BackendHealth::Healthy,
        BackendHealth::Degraded,
        BackendHealth::Unhealthy,
    ] {
        let json_str = serde_json::to_string(&health).unwrap();
        let deserialized: BackendHealth = serde_json::from_str(&json_str).unwrap();
        assert_eq!(health, deserialized);
    }
    // Verify lowercase serialization
    assert_eq!(
        serde_json::to_string(&BackendHealth::Healthy).unwrap(),
        "\"healthy\""
    );
}

#[test]
fn test_upstream_backend_serde_roundtrip() {
    let backend = UpstreamBackend {
        id: "backend-1".to_string(),
        url: "http://localhost:8001/mcp".to_string(),
        tool_prefixes: vec!["fs_".to_string(), "file_".to_string()],
        weight: 80,
        health: BackendHealth::Healthy,
    };
    let json_str = serde_json::to_string(&backend).unwrap();
    let deserialized: UpstreamBackend = serde_json::from_str(&json_str).unwrap();
    assert_eq!(backend.id, deserialized.id);
    assert_eq!(backend.url, deserialized.url);
    assert_eq!(backend.tool_prefixes, deserialized.tool_prefixes);
    assert_eq!(backend.weight, deserialized.weight);
    // Health is skip(deserialize), so it defaults to Healthy
    assert_eq!(deserialized.health, BackendHealth::Healthy);
}

#[test]
fn test_upstream_backend_default_weight() {
    let json_str = r#"{"id":"b","url":"http://localhost:8000","tool_prefixes":[]}"#;
    let backend: UpstreamBackend = serde_json::from_str(json_str).unwrap();
    assert_eq!(backend.weight, 100);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 21: ABAC types tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_abac_effect_serde_roundtrip() {
    let permit = AbacEffect::Permit;
    let forbid = AbacEffect::Forbid;
    let permit_json = serde_json::to_string(&permit).unwrap();
    let forbid_json = serde_json::to_string(&forbid).unwrap();
    assert_eq!(permit_json, r#""permit""#);
    assert_eq!(forbid_json, r#""forbid""#);
    let p: AbacEffect = serde_json::from_str(&permit_json).unwrap();
    let f: AbacEffect = serde_json::from_str(&forbid_json).unwrap();
    assert_eq!(p, AbacEffect::Permit);
    assert_eq!(f, AbacEffect::Forbid);
}

#[test]
fn test_abac_policy_serde_roundtrip() {
    let policy = AbacPolicy {
        id: "policy-1".to_string(),
        description: "Allow agents to read files".to_string(),
        effect: AbacEffect::Permit,
        priority: 100,
        principal: PrincipalConstraint {
            principal_type: Some("Agent".to_string()),
            id_patterns: vec!["code-*".to_string()],
            claims: HashMap::new(),
        },
        action: ActionConstraint {
            patterns: vec!["filesystem:read_*".to_string()],
        },
        resource: ResourceConstraint {
            path_patterns: vec!["/home/**".to_string()],
            domain_patterns: vec![],
            tags: vec![],
        },
        conditions: vec![AbacCondition {
            field: "context.verified".to_string(),
            op: AbacOp::Eq,
            value: json!(true),
        }],
    };
    let json_str = serde_json::to_string(&policy).unwrap();
    let deserialized: AbacPolicy = serde_json::from_str(&json_str).unwrap();
    assert_eq!(policy, deserialized);
}

#[test]
fn test_risk_score_defaults() {
    let score = RiskScore {
        score: 0.42,
        factors: vec![],
        updated_at: "2026-02-14T00:00:00Z".to_string(),
    };
    assert_eq!(score.score, 0.42);
    assert!(score.factors.is_empty());
}

#[test]
fn test_abac_op_all_variants() {
    let ops = vec![
        AbacOp::Eq,
        AbacOp::Ne,
        AbacOp::In,
        AbacOp::NotIn,
        AbacOp::Contains,
        AbacOp::StartsWith,
        AbacOp::Gt,
        AbacOp::Lt,
        AbacOp::Gte,
        AbacOp::Lte,
    ];
    for op in ops {
        let json_str = serde_json::to_string(&op).unwrap();
        let deserialized: AbacOp = serde_json::from_str(&json_str).unwrap();
        assert_eq!(op, deserialized);
    }
}

#[test]
fn test_abac_entity_with_parents() {
    let entity = AbacEntity {
        entity_type: "Agent".to_string(),
        id: "agent-42".to_string(),
        attributes: {
            let mut m = HashMap::new();
            m.insert("team".to_string(), json!("security"));
            m
        },
        parents: vec!["Group::admins".to_string()],
    };
    let json_str = serde_json::to_string(&entity).unwrap();
    let deserialized: AbacEntity = serde_json::from_str(&json_str).unwrap();
    assert_eq!(entity, deserialized);
    assert_eq!(deserialized.parents.len(), 1);
}

// ═══════════════════════════════════════════════════
// PHASE 24: EU AI ACT FINAL COMPLIANCE TYPES TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_explanation_verbosity_default() {
    let v = ExplanationVerbosity::default();
    assert_eq!(v, ExplanationVerbosity::None);
}

#[test]
fn test_explanation_verbosity_display() {
    assert_eq!(ExplanationVerbosity::None.to_string(), "none");
    assert_eq!(ExplanationVerbosity::Summary.to_string(), "summary");
    assert_eq!(ExplanationVerbosity::Full.to_string(), "full");
}

#[test]
fn test_explanation_verbosity_serde_roundtrip() {
    for v in [
        ExplanationVerbosity::None,
        ExplanationVerbosity::Summary,
        ExplanationVerbosity::Full,
    ] {
        let json_str = serde_json::to_string(&v).unwrap();
        let deserialized: ExplanationVerbosity = serde_json::from_str(&json_str).unwrap();
        assert_eq!(v, deserialized);
    }
    // Verify rename_all = "snake_case"
    assert_eq!(
        serde_json::to_string(&ExplanationVerbosity::None).unwrap(),
        r#""none""#
    );
}

#[test]
fn test_data_classification_display_and_serde() {
    let all = vec![
        DataClassification::Training,
        DataClassification::Input,
        DataClassification::Output,
        DataClassification::Testing,
        DataClassification::Operational,
        DataClassification::Personal,
        DataClassification::NonPersonal,
    ];
    for dc in all {
        let json_str = serde_json::to_string(&dc).unwrap();
        let deserialized: DataClassification = serde_json::from_str(&json_str).unwrap();
        assert_eq!(dc, deserialized);
        assert!(!dc.to_string().is_empty());
    }
}

#[test]
fn test_processing_purpose_display_and_serde() {
    let all = vec![
        ProcessingPurpose::ToolExecution,
        ProcessingPurpose::SecurityAudit,
        ProcessingPurpose::ComplianceEvidence,
        ProcessingPurpose::PolicyEvaluation,
        ProcessingPurpose::ModelInference,
    ];
    for pp in all {
        let json_str = serde_json::to_string(&pp).unwrap();
        let deserialized: ProcessingPurpose = serde_json::from_str(&json_str).unwrap();
        assert_eq!(pp, deserialized);
        assert!(!pp.to_string().is_empty());
    }
}

#[test]
fn test_data_governance_record_serde_roundtrip() {
    let record = DataGovernanceRecord {
        tool: "filesystem.*".to_string(),
        classifications: vec![DataClassification::Input, DataClassification::Output],
        purpose: ProcessingPurpose::ToolExecution,
        provenance: Some("user-provided".to_string()),
        retention_days: Some(365),
    };
    let json_str = serde_json::to_string(&record).unwrap();
    let deserialized: DataGovernanceRecord = serde_json::from_str(&json_str).unwrap();
    assert_eq!(record, deserialized);
}

#[test]
fn test_data_governance_record_optional_fields() {
    let record = DataGovernanceRecord {
        tool: "http.*".to_string(),
        classifications: vec![DataClassification::Operational],
        purpose: ProcessingPurpose::SecurityAudit,
        provenance: None,
        retention_days: None,
    };
    let json_str = serde_json::to_string(&record).unwrap();
    // Optional fields should be skipped
    assert!(!json_str.contains("provenance"));
    assert!(!json_str.contains("retention_days"));
}

#[test]
fn test_verdict_explanation_summary() {
    let trace = EvaluationTrace {
        action_summary: ActionSummary {
            tool: "read_file".to_string(),
            function: "execute".to_string(),
            param_count: 1,
            param_keys: vec!["path".to_string()],
        },
        policies_checked: 3,
        policies_matched: 1,
        matches: vec![PolicyMatch {
            policy_id: "p1".to_string(),
            policy_name: "Allow reads".to_string(),
            policy_type: "Allow".to_string(),
            priority: 100,
            tool_matched: true,
            constraint_results: vec![],
            verdict_contribution: Some(Verdict::Allow),
        }],
        verdict: Verdict::Allow,
        duration_us: 42,
    };
    let explanation = VerdictExplanation::summary(&trace);
    assert_eq!(explanation.verdict, "Allow");
    assert!(explanation.reason.is_none());
    assert_eq!(explanation.policies_checked, 3);
    assert_eq!(explanation.policies_matched, 1);
    assert_eq!(explanation.duration_us, 42);
    assert!(explanation.policy_details.is_none());
}

#[test]
fn test_verdict_explanation_full_with_failed_constraints() {
    let trace = EvaluationTrace {
        action_summary: ActionSummary {
            tool: "shell".to_string(),
            function: "exec".to_string(),
            param_count: 1,
            param_keys: vec!["cmd".to_string()],
        },
        policies_checked: 2,
        policies_matched: 1,
        matches: vec![PolicyMatch {
            policy_id: "deny-shell".to_string(),
            policy_name: "Block shell".to_string(),
            policy_type: "Deny".to_string(),
            priority: 200,
            tool_matched: true,
            constraint_results: vec![ConstraintResult {
                constraint_type: "tool_pattern".to_string(),
                param: "tool".to_string(),
                expected: "shell*".to_string(),
                actual: "shell".to_string(),
                passed: false,
            }],
            verdict_contribution: Some(Verdict::Deny {
                reason: "blocked by policy".to_string(),
            }),
        }],
        verdict: Verdict::Deny {
            reason: "blocked by policy".to_string(),
        },
        duration_us: 55,
    };
    let explanation = VerdictExplanation::full(&trace);
    assert_eq!(explanation.verdict, "Deny");
    assert_eq!(explanation.reason, Some("blocked by policy".to_string()));
    let details = explanation.policy_details.unwrap();
    assert_eq!(details.len(), 1);
    assert_eq!(details[0].policy_id, "deny-shell");
    assert!(details[0].failed_constraints.is_some());
    assert_eq!(details[0].failed_constraints.as_ref().unwrap().len(), 1);
}

#[test]
fn test_verdict_explanation_serde_roundtrip() {
    let explanation = VerdictExplanation {
        verdict: "Allow".to_string(),
        reason: None,
        policies_checked: 5,
        policies_matched: 2,
        duration_us: 100,
        policy_details: Some(vec![PolicyMatchDetail {
            policy_id: "p1".to_string(),
            policy_name: "Test".to_string(),
            priority: 50,
            verdict_contribution: Some("Allow".to_string()),
            failed_constraints: None,
        }]),
    };
    let json_str = serde_json::to_string(&explanation).unwrap();
    let deserialized: VerdictExplanation = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.policies_checked, 5);
    assert!(deserialized.policy_details.is_some());
}

// ═══════════════════════════════════════════════════
// Phase 25.6: RequestContext trait and StatelessContextBlob tests
// ═══════════════════════════════════════════════════

/// Phase 25.6: StatelessContextBlob serialization roundtrip.
#[test]
fn test_stateless_blob_roundtrip() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-123".to_string(),
        call_counts: {
            let mut m = HashMap::new();
            m.insert("read_file".to_string(), 5);
            m.insert("write_file".to_string(), 2);
            m
        },
        recent_actions: vec!["read_file".to_string(), "write_file".to_string()],
        call_chain: vec![CallChainEntry {
            agent_id: "upstream-1".to_string(),
            tool: "read_file".to_string(),
            function: "read".to_string(),
            timestamp: "2026-02-15T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        risk_score: None,
        issued_at: 1739613600,
        signature: "deadbeef".to_string(),
    };

    let json_str = serde_json::to_string(&blob).unwrap();
    let deserialized: StatelessContextBlob = serde_json::from_str(&json_str).unwrap();

    assert_eq!(deserialized.version, 1);
    assert_eq!(deserialized.agent_id, "agent-123");
    assert_eq!(deserialized.call_counts.len(), 2);
    assert_eq!(deserialized.call_counts["read_file"], 5);
    assert_eq!(deserialized.recent_actions.len(), 2);
    assert_eq!(deserialized.call_chain.len(), 1);
    assert_eq!(deserialized.issued_at, 1739613600);
    assert_eq!(deserialized.signature, "deadbeef");
}

/// Phase 25.6: Expired blob detection.
#[test]
fn test_stateless_blob_expiry() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: String::new(),
    };

    // 301 seconds later — expired (max age is 300)
    assert!(blob.is_expired(1301));
    // 300 seconds later — not expired (boundary)
    assert!(!blob.is_expired(1300));
    // Same time — not expired
    assert!(!blob.is_expired(1000));
}

/// Phase 25.6: StatelessContextBlob implements RequestContext.
#[test]
fn test_stateless_blob_request_context_trait() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-ctx".to_string(),
        call_counts: {
            let mut m = HashMap::new();
            m.insert("tool_a".to_string(), 3);
            m
        },
        recent_actions: vec!["tool_a".to_string(), "tool_b".to_string()],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: String::new(),
    };

    // Test via trait
    let ctx: &dyn RequestContext = &blob;
    assert_eq!(ctx.call_counts()["tool_a"], 3);
    assert_eq!(ctx.previous_actions().len(), 2);
    assert!(ctx.call_chain().is_empty());
    assert!(ctx.agent_identity().is_none());
    assert!(ctx.session_guard_state().is_none());
    assert!(ctx.risk_score().is_none());
}

/// Phase 25.6: EvaluationContext built from StatelessContextBlob via trait.
#[test]
fn test_evaluation_context_from_stateless() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-eval".to_string(),
        call_counts: {
            let mut m = HashMap::new();
            m.insert("read".to_string(), 10);
            m
        },
        recent_actions: vec!["read".to_string()],
        call_chain: vec![CallChainEntry {
            agent_id: "hop-1".to_string(),
            tool: "read".to_string(),
            function: "get".to_string(),
            timestamp: "2026-02-15T12:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        risk_score: None,
        issued_at: 1000,
        signature: String::new(),
    };

    let eval_ctx = blob.to_evaluation_context();
    assert_eq!(eval_ctx.call_counts["read"], 10);
    assert_eq!(eval_ctx.previous_actions, vec!["read".to_string()]);
    assert_eq!(eval_ctx.call_chain.len(), 1);
    assert_eq!(eval_ctx.call_chain[0].agent_id, "hop-1");
    // Stateless blob doesn't carry agent_identity or session_state
    assert!(eval_ctx.agent_identity.is_none());
    assert!(eval_ctx.session_state.is_none());
}

// ═══════════════════════════════════════════════════
// Phase 27: Deployment types serde tests
// ═══════════════════════════════════════════════════

#[test]
fn test_leader_status_leader_roundtrip() {
    let status = LeaderStatus::Leader {
        since: "2026-02-15T10:00:00Z".to_string(),
    };
    let json_str = serde_json::to_string(&status).unwrap();
    let deserialized: LeaderStatus = serde_json::from_str(&json_str).unwrap();
    assert_eq!(status, deserialized);
}

#[test]
fn test_leader_status_follower_roundtrip() {
    let status = LeaderStatus::Follower {
        leader_id: Some("vellaveto-0".to_string()),
    };
    let json_str = serde_json::to_string(&status).unwrap();
    let deserialized: LeaderStatus = serde_json::from_str(&json_str).unwrap();
    assert_eq!(status, deserialized);
}

#[test]
fn test_leader_status_follower_no_leader_roundtrip() {
    let status = LeaderStatus::Follower { leader_id: None };
    let json_str = serde_json::to_string(&status).unwrap();
    let deserialized: LeaderStatus = serde_json::from_str(&json_str).unwrap();
    assert_eq!(status, deserialized);
}

#[test]
fn test_leader_status_unknown_roundtrip() {
    let status = LeaderStatus::Unknown;
    let json_str = serde_json::to_string(&status).unwrap();
    let deserialized: LeaderStatus = serde_json::from_str(&json_str).unwrap();
    assert_eq!(status, deserialized);
}

#[test]
fn test_leader_status_default_is_unknown() {
    let status = LeaderStatus::default();
    assert_eq!(status, LeaderStatus::Unknown);
}

#[test]
fn test_service_endpoint_roundtrip() {
    let mut labels = HashMap::new();
    labels.insert("region".to_string(), "us-east-1".to_string());
    let ep = ServiceEndpoint {
        id: "vellaveto-0".to_string(),
        url: "http://vellaveto-0.vellaveto:3000".to_string(),
        labels,
        healthy: true,
    };
    let json_str = serde_json::to_string(&ep).unwrap();
    let deserialized: ServiceEndpoint = serde_json::from_str(&json_str).unwrap();
    assert_eq!(ep, deserialized);
}

#[test]
fn test_service_endpoint_empty_labels_skipped() {
    let ep = ServiceEndpoint {
        id: "node-1".to_string(),
        url: "http://node-1:3000".to_string(),
        labels: HashMap::new(),
        healthy: false,
    };
    let json_str = serde_json::to_string(&ep).unwrap();
    assert!(!json_str.contains("labels"), "empty labels should be skipped");
}

#[test]
fn test_discovery_event_added_roundtrip() {
    let event = DiscoveryEvent::Added(ServiceEndpoint {
        id: "pod-1".to_string(),
        url: "http://pod-1:3000".to_string(),
        labels: HashMap::new(),
        healthy: true,
    });
    let json_str = serde_json::to_string(&event).unwrap();
    let deserialized: DiscoveryEvent = serde_json::from_str(&json_str).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn test_discovery_event_removed_roundtrip() {
    let event = DiscoveryEvent::Removed {
        id: "pod-2".to_string(),
    };
    let json_str = serde_json::to_string(&event).unwrap();
    let deserialized: DiscoveryEvent = serde_json::from_str(&json_str).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn test_discovery_event_updated_roundtrip() {
    let event = DiscoveryEvent::Updated(ServiceEndpoint {
        id: "pod-3".to_string(),
        url: "http://pod-3:3000".to_string(),
        labels: HashMap::new(),
        healthy: false,
    });
    let json_str = serde_json::to_string(&event).unwrap();
    let deserialized: DiscoveryEvent = serde_json::from_str(&json_str).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn test_deployment_info_roundtrip() {
    let info = DeploymentInfo {
        instance_id: "vellaveto-0".to_string(),
        leader_status: LeaderStatus::Leader {
            since: "2026-02-15T10:00:00Z".to_string(),
        },
        discovered_endpoints: 3,
        uptime_secs: 86400,
        mode: "kubernetes".to_string(),
    };
    let json_str = serde_json::to_string(&info).unwrap();
    let deserialized: DeploymentInfo = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.instance_id, "vellaveto-0");
    assert_eq!(deserialized.discovered_endpoints, 3);
    assert_eq!(deserialized.uptime_secs, 86400);
    assert_eq!(deserialized.mode, "kubernetes");
}
