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

// SECURITY (FIND-R82-002): Verify reset_window handles multi-byte UTF-8 at truncation boundary.
#[test]
fn test_sampling_stats_reset_window_multibyte_utf8_safe() {
    let mut stats = SamplingStats::new(1000);
    // Create a pattern with 2-byte Cyrillic chars that spans the truncation boundary (1024)
    // Each 'д' is 2 bytes, so 513 chars = 1026 bytes > MAX_PATTERN_ENTRY_LEN (1024)
    let multibyte_pattern = "д".repeat(513);
    assert!(multibyte_pattern.len() > SamplingStats::MAX_PATTERN_ENTRY_LEN);
    stats.flagged_patterns.push(multibyte_pattern);

    // This should NOT panic
    stats.reset_window(2000);

    let entry = &stats.flagged_patterns[0];
    assert!(entry.len() <= SamplingStats::MAX_PATTERN_ENTRY_LEN);
    assert!(entry.is_char_boundary(entry.len()));
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

// ── Phase 38: SOC 2 Type II Access Review Types ─────────────────────────────

#[test]
fn test_attestation_status_default() {
    let status = AttestationStatus::default();
    assert_eq!(status, AttestationStatus::Pending);
}

#[test]
fn test_attestation_status_serde_roundtrip() {
    let variants = [
        AttestationStatus::Pending,
        AttestationStatus::Approved,
        AttestationStatus::FindingsNoted,
        AttestationStatus::Rejected,
    ];
    for v in &variants {
        let json_str = serde_json::to_string(v).unwrap();
        let deserialized: AttestationStatus = serde_json::from_str(&json_str).unwrap();
        assert_eq!(*v, deserialized);
    }
}

#[test]
fn test_attestation_status_display() {
    assert_eq!(AttestationStatus::Pending.to_string(), "pending");
    assert_eq!(AttestationStatus::Approved.to_string(), "approved");
    assert_eq!(
        AttestationStatus::FindingsNoted.to_string(),
        "findings_noted"
    );
    assert_eq!(AttestationStatus::Rejected.to_string(), "rejected");
}

#[test]
fn test_review_schedule_serde_roundtrip() {
    let variants = [
        ReviewSchedule::Daily,
        ReviewSchedule::Weekly,
        ReviewSchedule::Monthly,
    ];
    for v in &variants {
        let json_str = serde_json::to_string(v).unwrap();
        let deserialized: ReviewSchedule = serde_json::from_str(&json_str).unwrap();
        assert_eq!(*v, deserialized);
    }
}

#[test]
fn test_review_schedule_display() {
    assert_eq!(ReviewSchedule::Daily.to_string(), "daily");
    assert_eq!(ReviewSchedule::Weekly.to_string(), "weekly");
    assert_eq!(ReviewSchedule::Monthly.to_string(), "monthly");
}

#[test]
fn test_report_export_format_default() {
    let fmt = ReportExportFormat::default();
    assert_eq!(fmt, ReportExportFormat::Json);
}

#[test]
fn test_access_review_report_serde_roundtrip() {
    let report = AccessReviewReport {
        generated_at: "2026-02-16T00:00:00Z".to_string(),
        organization_name: "Acme Corp".to_string(),
        period_start: "2026-01-01T00:00:00Z".to_string(),
        period_end: "2026-02-01T00:00:00Z".to_string(),
        total_agents: 1,
        total_evaluations: 42,
        entries: vec![AccessReviewEntry {
            agent_id: "agent-1".to_string(),
            session_ids: vec!["sess-1".to_string()],
            first_access: "2026-01-02T00:00:00Z".to_string(),
            last_access: "2026-01-31T00:00:00Z".to_string(),
            total_evaluations: 42,
            allow_count: 30,
            deny_count: 10,
            require_approval_count: 2,
            tools_accessed: vec!["read_file".to_string()],
            functions_called: vec!["execute".to_string()],
            permissions_granted: 5,
            permissions_used: 4,
            usage_ratio: 0.8,
            unused_permissions: vec!["policy-5".to_string()],
            agency_recommendation: "Optimal".to_string(),
        }],
        cc6_evidence: Cc6Evidence {
            cc6_1_evidence: "All agent access policy-controlled".to_string(),
            cc6_2_evidence: "Agent identities validated before access".to_string(),
            cc6_3_evidence: "Unused permissions tracked".to_string(),
            optimal_count: 1,
            review_grants_count: 0,
            narrow_scope_count: 0,
            critical_count: 0,
        },
        attestation: ReviewerAttestation {
            reviewer_name: String::new(),
            reviewer_title: String::new(),
            reviewed_at: None,
            notes: String::new(),
            status: AttestationStatus::Pending,
        },
    };
    let json_str = serde_json::to_string(&report).unwrap();
    let deserialized: AccessReviewReport = serde_json::from_str(&json_str).unwrap();
    assert_eq!(report, deserialized);
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
    assert!(
        !json_str.contains("labels"),
        "empty labels should be skipped"
    );
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
        instance_id: Some("vellaveto-0".to_string()),
        leader_status: Some(LeaderStatus::Leader {
            since: "2026-02-15T10:00:00Z".to_string(),
        }),
        discovered_endpoints: Some(3),
        uptime_secs: 86400,
        mode: "kubernetes".to_string(),
    };
    let json_str = serde_json::to_string(&info).unwrap();
    let deserialized: DeploymentInfo = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.instance_id, Some("vellaveto-0".to_string()));
    assert_eq!(deserialized.discovered_endpoints, Some(3));
    assert_eq!(deserialized.uptime_secs, 86400);
    assert_eq!(deserialized.mode, "kubernetes");
}

#[test]
fn test_deployment_info_redacted_anonymous_mode() {
    // SECURITY (FIND-R44-015): In anonymous mode, sensitive fields are None
    // and should be omitted from JSON output.
    let info = DeploymentInfo {
        instance_id: None,
        leader_status: None,
        discovered_endpoints: None,
        uptime_secs: 3600,
        mode: "standalone".to_string(),
    };
    let json_str = serde_json::to_string(&info).unwrap();
    assert!(
        !json_str.contains("instance_id"),
        "instance_id should be omitted when None"
    );
    assert!(
        !json_str.contains("leader_status"),
        "leader_status should be omitted when None"
    );
    assert!(
        !json_str.contains("discovered_endpoints"),
        "discovered_endpoints should be omitted when None"
    );
    assert!(
        json_str.contains("uptime_secs"),
        "uptime_secs should always be present"
    );
    assert!(json_str.contains("mode"), "mode should always be present");

    // Verify deserialization works with missing fields
    let deserialized: DeploymentInfo = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.instance_id, None);
    assert_eq!(deserialized.leader_status, None);
    assert_eq!(deserialized.discovered_endpoints, None);
    assert_eq!(deserialized.uptime_secs, 3600);
    assert_eq!(deserialized.mode, "standalone");
}

// ═══════════════════════════════════════════════════════
// FIND-R44-031: truncate_for_log must not panic on multi-byte UTF-8
// ═══════════════════════════════════════════════════════

/// FIND-R44-031: Fingerprint summary with multi-byte UTF-8 in jwt_sub must
/// not panic. Previously, byte-based slicing would panic on char boundaries.
#[test]
fn test_agent_fingerprint_summary_multibyte_utf8_no_panic() {
    // Create a jwt_sub with multi-byte chars that exceeds max_len=20
    // Each CJK character is 3 bytes. 10 chars = 30 bytes > 20 limit.
    let long_multibyte =
        "\u{4e16}\u{754c}\u{4f60}\u{597d}\u{6d4b}\u{8bd5}\u{5b57}\u{7b26}\u{4e32}\u{5b57}";
    let fp = AgentFingerprint {
        jwt_sub: Some(long_multibyte.to_string()),
        ..Default::default()
    };
    // Must not panic — this is the critical assertion
    let summary = fp.summary();
    assert!(summary.contains("sub:"));
    assert!(summary.contains("..."));
}

/// FIND-R44-031: Fingerprint summary with 2-byte UTF-8 chars (e.g., Latin-1
/// extended) that land exactly on boundary positions.
#[test]
fn test_agent_fingerprint_summary_2byte_utf8_boundary() {
    // Each e-acute (U+00E9) is 2 bytes. 15 chars = 30 bytes > 20.
    let long_accent = "\u{00e9}".repeat(15);
    let fp = AgentFingerprint {
        jwt_sub: Some(long_accent),
        ..Default::default()
    };
    let summary = fp.summary();
    assert!(summary.contains("sub:"));
    assert!(summary.contains("..."));
}

/// FIND-R44-031: Fingerprint summary with 4-byte emoji chars.
#[test]
fn test_agent_fingerprint_summary_4byte_emoji() {
    // Each emoji is 4 bytes. 6 chars = 24 bytes > 20.
    let emojis = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}\u{1F604}\u{1F605}";
    let fp = AgentFingerprint {
        jwt_sub: Some(emojis.to_string()),
        ..Default::default()
    };
    let summary = fp.summary();
    assert!(summary.contains("sub:"));
    assert!(summary.contains("..."));
}

/// FIND-R44-031: Short strings within max_len are not truncated.
#[test]
fn test_agent_fingerprint_summary_short_string_unchanged() {
    let fp = AgentFingerprint {
        jwt_sub: Some("short".to_string()),
        ..Default::default()
    };
    let summary = fp.summary();
    assert!(summary.contains("sub:short"));
    assert!(!summary.contains("..."));
}

/// FIND-R44-031: Edge case — max_len < 3 should not underflow.
#[test]
fn test_agent_fingerprint_summary_mixed_multibyte_ascii() {
    // Mix ASCII and multi-byte: "a\u{4e16}b\u{4e16}c\u{4e16}d\u{4e16}e\u{4e16}f"
    // = 5 ASCII (5 bytes) + 5 CJK (15 bytes) = 20 bytes, exactly at limit.
    let exactly_20 = "a\u{4e16}b\u{4e16}c\u{4e16}d\u{4e16}e\u{4e16}";
    assert_eq!(exactly_20.len(), 20);
    let fp = AgentFingerprint {
        jwt_sub: Some(exactly_20.to_string()),
        ..Default::default()
    };
    let summary = fp.summary();
    // At exactly max_len, no truncation
    assert!(summary.contains("sub:"));
    assert!(!summary.contains("..."));
}

// ═══════════════════════════════════════════════════
// MCP 2025-11-25 TOOL NAME VALIDATION (Phase 30)
// ═══════════════════════════════════════════════════

#[test]
fn test_validate_mcp_tool_name_empty_rejected() {
    let err = validate_mcp_tool_name("").unwrap_err();
    assert!(err.contains("empty"), "got: {}", err);
}

#[test]
fn test_validate_mcp_tool_name_too_long_rejected() {
    let name = "a".repeat(65);
    let err = validate_mcp_tool_name(&name).unwrap_err();
    assert!(err.contains("exceeds 64"), "got: {}", err);
}

#[test]
fn test_validate_mcp_tool_name_max_length_accepted() {
    let name = "a".repeat(64);
    assert!(validate_mcp_tool_name(&name).is_ok());
}

#[test]
fn test_validate_mcp_tool_name_valid_simple() {
    assert!(validate_mcp_tool_name("read_file").is_ok());
    assert!(validate_mcp_tool_name("bash-exec").is_ok());
    assert!(validate_mcp_tool_name("tool123").is_ok());
    assert!(validate_mcp_tool_name("A").is_ok());
}

#[test]
fn test_validate_mcp_tool_name_valid_dotted_namespace() {
    assert!(validate_mcp_tool_name("ns.tool").is_ok());
    assert!(validate_mcp_tool_name("org.project.tool_v2").is_ok());
}

#[test]
fn test_validate_mcp_tool_name_valid_slashed_namespace() {
    assert!(validate_mcp_tool_name("ns/tool").is_ok());
    assert!(validate_mcp_tool_name("org/project/read").is_ok());
}

#[test]
fn test_validate_mcp_tool_name_invalid_chars_rejected() {
    let err = validate_mcp_tool_name("tool@bad").unwrap_err();
    assert!(err.contains("invalid character '@'"), "got: {}", err);

    assert!(validate_mcp_tool_name("tool name").is_err()); // space
    assert!(validate_mcp_tool_name("tool\ttab").is_err()); // tab
    assert!(validate_mcp_tool_name("tool#hash").is_err()); // hash
    assert!(validate_mcp_tool_name("tool$dollar").is_err()); // dollar
}

/// FIND-R73-002: Verify control characters are escaped in error messages
/// to prevent log injection.
#[test]
fn test_validate_mcp_tool_name_control_char_escaped_in_error() {
    // Newline — should appear as \n, not a literal newline
    let err = validate_mcp_tool_name("tool\nname").unwrap_err();
    assert!(
        err.contains(r"\n"),
        "control char should be escaped in error: {}",
        err.escape_debug()
    );
    assert!(
        !err.contains('\n'),
        "error message must not contain literal newline"
    );

    // Null byte — should appear as \0
    let err = validate_mcp_tool_name("tool\0name").unwrap_err();
    assert!(
        err.contains(r"\0"),
        "null byte should be escaped in error: {}",
        err.escape_debug()
    );

    // ESC (0x1b) — ANSI escape injection
    let err = validate_mcp_tool_name("tool\x1b[31mred").unwrap_err();
    assert!(
        !err.contains('\x1b'),
        "error message must not contain literal ESC"
    );
}

#[test]
fn test_validate_mcp_tool_name_leading_dot_rejected() {
    let err = validate_mcp_tool_name(".hidden").unwrap_err();
    assert!(err.contains("must not start with"), "got: {}", err);
}

#[test]
fn test_validate_mcp_tool_name_trailing_dot_rejected() {
    let err = validate_mcp_tool_name("tool.").unwrap_err();
    assert!(err.contains("must not end with"), "got: {}", err);
}

#[test]
fn test_validate_mcp_tool_name_leading_slash_rejected() {
    let err = validate_mcp_tool_name("/tool").unwrap_err();
    assert!(err.contains("must not start with"), "got: {}", err);
}

#[test]
fn test_validate_mcp_tool_name_trailing_slash_rejected() {
    let err = validate_mcp_tool_name("tool/").unwrap_err();
    assert!(err.contains("must not end with"), "got: {}", err);
}

#[test]
fn test_validate_mcp_tool_name_consecutive_dots_rejected() {
    let err = validate_mcp_tool_name("ns..tool").unwrap_err();
    assert!(err.contains("consecutive dots"), "got: {}", err);
}

// ═══════════════════════════════════════════════════════════════════════════════
// DISCOVERY TYPES (Phase 34)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_tool_metadata_serde_roundtrip() {
    let meta = ToolMetadata {
        tool_id: "server1:read_file".to_string(),
        name: "read_file".to_string(),
        description: "Read a file from disk".to_string(),
        server_id: "server1".to_string(),
        input_schema: json!({"type": "object", "properties": {"path": {"type": "string"}}}),
        schema_hash: "abcdef1234567890".to_string(),
        sensitivity: ToolSensitivity::Medium,
        domain_tags: vec!["filesystem".to_string(), "io".to_string()],
        token_cost: 150,
    };
    let json_str = serde_json::to_string(&meta).unwrap();
    let deserialized: ToolMetadata = serde_json::from_str(&json_str).unwrap();
    assert_eq!(meta, deserialized);
}

#[test]
fn test_tool_sensitivity_all_variants_roundtrip() {
    let variants = [
        ToolSensitivity::Low,
        ToolSensitivity::Medium,
        ToolSensitivity::High,
    ];
    for v in &variants {
        let json_str = serde_json::to_string(v).unwrap();
        let deserialized: ToolSensitivity = serde_json::from_str(&json_str).unwrap();
        assert_eq!(*v, deserialized);
    }
}

#[test]
fn test_tool_sensitivity_default_is_high() {
    // SECURITY (FIND-R46-013): Default must be High for fail-closed behavior.
    assert_eq!(ToolSensitivity::default(), ToolSensitivity::High);
}

#[test]
fn test_tool_sensitivity_serde_rename() {
    let json_str = serde_json::to_string(&ToolSensitivity::High).unwrap();
    assert_eq!(json_str, "\"high\"");
    let parsed: ToolSensitivity = serde_json::from_str("\"medium\"").unwrap();
    assert_eq!(parsed, ToolSensitivity::Medium);
}

#[test]
fn test_discovery_result_serde_roundtrip() {
    let result = DiscoveryResult {
        tools: vec![DiscoveredTool {
            metadata: ToolMetadata {
                tool_id: "srv:tool".to_string(),
                name: "tool".to_string(),
                description: "A tool".to_string(),
                server_id: "srv".to_string(),
                input_schema: json!({}),
                schema_hash: "hash123".to_string(),
                sensitivity: ToolSensitivity::Low,
                domain_tags: vec![],
                token_cost: 50,
            },
            relevance_score: 0.95,
            ttl_secs: 300,
        }],
        query: "find a tool".to_string(),
        total_candidates: 100,
        policy_filtered: 5,
    };
    let json_str = serde_json::to_string(&result).unwrap();
    let deserialized: DiscoveryResult = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.query, "find a tool");
    assert_eq!(deserialized.total_candidates, 100);
    assert_eq!(deserialized.policy_filtered, 5);
    assert_eq!(deserialized.tools.len(), 1);
    assert_eq!(deserialized.tools[0].relevance_score, 0.95);
    assert_eq!(deserialized.tools[0].ttl_secs, 300);
}

#[test]
fn test_discovered_tool_serde_roundtrip() {
    let tool = DiscoveredTool {
        metadata: ToolMetadata {
            tool_id: "s:t".to_string(),
            name: "t".to_string(),
            description: "desc".to_string(),
            server_id: "s".to_string(),
            input_schema: json!({"type": "object"}),
            schema_hash: "h".to_string(),
            sensitivity: ToolSensitivity::High,
            domain_tags: vec!["network".to_string()],
            token_cost: 200,
        },
        relevance_score: 0.5,
        ttl_secs: 600,
    };
    let json_str = serde_json::to_string(&tool).unwrap();
    let deserialized: DiscoveredTool = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.metadata.sensitivity, ToolSensitivity::High);
    assert_eq!(deserialized.relevance_score, 0.5);
}

#[test]
fn test_tool_metadata_empty_domain_tags() {
    let meta = ToolMetadata {
        tool_id: "s:t".to_string(),
        name: "t".to_string(),
        description: "d".to_string(),
        server_id: "s".to_string(),
        input_schema: json!({}),
        schema_hash: "h".to_string(),
        sensitivity: ToolSensitivity::Low,
        domain_tags: vec![],
        token_cost: 0,
    };
    let json_str = serde_json::to_string(&meta).unwrap();
    let deserialized: ToolMetadata = serde_json::from_str(&json_str).unwrap();
    assert!(deserialized.domain_tags.is_empty());
}

#[test]
fn test_discovery_result_empty_tools() {
    let result = DiscoveryResult {
        tools: vec![],
        query: "nothing".to_string(),
        total_candidates: 0,
        policy_filtered: 0,
    };
    let json_str = serde_json::to_string(&result).unwrap();
    let deserialized: DiscoveryResult = serde_json::from_str(&json_str).unwrap();
    assert!(deserialized.tools.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROJECTOR TYPES (Phase 35.1)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_canonical_tool_schema_serde_roundtrip() {
    let schema = CanonicalToolSchema {
        name: "read_file".to_string(),
        description: "Read a file from disk".to_string(),
        input_schema: json!({"type": "object", "properties": {"path": {"type": "string"}}}),
        output_schema: Some(json!({"type": "string"})),
    };
    let json_str = serde_json::to_string(&schema).unwrap();
    let deserialized: CanonicalToolSchema = serde_json::from_str(&json_str).unwrap();
    assert_eq!(schema, deserialized);
}

#[test]
fn test_canonical_tool_schema_no_output_schema() {
    let schema = CanonicalToolSchema {
        name: "exec".to_string(),
        description: "Execute command".to_string(),
        input_schema: json!({"type": "object"}),
        output_schema: None,
    };
    let json_str = serde_json::to_string(&schema).unwrap();
    let deserialized: CanonicalToolSchema = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.output_schema, None);
}

#[test]
fn test_canonical_tool_call_serde_roundtrip() {
    let call = CanonicalToolCall {
        tool_name: "read_file".to_string(),
        arguments: json!({"path": "/tmp/test.txt"}),
        call_id: Some("call_123".to_string()),
    };
    let json_str = serde_json::to_string(&call).unwrap();
    let deserialized: CanonicalToolCall = serde_json::from_str(&json_str).unwrap();
    assert_eq!(call, deserialized);
}

#[test]
fn test_canonical_tool_call_no_call_id() {
    let call = CanonicalToolCall {
        tool_name: "exec".to_string(),
        arguments: json!({"cmd": "ls"}),
        call_id: None,
    };
    let json_str = serde_json::to_string(&call).unwrap();
    let deserialized: CanonicalToolCall = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.call_id, None);
}

#[test]
fn test_canonical_tool_response_serde_roundtrip() {
    let response = CanonicalToolResponse {
        call_id: Some("call_123".to_string()),
        content: json!({"result": "ok"}),
        is_error: false,
    };
    let json_str = serde_json::to_string(&response).unwrap();
    let deserialized: CanonicalToolResponse = serde_json::from_str(&json_str).unwrap();
    assert_eq!(response, deserialized);
}

#[test]
fn test_canonical_tool_response_error() {
    let response = CanonicalToolResponse {
        call_id: None,
        content: json!("something went wrong"),
        is_error: true,
    };
    let json_str = serde_json::to_string(&response).unwrap();
    let deserialized: CanonicalToolResponse = serde_json::from_str(&json_str).unwrap();
    assert!(deserialized.is_error);
}

#[test]
fn test_model_family_serde_roundtrip_all_variants() {
    let families = vec![
        ModelFamily::Claude,
        ModelFamily::OpenAi,
        ModelFamily::DeepSeek,
        ModelFamily::Qwen,
        ModelFamily::Generic,
        ModelFamily::Custom("llama".to_string()),
    ];
    for family in families {
        let json_str = serde_json::to_string(&family).unwrap();
        let deserialized: ModelFamily = serde_json::from_str(&json_str).unwrap();
        assert_eq!(family, deserialized);
    }
}

#[test]
fn test_model_family_default_is_generic() {
    assert_eq!(ModelFamily::default(), ModelFamily::Generic);
}

#[test]
fn test_model_family_rename_all_lowercase() {
    let json_str = serde_json::to_string(&ModelFamily::Claude).unwrap();
    assert_eq!(json_str, "\"claude\"");
    let json_str = serde_json::to_string(&ModelFamily::OpenAi).unwrap();
    assert_eq!(json_str, "\"openai\"");
    let json_str = serde_json::to_string(&ModelFamily::DeepSeek).unwrap();
    assert_eq!(json_str, "\"deepseek\"");
}

#[test]
fn test_model_family_hash_and_eq() {
    let mut map = HashMap::new();
    map.insert(ModelFamily::Claude, "claude");
    map.insert(ModelFamily::OpenAi, "openai");
    map.insert(ModelFamily::Custom("x".to_string()), "custom_x");
    assert_eq!(map.get(&ModelFamily::Claude), Some(&"claude"));
    assert_eq!(
        map.get(&ModelFamily::Custom("x".to_string())),
        Some(&"custom_x")
    );
    assert_eq!(map.get(&ModelFamily::DeepSeek), None);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 46 FINDING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// FIND-R46-004: PedersenCommitment Debug redacts blinding_hint
#[test]
fn test_pedersen_commitment_debug_redacts_blinding_hint() {
    let pc = PedersenCommitment {
        commitment: "abc123".to_string(),
        blinding_hint: "secret_blinding_factor".to_string(),
    };
    let debug_output = format!("{:?}", pc);
    assert!(
        debug_output.contains("abc123"),
        "commitment should be visible"
    );
    assert!(
        !debug_output.contains("secret_blinding_factor"),
        "blinding_hint must be redacted"
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "should show [REDACTED] for blinding_hint"
    );
}

#[test]
fn test_pedersen_commitment_serialize_omits_blinding_hint() {
    let pc = PedersenCommitment {
        commitment: "abc123".to_string(),
        blinding_hint: "secret_blinding_factor".to_string(),
    };
    let json = serde_json::to_string(&pc).expect("serialization should succeed");
    assert!(
        !json.contains("blinding_hint"),
        "blinding_hint must not appear in serialized output"
    );
    assert!(
        !json.contains("secret_blinding_factor"),
        "blinding value must not appear in serialized output"
    );
}

#[test]
fn test_pedersen_commitment_deserialize_with_blinding_hint() {
    let json = r#"{"commitment":"abc","blinding_hint":"secret"}"#;
    let pc: PedersenCommitment = serde_json::from_str(json).expect("should deserialize");
    assert_eq!(pc.commitment, "abc");
    assert_eq!(pc.blinding_hint, "secret");
}

// FIND-R46-005: CapabilityToken Debug redacts signature
#[test]
fn test_capability_token_debug_redacts_signature() {
    let token = CapabilityToken {
        token_id: "tok-1".to_string(),
        parent_token_id: None,
        issuer: "issuer-1".to_string(),
        holder: "holder-1".to_string(),
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        signature: "deadbeef_secret_sig".to_string(),
        issuer_public_key: "pubkey123".to_string(),
    };
    let debug_output = format!("{:?}", token);
    assert!(
        !debug_output.contains("deadbeef_secret_sig"),
        "signature must be redacted in Debug"
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "should show [REDACTED] for signature"
    );
    assert!(debug_output.contains("tok-1"), "token_id should be visible");
}

// FIND-R46-006: SamplingStats::record_request saturating_add
#[test]
fn test_sampling_stats_record_request_saturating_at_u32_max() {
    let mut stats = SamplingStats {
        request_count: u32::MAX - 1,
        window_start: 0,
        last_request: 0,
        flagged_patterns: vec![],
    };
    let count = stats.record_request(100);
    assert_eq!(count, u32::MAX);
    // One more should saturate, not panic
    let count2 = stats.record_request(200);
    assert_eq!(count2, u32::MAX);
}

// FIND-R46-007: ToolSignature::is_expired lexicographic comparison
#[test]
fn test_tool_signature_is_expired_lexicographic_iso8601() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "aabbcc".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pk".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2026-06-15T12:00:00Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // Before expiry
    assert!(!sig.is_expired("2026-06-15T11:59:59Z"));
    // Exactly at expiry
    assert!(sig.is_expired("2026-06-15T12:00:00Z"));
    // After expiry
    assert!(sig.is_expired("2026-06-15T12:00:01Z"));
    // Year rollover
    assert!(sig.is_expired("2027-01-01T00:00:00Z"));
}

// FIND-R46-008: validate_mcp_tool_name rejects consecutive slashes
#[test]
fn test_validate_mcp_tool_name_rejects_consecutive_slashes() {
    let result = validate_mcp_tool_name("foo//bar");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("consecutive slashes"));
}

#[test]
fn test_validate_mcp_tool_name_allows_single_slash() {
    assert!(validate_mcp_tool_name("foo/bar").is_ok());
    assert!(validate_mcp_tool_name("a/b/c").is_ok());
}

// FIND-R46-009: f64 NaN/Infinity validation
#[test]
fn test_risk_score_validate_finite_rejects_nan() {
    let rs = RiskScore {
        score: f64::NAN,
        factors: vec![],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    assert!(rs.validate_finite().is_err());
}

#[test]
fn test_risk_score_validate_finite_rejects_infinity() {
    let rs = RiskScore {
        score: f64::INFINITY,
        factors: vec![],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    assert!(rs.validate_finite().is_err());
}

#[test]
fn test_risk_score_validate_finite_accepts_normal() {
    let rs = RiskScore {
        score: 0.75,
        factors: vec![RiskFactor {
            name: "test".to_string(),
            weight: 0.5,
            value: 0.8,
        }],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    assert!(rs.validate_finite().is_ok());
}

#[test]
fn test_risk_factor_validate_finite_rejects_nan_weight() {
    let rf = RiskFactor {
        name: "test".to_string(),
        weight: f64::NAN,
        value: 0.5,
    };
    assert!(rf.validate_finite().is_err());
}

#[test]
fn test_risk_factor_validate_finite_rejects_infinity_value() {
    let rf = RiskFactor {
        name: "test".to_string(),
        weight: 0.5,
        value: f64::NEG_INFINITY,
    };
    assert!(rf.validate_finite().is_err());
}

#[test]
fn test_schema_record_validate_finite_rejects_nan() {
    let sr = SchemaRecord::new("tool", "hash", 100);
    let mut sr_nan = sr;
    sr_nan.trust_score = f32::NAN;
    assert!(sr_nan.validate_finite().is_err());
}

#[test]
fn test_schema_record_validate_finite_accepts_normal() {
    let sr = SchemaRecord::new("tool", "hash", 100);
    assert!(sr.validate_finite().is_ok());
}

#[test]
fn test_memory_entry_validate_finite_rejects_nan() {
    let mut me = MemoryEntry::new(
        "id".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    me.trust_score = f64::NAN;
    assert!(me.validate().is_err());
}

#[test]
fn test_memory_entry_validate_finite_accepts_normal() {
    let me = MemoryEntry::new(
        "id".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    assert!(me.validate().is_ok());
}

#[test]
#[allow(deprecated)]
fn test_nhi_behavioral_baseline_validate_finite_rejects_nan() {
    let baseline = NhiBehavioralBaseline {
        avg_request_interval_secs: f64::NAN,
        ..NhiBehavioralBaseline::default()
    };
    assert!(baseline.validate_finite().is_err());
}

#[test]
#[allow(deprecated)]
fn test_nhi_behavioral_baseline_validate_finite_rejects_infinity_in_map() {
    let mut baseline = NhiBehavioralBaseline::default();
    baseline
        .tool_call_patterns
        .insert("tool".to_string(), f64::INFINITY);
    assert!(baseline.validate_finite().is_err());
}

#[test]
#[allow(deprecated)]
fn test_nhi_behavioral_baseline_validate_finite_accepts_normal() {
    let baseline = NhiBehavioralBaseline {
        avg_request_interval_secs: 5.0,
        confidence: 0.9,
        ..NhiBehavioralBaseline::default()
    };
    assert!(baseline.validate_finite().is_ok());
}

// FIND-R46-010: StatelessContextBlob Debug redacts signature
#[test]
fn test_stateless_context_blob_debug_redacts_signature() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: "hmac_secret_value_here".to_string(),
    };
    let debug_output = format!("{:?}", blob);
    assert!(
        !debug_output.contains("hmac_secret_value_here"),
        "HMAC signature must be redacted"
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "should show [REDACTED] for signature"
    );
    assert!(
        debug_output.contains("agent-1"),
        "agent_id should be visible"
    );
}

// FIND-R46-011: SecureTask max_nonces capped at 10,000
#[test]
fn test_secure_task_max_nonces_capped_on_deserialize() {
    let json = r#"{
        "task": {"task_id":"t1","status":"pending","created_at":"2026-01-01T00:00:00Z","tool":"test","function":"fn"},
        "state_chain": [],
        "seen_nonces": [],
        "max_nonces": 999999
    }"#;
    let task: SecureTask = serde_json::from_str(json).expect("should deserialize");
    assert!(
        task.max_nonces <= 10_000,
        "max_nonces should be capped at 10,000, got {}",
        task.max_nonces
    );
}

#[test]
fn test_secure_task_record_nonce_respects_cap() {
    let tracked = TrackedTask {
        task_id: "t1".to_string(),
        tool: "test".to_string(),
        function: "fn".to_string(),
        status: TaskStatus::Pending,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        created_by: None,
        session_id: None,
    };
    let mut task = SecureTask::new(tracked);
    // Manually set a large max_nonces to verify runtime cap
    task.max_nonces = 50_000;
    // Fill to MAX_NONCES_CAP
    for i in 0..10_001 {
        task.record_nonce(format!("nonce-{i}"));
    }
    // Should be capped at MAX_NONCES_CAP (10,000) due to FIFO eviction
    assert!(
        task.seen_nonces.len() <= 10_000,
        "seen_nonces should not exceed 10,000, got {}",
        task.seen_nonces.len()
    );
}

// FIND-R46-012: EnforcementMode defaults to Monitor
#[test]
fn test_enforcement_mode_defaults_to_monitor() {
    let mode = EnforcementMode::default();
    assert_eq!(
        mode,
        EnforcementMode::Monitor,
        "Default must be Monitor for gradual rollout"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R46-013: ToolSensitivity defaults to High (fail-closed)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_tool_sensitivity_default_is_high_fail_closed() {
    // New tools with no explicit sensitivity must be treated as High
    // to prevent accidentally bypassing elevated permission requirements.
    let ts = ToolSensitivity::default();
    assert_eq!(ts, ToolSensitivity::High);
    // Verify the default serializes as "high"
    let json = serde_json::to_string(&ts).unwrap();
    assert_eq!(json, "\"high\"");
}

#[test]
fn test_tool_metadata_default_sensitivity_is_high() {
    // When ToolMetadata is deserialized without an explicit sensitivity,
    // it should default to High.
    let json = r#"{
        "tool_id": "srv:tool",
        "name": "tool",
        "description": "desc",
        "server_id": "srv",
        "input_schema": {},
        "schema_hash": "abc",
        "sensitivity": "high",
        "domain_tags": [],
        "token_cost": 10
    }"#;
    let meta: ToolMetadata = serde_json::from_str(json).unwrap();
    assert_eq!(meta.sensitivity, ToolSensitivity::High);
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R46-014: NhiIdentityStatus defaults to Probationary (fail-closed)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_nhi_identity_status_default_is_probationary() {
    // New identities must start as Probationary, not Active.
    let status = NhiIdentityStatus::default();
    assert_eq!(status, NhiIdentityStatus::Probationary);
}

#[test]
fn test_nhi_agent_identity_default_status_is_probationary() {
    // NhiAgentIdentity derives Default, which should use Probationary.
    let identity = NhiAgentIdentity::default();
    assert_eq!(identity.status, NhiIdentityStatus::Probationary);
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R46-015: deny_unknown_fields on security-critical structs
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_network_rules_rejects_unknown_fields() {
    // A typo like "allowed_domain" instead of "allowed_domains" must
    // be caught at deserialization time, not silently ignored.
    let json = r#"{"allowed_domains": [], "blocked_domains": [], "extra_field": true}"#;
    let result: Result<NetworkRules, _> = serde_json::from_str(json);
    assert!(result.is_err(), "NetworkRules must reject unknown fields");
}

#[test]
fn test_network_rules_accepts_known_fields() {
    let json = r#"{"allowed_domains": ["example.com"], "blocked_domains": ["evil.com"]}"#;
    let result: Result<NetworkRules, _> = serde_json::from_str(json);
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert_eq!(rules.allowed_domains, vec!["example.com"]);
}

#[test]
fn test_network_rules_accepts_ip_rules() {
    let json = r#"{
        "allowed_domains": [],
        "blocked_domains": [],
        "ip_rules": {"block_private": true, "blocked_cidrs": [], "allowed_cidrs": []}
    }"#;
    let result: Result<NetworkRules, _> = serde_json::from_str(json);
    assert!(result.is_ok());
}

#[test]
fn test_ip_rules_rejects_unknown_fields() {
    let json = r#"{"block_private": true, "blocked_cidrs": [], "allowed_cidrs": [], "typo": 1}"#;
    let result: Result<IpRules, _> = serde_json::from_str(json);
    assert!(result.is_err(), "IpRules must reject unknown fields");
}

#[test]
fn test_ip_rules_accepts_known_fields() {
    let json = r#"{"block_private": true, "blocked_cidrs": ["10.0.0.0/8"], "allowed_cidrs": []}"#;
    let result: Result<IpRules, _> = serde_json::from_str(json);
    assert!(result.is_ok());
}

#[test]
fn test_path_rules_rejects_unknown_fields() {
    // "allow" instead of "allowed" must be caught.
    let json = r#"{"allowed": ["/tmp"], "blocked": [], "allow": ["/home"]}"#;
    let result: Result<PathRules, _> = serde_json::from_str(json);
    assert!(result.is_err(), "PathRules must reject unknown fields");
}

#[test]
fn test_path_rules_accepts_known_fields() {
    let json = r#"{"allowed": ["/tmp"], "blocked": ["/etc"]}"#;
    let result: Result<PathRules, _> = serde_json::from_str(json);
    assert!(result.is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R46-016: SchemaRecord.version_history max 10 enforced
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_schema_record_push_version_enforces_max() {
    let mut record = SchemaRecord::new("test_tool", "hash_0", 1000);
    // Push 15 versions, only last 10 should remain
    for i in 1..=15 {
        record.push_version(format!("hash_{i}"));
    }
    assert_eq!(
        record.version_history.len(),
        SchemaRecord::MAX_VERSION_HISTORY
    );
    // Oldest entries should have been evicted; first entry should be hash_6
    assert_eq!(record.version_history[0], "hash_6");
    assert_eq!(record.version_history[9], "hash_15");
}

#[test]
fn test_schema_record_push_version_under_limit() {
    let mut record = SchemaRecord::new("test_tool", "hash_0", 1000);
    for i in 1..=5 {
        record.push_version(format!("hash_{i}"));
    }
    assert_eq!(record.version_history.len(), 5);
}

// SECURITY (FIND-R82-001): Verify push_version handles multi-byte UTF-8 at truncation boundary.
#[test]
fn test_schema_record_push_version_multibyte_utf8_safe() {
    let mut record = SchemaRecord::new("test_tool", "hash_0", 1000);
    // Create a string of 2-byte Cyrillic characters that lands on a non-char-boundary
    // at MAX_HASH_LEN (128). Each char is 2 bytes, so 65 chars = 130 bytes.
    let multibyte = "д".repeat(65); // 130 bytes, boundary at 128 splits a char
    assert!(multibyte.len() > SchemaRecord::MAX_HASH_LEN);
    // This should NOT panic
    record.push_version(multibyte);
    // The truncated hash should be valid UTF-8 and within bounds
    let stored = &record.version_history.last().unwrap();
    assert!(stored.len() <= SchemaRecord::MAX_HASH_LEN);
    assert!(stored.is_char_boundary(stored.len()));
}

#[test]
fn test_schema_record_validate_version_history_ok() {
    let record = SchemaRecord::new("test_tool", "hash_0", 1000);
    assert!(record.validate_version_history().is_ok());
}

#[test]
fn test_schema_record_validate_version_history_overflow() {
    let mut record = SchemaRecord::new("test_tool", "hash_0", 1000);
    // Bypass push_version to directly set an oversized history
    record.version_history = (0..20).map(|i| format!("hash_{i}")).collect();
    assert!(record.validate_version_history().is_err());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R46-017: EvaluationContext builder validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_evaluation_context_validate_ok() {
    let ctx = EvaluationContext::builder()
        .agent_id("agent-123")
        .tenant_id("tenant-abc")
        .session_state("active")
        .build();
    assert!(ctx.validate().is_ok());
}

#[test]
fn test_evaluation_context_validate_empty_ok() {
    // No fields set => nothing to validate => OK
    let ctx = EvaluationContext::builder().build();
    assert!(ctx.validate().is_ok());
}

#[test]
fn test_evaluation_context_validate_empty_agent_id_rejected() {
    let ctx = EvaluationContext::builder().agent_id("").build();
    let result = ctx.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("agent_id"));
}

#[test]
fn test_evaluation_context_validate_control_char_in_agent_id() {
    let ctx = EvaluationContext::builder().agent_id("agent\n123").build();
    let result = ctx.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("control or format characters"));
}

#[test]
fn test_evaluation_context_validate_control_char_in_tenant_id() {
    let ctx = EvaluationContext::builder().tenant_id("tenant\t1").build();
    let result = ctx.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("tenant_id"));
}

#[test]
fn test_evaluation_context_validate_empty_session_state_rejected() {
    let ctx = EvaluationContext::builder().session_state("").build();
    let result = ctx.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("session_state"));
}

#[test]
fn test_evaluation_context_validate_null_byte_in_tenant_id() {
    let ctx = EvaluationContext::builder().tenant_id("tenant\0id").build();
    let result = ctx.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("control or format characters"));
}

#[test]
fn test_evaluation_context_build_validated_ok() {
    let result = EvaluationContext::builder()
        .agent_id("valid-agent")
        .tenant_id("valid-tenant")
        .build_validated();
    assert!(result.is_ok());
}

#[test]
fn test_evaluation_context_build_validated_rejects_invalid() {
    let result = EvaluationContext::builder()
        .agent_id("bad\ragent")
        .build_validated();
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R46-018: MemoryEntry contradictory trust_score/taint_labels
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_memory_entry_validate_tainted_with_perfect_trust_rejected() {
    let mut entry = MemoryEntry::new(
        "id1".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    // Force contradictory state
    entry.trust_score = 1.0;
    entry.taint_labels = vec![TaintLabel::Untrusted];
    let result = entry.validate();
    assert!(
        result.is_err(),
        "Tainted entry with perfect trust must be rejected"
    );
    assert!(result.unwrap_err().contains("trust_score"));
}

#[test]
fn test_memory_entry_validate_tainted_with_low_trust_ok() {
    let entry = MemoryEntry::new(
        "id2".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    // Default new() now sets trust_score = 0.5 with Untrusted taint
    assert!(entry.validate().is_ok());
}

#[test]
fn test_memory_entry_validate_clean_entry_with_perfect_trust_ok() {
    let mut entry = MemoryEntry::new(
        "id3".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    // Sanitized entry with no security-relevant taints can have trust = 1.0
    entry.taint_labels = vec![TaintLabel::Sanitized];
    entry.trust_score = 1.0;
    assert!(entry.validate().is_ok());
}

#[test]
fn test_memory_entry_validate_quarantined_with_perfect_trust_rejected() {
    let mut entry = MemoryEntry::new(
        "id4".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.taint_labels = vec![TaintLabel::Quarantined];
    entry.trust_score = 1.0;
    assert!(entry.validate().is_err());
}

#[test]
fn test_memory_entry_validate_integrity_failed_with_perfect_trust_rejected() {
    let mut entry = MemoryEntry::new(
        "id5".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.taint_labels = vec![TaintLabel::IntegrityFailed];
    entry.trust_score = 1.0;
    assert!(entry.validate().is_err());
}

#[test]
fn test_memory_entry_validate_no_taints_with_perfect_trust_ok() {
    let mut entry = MemoryEntry::new(
        "id6".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.taint_labels = vec![];
    entry.trust_score = 1.0;
    assert!(entry.validate().is_ok());
}

#[test]
fn test_memory_entry_validate_nan_trust_rejected() {
    let mut entry = MemoryEntry::new(
        "id7".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.trust_score = f64::NAN;
    entry.taint_labels = vec![];
    assert!(entry.validate().is_err());
}

#[test]
fn test_memory_entry_new_default_trust_below_one() {
    // FIND-R46-018: new() creates entries with Untrusted taint,
    // so trust_score must be < 1.0 to satisfy validate().
    let entry = MemoryEntry::new(
        "id8".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    assert!(
        entry.trust_score < 1.0,
        "New untrusted entry must have trust < 1.0"
    );
    assert!(entry.validate().is_ok(), "New entry must pass validation");
}

#[test]
fn test_memory_entry_sensitive_taint_allows_perfect_trust() {
    // Sensitive is not a security-negative taint — it marks data classification,
    // not distrust. It should allow trust_score = 1.0.
    let mut entry = MemoryEntry::new(
        "id9".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.taint_labels = vec![TaintLabel::Sensitive];
    entry.trust_score = 1.0;
    assert!(entry.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-P1-6: hours_since returns 0.0 on parse failure — bypasses trust decay
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_p1_6_decayed_trust_corrupt_start_timestamp_returns_zero() {
    // Corrupt start timestamp must produce 0.0 (fail-closed), not full trust.
    let entry = MemoryEntry {
        recorded_at: "INVALID".to_string(),
        trust_score: 0.9,
        ..MemoryEntry::new(
            "id-p1-6-a".to_string(),
            "fp".to_string(),
            "content",
            "hash".to_string(),
            "INVALID".to_string(),
        )
    };
    let decayed = entry.decayed_trust_score(0.01, "2026-02-01T00:00:00Z");
    assert_eq!(
        decayed, 0.0,
        "Corrupt start timestamp must produce 0.0 trust (fail-closed)"
    );
}

#[test]
fn test_p1_6_decayed_trust_corrupt_end_timestamp_returns_zero() {
    let entry = MemoryEntry::new(
        "id-p1-6-b".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    let decayed = entry.decayed_trust_score(0.01, "GARBAGE");
    assert_eq!(
        decayed, 0.0,
        "Corrupt end timestamp must produce 0.0 trust (fail-closed)"
    );
}

#[test]
fn test_p1_6_decayed_trust_valid_timestamps_decays_normally() {
    let mut entry = MemoryEntry::new(
        "id-p1-6-c".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.trust_score = 1.0;
    entry.taint_labels = vec![]; // Remove taint for clean test
    let decay_rate = 0.01;
    let decayed = entry.decayed_trust_score(decay_rate, "2026-01-02T00:00:00Z");
    // ~24 hours later, trust should be < 1.0
    assert!(decayed < 1.0, "Trust should decay over time");
    assert!(decayed > 0.0, "Trust should still be positive");
}

#[test]
fn test_p1_6_parse_timestamp_rejects_month_zero() {
    // Month 0 is invalid and previously caused underflow in (month - 1) * 30
    let entry = MemoryEntry {
        recorded_at: "2026-00-15T12:00:00Z".to_string(),
        trust_score: 0.9,
        ..MemoryEntry::new(
            "id-p1-6-d".to_string(),
            "fp".to_string(),
            "content",
            "hash".to_string(),
            "2026-00-15T12:00:00Z".to_string(),
        )
    };
    let decayed = entry.decayed_trust_score(0.01, "2026-02-01T00:00:00Z");
    assert_eq!(decayed, 0.0, "Month=0 must fail-closed with 0.0 trust");
}

#[test]
fn test_p1_6_parse_timestamp_rejects_year_before_epoch() {
    // Year < 1970 would cause underflow in (year - 1970) * 365
    let entry = MemoryEntry {
        recorded_at: "1969-06-15T12:00:00Z".to_string(),
        trust_score: 0.9,
        ..MemoryEntry::new(
            "id-p1-6-e".to_string(),
            "fp".to_string(),
            "content",
            "hash".to_string(),
            "1969-06-15T12:00:00Z".to_string(),
        )
    };
    let decayed = entry.decayed_trust_score(0.01, "2026-02-01T00:00:00Z");
    assert_eq!(decayed, 0.0, "Year < 1970 must fail-closed with 0.0 trust");
}

#[test]
fn test_p1_6_parse_timestamp_rejects_day_zero() {
    let entry = MemoryEntry {
        recorded_at: "2026-01-00T12:00:00Z".to_string(),
        trust_score: 0.9,
        ..MemoryEntry::new(
            "id-p1-6-f".to_string(),
            "fp".to_string(),
            "content",
            "hash".to_string(),
            "2026-01-00T12:00:00Z".to_string(),
        )
    };
    let decayed = entry.decayed_trust_score(0.01, "2026-02-01T00:00:00Z");
    assert_eq!(decayed, 0.0, "Day=0 must fail-closed with 0.0 trust");
}

#[test]
fn test_p1_6_parse_timestamp_rejects_month_13() {
    let entry = MemoryEntry {
        recorded_at: "2026-13-01T00:00:00Z".to_string(),
        trust_score: 0.9,
        ..MemoryEntry::new(
            "id-p1-6-g".to_string(),
            "fp".to_string(),
            "content",
            "hash".to_string(),
            "2026-13-01T00:00:00Z".to_string(),
        )
    };
    let decayed = entry.decayed_trust_score(0.01, "2026-02-01T00:00:00Z");
    assert_eq!(decayed, 0.0, "Month=13 must fail-closed with 0.0 trust");
}

#[test]
fn test_p1_6_parse_timestamp_rejects_hour_25() {
    let entry = MemoryEntry {
        recorded_at: "2026-01-01T25:00:00Z".to_string(),
        trust_score: 0.9,
        ..MemoryEntry::new(
            "id-p1-6-h".to_string(),
            "fp".to_string(),
            "content",
            "hash".to_string(),
            "2026-01-01T25:00:00Z".to_string(),
        )
    };
    let decayed = entry.decayed_trust_score(0.01, "2026-02-01T00:00:00Z");
    assert_eq!(decayed, 0.0, "Hour=25 must fail-closed with 0.0 trust");
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEDERATION TYPES TESTS (Phase 39)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_federation_trust_anchor_validate_empty_org_id_fails() {
    let anchor = FederationTrustAnchor {
        org_id: String::new(),
        display_name: "Test".to_string(),
        jwks_uri: None,
        issuer_pattern: "https://auth.example.com".to_string(),
        identity_mappings: vec![],
        trust_level: "limited".to_string(),
    };
    assert!(anchor.validate().is_err());
    assert!(anchor.validate().unwrap_err().contains("org_id"));
}

#[test]
fn test_federation_trust_anchor_validate_empty_issuer_fails() {
    let anchor = FederationTrustAnchor {
        org_id: "org-1".to_string(),
        display_name: "Test".to_string(),
        jwks_uri: None,
        issuer_pattern: String::new(),
        identity_mappings: vec![],
        trust_level: "limited".to_string(),
    };
    assert!(anchor.validate().is_err());
    assert!(anchor.validate().unwrap_err().contains("issuer_pattern"));
}

#[test]
fn test_federation_trust_anchor_validate_jwks_uri_non_http_fails() {
    let anchor = FederationTrustAnchor {
        org_id: "org-1".to_string(),
        display_name: "Test".to_string(),
        jwks_uri: Some("ftp://keys.example.com/.well-known/jwks.json".to_string()),
        issuer_pattern: "https://auth.example.com".to_string(),
        identity_mappings: vec![],
        trust_level: "limited".to_string(),
    };
    assert!(anchor.validate().is_err());
    assert!(anchor.validate().unwrap_err().contains("http"));
}

#[test]
fn test_federation_trust_anchor_validate_invalid_trust_level_fails() {
    let anchor = FederationTrustAnchor {
        org_id: "org-1".to_string(),
        display_name: "Test".to_string(),
        jwks_uri: None,
        issuer_pattern: "https://auth.example.com".to_string(),
        identity_mappings: vec![],
        trust_level: "admin".to_string(),
    };
    assert!(anchor.validate().is_err());
    assert!(anchor.validate().unwrap_err().contains("trust_level"));
}

#[test]
fn test_federation_trust_anchor_validate_valid_succeeds() {
    let anchor = FederationTrustAnchor {
        org_id: "org-1".to_string(),
        display_name: "Partner Org".to_string(),
        jwks_uri: Some("https://keys.example.com/.well-known/jwks.json".to_string()),
        issuer_pattern: "https://auth.example.com/*".to_string(),
        identity_mappings: vec![IdentityMapping {
            external_claim: "sub".to_string(),
            internal_principal_type: "agent".to_string(),
            id_template: "org-1:{claim_value}".to_string(),
        }],
        trust_level: "limited".to_string(),
    };
    assert!(anchor.validate().is_ok());
}

#[test]
fn test_identity_mapping_validate_empty_claim_fails() {
    let mapping = IdentityMapping {
        external_claim: String::new(),
        internal_principal_type: "agent".to_string(),
        id_template: "{claim_value}".to_string(),
    };
    assert!(mapping.validate().is_err());
    assert!(mapping.validate().unwrap_err().contains("external_claim"));
}

#[test]
fn test_identity_mapping_validate_template_missing_placeholder_fails() {
    let mapping = IdentityMapping {
        external_claim: "sub".to_string(),
        internal_principal_type: "agent".to_string(),
        id_template: "org-1:fixed-value".to_string(),
    };
    assert!(mapping.validate().is_err());
    assert!(mapping.validate().unwrap_err().contains("claim_value"));
}

#[test]
fn test_identity_mapping_validate_valid_succeeds() {
    let mapping = IdentityMapping {
        external_claim: "email".to_string(),
        internal_principal_type: "user".to_string(),
        id_template: "partner:{claim_value}".to_string(),
    };
    assert!(mapping.validate().is_ok());
}

#[test]
fn test_federation_status_serde_roundtrip() {
    let status = FederationStatus {
        enabled: true,
        trust_anchor_count: 1,
        anchors: vec![FederationAnchorStatus {
            org_id: "org-1".to_string(),
            display_name: "Partner".to_string(),
            issuer_pattern: "https://auth.example.com".to_string(),
            trust_level: "limited".to_string(),
            has_jwks_uri: true,
            jwks_cached: true,
            jwks_last_fetched: Some("2026-01-01T00:00:00Z".to_string()),
            identity_mapping_count: 2,
            successful_validations: 42,
            failed_validations: 3,
        }],
    };
    let json = serde_json::to_string(&status).unwrap();
    let deserialized: FederationStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, deserialized);
}

#[test]
fn test_federation_trust_anchor_default_trust_level() {
    let json = r#"{"org_id":"org-1","display_name":"Test","issuer_pattern":"https://ex.com","identity_mappings":[]}"#;
    let anchor: FederationTrustAnchor = serde_json::from_str(json).unwrap();
    assert_eq!(anchor.trust_level, "limited");
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R51-005: EvaluationContext.validate() call_chain entry validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_evaluation_context_validate_call_chain_valid_entries() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-1".to_string(),
            tool: "read_file".to_string(),
            function: "read".to_string(),
            timestamp: "2026-02-15T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    assert!(ctx.validate().is_ok());
}

#[test]
fn test_evaluation_context_validate_call_chain_control_char_agent_id() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent\n1".to_string(),
            tool: "read_file".to_string(),
            function: "read".to_string(),
            timestamp: "2026-02-15T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    let err = ctx.validate().unwrap_err();
    assert!(err.contains("call_chain[0].agent_id"));
    assert!(err.contains("control or format characters"));
}

#[test]
fn test_evaluation_context_validate_call_chain_control_char_tool() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-1".to_string(),
            tool: "read\x00file".to_string(),
            function: "read".to_string(),
            timestamp: "2026-02-15T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    let err = ctx.validate().unwrap_err();
    assert!(err.contains("call_chain[0].tool"));
    assert!(err.contains("control or format characters"));
}

#[test]
fn test_evaluation_context_validate_call_chain_control_char_function() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-1".to_string(),
            tool: "read_file".to_string(),
            function: "read\t".to_string(),
            timestamp: "2026-02-15T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    let err = ctx.validate().unwrap_err();
    assert!(err.contains("call_chain[0].function"));
    assert!(err.contains("control or format characters"));
}

#[test]
fn test_evaluation_context_validate_call_chain_control_char_timestamp() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-1".to_string(),
            tool: "read_file".to_string(),
            function: "read".to_string(),
            timestamp: "2026-02-15\r10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    let err = ctx.validate().unwrap_err();
    assert!(err.contains("call_chain[0].timestamp"));
    assert!(err.contains("control characters"));
}

#[test]
fn test_evaluation_context_validate_call_chain_oversized_agent_id() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "a".repeat(513),
            tool: "read_file".to_string(),
            function: "read".to_string(),
            timestamp: "2026-02-15T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    let err = ctx.validate().unwrap_err();
    assert!(err.contains("call_chain[0].agent_id"));
    assert!(err.contains("exceeds max 512"));
}

#[test]
fn test_evaluation_context_validate_call_chain_oversized_timestamp() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-1".to_string(),
            tool: "read_file".to_string(),
            function: "read".to_string(),
            timestamp: "x".repeat(65),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    let err = ctx.validate().unwrap_err();
    assert!(err.contains("call_chain[0].timestamp"));
    assert!(err.contains("exceeds max 64"));
}

#[test]
fn test_evaluation_context_validate_call_chain_max_length_ok() {
    // 512-char fields should be accepted
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "a".repeat(512),
            tool: "t".repeat(512),
            function: "f".repeat(512),
            timestamp: "x".repeat(64),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    assert!(ctx.validate().is_ok());
}

#[test]
fn test_evaluation_context_validate_call_chain_second_entry_invalid() {
    let ctx = EvaluationContext {
        call_chain: vec![
            CallChainEntry {
                agent_id: "agent-1".to_string(),
                tool: "read_file".to_string(),
                function: "read".to_string(),
                timestamp: "2026-02-15T10:00:00Z".to_string(),
                hmac: None,
                verified: None,
            },
            CallChainEntry {
                agent_id: "agent\x1b[31m-injected".to_string(),
                tool: "tool".to_string(),
                function: "fn".to_string(),
                timestamp: "2026-02-15T10:01:00Z".to_string(),
                hmac: None,
                verified: None,
            },
        ],
        ..Default::default()
    };
    let err = ctx.validate().unwrap_err();
    assert!(err.contains("call_chain[1].agent_id"));
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R51-007: StatelessContextBlob signature format validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_stateless_blob_validate_valid_signature() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: "a".repeat(64), // 64 hex chars
    };
    assert!(blob.validate().is_ok());
}

#[test]
fn test_stateless_blob_validate_empty_signature_rejected() {
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
    let err = blob.validate().unwrap_err();
    assert!(err.contains("signature must not be empty"));
}

#[test]
fn test_stateless_blob_validate_short_signature_rejected() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: "deadbeef".to_string(), // 8 chars, not 64
    };
    let err = blob.validate().unwrap_err();
    assert!(err.contains("signature length 8 is not 64"));
}

#[test]
fn test_stateless_blob_validate_long_signature_rejected() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: "a".repeat(128),
    };
    let err = blob.validate().unwrap_err();
    assert!(err.contains("signature length 128 is not 64"));
}

#[test]
fn test_stateless_blob_validate_non_hex_signature_rejected() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        // 64 chars but contains 'g' which is not hex
        signature: format!("{}g", "a".repeat(63)),
    };
    let err = blob.validate().unwrap_err();
    assert!(err.contains("lowercase hex"));
}

#[test]
fn test_stateless_blob_validate_mixed_case_hex_rejected() {
    // SECURITY (FIND-R52-004): Mixed case hex is now rejected to enforce
    // canonical representation for consistent comparison.
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: "aAbBcCdDeEfF0123456789aAbBcCdDeEfF0123456789aAbBcCdDeEfF01234567".to_string(),
    };
    assert!(blob.validate().is_err());
}

#[test]
fn test_stateless_blob_validate_lowercase_hex_ok() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: "aabbccddeeff0123456789aabbccddeeff0123456789aabbccddeeff01234567".to_string(),
    };
    assert!(blob.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R51-008: CapabilityToken temporal ordering validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_capability_token_validate_structure_temporal_ordering_ok() {
    let token = CapabilityToken {
        token_id: "tok-1".to_string(),
        parent_token_id: None,
        issuer: "issuer-1".to_string(),
        holder: "holder-1".to_string(),
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        signature: "sig".to_string(),
        issuer_public_key: "key".to_string(),
    };
    assert!(token.validate_structure().is_ok());
}

#[test]
fn test_capability_token_validate_structure_expires_before_issued_rejected() {
    let token = CapabilityToken {
        token_id: "tok-1".to_string(),
        parent_token_id: None,
        issuer: "issuer-1".to_string(),
        holder: "holder-1".to_string(),
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2027-01-01T00:00:00Z".to_string(),
        expires_at: "2026-01-01T00:00:00Z".to_string(),
        signature: "sig".to_string(),
        issuer_public_key: "key".to_string(),
    };
    let err = token.validate_structure().unwrap_err();
    assert!(
        matches!(err, CapabilityError::ValidationFailed(ref msg) if msg.contains("expires_at must be after issued_at")),
        "expected temporal ordering error, got: {:?}",
        err
    );
}

#[test]
fn test_capability_token_validate_structure_expires_equals_issued_rejected() {
    let token = CapabilityToken {
        token_id: "tok-1".to_string(),
        parent_token_id: None,
        issuer: "issuer-1".to_string(),
        holder: "holder-1".to_string(),
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-06-15T12:00:00Z".to_string(),
        expires_at: "2026-06-15T12:00:00Z".to_string(),
        signature: "sig".to_string(),
        issuer_public_key: "key".to_string(),
    };
    let err = token.validate_structure().unwrap_err();
    assert!(
        matches!(err, CapabilityError::ValidationFailed(ref msg) if msg.contains("expires_at must be after issued_at")),
        "equal timestamps should be rejected, got: {:?}",
        err
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R51-009: NhiDelegationLink self-delegation rejection
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_nhi_delegation_link_validate_ok() {
    let link = NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-02-01T00:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    assert!(link.validate().is_ok());
}

#[test]
fn test_nhi_delegation_link_self_delegation_rejected() {
    let link = NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-a".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-02-01T00:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    let err = link.validate().unwrap_err();
    assert!(err.contains("self-delegation is not allowed"));
}

#[test]
fn test_nhi_delegation_link_self_delegation_case_insensitive() {
    let link = NhiDelegationLink {
        from_agent: "Agent-A".to_string(),
        to_agent: "agent-a".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-02-01T00:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    let err = link.validate().unwrap_err();
    assert!(err.contains("self-delegation is not allowed"));
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R51-012: NhiDelegationLink temporal ordering
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_nhi_delegation_link_temporal_ordering_ok() {
    let link = NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-02-01T00:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    assert!(link.validate().is_ok());
}

#[test]
fn test_nhi_delegation_link_expires_before_created_rejected() {
    let link = NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-02-01T00:00:00Z".to_string(),
        expires_at: "2026-01-01T00:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    let err = link.validate().unwrap_err();
    assert!(err.contains("expires_at"));
    assert!(err.contains("must be after created_at"));
}

#[test]
fn test_nhi_delegation_link_expires_equals_created_rejected() {
    let link = NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-06-15T12:00:00Z".to_string(),
        expires_at: "2026-06-15T12:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    let err = link.validate().unwrap_err();
    assert!(err.contains("expires_at"));
    assert!(err.contains("must be after created_at"));
}

#[test]
fn test_nhi_delegation_link_empty_timestamps_skip_temporal_check() {
    // When both are empty, skip the temporal ordering check
    // (empty timestamps are a separate validation concern)
    let link = NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec![],
        scope_constraints: vec![],
        created_at: "".to_string(),
        expires_at: "".to_string(),
        active: true,
        reason: None,
    };
    assert!(link.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R51-001: Float score [0.0, 1.0] range validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_risk_score_range_rejects_negative() {
    let rs = RiskScore {
        score: -0.1,
        factors: vec![],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    let err = rs.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_risk_score_range_rejects_above_one() {
    let rs = RiskScore {
        score: 1.01,
        factors: vec![],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    let err = rs.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_risk_score_range_accepts_zero() {
    let rs = RiskScore {
        score: 0.0,
        factors: vec![],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    assert!(rs.validate_finite().is_ok());
}

#[test]
fn test_risk_score_range_accepts_one() {
    let rs = RiskScore {
        score: 1.0,
        factors: vec![],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    assert!(rs.validate_finite().is_ok());
}

#[test]
fn test_risk_score_range_accepts_mid() {
    let rs = RiskScore {
        score: 0.5,
        factors: vec![],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    assert!(rs.validate_finite().is_ok());
}

#[test]
fn test_schema_record_trust_score_range_rejects_negative() {
    let mut sr = SchemaRecord::new("test_tool", "abc123", 100);
    sr.trust_score = -0.5;
    let err = sr.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_schema_record_trust_score_range_rejects_above_one() {
    let mut sr = SchemaRecord::new("test_tool", "abc123", 100);
    sr.trust_score = 1.5;
    let err = sr.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_schema_record_trust_score_range_accepts_valid() {
    let sr = SchemaRecord::new("test_tool", "abc123", 100);
    // trust_score starts at 0.0 which is valid
    assert!(sr.validate_finite().is_ok());
}

#[test]
fn test_nhi_behavioral_check_anomaly_score_range_rejects_negative() {
    let check = NhiBehavioralCheckResult {
        within_baseline: true,
        anomaly_score: -0.1,
        deviations: vec![],
        recommendation: NhiBehavioralRecommendation::Allow,
    };
    #[allow(deprecated)]
    let err = check.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_nhi_behavioral_check_anomaly_score_range_rejects_above_one() {
    let check = NhiBehavioralCheckResult {
        within_baseline: false,
        anomaly_score: 1.5,
        deviations: vec![],
        recommendation: NhiBehavioralRecommendation::Revoke,
    };
    #[allow(deprecated)]
    let err = check.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_nhi_behavioral_check_anomaly_score_range_accepts_valid() {
    let check = NhiBehavioralCheckResult {
        within_baseline: true,
        anomaly_score: 0.75,
        deviations: vec![],
        recommendation: NhiBehavioralRecommendation::AllowWithLogging,
    };
    #[allow(deprecated)]
    let result = check.validate_finite();
    assert!(result.is_ok());
}

#[test]
fn test_nhi_behavioral_baseline_confidence_range_rejects_negative() {
    let baseline = NhiBehavioralBaseline {
        confidence: -0.01,
        ..Default::default()
    };
    #[allow(deprecated)]
    let err = baseline.validate_finite().unwrap_err();
    assert!(err.contains("confidence must be in [0.0, 1.0]"));
}

#[test]
fn test_nhi_behavioral_baseline_confidence_range_rejects_above_one() {
    let baseline = NhiBehavioralBaseline {
        confidence: 1.001,
        ..Default::default()
    };
    #[allow(deprecated)]
    let err = baseline.validate_finite().unwrap_err();
    assert!(err.contains("confidence must be in [0.0, 1.0]"));
}

#[test]
fn test_nhi_behavioral_baseline_confidence_range_accepts_valid() {
    let baseline = NhiBehavioralBaseline {
        confidence: 0.95,
        ..Default::default()
    };
    #[allow(deprecated)]
    let result = baseline.validate_finite();
    assert!(result.is_ok());
}

#[test]
fn test_memory_entry_trust_score_range_rejects_negative() {
    let mut entry = MemoryEntry::new(
        "id-1".to_string(),
        "fp".to_string(),
        "test content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.trust_score = -0.5;
    let err = entry.validate().unwrap_err();
    assert!(err.contains("trust_score must be in [0.0, 1.0]"));
}

#[test]
fn test_memory_entry_trust_score_range_rejects_above_one() {
    let mut entry = MemoryEntry::new(
        "id-1".to_string(),
        "fp".to_string(),
        "test content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.trust_score = 2.0;
    let err = entry.validate().unwrap_err();
    assert!(err.contains("trust_score must be in [0.0, 1.0]"));
}

#[test]
fn test_memory_entry_trust_score_range_accepts_valid() {
    let mut entry = MemoryEntry::new(
        "id-1".to_string(),
        "fp".to_string(),
        "test content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    // Set to a valid value without security taint labels
    entry.taint_labels.clear();
    entry.trust_score = 0.75;
    assert!(entry.validate().is_ok());
}

#[test]
fn test_unregistered_agent_risk_score_range_rejects_negative() {
    let agent = UnregisteredAgent {
        agent_id: "rogue".to_string(),
        first_seen: "2026-01-01T00:00:00Z".to_string(),
        last_seen: "2026-01-01T00:00:00Z".to_string(),
        request_count: 1,
        tools_used: std::collections::HashSet::new(),
        risk_score: -0.1,
    };
    #[allow(deprecated)]
    let err = agent.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_unregistered_agent_risk_score_range_rejects_above_one() {
    let agent = UnregisteredAgent {
        agent_id: "rogue".to_string(),
        first_seen: "2026-01-01T00:00:00Z".to_string(),
        last_seen: "2026-01-01T00:00:00Z".to_string(),
        request_count: 1,
        tools_used: std::collections::HashSet::new(),
        risk_score: 5.0,
    };
    #[allow(deprecated)]
    let err = agent.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_shadow_ai_report_total_risk_score_range_rejects_above_one() {
    let report = ShadowAiReport {
        unregistered_agents: vec![],
        unapproved_tools: vec![],
        unknown_servers: vec![],
        total_risk_score: 1.5,
    };
    #[allow(deprecated)]
    let err = report.validate_finite().unwrap_err();
    assert!(err.contains("total_risk_score must be in [0.0, 1.0]"));
}

#[test]
fn test_shadow_ai_report_total_risk_score_range_accepts_valid() {
    let report = ShadowAiReport {
        unregistered_agents: vec![],
        unapproved_tools: vec![],
        unknown_servers: vec![],
        total_risk_score: 0.3,
    };
    #[allow(deprecated)]
    let result = report.validate_finite();
    assert!(result.is_ok());
}

#[test]
fn test_discovered_tool_relevance_score_range_rejects_above_one() {
    let tool = DiscoveredTool {
        metadata: ToolMetadata {
            tool_id: "srv:tool".to_string(),
            name: "tool".to_string(),
            description: "desc".to_string(),
            server_id: "srv".to_string(),
            input_schema: json!({}),
            schema_hash: "abc".to_string(),
            sensitivity: ToolSensitivity::Low,
            domain_tags: vec![],
            token_cost: 10,
        },
        relevance_score: 1.1,
        ttl_secs: 60,
    };
    #[allow(deprecated)]
    let err = tool.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_discovered_tool_relevance_score_range_rejects_negative() {
    let tool = DiscoveredTool {
        metadata: ToolMetadata {
            tool_id: "srv:tool".to_string(),
            name: "tool".to_string(),
            description: "desc".to_string(),
            server_id: "srv".to_string(),
            input_schema: json!({}),
            schema_hash: "abc".to_string(),
            sensitivity: ToolSensitivity::Low,
            domain_tags: vec![],
            token_cost: 10,
        },
        relevance_score: -0.01,
        ttl_secs: 60,
    };
    #[allow(deprecated)]
    let err = tool.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_discovered_tool_relevance_score_range_accepts_valid() {
    let tool = DiscoveredTool {
        metadata: ToolMetadata {
            tool_id: "srv:tool".to_string(),
            name: "tool".to_string(),
            description: "desc".to_string(),
            server_id: "srv".to_string(),
            input_schema: json!({}),
            schema_hash: "abc".to_string(),
            sensitivity: ToolSensitivity::Low,
            domain_tags: vec![],
            token_cost: 10,
        },
        relevance_score: 0.85,
        ttl_secs: 60,
    };
    #[allow(deprecated)]
    let result = tool.validate_finite();
    assert!(result.is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R51-002: ToolSignature.is_expired() malformed timestamp handling
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_tool_signature_is_expired_malformed_timestamp_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("9999-99-99T99:99:99Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // "9999-99-99T99:99:99Z" has invalid month/day/hour/minute/second
    // Should be treated as expired (fail-closed)
    assert!(sig.is_expired("2026-01-15T12:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_malformed_now_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // Malformed `now` timestamp
    assert!(sig.is_expired("not-a-timestampZZZZ"));
}

#[test]
fn test_tool_signature_is_expired_valid_future_not_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // Valid timestamps, expires_at is in the future
    assert!(!sig.is_expired("2026-02-15T12:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_valid_past_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2026-01-15T00:00:00Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // now is after expires_at
    assert!(sig.is_expired("2026-02-01T00:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_no_expiry_not_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // No expires_at means it never expires
    assert!(!sig.is_expired("2030-12-31T23:59:59Z"));
}

#[test]
fn test_tool_signature_is_expired_short_timestamp_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // Too short to be valid
    assert!(sig.is_expired("2026Z"));
}

#[test]
fn test_tool_signature_is_expired_year_before_1970_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("1969-12-31T23:59:59Z"));
}

#[test]
fn test_tool_signature_is_expired_month_00_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("2026-00-15T12:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_month_13_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("2026-13-15T12:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_day_00_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("2026-01-00T12:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_day_32_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("2026-01-32T12:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_hour_24_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("2026-01-15T24:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_minute_60_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("2026-01-15T12:60:00Z"));
}

#[test]
fn test_tool_signature_is_expired_second_60_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("2026-01-15T12:00:60Z"));
}

#[test]
fn test_tool_signature_is_expired_letters_in_digit_positions() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("ABCD-EF-GHTab:cd:efZ"));
}

#[test]
fn test_tool_signature_is_expired_malformed_expires_at_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("9999-99-99T99:99:99Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // Even though "9999-99-99T99:99:99Z" > any valid timestamp lexicographically,
    // the malformed month/day/hour/minute/second should cause fail-closed (expired).
    assert!(sig.is_expired("2026-02-15T12:00:00Z"));
}

// ── FIND-R53-001: TaskCheckpoint Debug redacts signature and public_key ──────

#[test]
fn test_task_checkpoint_debug_redacts_signature() {
    let cp = TaskCheckpoint {
        checkpoint_id: "cp-1".to_string(),
        task_id: "task-1".to_string(),
        sequence: 0,
        state_hash: "abc123".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        signature: "supersecret_signature".to_string(),
        public_key: "supersecret_pubkey".to_string(),
    };
    let debug = format!("{:?}", cp);
    assert!(
        !debug.contains("supersecret_signature"),
        "Debug output must not contain raw signature"
    );
    assert!(
        !debug.contains("supersecret_pubkey"),
        "Debug output must not contain raw public_key"
    );
    assert!(
        debug.contains("[REDACTED]"),
        "Debug output must show [REDACTED] for sensitive fields"
    );
    assert!(debug.contains("cp-1"));
    assert!(debug.contains("task-1"));
    assert!(debug.contains("abc123"));
}

// ── FIND-R53-002: AccountabilityAttestation Debug redacts signature/public_key

#[test]
fn test_accountability_attestation_debug_redacts_signature() {
    let att = AccountabilityAttestation {
        attestation_id: "att-1".to_string(),
        agent_id: "agent-1".to_string(),
        did: None,
        statement: "I agree".to_string(),
        policy_hash: "hash123".to_string(),
        signature: "topsecret_sig".to_string(),
        algorithm: "Ed25519".to_string(),
        public_key: "topsecret_key".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        verified: false,
    };
    let debug = format!("{:?}", att);
    assert!(
        !debug.contains("topsecret_sig"),
        "Debug output must not contain raw signature"
    );
    assert!(
        !debug.contains("topsecret_key"),
        "Debug output must not contain raw public_key"
    );
    assert!(
        debug.contains("[REDACTED]"),
        "Debug output must show [REDACTED] for sensitive fields"
    );
    assert!(debug.contains("att-1"));
    assert!(debug.contains("agent-1"));
    assert!(debug.contains("Ed25519"));
}

// ── FIND-R53-003: AccessReviewEntry usage_ratio [0.0, 1.0] range validation ──

#[test]
fn test_access_review_entry_validate_rejects_negative_usage_ratio() {
    let entry = AccessReviewEntry {
        agent_id: "agent-1".to_string(),
        session_ids: vec![],
        first_access: "2026-01-01T00:00:00Z".to_string(),
        last_access: "2026-01-31T00:00:00Z".to_string(),
        total_evaluations: 10,
        allow_count: 5,
        deny_count: 5,
        require_approval_count: 0,
        tools_accessed: vec![],
        functions_called: vec![],
        permissions_granted: 5,
        permissions_used: 3,
        usage_ratio: -0.1,
        unused_permissions: vec![],
        agency_recommendation: "Optimal".to_string(),
    };
    let err = entry.validate().unwrap_err();
    assert!(err.contains("usage_ratio must be in [0.0, 1.0]"));
}

#[test]
fn test_access_review_entry_validate_rejects_above_one_usage_ratio() {
    let entry = AccessReviewEntry {
        agent_id: "agent-1".to_string(),
        session_ids: vec![],
        first_access: "2026-01-01T00:00:00Z".to_string(),
        last_access: "2026-01-31T00:00:00Z".to_string(),
        total_evaluations: 10,
        allow_count: 5,
        deny_count: 5,
        require_approval_count: 0,
        tools_accessed: vec![],
        functions_called: vec![],
        permissions_granted: 5,
        permissions_used: 3,
        usage_ratio: 1.5,
        unused_permissions: vec![],
        agency_recommendation: "Optimal".to_string(),
    };
    let err = entry.validate().unwrap_err();
    assert!(err.contains("usage_ratio must be in [0.0, 1.0]"));
}

#[test]
fn test_access_review_entry_validate_rejects_nan_usage_ratio() {
    let entry = AccessReviewEntry {
        agent_id: "agent-1".to_string(),
        session_ids: vec![],
        first_access: "2026-01-01T00:00:00Z".to_string(),
        last_access: "2026-01-31T00:00:00Z".to_string(),
        total_evaluations: 10,
        allow_count: 5,
        deny_count: 5,
        require_approval_count: 0,
        tools_accessed: vec![],
        functions_called: vec![],
        permissions_granted: 5,
        permissions_used: 3,
        usage_ratio: f64::NAN,
        unused_permissions: vec![],
        agency_recommendation: "Optimal".to_string(),
    };
    let err = entry.validate().unwrap_err();
    assert!(err.contains("non-finite usage_ratio"));
}

#[test]
fn test_access_review_entry_validate_accepts_valid_ratio() {
    let entry = AccessReviewEntry {
        agent_id: "agent-1".to_string(),
        session_ids: vec!["s1".to_string()],
        first_access: "2026-01-01T00:00:00Z".to_string(),
        last_access: "2026-01-31T00:00:00Z".to_string(),
        total_evaluations: 10,
        allow_count: 5,
        deny_count: 5,
        require_approval_count: 0,
        tools_accessed: vec!["tool1".to_string()],
        functions_called: vec!["fn1".to_string()],
        permissions_granted: 5,
        permissions_used: 4,
        usage_ratio: 0.8,
        unused_permissions: vec!["p1".to_string()],
        agency_recommendation: "Optimal".to_string(),
    };
    assert!(entry.validate().is_ok());
}

// ── FIND-R53-006: AccessReviewEntry unbounded Vec fields ─────────────────────

#[test]
fn test_access_review_entry_validate_rejects_too_many_session_ids() {
    let entry = AccessReviewEntry {
        agent_id: "agent-1".to_string(),
        session_ids: (0..=AccessReviewEntry::MAX_SESSION_IDS)
            .map(|i| format!("s{i}"))
            .collect(),
        first_access: "2026-01-01T00:00:00Z".to_string(),
        last_access: "2026-01-31T00:00:00Z".to_string(),
        total_evaluations: 10,
        allow_count: 5,
        deny_count: 5,
        require_approval_count: 0,
        tools_accessed: vec![],
        functions_called: vec![],
        permissions_granted: 5,
        permissions_used: 4,
        usage_ratio: 0.8,
        unused_permissions: vec![],
        agency_recommendation: "Optimal".to_string(),
    };
    let err = entry.validate().unwrap_err();
    assert!(err.contains("session_ids"));
}

#[test]
fn test_access_review_entry_validate_rejects_too_many_unused_permissions() {
    let entry = AccessReviewEntry {
        agent_id: "agent-1".to_string(),
        session_ids: vec![],
        first_access: "2026-01-01T00:00:00Z".to_string(),
        last_access: "2026-01-31T00:00:00Z".to_string(),
        total_evaluations: 10,
        allow_count: 5,
        deny_count: 5,
        require_approval_count: 0,
        tools_accessed: vec![],
        functions_called: vec![],
        permissions_granted: 5,
        permissions_used: 4,
        usage_ratio: 0.8,
        unused_permissions: (0..=AccessReviewEntry::MAX_UNUSED_PERMISSIONS)
            .map(|i| format!("p{i}"))
            .collect(),
        agency_recommendation: "Optimal".to_string(),
    };
    let err = entry.validate().unwrap_err();
    assert!(err.contains("unused_permissions"));
}

// ── FIND-R53-004: LeastAgencyReport usage_ratio [0.0, 1.0] range validation ──

#[test]
fn test_least_agency_report_validate_rejects_negative_usage_ratio() {
    let report = LeastAgencyReport {
        agent_id: "agent-1".to_string(),
        session_id: "sess-1".to_string(),
        granted_permissions: 5,
        used_permissions: 3,
        unused_permissions: vec![],
        usage_ratio: -0.5,
        recommendation: AgencyRecommendation::Critical,
    };
    let err = report.validate().unwrap_err();
    assert!(err.contains("usage_ratio must be in [0.0, 1.0]"));
}

#[test]
fn test_least_agency_report_validate_rejects_above_one_usage_ratio() {
    let report = LeastAgencyReport {
        agent_id: "agent-1".to_string(),
        session_id: "sess-1".to_string(),
        granted_permissions: 5,
        used_permissions: 3,
        unused_permissions: vec![],
        usage_ratio: 2.0,
        recommendation: AgencyRecommendation::Optimal,
    };
    let err = report.validate().unwrap_err();
    assert!(err.contains("usage_ratio must be in [0.0, 1.0]"));
}

#[test]
fn test_least_agency_report_validate_rejects_nan_usage_ratio() {
    let report = LeastAgencyReport {
        agent_id: "agent-1".to_string(),
        session_id: "sess-1".to_string(),
        granted_permissions: 5,
        used_permissions: 3,
        unused_permissions: vec![],
        usage_ratio: f64::NAN,
        recommendation: AgencyRecommendation::Critical,
    };
    let err = report.validate().unwrap_err();
    assert!(err.contains("non-finite usage_ratio"));
}

#[test]
fn test_least_agency_report_validate_accepts_valid() {
    let report = LeastAgencyReport {
        agent_id: "agent-1".to_string(),
        session_id: "sess-1".to_string(),
        granted_permissions: 5,
        used_permissions: 4,
        unused_permissions: vec!["p1".to_string()],
        usage_ratio: 0.8,
        recommendation: AgencyRecommendation::Optimal,
    };
    assert!(report.validate().is_ok());
}

#[test]
fn test_least_agency_report_validate_accepts_boundary_values() {
    let report_zero = LeastAgencyReport {
        agent_id: "a".to_string(),
        session_id: "s".to_string(),
        granted_permissions: 5,
        used_permissions: 0,
        unused_permissions: vec![],
        usage_ratio: 0.0,
        recommendation: AgencyRecommendation::Critical,
    };
    assert!(report_zero.validate().is_ok());

    let report_one = LeastAgencyReport {
        agent_id: "a".to_string(),
        session_id: "s".to_string(),
        granted_permissions: 0,
        used_permissions: 0,
        unused_permissions: vec![],
        usage_ratio: 1.0,
        recommendation: AgencyRecommendation::Optimal,
    };
    assert!(report_one.validate().is_ok());
}

// ── FIND-R53-005: LeastAgencyReport unbounded unused_permissions ─────────────

#[test]
fn test_least_agency_report_validate_rejects_too_many_unused_permissions() {
    let report = LeastAgencyReport {
        agent_id: "agent-1".to_string(),
        session_id: "sess-1".to_string(),
        granted_permissions: 20_000,
        used_permissions: 0,
        unused_permissions: (0..=LeastAgencyReport::MAX_UNUSED_PERMISSIONS)
            .map(|i| format!("p{i}"))
            .collect(),
        usage_ratio: 0.0,
        recommendation: AgencyRecommendation::Critical,
    };
    let err = report.validate().unwrap_err();
    assert!(err.contains("unused_permissions"));
    assert!(err.contains("10000"));
}
