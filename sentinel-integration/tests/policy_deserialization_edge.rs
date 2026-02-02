//! Tests Policy deserialization from JSON edge cases.
//! The config → engine pipeline depends on Policy deserializing correctly
//! from user-provided JSON. These tests verify edge cases in that path.

use sentinel_types::{Policy, PolicyType, Verdict};
use serde_json::json;

// ═══════════════════════════════════
// BASIC POLICY DESERIALIZATION
// ═══════════════════════════════════

#[test]
fn policy_with_allow_type_from_json() {
    let val = json!({
        "id": "file:read",
        "name": "Allow reads",
        "policy_type": "Allow",
        "priority": 10
    });
    let policy: Policy = serde_json::from_value(val).unwrap();
    assert_eq!(policy.id, "file:read");
    assert_eq!(policy.priority, 10);
    assert!(matches!(policy.policy_type, PolicyType::Allow));
}

#[test]
fn policy_with_deny_type_from_json() {
    let val = json!({
        "id": "*",
        "name": "Deny all",
        "policy_type": "Deny",
        "priority": 1000
    });
    let policy: Policy = serde_json::from_value(val).unwrap();
    assert!(matches!(policy.policy_type, PolicyType::Deny));
}

#[test]
fn policy_with_conditional_type_from_json() {
    let val = json!({
        "id": "net:*",
        "name": "Network approval",
        "policy_type": {
            "Conditional": {
                "conditions": {
                    "require_approval": true,
                    "forbidden_parameters": ["exfiltrate"]
                }
            }
        },
        "priority": 500
    });
    let policy: Policy = serde_json::from_value(val).unwrap();
    match &policy.policy_type {
        PolicyType::Conditional { conditions } => {
            assert_eq!(conditions.get("require_approval").unwrap().as_bool().unwrap(), true);
            assert!(conditions.get("forbidden_parameters").unwrap().is_array());
        }
        _ => panic!("Expected Conditional"),
    }
}

// ═══════════════════════════════════
// PRIORITY EDGE CASES
// ═══════════════════════════════════

#[test]
fn policy_with_negative_priority() {
    let val = json!({
        "id": "*",
        "name": "Low priority",
        "policy_type": "Allow",
        "priority": -100
    });
    let policy: Policy = serde_json::from_value(val).unwrap();
    assert_eq!(policy.priority, -100);
}

#[test]
fn policy_with_zero_priority() {
    let val = json!({
        "id": "*",
        "name": "Zero priority",
        "policy_type": "Allow",
        "priority": 0
    });
    let policy: Policy = serde_json::from_value(val).unwrap();
    assert_eq!(policy.priority, 0);
}

#[test]
fn policy_with_i32_max_priority() {
    let val = json!({
        "id": "*",
        "name": "Max priority",
        "policy_type": "Deny",
        "priority": i32::MAX
    });
    let policy: Policy = serde_json::from_value(val).unwrap();
    assert_eq!(policy.priority, i32::MAX);
}

#[test]
fn policy_with_i32_min_priority() {
    let val = json!({
        "id": "*",
        "name": "Min priority",
        "policy_type": "Allow",
        "priority": i32::MIN
    });
    let policy: Policy = serde_json::from_value(val).unwrap();
    assert_eq!(policy.priority, i32::MIN);
}

// ═══════════════════════════════════
// INVALID JSON SHAPES
// ═══════════════════════════════════

#[test]
fn policy_missing_id_fails() {
    let val = json!({
        "name": "No id",
        "policy_type": "Allow",
        "priority": 10
    });
    assert!(serde_json::from_value::<Policy>(val).is_err());
}

#[test]
fn policy_missing_name_fails() {
    let val = json!({
        "id": "*",
        "policy_type": "Allow",
        "priority": 10
    });
    assert!(serde_json::from_value::<Policy>(val).is_err());
}

#[test]
fn policy_missing_policy_type_fails() {
    let val = json!({
        "id": "*",
        "name": "No type",
        "priority": 10
    });
    assert!(serde_json::from_value::<Policy>(val).is_err());
}

#[test]
fn policy_missing_priority_fails() {
    let val = json!({
        "id": "*",
        "name": "No priority",
        "policy_type": "Allow"
    });
    assert!(serde_json::from_value::<Policy>(val).is_err());
}

#[test]
fn policy_with_float_priority_fails() {
    let val = json!({
        "id": "*",
        "name": "Float priority",
        "policy_type": "Allow",
        "priority": 10.5
    });
    // serde will reject a float for an i32 field
    assert!(serde_json::from_value::<Policy>(val).is_err());
}

#[test]
fn policy_with_string_priority_fails() {
    let val = json!({
        "id": "*",
        "name": "String priority",
        "policy_type": "Allow",
        "priority": "high"
    });
    assert!(serde_json::from_value::<Policy>(val).is_err());
}

#[test]
fn policy_with_invalid_policy_type_string_fails() {
    let val = json!({
        "id": "*",
        "name": "Bad type",
        "policy_type": "Block",
        "priority": 10
    });
    assert!(serde_json::from_value::<Policy>(val).is_err());
}

// ═══════════════════════════════════
// ROUNDTRIP: SERIALIZE → DESERIALIZE
// ════════════════════════════════════

#[test]
fn policy_roundtrip_with_all_types() {
    let policies = vec![
        Policy {
            id: "a:b".to_string(),
            name: "Allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 1,
        },
        Policy {
            id: "c:d".to_string(),
            name: "Deny".to_string(),
            policy_type: PolicyType::Deny,
            priority: -1,
        },
        Policy {
            id: "*".to_string(),
            name: "Conditional".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true, "forbidden_parameters": ["x"]}),
            },
            priority: i32::MAX,
        },
    ];

    for policy in &policies {
        let json_str = serde_json::to_string(policy).unwrap();
        let deserialized: Policy = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.id, policy.id);
        assert_eq!(deserialized.name, policy.name);
        assert_eq!(deserialized.priority, policy.priority);
        assert_eq!(deserialized.policy_type, policy.policy_type);
    }
}

/// Array of policies roundtrips (simulating config file load).
#[test]
fn policy_array_roundtrip() {
    let policies = vec![
        Policy {
            id: "file:*".to_string(),
            name: "File policy".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
        },
        Policy {
            id: "shell:*".to_string(),
            name: "Shell policy".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
        },
    ];

    let json_str = serde_json::to_string(&policies).unwrap();
    let deserialized: Vec<Policy> = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.len(), 2);
    assert_eq!(deserialized[0].id, "file:*");
    assert_eq!(deserialized[1].id, "shell:*");
}