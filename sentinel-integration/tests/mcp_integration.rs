//! Integration tests for the MCP server with realistic multi-step workflows.

use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

// Note: sentinel-integration doesn't depend on sentinel-mcp directly,
// so these tests exercise the engine + types pipeline that MCP would use.

// ════════════════════════════════════════════════
// SIMULATED MCP REQUEST/RESPONSE FLOWS
// ═════════════════════════════════════════════════

#[test]
fn mcp_style_add_policy_then_evaluate() {
    let engine = sentinel_engine::PolicyEngine::new(false);

    // Simulate MCP "add_policy" by deserializing from JSON (same as MCP handler does)
    let policy_json = json!({
        "id": "bash:*",
        "name": "Block bash",
        "policy_type": "Deny",
        "priority": 100
    });
    let policy: Policy =
        serde_json::from_value(policy_json).expect("policy deserialization failed");

    // Simulate MCP "evaluate_action" by deserializing action from JSON
    let action_json = json!({
        "tool": "bash",
        "function": "execute",
        "parameters": {"cmd": "rm -rf /"}
    });
    let action: Action =
        serde_json::from_value(action_json).expect("action deserialization failed");

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));

    // Verify verdict serializes to expected JSON shape
    let verdict_json = serde_json::to_value(&verdict).unwrap();
    assert!(verdict_json.get("Deny").is_some());
    assert!(verdict_json["Deny"]["reason"]
        .as_str()
        .unwrap()
        .contains("Block bash"));
}

#[test]
fn mcp_style_policy_lifecycle() {
    let engine = sentinel_engine::PolicyEngine::new(false);

    // Start with no policies
    let mut policies: Vec<Policy> = Vec::new();

    let action = Action {
        tool: "file".into(),
        function: "read".into(),
        parameters: json!({}),
    };

    // No policies  deny (fail-closed)
    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));

    // Add allow policy
    let p1: Policy = serde_json::from_value(json!({
        "id": "file:*",
        "name": "Allow file ops",
        "policy_type": "Allow",
        "priority": 10
    }))
    .unwrap();
    policies.push(p1);

    assert_eq!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Allow
    );

    // Add higher-priority deny
    let p2: Policy = serde_json::from_value(json!({
        "id": "file:*",
        "name": "Deny file ops",
        "policy_type": "Deny",
        "priority": 100
    }))
    .unwrap();
    policies.push(p2);

    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));

    // Remove deny policy (simulate MCP remove_policy by id)
    policies.retain(|p| p.name != "Deny file ops");

    assert_eq!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Allow
    );
}

#[test]
fn mcp_style_batch_evaluation() {
    let engine = sentinel_engine::PolicyEngine::new(false);

    let policies: Vec<Policy> = vec![
        serde_json::from_value(json!({
            "id": "file:read",
            "name": "Allow reads",
            "policy_type": "Allow",
            "priority": 10
        }))
        .unwrap(),
        serde_json::from_value(json!({
            "id": "file:write",
            "name": "Require approval for writes",
            "policy_type": {"Conditional": {"conditions": {"require_approval": true}}},
            "priority": 10
        }))
        .unwrap(),
        serde_json::from_value(json!({
            "id": "file:delete",
            "name": "Block deletes",
            "policy_type": "Deny",
            "priority": 10
        }))
        .unwrap(),
    ];

    // Batch evaluate multiple actions (simulating a burst of MCP requests)
    #[allow(clippy::type_complexity)]
    let actions: Vec<(Action, Box<dyn Fn(&Verdict) -> bool>)> = vec![
        (
            serde_json::from_value(json!({"tool": "file", "function": "read", "parameters": {}}))
                .unwrap(),
            Box::new(|v| *v == Verdict::Allow),
        ),
        (
            serde_json::from_value(json!({"tool": "file", "function": "write", "parameters": {}}))
                .unwrap(),
            Box::new(|v| matches!(v, Verdict::RequireApproval { .. })),
        ),
        (
            serde_json::from_value(json!({"tool": "file", "function": "delete", "parameters": {}}))
                .unwrap(),
            Box::new(|v| matches!(v, Verdict::Deny { .. })),
        ),
        (
            serde_json::from_value(json!({"tool": "file", "function": "chmod", "parameters": {}}))
                .unwrap(),
            Box::new(|v| matches!(v, Verdict::Deny { .. })), // no matching policy → deny
        ),
    ];

    for (action, check) in &actions {
        let verdict = engine.evaluate_action(action, &policies).unwrap();
        assert!(
            check(&verdict),
            "{}:{} got unexpected verdict: {:?}",
            action.tool,
            action.function,
            verdict
        );
    }
}

// ═════════════════════════════════════════════════
// JSON WIRE FORMAT COMPATIBILITY
// ═════════════════════════════════════════════════

#[test]
fn verdict_json_wire_format() {
    // Verify that the JSON representation matches what an MCP client would expect
    let allow_json = serde_json::to_value(Verdict::Allow).unwrap();
    assert_eq!(allow_json, json!("Allow"));

    let deny_json = serde_json::to_value(Verdict::Deny {
        reason: "blocked".to_string(),
    })
    .unwrap();
    assert_eq!(deny_json, json!({"Deny": {"reason": "blocked"}}));

    let approval_json = serde_json::to_value(Verdict::RequireApproval {
        reason: "needs review".to_string(),
    })
    .unwrap();
    assert_eq!(
        approval_json,
        json!({"RequireApproval": {"reason": "needs review"}})
    );
}

#[test]
fn policy_type_json_wire_format() {
    assert_eq!(
        serde_json::to_value(PolicyType::Allow).unwrap(),
        json!("Allow")
    );
    assert_eq!(
        serde_json::to_value(PolicyType::Deny).unwrap(),
        json!("Deny")
    );

    let conditional = PolicyType::Conditional {
        conditions: json!({"require_approval": true}),
    };
    let expected = json!({"Conditional": {"conditions": {"require_approval": true}}});
    assert_eq!(serde_json::to_value(conditional).unwrap(), expected);
}
