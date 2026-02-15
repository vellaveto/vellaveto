//! Tests that the shipped example-config.toml is valid, produces
//! correct engine behavior, and survives roundtrip serialization.

use serde_json::json;
use vellaveto_config::PolicyConfig;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, PolicyType, Verdict};

fn load_example_config() -> PolicyConfig {
    PolicyConfig::load_file("vellaveto-server/example-config.toml")
        .or_else(|_| PolicyConfig::load_file("example-config.toml"))
        .expect("example-config.toml should be loadable")
}

#[test]
fn example_config_has_at_least_three_policies() {
    let config = load_example_config();
    assert!(
        config.policies.len() >= 3,
        "Example should demonstrate multiple policy types, has {}",
        config.policies.len()
    );
}

#[test]
fn example_config_has_allow_deny_and_conditional() {
    let config = load_example_config();
    let policies = config.to_policies();
    let has_allow = policies
        .iter()
        .any(|p| matches!(p.policy_type, PolicyType::Allow));
    let has_deny = policies
        .iter()
        .any(|p| matches!(p.policy_type, PolicyType::Deny));
    let has_conditional = policies
        .iter()
        .any(|p| matches!(p.policy_type, PolicyType::Conditional { .. }));

    assert!(has_allow, "Example should have at least one Allow policy");
    assert!(has_deny, "Example should have at least one Deny policy");
    assert!(
        has_conditional,
        "Example should have at least one Conditional policy"
    );
}

#[test]
fn example_config_file_read_is_allowed() {
    let policies = load_example_config().to_policies();
    let engine = PolicyEngine::new(false);
    let action = Action::new("file".to_string(), "read".to_string(), json!({}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "file:read should be allowed by example config, got {:?}",
        verdict
    );
}

#[test]
fn example_config_bash_is_denied() {
    let policies = load_example_config().to_policies();
    let engine = PolicyEngine::new(false);
    let action = Action::new("bash".to_string(), "execute".to_string(), json!({}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "bash:execute should be denied by example config, got {:?}",
        verdict
    );
}

#[test]
fn example_config_file_delete_is_denied() {
    let policies = load_example_config().to_policies();
    let engine = PolicyEngine::new(false);
    let action = Action::new("file".to_string(), "delete".to_string(), json!({}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "file:delete should be denied by example config, got {:?}",
        verdict
    );
}

#[test]
fn example_config_network_requires_approval() {
    let policies = load_example_config().to_policies();
    let engine = PolicyEngine::new(false);
    let action = Action::new("network".to_string(), "fetch".to_string(), json!({}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::RequireApproval { .. }),
        "network:* should require approval by example config, got {:?}",
        verdict
    );
}

#[test]
fn example_config_unknown_tool_gets_default_allow() {
    let policies = load_example_config().to_policies();
    let engine = PolicyEngine::new(false);
    let action = Action::new(
        "unknown_tool_xyz".to_string(),
        "do_something".to_string(),
        json!({}),
    );
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    // The example config has a default allow at priority 1
    assert!(
        matches!(verdict, Verdict::Allow),
        "Unknown tool should hit default allow, got {:?}",
        verdict
    );
}

#[test]
fn example_config_toml_roundtrips_through_serialization() {
    let config = load_example_config();
    let serialized = toml::to_string_pretty(&config).expect("serialize to TOML");
    let reparsed = PolicyConfig::from_toml(&serialized).expect("reparse serialized TOML");
    assert_eq!(
        config.policies.len(),
        reparsed.policies.len(),
        "Policy count should survive TOML roundtrip"
    );
}
