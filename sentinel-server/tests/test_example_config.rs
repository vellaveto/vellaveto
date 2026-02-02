//! Tests that the shipped example-config.toml is valid and produces
//! the expected policies when loaded.

use sentinel_config::PolicyConfig;
use sentinel_types::PolicyType;

#[test]
fn example_config_toml_is_parseable() {
    let config = PolicyConfig::load_file("sentinel-server/example-config.toml")
        .or_else(|_| PolicyConfig::load_file("example-config.toml"))
        .expect("example-config.toml should be parseable");

    assert!(!config.policies.is_empty(),
        "example config should have at least one policy");
}

#[test]
fn example_config_produces_valid_policies() {
    let config = PolicyConfig::load_file("sentinel-server/example-config.toml")
        .or_else(|_| PolicyConfig::load_file("example-config.toml"))
        .expect("load example config");

    let policies = config.to_policies();
    assert!(!policies.is_empty());

    // Every policy should have a non-empty name
    for p in &policies {
        assert!(!p.name.is_empty(), "Policy name should not be empty");
        assert!(!p.id.is_empty(), "Policy id should not be empty");
    }
}

#[test]
fn example_config_has_expected_policy_types() {
    let config = PolicyConfig::load_file("sentinel-server/example-config.toml")
        .or_else(|_| PolicyConfig::load_file("example-config.toml"))
        .expect("load example config");

    let policies = config.to_policies();
    let has_allow = policies.iter().any(|p| matches!(p.policy_type, PolicyType::Allow));
    let has_deny = policies.iter().any(|p| matches!(p.policy_type, PolicyType::Deny));

    assert!(has_allow, "Example config should have at least one Allow policy");
    assert!(has_deny, "Example config should have at least one Deny policy");
}

#[test]
fn example_config_evaluates_correctly_through_engine() {
    use sentinel_engine::PolicyEngine;
    use sentinel_types::{Action, Verdict};
    use serde_json::json;

    let config = PolicyConfig::load_file("sentinel-server/example-config.toml")
        .or_else(|_| PolicyConfig::load_file("example-config.toml"))
        .expect("load example config");

    let policies = config.to_policies();
    let engine = PolicyEngine::new(false);

    // Based on the example config: bash should be denied (priority 200 deny)
    let bash_action = Action {
        tool: "bash".to_string(),
        function: "execute".to_string(),
        parameters: json!({}),
    };
    let verdict = engine.evaluate_action(&bash_action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }),
        "bash execute should be denied by example config. Got: {:?}", verdict);

    // file:read should be allowed (priority 10 allow)
    let read_action = Action {
        tool: "file".to_string(),
        function: "read".to_string(),
        parameters: json!({}),
    };
    let verdict = engine.evaluate_action(&read_action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow),
        "file:read should be allowed by example config. Got: {:?}", verdict);
}