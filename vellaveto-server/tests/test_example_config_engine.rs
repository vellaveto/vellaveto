// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests that the shipped example-config.toml produces correct engine
//! behavior when policies are loaded and evaluated.

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
fn example_config_has_all_three_policy_types() {
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
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "file:read should be allowed, got {result:?}"
    );
}

#[test]
fn example_config_file_delete_is_denied() {
    let policies = load_example_config().to_policies();
    let engine = PolicyEngine::new(false);
    let action = Action::new("file".to_string(), "delete".to_string(), json!({}));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "file:delete should be denied, got {result:?}"
    );
}

#[test]
fn example_config_bash_execute_is_denied() {
    let policies = load_example_config().to_policies();
    let engine = PolicyEngine::new(false);
    let action = Action::new("bash".to_string(), "execute".to_string(), json!({}));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "bash:execute should be denied, got {result:?}"
    );
}

#[test]
fn example_config_network_requires_approval() {
    let policies = load_example_config().to_policies();
    let engine = PolicyEngine::new(false);
    let action = Action::new("network".to_string(), "connect".to_string(), json!({}));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "network:connect should require approval, got {result:?}"
    );
}

#[test]
fn example_config_unknown_tool_gets_default_allow() {
    let policies = load_example_config().to_policies();
    let engine = PolicyEngine::new(false);
    let action = Action::new(
        "unknown_tool".to_string(),
        "unknown_func".to_string(),
        json!({}),
    );
    let result = engine.evaluate_action(&action, &policies).unwrap();
    // The default allow at priority 1 should catch this
    assert!(
        matches!(result, Verdict::Allow),
        "Unknown tool should fall through to default allow, got {result:?}"
    );
}

#[test]
fn example_config_toml_roundtrips_through_serialize() {
    let config = load_example_config();
    // Serialize to TOML
    let toml_str = toml::to_string_pretty(&config).expect("config should serialize to TOML");
    // Parse it back
    let reparsed = PolicyConfig::from_toml(&toml_str).expect("serialized TOML should be parseable");
    // Same number of policies
    assert_eq!(config.policies.len(), reparsed.policies.len());
}
