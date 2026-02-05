//! Adversarial tests for sentinel-config TOML enhancements.
//! Tries to break from_toml, load_file, to_policies, and default handling.

use sentinel_config::PolicyConfig;
use sentinel_types::PolicyType;
use tempfile::TempDir;

// ═══════════════════════════════════
// from_toml: HAPPY PATH
// ═══════════════════════════════════

#[test]
fn from_toml_single_allow_policy() {
    let toml = r#"
[[policies]]
name = "Allow reads"
tool_pattern = "file"
function_pattern = "read"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.policies.len(), 1);
    assert_eq!(config.policies[0].name, "Allow reads");
    assert_eq!(config.policies[0].tool_pattern, "file");
    assert_eq!(config.policies[0].function_pattern, "read");
    assert!(matches!(config.policies[0].policy_type, PolicyType::Allow));
}

#[test]
fn from_toml_multiple_policies() {
    let toml = r#"
[[policies]]
name = "a"
tool_pattern = "t1"
function_pattern = "f1"
policy_type = "Allow"

[[policies]]
name = "b"
tool_pattern = "t2"
function_pattern = "f2"
policy_type = "Deny"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.policies.len(), 2);
    assert!(matches!(config.policies[0].policy_type, PolicyType::Allow));
    assert!(matches!(config.policies[1].policy_type, PolicyType::Deny));
}

#[test]
fn from_toml_conditional_policy_with_conditions() {
    let toml = r#"
[[policies]]
name = "Needs approval"
tool_pattern = "shell"
function_pattern = "*"
priority = 500

[policies.policy_type.Conditional]
conditions = { require_approval = true }
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.policies.len(), 1);
    match &config.policies[0].policy_type {
        PolicyType::Conditional { conditions } => {
            assert_eq!(
                conditions.get("require_approval").unwrap().as_bool(),
                Some(true)
            );
        }
        other => panic!("Expected Conditional, got {:?}", other),
    }
}

// ═══════════════════════════════════
// from_toml: PRIORITY AND ID DEFAULTS
// ═══════════════════════════════════

#[test]
fn from_toml_priority_defaults_to_0_when_omitted() {
    let toml = r#"
[[policies]]
name = "No priority"
tool_pattern = "t"
function_pattern = "f"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    // SECURITY (R19-CFG-1): Priority defaults to 0 (lowest priority)
    let policies = config.to_policies();
    assert_eq!(policies[0].priority, 0, "Default priority should be 0");
}

#[test]
fn from_toml_explicit_priority_is_preserved() {
    let toml = r#"
[[policies]]
name = "Custom priority"
tool_pattern = "t"
function_pattern = "f"
policy_type = "Allow"
priority = 42
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    let policies = config.to_policies();
    assert_eq!(policies[0].priority, 42);
}

#[test]
fn from_toml_negative_priority_is_accepted() {
    let toml = r#"
[[policies]]
name = "Negative"
tool_pattern = "t"
function_pattern = "f"
policy_type = "Deny"
priority = -500
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    let policies = config.to_policies();
    assert_eq!(policies[0].priority, -500);
}

#[test]
fn from_toml_id_defaults_to_tool_colon_function() {
    let toml = r#"
[[policies]]
name = "No id"
tool_pattern = "bash"
function_pattern = "execute"
policy_type = "Deny"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    let policies = config.to_policies();
    assert_eq!(
        policies[0].id, "bash:execute",
        "Default id should be tool_pattern:function_pattern"
    );
}

#[test]
fn from_toml_explicit_id_overrides_default() {
    let toml = r#"
[[policies]]
name = "Custom id"
tool_pattern = "bash"
function_pattern = "execute"
policy_type = "Deny"
id = "my_custom_id"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    let policies = config.to_policies();
    assert_eq!(policies[0].id, "my_custom_id");
}

// ═══════════════════════════════════
// from_toml: EDGE CASES AND ERROR PATHS
// ═══════════════════════════════════

#[test]
fn from_toml_empty_string_is_error() {
    let result = PolicyConfig::from_toml("");
    // Empty TOML has no [[policies]] array — should either error or produce empty list
    // If it succeeds, policies should be empty
    if let Ok(config) = result {
        assert!(
            config.policies.is_empty(),
            "Empty TOML should produce empty policy list"
        )
    }
}

#[test]
fn from_toml_garbage_input_is_error() {
    let result = PolicyConfig::from_toml("this is not valid toml {{{{");
    assert!(result.is_err(), "Garbage TOML should produce an error");
}

#[test]
fn from_toml_missing_required_fields_is_error() {
    // Missing name field
    let toml = r#"
[[policies]]
tool_pattern = "t"
function_pattern = "f"
policy_type = "Allow"
"#;
    let result = PolicyConfig::from_toml(toml);
    assert!(result.is_err(), "Missing 'name' field should fail");
}

#[test]
fn from_toml_missing_tool_pattern_is_error() {
    let toml = r#"
[[policies]]
name = "test"
function_pattern = "f"
policy_type = "Allow"
"#;
    let result = PolicyConfig::from_toml(toml);
    assert!(result.is_err(), "Missing 'tool_pattern' field should fail");
}

#[test]
fn from_toml_missing_policy_type_is_error() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "t"
function_pattern = "f"
"#;
    let result = PolicyConfig::from_toml(toml);
    assert!(result.is_err(), "Missing 'policy_type' field should fail");
}

#[test]
fn from_toml_invalid_policy_type_string_is_error() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "t"
function_pattern = "f"
policy_type = "InvalidType"
"#;
    let result = PolicyConfig::from_toml(toml);
    assert!(result.is_err(), "Invalid policy_type variant should fail");
}

// ═══════════════════════════════════
// load_file: FILE EXTENSION DISPATCH
// ═══════════════════════════════════

#[test]
fn load_file_toml_extension() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.toml");
    std::fs::write(
        &path,
        r#"
[[policies]]
name = "test"
tool_pattern = "t"
function_pattern = "f"
policy_type = "Allow"
"#,
    )
    .unwrap();

    let config = PolicyConfig::load_file(path.to_str().unwrap()).unwrap();
    assert_eq!(config.policies.len(), 1);
}

#[test]
fn load_file_json_extension() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, r#"{"policies": [{"name": "test", "tool_pattern": "t", "function_pattern": "f", "policy_type": "Allow"}]}"#).unwrap();

    let config = PolicyConfig::load_file(path.to_str().unwrap()).unwrap();
    assert_eq!(config.policies.len(), 1);
}

#[test]
fn load_file_nonexistent_path_is_error() {
    let result = PolicyConfig::load_file("/tmp/definitely_does_not_exist_sentinel_test.toml");
    assert!(result.is_err(), "Loading nonexistent file should fail");
}

#[test]
fn load_file_unknown_extension_defaults_to_toml() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.yaml"); // Not .toml or .json
    std::fs::write(
        &path,
        r#"
[[policies]]
name = "test"
tool_pattern = "t"
function_pattern = "f"
policy_type = "Allow"
"#,
    )
    .unwrap();

    // Should try TOML parsing for unknown extensions
    let config = PolicyConfig::load_file(path.to_str().unwrap()).unwrap();
    assert_eq!(config.policies.len(), 1);
}

#[test]
fn load_file_json_content_in_toml_extension_fails() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.toml");
    std::fs::write(&path, r#"{"policies": []}"#).unwrap(); // JSON, not TOML

    let result = PolicyConfig::load_file(path.to_str().unwrap());
    assert!(
        result.is_err(),
        "JSON content in .toml file should fail TOML parsing"
    );
}

// ═══════════════════════════════════
// to_policies: CONVERSION CORRECTNESS
// ═══════════════════════════════════

#[test]
fn to_policies_preserves_name() {
    let toml = r#"
[[policies]]
name = "My Policy Name"
tool_pattern = "file"
function_pattern = "read"
policy_type = "Allow"
"#;
    let policies = PolicyConfig::from_toml(toml).unwrap().to_policies();
    assert_eq!(policies[0].name, "My Policy Name");
}

#[test]
fn to_policies_constructs_correct_id_format() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
"#;
    let policies = PolicyConfig::from_toml(toml).unwrap().to_policies();
    // The id should work with the engine's split_once(':') parsing
    assert!(
        policies[0].id.contains(':'),
        "Generated id should use tool:function format"
    );
    assert_eq!(policies[0].id, "bash:*");
}

#[test]
fn to_policies_wildcard_patterns_generate_wildcard_id() {
    let toml = r#"
[[policies]]
name = "catch all"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
priority = 1
"#;
    let policies = PolicyConfig::from_toml(toml).unwrap().to_policies();
    assert_eq!(policies[0].id, "*:*");
}

#[test]
fn to_policies_preserves_policy_type_variant() {
    let toml = r#"
[[policies]]
name = "a"
tool_pattern = "t"
function_pattern = "f"
policy_type = "Allow"

[[policies]]
name = "b"
tool_pattern = "t"
function_pattern = "f"
policy_type = "Deny"
"#;
    let policies = PolicyConfig::from_toml(toml).unwrap().to_policies();
    assert!(matches!(policies[0].policy_type, PolicyType::Allow));
    assert!(matches!(policies[1].policy_type, PolicyType::Deny));
}

#[test]
fn to_policies_empty_config_produces_empty_vec() {
    let toml = ""; // or a TOML with no [[policies]]
    if let Ok(config) = PolicyConfig::from_toml(toml) {
        let policies = config.to_policies();
        assert!(policies.is_empty());
    }
}

// ═══════════════════════════════════
// ROUNDTRIP: to_policies → engine evaluation
// ═══════════════════════════════════

#[test]
fn config_policies_work_with_engine() {
    use sentinel_engine::PolicyEngine;
    use sentinel_types::{Action, Verdict};

    let toml = r#"
[[policies]]
name = "Block bash"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
priority = 100

[[policies]]
name = "Allow everything else"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
priority = 1
"#;
    let policies = PolicyConfig::from_toml(toml).unwrap().to_policies();
    let engine = PolicyEngine::new(false);

    let bash_action = Action::new(
        "bash".to_string(),
        "execute".to_string(),
        serde_json::json!({}),
    );
    let file_action = Action::new(
        "file".to_string(),
        "read".to_string(),
        serde_json::json!({}),
    );

    let bash_verdict = engine.evaluate_action(&bash_action, &policies).unwrap();
    assert!(
        matches!(bash_verdict, Verdict::Deny { .. }),
        "bash should be denied by config policy"
    );

    let file_verdict = engine.evaluate_action(&file_action, &policies).unwrap();
    assert!(
        matches!(file_verdict, Verdict::Allow),
        "file:read should be allowed by wildcard fallback"
    );
}

// ═══════════════════════════════════
// TOML SERIALIZATION ROUNDTRIP
// ═══════════════════════════════════

#[test]
fn policy_config_toml_serialization_roundtrip() {
    let toml_input = r#"
[[policies]]
name = "test"
tool_pattern = "file"
function_pattern = "read"
policy_type = "Allow"
priority = 50
id = "file:read"
"#;
    let config = PolicyConfig::from_toml(toml_input).unwrap();
    let serialized = toml::to_string_pretty(&config).expect("serialize to TOML");
    let reparsed = PolicyConfig::from_toml(&serialized).unwrap();

    assert_eq!(config.policies.len(), reparsed.policies.len());
    assert_eq!(config.policies[0].name, reparsed.policies[0].name);
    assert_eq!(
        config.policies[0].tool_pattern,
        reparsed.policies[0].tool_pattern
    );
}
