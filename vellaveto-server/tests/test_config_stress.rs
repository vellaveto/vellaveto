//! Stress and adversarial tests for vellaveto-config enhancements.
//! Targets from_toml, load_file, to_policies, and default field handling.

use vellaveto_config::PolicyConfig;
use vellaveto_types::PolicyType;
use tempfile::TempDir;

// ════════════════════════════════
// from_toml: VALID INPUTS
// ═══════════════════════════════

#[test]
fn from_toml_empty_policies_array() {
    // Edge: valid TOML but zero policies
    let toml = r#"
policies = []
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.policies.len(), 0);
    assert_eq!(config.to_policies().len(), 0);
}

#[test]
fn from_toml_single_deny_policy() {
    let toml = r#"
[[policies]]
name = "Block all"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Deny"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.policies.len(), 1);
    assert!(matches!(config.policies[0].policy_type, PolicyType::Deny));
}

#[test]
fn from_toml_conditional_with_require_approval() {
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

#[test]
fn from_toml_conditional_with_forbidden_parameters() {
    let toml = r#"
[[policies]]
name = "Forbid secrets"
tool_pattern = "*"
function_pattern = "*"
priority = 300

[policies.policy_type.Conditional]
conditions = { forbidden_parameters = ["secret", "password", "token"] }
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    let policies = config.to_policies();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].priority, 300);
}

// ════════════════════════════════
// PRIORITY DEFAULTS
// ════════════════════════════════

#[test]
fn priority_defaults_to_0_when_omitted() {
    let toml = r#"
[[policies]]
name = "No priority field"
tool_pattern = "t"
function_pattern = "f"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    // SECURITY (R19-CFG-1): Priority defaults to 0 (lowest priority)
    assert_eq!(config.policies[0].priority, Some(0));
    let policies = config.to_policies();
    assert_eq!(policies[0].priority, 0);
}

#[test]
fn explicit_priority_zero_is_preserved() {
    let toml = r#"
[[policies]]
name = "Zero priority"
tool_pattern = "t"
function_pattern = "f"
policy_type = "Allow"
priority = 0
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.policies[0].priority, Some(0));
    let policies = config.to_policies();
    assert_eq!(policies[0].priority, 0);
}

#[test]
fn negative_priority_is_preserved() {
    let toml = r#"
[[policies]]
name = "Negative priority"
tool_pattern = "t"
function_pattern = "f"
policy_type = "Deny"
priority = -500
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.policies[0].priority, Some(-500));
    let policies = config.to_policies();
    assert_eq!(policies[0].priority, -500);
}

// ════════════════════════════════
// ID DEFAULTS
// ════════════════════════════════

#[test]
fn id_defaults_to_tool_colon_function() {
    let toml = r#"
[[policies]]
name = "Auto ID"
tool_pattern = "bash"
function_pattern = "execute"
policy_type = "Deny"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.policies[0].id.is_none());
    let policies = config.to_policies();
    assert_eq!(policies[0].id, "bash:execute");
}

#[test]
fn explicit_id_overrides_default() {
    let toml = r#"
[[policies]]
name = "Custom ID"
tool_pattern = "bash"
function_pattern = "execute"
policy_type = "Deny"
id = "my-custom-id"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.policies[0].id, Some("my-custom-id".to_string()));
    let policies = config.to_policies();
    assert_eq!(policies[0].id, "my-custom-id");
}

#[test]
fn wildcard_patterns_produce_wildcard_id() {
    let toml = r#"
[[policies]]
name = "Wildcard"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    let policies = config.to_policies();
    assert_eq!(policies[0].id, "*:*");
}

// ════════════════════════════════
// load_file: FILE EXTENSION DISPATCH
// ═══════════════════════════════

#[test]
fn load_file_toml_extension() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("test.toml");
    std::fs::write(
        &path,
        r#"
[[policies]]
name = "t"
tool_pattern = "a"
function_pattern = "b"
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
    let path = tmp.path().join("test.json");
    std::fs::write(&path, r#"{"policies":[{"name":"j","tool_pattern":"x","function_pattern":"y","policy_type":"Deny"}]}"#).unwrap();
    let config = PolicyConfig::load_file(path.to_str().unwrap()).unwrap();
    assert_eq!(config.policies.len(), 1);
    assert!(matches!(config.policies[0].policy_type, PolicyType::Deny));
}

#[test]
fn load_file_unknown_extension_tries_toml() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("test.cfg");
    std::fs::write(
        &path,
        r#"
[[policies]]
name = "fallback"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    )
    .unwrap();
    let config = PolicyConfig::load_file(path.to_str().unwrap()).unwrap();
    assert_eq!(config.policies[0].name, "fallback");
}

#[test]
fn load_file_nonexistent_path_fails() {
    let result = PolicyConfig::load_file("/nonexistent/path/to/config.toml");
    assert!(result.is_err());
}

#[test]
fn load_file_empty_file_fails() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("empty.toml");
    std::fs::write(&path, "").unwrap();
    let result = PolicyConfig::load_file(path.to_str().unwrap());
    // Empty TOML has no `policies` key — should fail deserialization
    assert!(
        result.is_err(),
        "Empty TOML file should fail to parse as PolicyConfig"
    );
}

#[test]
fn load_file_garbage_content_fails() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("garbage.toml");
    std::fs::write(&path, "{{{{not valid toml or json}}}}").unwrap();
    let result = PolicyConfig::load_file(path.to_str().unwrap());
    assert!(result.is_err());
}

// ════════════════════════════════
// from_toml: INVALID INPUTS
// ═══════════════════════════════

#[test]
fn from_toml_missing_name_field_fails() {
    let toml = r#"
[[policies]]
tool_pattern = "x"
function_pattern = "y"
policy_type = "Allow"
"#;
    assert!(PolicyConfig::from_toml(toml).is_err());
}

#[test]
fn from_toml_missing_tool_pattern_fails() {
    let toml = r#"
[[policies]]
name = "x"
function_pattern = "y"
policy_type = "Allow"
"#;
    assert!(PolicyConfig::from_toml(toml).is_err());
}

#[test]
fn from_toml_missing_policy_type_fails() {
    let toml = r#"
[[policies]]
name = "x"
tool_pattern = "a"
function_pattern = "b"
"#;
    assert!(PolicyConfig::from_toml(toml).is_err());
}

#[test]
fn from_toml_invalid_policy_type_string_fails() {
    let toml = r#"
[[policies]]
name = "x"
tool_pattern = "a"
function_pattern = "b"
policy_type = "BlockAll"
"#;
    assert!(
        PolicyConfig::from_toml(toml).is_err(),
        "Invalid policy_type variant should fail deserialization"
    );
}

// ════════════════════════════════
// to_policies: MULTIPLE POLICY CONVERSION
// ═══════════════════════════════

#[test]
fn to_policies_preserves_order() {
    let toml = r#"
[[policies]]
name = "first"
tool_pattern = "a"
function_pattern = "b"
policy_type = "Allow"
priority = 1

[[policies]]
name = "second"
tool_pattern = "c"
function_pattern = "d"
policy_type = "Deny"
priority = 2

[[policies]]
name = "third"
tool_pattern = "e"
function_pattern = "f"
policy_type = "Allow"
priority = 3
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    let policies = config.to_policies();
    assert_eq!(policies.len(), 3);
    assert_eq!(policies[0].name, "first");
    assert_eq!(policies[1].name, "second");
    assert_eq!(policies[2].name, "third");
    assert_eq!(policies[0].priority, 1);
    assert_eq!(policies[1].priority, 2);
    assert_eq!(policies[2].priority, 3);
}

// ════════════════════════════════
// JSON/TOML CROSS-FORMAT CONSISTENCY
// ════════════════════════════════

#[test]
fn json_and_toml_produce_same_policies() {
    let toml_str = r#"
[[policies]]
name = "test"
tool_pattern = "bash"
function_pattern = "exec"
policy_type = "Deny"
priority = 42
id = "bash:exec"
"#;
    let json_str = r#"{"policies":[{"name":"test","tool_pattern":"bash","function_pattern":"exec","policy_type":"Deny","priority":42,"id":"bash:exec"}]}"#;

    let toml_config = PolicyConfig::from_toml(toml_str).unwrap();
    let json_config = PolicyConfig::from_json(json_str).unwrap();

    let toml_policies = toml_config.to_policies();
    let json_policies = json_config.to_policies();

    assert_eq!(toml_policies.len(), json_policies.len());
    assert_eq!(toml_policies[0].id, json_policies[0].id);
    assert_eq!(toml_policies[0].name, json_policies[0].name);
    assert_eq!(toml_policies[0].priority, json_policies[0].priority);
}
