//! CLI integration tests for the sentinel binary.
//! These spawn the actual binary and verify exit codes and output.
//! Requires: `cargo build -p sentinel-server` to have completed.

use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn sentinel_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
}

fn write_toml_config(dir: &Path, content: &str) -> std::path::PathBuf {
    let path = dir.join("test-config.toml");
    std::fs::write(&path, content).expect("write config");
    path
}

fn minimal_toml_config() -> &'static str {
    r#"
[[policies]]
name = "Default allow"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
priority = 1
"#
}

// ═════════════════════════════
// HELP AND SUBCOMMAND DISCOVERY
// ════════════════════════════

#[test]
fn binary_responds_to_help_flag() {
    let output = sentinel_bin()
        .arg("--help")
        .output()
        .expect("failed to run sentinel");
    assert!(output.status.success(), "sentinel --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sentinel"), "Help should mention sentinel");
    assert!(
        stdout.contains("serve"),
        "Help should list serve subcommand"
    );
    assert!(
        stdout.contains("evaluate"),
        "Help should list evaluate subcommand"
    );
    assert!(
        stdout.contains("check"),
        "Help should list check subcommand"
    );
    assert!(
        stdout.contains("policies"),
        "Help should list policies subcommand"
    );
}

#[test]
fn no_subcommand_shows_help_or_error() {
    let output = sentinel_bin().output().expect("failed to run sentinel");
    // clap either shows help or exits with error when no subcommand given
    assert!(
        !output.status.success() || !output.stdout.is_empty(),
        "No subcommand should produce output"
    );
}

// ═════════════════════════════
// CHECK SUBCOMMAND
// ═════════════════════════════

#[test]
fn check_valid_toml_config_succeeds() {
    let tmp = TempDir::new().unwrap();
    let config_path = write_toml_config(tmp.path(), minimal_toml_config());

    let output = sentinel_bin()
        .args(["check", "--config", config_path.to_str().unwrap()])
        .output()
        .expect("failed to run sentinel check");

    assert!(
        output.status.success(),
        "check should succeed with valid config. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Policies loaded: 1")
            || stdout.contains("1 policies loaded")
            || stdout.contains("Config OK"),
        "check should report loaded policies. Got: {}",
        stdout
    );
}

#[test]
fn check_nonexistent_config_fails() {
    let output = sentinel_bin()
        .args(["check", "--config", "/nonexistent/path/config.toml"])
        .output()
        .expect("failed to run sentinel check");

    assert!(
        !output.status.success(),
        "check should fail when config file doesn't exist"
    );
}

#[test]
fn check_invalid_toml_fails() {
    let tmp = TempDir::new().unwrap();
    let config_path = write_toml_config(tmp.path(), "this is not valid TOML {{{");

    let output = sentinel_bin()
        .args(["check", "--config", config_path.to_str().unwrap()])
        .output()
        .expect("failed to run sentinel check");

    assert!(
        !output.status.success(),
        "check should fail with invalid TOML"
    );
}

#[test]
fn check_with_opa_enabled_succeeds_when_config_is_valid() {
    let tmp = TempDir::new().unwrap();
    let config_path = write_toml_config(
        tmp.path(),
        r#"
policies = []

[opa]
enabled = true
endpoint = "https://localhost:8181"
decision_path = "sentinel/allow"
"#,
    );

    let output = sentinel_bin()
        .args(["check", "--config", config_path.to_str().unwrap()])
        .output()
        .expect("failed to run sentinel check");

    assert!(
        output.status.success(),
        "check should succeed for valid OPA configuration. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn check_empty_policies_array_succeeds() {
    let tmp = TempDir::new().unwrap();
    // An empty file won't parse as PolicyConfig because `policies` field is required.
    // But a TOML with empty array should work.
    let config_path = write_toml_config(tmp.path(), "policies = []\n");

    let output = sentinel_bin()
        .args(["check", "--config", config_path.to_str().unwrap()])
        .output()
        .expect("failed to run sentinel check");

    assert!(
        output.status.success(),
        "check with empty policies should succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Policies loaded: 0") || stdout.contains("0 policies"),
        "Should report 0 policies. Got: {}",
        stdout
    );
}

#[test]
fn check_json_config_also_works() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, r#"{"policies": [{"name": "test", "tool_pattern": "*", "function_pattern": "*", "policy_type": "Allow"}]}"#).unwrap();

    let output = sentinel_bin()
        .args(["check", "--config", path.to_str().unwrap()])
        .output()
        .expect("failed to run sentinel check");

    assert!(
        output.status.success(),
        "check should work with JSON config. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ════════════════════════════
// EVALUATE SUBCOMMAND
// ═════════════════════════════

#[test]
fn evaluate_allowed_action_returns_allow() {
    let tmp = TempDir::new().unwrap();
    let config_path = write_toml_config(tmp.path(), minimal_toml_config());

    let output = sentinel_bin()
        .args([
            "evaluate",
            "--tool",
            "file",
            "--function",
            "read",
            "--params",
            "{}",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run sentinel evaluate");

    assert!(
        output.status.success(),
        "evaluate should succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Allow"),
        "Should produce Allow verdict. Got: {}",
        stdout
    );
}

#[test]
fn evaluate_denied_action_returns_deny() {
    let tmp = TempDir::new().unwrap();
    let config = r#"
[[policies]]
name = "Block all"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Deny"
priority = 1000
"#;
    let config_path = write_toml_config(tmp.path(), config);

    let output = sentinel_bin()
        .args([
            "evaluate",
            "--tool",
            "bash",
            "--function",
            "execute",
            "--params",
            "{}",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run sentinel evaluate");

    assert!(
        output.status.success(),
        "evaluate should succeed even for deny. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Deny"),
        "Should produce Deny verdict. Got: {}",
        stdout
    );
}

#[test]
fn evaluate_with_invalid_json_params_fails() {
    let tmp = TempDir::new().unwrap();
    let config_path = write_toml_config(tmp.path(), minimal_toml_config());

    let output = sentinel_bin()
        .args([
            "evaluate",
            "--tool",
            "file",
            "--function",
            "read",
            "--params",
            "not-json",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run sentinel evaluate");

    assert!(
        !output.status.success(),
        "evaluate with invalid JSON params should fail"
    );
}

#[test]
fn evaluate_with_opa_enabled_denies_fail_closed_on_opa_error() {
    let tmp = TempDir::new().unwrap();
    let config = r#"
[[policies]]
name = "Allow file reads"
tool_pattern = "file"
function_pattern = "read"
policy_type = "Allow"
priority = 10

[opa]
enabled = true
endpoint = "https://localhost:8181"
decision_path = "sentinel/allow"
"#;
    let config_path = write_toml_config(tmp.path(), config);

    let output = sentinel_bin()
        .args([
            "evaluate",
            "--tool",
            "file",
            "--function",
            "read",
            "--params",
            "{}",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run sentinel evaluate");

    assert!(
        output.status.success(),
        "evaluate should return JSON output"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid evaluate JSON");
    assert!(
        parsed["verdict"]["Deny"]["reason"]
            .as_str()
            .map(|r| r.contains("fail-closed"))
            .unwrap_or(false),
        "Expected fail-closed OPA denial. output: {}",
        stdout
    );
}

#[test]
fn evaluate_output_is_valid_json() {
    let tmp = TempDir::new().unwrap();
    let config_path = write_toml_config(tmp.path(), minimal_toml_config());

    let output = sentinel_bin()
        .args([
            "evaluate",
            "--tool",
            "file",
            "--function",
            "read",
            "--params",
            r#"{"path": "/tmp/test"}"#,
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run sentinel evaluate");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(stdout.trim());
    assert!(
        parsed.is_ok(),
        "evaluate output should be valid JSON. Got: {}",
        stdout
    );

    let val = parsed.unwrap();
    assert!(
        val.get("action").is_some(),
        "Output should contain 'action' field"
    );
    assert!(
        val.get("verdict").is_some(),
        "Output should contain 'verdict' field"
    );
}

#[test]
fn evaluate_default_params_is_empty_object() {
    let tmp = TempDir::new().unwrap();
    let config_path = write_toml_config(tmp.path(), minimal_toml_config());

    // Don't pass --params at all, should default to "{}"
    let output = sentinel_bin()
        .args([
            "evaluate",
            "--tool",
            "file",
            "--function",
            "read",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run sentinel evaluate");

    assert!(
        output.status.success(),
        "evaluate without --params should use default '{{}}'. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ═════════════════════════════
// POLICIES SUBCOMMAND
// ═════════════════════════════

#[test]
fn policies_dangerous_preset_outputs_toml() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "dangerous"])
        .output()
        .expect("failed to run sentinel policies");

    assert!(
        output.status.success(),
        "policies --preset dangerous should succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should be valid TOML
    assert!(
        stdout.contains("[[policies]]") || stdout.contains("name"),
        "policies output should look like TOML. Got: {}",
        stdout
    );
}

#[test]
fn policies_all_presets_succeed() {
    for preset in &[
        "dangerous",
        "network",
        "development",
        "deny-all",
        "allow-all",
    ] {
        let output = sentinel_bin()
            .args(["policies", "--preset", preset])
            .output()
            .unwrap_or_else(|_| panic!("failed to run sentinel policies --preset {}", preset));

        assert!(
            output.status.success(),
            "preset '{}' should succeed. stderr: {}",
            preset,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn policies_unknown_preset_fails() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "nonexistent"])
        .output()
        .expect("failed to run sentinel policies");

    assert!(!output.status.success(), "Unknown preset should fail");
}

#[test]
fn policies_output_is_parseable_toml_config() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "deny-all"])
        .output()
        .expect("failed to run sentinel policies");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // The output should be parseable back as a PolicyConfig TOML
    let parsed: Result<toml::Value, _> = toml::from_str(&stdout);
    assert!(
        parsed.is_ok(),
        "policies output should be valid TOML. Got: {}\nError: {:?}",
        stdout,
        parsed.err()
    );
}

// ════════════════════════════
// EDGE CASES
// ════════════════════════════

#[test]
fn evaluate_with_conditional_policy_requiring_approval() {
    let tmp = TempDir::new().unwrap();
    let config = r#"
[[policies]]
name = "Network needs approval"
tool_pattern = "network"
function_pattern = "*"
priority = 100
id = "network:*"

[policies.policy_type.Conditional]
conditions = { require_approval = true }
"#;
    let config_path = write_toml_config(tmp.path(), config);

    let output = sentinel_bin()
        .args([
            "evaluate",
            "--tool",
            "network",
            "--function",
            "fetch",
            "--params",
            "{}",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run sentinel evaluate");

    assert!(
        output.status.success(),
        "evaluate should succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("RequireApproval"),
        "Should get RequireApproval verdict. Got: {}",
        stdout
    );
}

#[test]
fn evaluate_with_forbidden_parameters_denied() {
    let tmp = TempDir::new().unwrap();
    let config = r#"
[[policies]]
name = "Block dangerous params"
tool_pattern = "*"
function_pattern = "*"
priority = 100

[policies.policy_type.Conditional]
conditions = { forbidden_parameters = ["rm", "delete"] }
"#;
    let config_path = write_toml_config(tmp.path(), config);

    let output = sentinel_bin()
        .args([
            "evaluate",
            "--tool",
            "shell",
            "--function",
            "exec",
            "--params",
            r#"{"rm": true, "safe": "value"}"#,
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run sentinel evaluate");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Deny"),
        "Should deny action with forbidden param. Got: {}",
        stdout
    );
}
