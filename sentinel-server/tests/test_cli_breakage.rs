//! Adversarial CLI tests that try to break the sentinel binary.
//! Exercises error paths, invalid inputs, and edge cases.

use std::process::Command;
use tempfile::TempDir;

fn sentinel_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
}

fn write_config(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).expect("write config");
    path
}

// ═════════════════════════════════
// NO SUBCOMMAND → ERROR
// ═══════════════════════════════

#[test]
fn no_subcommand_exits_nonzero() {
    let output = sentinel_bin().output().unwrap();
    assert!(!output.status.success());
}

// ════════════════════════════════
// EVALUATE: HAPPY PATH
// ════════════════════════════════

#[test]
fn evaluate_returns_json_with_verdict() {
    let tmp = TempDir::new().unwrap();
    let config = write_config(
        tmp.path(),
        "c.toml",
        r#"
[[policies]]
name = "Allow all"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
priority = 1
"#,
    );

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
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Must contain valid JSON with a verdict
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("evaluate output should be valid JSON");
    assert!(
        parsed.get("verdict").is_some(),
        "Output must contain verdict field"
    );
    assert!(
        parsed.get("action").is_some(),
        "Output must contain action field"
    );
}

#[test]
fn evaluate_deny_policy_returns_deny_verdict() {
    let tmp = TempDir::new().unwrap();
    let config = write_config(
        tmp.path(),
        "deny.toml",
        r#"
[[policies]]
name = "Block bash"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
priority = 100
id = "bash:*"
"#,
    );

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
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let verdict = parsed.get("verdict").unwrap();
    assert!(
        verdict.get("Deny").is_some(),
        "bash tool should be denied, got: {}",
        verdict
    );
}

// ═════════════════════════════════
// EVALUATE: ERROR PATHS
// ════════════════════════════════

#[test]
fn evaluate_nonexistent_config_fails() {
    let output = sentinel_bin()
        .args([
            "evaluate",
            "--tool",
            "x",
            "--function",
            "y",
            "--config",
            "/nonexistent/config.toml",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn evaluate_invalid_json_params_fails() {
    let tmp = TempDir::new().unwrap();
    let config = write_config(
        tmp.path(),
        "c.toml",
        r#"
[[policies]]
name = "a"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    );

    let output = sentinel_bin()
        .args([
            "evaluate",
            "--tool",
            "t",
            "--function",
            "f",
            "--params",
            "NOT_JSON",
            "--config",
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "Invalid JSON in --params should fail"
    );
}

#[test]
fn evaluate_empty_config_produces_deny() {
    let tmp = TempDir::new().unwrap();
    let config = write_config(
        tmp.path(),
        "empty.toml",
        r#"
policies = []
"#,
    );

    let output = sentinel_bin()
        .args([
            "evaluate",
            "--tool",
            "t",
            "--function",
            "f",
            "--params",
            "{}",
            "--config",
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let verdict = parsed.get("verdict").unwrap();
    // Empty policies → fail-closed  Deny
    assert!(
        verdict.get("Deny").is_some(),
        "Empty policies should deny (fail-closed), got: {}",
        verdict
    );
}

// ═════════════════════════════════
// CHECK SUBCOMMAND
// ═══════════════════════════════

#[test]
fn check_valid_config_exits_zero() {
    let tmp = TempDir::new().unwrap();
    let config = write_config(
        tmp.path(),
        "ok.toml",
        r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    );

    let output = sentinel_bin()
        .args(["check", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // New validation format outputs "Configuration is VALID" instead of "Config OK"
    assert!(
        stdout.contains("Configuration is VALID") || stdout.contains("Policies loaded"),
        "Expected validation output, got: {}",
        stdout
    );
}

#[test]
fn check_broken_config_exits_nonzero() {
    let tmp = TempDir::new().unwrap();
    let config = write_config(tmp.path(), "bad.toml", "this is not toml at all {{{");

    let output = sentinel_bin()
        .args(["check", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn check_nonexistent_config_exits_nonzero() {
    let output = sentinel_bin()
        .args(["check", "--config", "/does/not/exist.toml"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

// ════════════════════════════════
// POLICIES SUBCOMMAND
// ════════════════════════════════

#[test]
fn policies_dangerous_preset_outputs_toml() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "dangerous"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Output should be valid TOML containing [[policies]]
    assert!(
        stdout.contains("[[policies]]"),
        "policies output should be TOML with [[policies]] blocks"
    );
    // Should contain the dangerous tools policies
    assert!(
        stdout.contains("Bash") || stdout.contains("bash"),
        "dangerous preset should mention bash"
    );
}

#[test]
fn policies_deny_all_preset_outputs_toml() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "deny-all"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Deny"));
}

#[test]
fn policies_allow_all_preset_outputs_toml() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "allow-all"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Allow"));
}

#[test]
fn policies_unknown_preset_exits_nonzero() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "nonexistent-preset"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn policies_network_preset_outputs_toml() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "network"])
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn policies_development_preset_outputs_toml() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "development"])
        .output()
        .unwrap();
    assert!(output.status.success());
}

// ════════════════════════════════
// POLICIES OUTPUT IS ROUND-TRIPPABLE
// ════════════════════════════════

#[test]
fn policies_dangerous_output_is_parseable_config() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "dangerous"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // The output should be valid TOML that sentinel-config can parse
    let config = sentinel_config::PolicyConfig::from_toml(&stdout)
        .expect("policies output should be valid PolicyConfig TOML");
    assert!(
        !config.policies.is_empty(),
        "dangerous preset should produce at least one policy"
    );
    let policies = config.to_policies();
    assert!(!policies.is_empty());
}

// ═════════════════════════════════
// --help FLAG
// ═══════════════════════════════

#[test]
fn help_flag_exits_zero() {
    let output = sentinel_bin().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sentinel") || stdout.contains("Sentinel"));
    // Should list subcommands
    assert!(stdout.contains("serve"));
    assert!(stdout.contains("evaluate"));
    assert!(stdout.contains("check"));
    assert!(stdout.contains("policies"));
}
