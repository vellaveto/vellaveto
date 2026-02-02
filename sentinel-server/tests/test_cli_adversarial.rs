//! Adversarial CLI tests that try to break the sentinel binary.
//! Tests error handling, invalid inputs, and edge cases.

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

// ════════════════════════════════════
// MISSING SUBCOMMAND
// ═══════════════════════════════════

#[test]
fn no_subcommand_prints_help_and_fails() {
    let output = sentinel_bin().output().unwrap();
    assert!(!output.status.success(),
        "Running with no subcommand should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // clap should print usage info
    assert!(stderr.contains("Usage") || stderr.contains("usage") || stderr.contains("help"),
        "Should print usage info, got: {}", stderr);
}

// ════════════════════════════════════
// EVALUATE SUBCOMMAND
// ═══════════════════════════════════

#[test]
fn evaluate_with_valid_config_produces_json_output() {
    let tmp = TempDir::new().unwrap();
    let config = write_config(tmp.path(), "c.toml", r#"
[[policies]]
name = "Allow all"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
priority = 1
"#);
    let output = sentinel_bin()
        .args(["evaluate", "--tool", "file", "--function", "read",
               "--params", "{}", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success(), "evaluate should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("verdict"), "Output should contain verdict: {}", stdout);
    assert!(stdout.contains("Allow"), "Should get Allow verdict: {}", stdout);
}

#[test]
fn evaluate_deny_policy_produces_deny_verdict() {
    let tmp = TempDir::new().unwrap();
    let config = write_config(tmp.path(), "c.toml", r#"
[[policies]]
name = "Block bash"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
priority = 100
"#);
    let output = sentinel_bin()
        .args(["evaluate", "--tool", "bash", "--function", "execute",
               "--params", "{}", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Deny"), "Should get Deny verdict: {}", stdout);
}

#[test]
fn evaluate_with_invalid_json_params_fails() {
    let tmp = TempDir::new().unwrap();
    let config = write_config(tmp.path(), "c.toml", r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#);
    let output = sentinel_bin()
        .args(["evaluate", "--tool", "x", "--function", "y",
               "--params", "NOT VALID JSON",
               "--config", config.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success(),
        "Invalid JSON params should cause failure");
}

#[test]
fn evaluate_with_nonexistent_config_fails() {
    let output = sentinel_bin()
        .args(["evaluate", "--tool", "x", "--function", "y",
               "--config", "/tmp/sentinel_nonexistent_config_12345.toml"])
        .output()
        .unwrap();

    assert!(!output.status.success(),
        "Nonexistent config should cause failure");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed") || stderr.contains("error") || stderr.contains("Error"),
        "Should report config load failure: {}", stderr);
}

#[test]
fn evaluate_with_empty_config_still_works() {
    // An empty config means no policies — engine should return Deny (fail-closed)
    let tmp = TempDir::new().unwrap();
    let config = write_config(tmp.path(), "c.toml", "");
    let output = sentinel_bin()
        .args(["evaluate", "--tool", "x", "--function", "y",
               "--config", config.to_str().unwrap()])
        .output()
        .unwrap();

    // Either it fails to parse empty TOML, or it succeeds with empty policies and returns Deny
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Deny"),
            "Empty config should produce Deny (fail-closed): {}", stdout);
    }
    // Failing is also acceptable for empty config
}

#[test]
fn evaluate_default_params_is_empty_object() {
    // --params defaults to "{}" per clap definition
    let tmp = TempDir::new().unwrap();
    let config = write_config(tmp.path(), "c.toml", r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#);
    let output = sentinel_bin()
        .args(["evaluate", "--tool", "x", "--function", "y",
               "--config", config.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success(), "Should work without explicit --params");
}

// ═══════════════════════════════════
// CHECK SUBCOMMAND
// ═══════════════════════════════════

#[test]
fn check_valid_config_succeeds() {
    let tmp = TempDir::new().unwrap();
    let config = write_config(tmp.path(), "c.toml", r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#);
    let output = sentinel_bin()
        .args(["check", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("OK") || stdout.contains("ok") || stdout.contains("1"),
        "Should confirm config is valid: {}", stdout);
}

#[test]
fn check_invalid_toml_config_fails() {
    let tmp = TempDir::new().unwrap();
    let config = write_config(tmp.path(), "c.toml", "this is {{{{ not toml");
    let output = sentinel_bin()
        .args(["check", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success(), "Invalid TOML should fail check");
}

#[test]
fn check_nonexistent_config_fails() {
    let output = sentinel_bin()
        .args(["check", "--config", "/tmp/sentinel_nonexistent_98765.toml"])
        .output()
        .unwrap();

    assert!(!output.status.success());
}

// ═══════════════════════════════════
// POLICIES SUBCOMMAND
// ═══════════════════════════════════

#[test]
fn policies_dangerous_preset_outputs_toml() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "dangerous"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[[policies]]"),
        "Should output TOML array of tables: {}", stdout);
    assert!(stdout.contains("Bash") || stdout.contains("bash"),
        "Dangerous preset should mention bash: {}", stdout);
}

#[test]
fn policies_deny_all_preset() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "deny-all"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Deny"), "deny-all should contain Deny: {}", stdout);
}

#[test]
fn policies_allow_all_preset() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "allow-all"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Allow"), "allow-all should contain Allow: {}", stdout);
}

#[test]
fn policies_unknown_preset_fails() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "nonexistent_preset"])
        .output()
        .unwrap();

    assert!(!output.status.success(),
        "Unknown preset should fail");
}

#[test]
fn policies_network_preset() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "network"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[[policies]]"));
}

#[test]
fn policies_development_preset() {
    let output = sentinel_bin()
        .args(["policies", "--preset", "development"])
        .output()
        .unwrap();

    assert!(output.status.success());
}

// ═══════════════════════════════════
// POLICIES PRESET ROUNDTRIP THROUGH CONFIG
// ════════════════════════════════════

#[test]
fn policies_preset_output_is_valid_toml_config() {
    // The TOML output from `policies --preset` should be parseable by from_toml
    let output = sentinel_bin()
        .args(["policies", "--preset", "dangerous"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let toml_output = String::from_utf8_lossy(&output.stdout);

    // Write it to a file and use `check` to validate
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("generated.toml");
    std::fs::write(&config_path, toml_output.as_ref()).unwrap();

    let check_output = sentinel_bin()
        .args(["check", "--config", config_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(check_output.status.success(),
        "Preset output should be valid config. check stderr: {}",
        String::from_utf8_lossy(&check_output.stderr));
}