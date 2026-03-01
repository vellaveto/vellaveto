// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Built-in policy presets for zero-config usage.
//!
//! Embeds preset TOML configs from `examples/presets/` at compile time
//! so users can run `vellaveto-proxy --preset dev-laptop` without a config file.

use vellaveto_config::PolicyConfig;

/// Available preset definitions: (name, description, embedded TOML content).
const PRESETS: &[(&str, &str, &str)] = &[
    (
        "dev-laptop",
        "Developer laptop — blocks credentials, detects injection",
        include_str!("../presets/dev-laptop.toml"),
    ),
    (
        "ci-agent",
        "CI/CD pipeline — strict network controls, blocking injection/DLP",
        include_str!("../presets/ci-agent.toml"),
    ),
    (
        "browser-agent",
        "Browser automation — blocks malicious domains, restricts downloads",
        include_str!("../presets/browser-agent.toml"),
    ),
    (
        "database-agent",
        "Database access — blocks destructive DDL, scans for credential leaks",
        include_str!("../presets/database-agent.toml"),
    ),
    (
        "api-gateway-agent",
        "API gateway — domain allowlisting, blocks internal networks",
        include_str!("../presets/api-gateway-agent.toml"),
    ),
    (
        "rag-agent",
        "RAG agent — vector DB access controls, response scanning",
        include_str!("../presets/rag-agent.toml"),
    ),
    (
        "data-science-agent",
        "Data science — notebook/ML controls, data export restrictions",
        include_str!("../presets/data-science-agent.toml"),
    ),
    (
        "customer-support-agent",
        "Customer support — CRM/ticketing controls, PII redaction",
        include_str!("../presets/customer-support-agent.toml"),
    ),
    (
        "devops-agent",
        "DevOps/infrastructure — Terraform/K8s controls, approval gates",
        include_str!("../presets/devops-agent.toml"),
    ),
    (
        "financial-agent",
        "Financial services — DORA/NIS2 controls, strict audit",
        include_str!("../presets/financial-agent.toml"),
    ),
    (
        "healthcare-agent",
        "Healthcare — HIPAA-aligned controls, PHI protection",
        include_str!("../presets/healthcare-agent.toml"),
    ),
    (
        "sandworm-hardened",
        "Maximum security — all defensive layers, default deny",
        include_str!("../presets/sandworm-hardened.toml"),
    ),
    (
        "consumer-shield",
        "Consumer privacy — PII sanitization, encrypted audit",
        include_str!("../presets/consumer-shield.toml"),
    ),
];

/// Built-in default config TOML used when no --config or --preset is given.
/// Blocks credential files, enables non-blocking injection scanning, allows
/// everything else. This provides basic protection with zero configuration.
const DEFAULT_CONFIG_TOML: &str = r#"# Vellaveto built-in default configuration
# Generated automatically when no --config or --preset is specified.
# Run `vellaveto-proxy init` to create a customizable config file.

# --- Block credential and secret files ---
[[policies]]
name = "Block credential files"
tool_pattern = "*"
function_pattern = "*"
priority = 300
id = "default:*:credential-block"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "*", op = "glob", pattern = "/home/*/.aws/**",       on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.ssh/**",       on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.gnupg/**",     on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/.env",               on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/.env.*",             on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/credentials.json",   on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/secrets.yaml",       on_match = "deny", on_missing = "skip" },
]

# --- Allow all other tool calls ---
[[policies]]
name = "Default allow"
tool_pattern = "*"
function_pattern = "*"
priority = 1
id = "default:*:allow"
policy_type = "Allow"

# --- Injection detection (non-blocking) ---
[injection]
enabled = true
block_on_injection = false
"#;

/// Load a named preset and parse it into a `PolicyConfig`.
///
/// Returns `Err` with a descriptive message if the preset name is unknown
/// or the embedded TOML fails to parse (which would be a build-time bug).
pub fn load_preset(name: &str) -> Result<PolicyConfig, String> {
    let toml = preset_toml(name).ok_or_else(|| {
        let available: Vec<&str> = PRESETS.iter().map(|(n, _, _)| *n).collect();
        format!(
            "Unknown preset '{}'. Available presets: {}",
            name,
            available.join(", ")
        )
    })?;
    PolicyConfig::from_toml(toml).map_err(|e| format!("Failed to parse preset '{}': {}", name, e))
}

/// List all available presets as `(name, description)` pairs.
pub fn list_presets() -> Vec<(&'static str, &'static str)> {
    PRESETS.iter().map(|(n, d, _)| (*n, *d)).collect()
}

/// Get the raw TOML content for a named preset.
pub fn preset_toml(name: &str) -> Option<&'static str> {
    PRESETS
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, _, toml)| *toml)
}

/// Load the built-in default configuration.
///
/// This is used when no `--config` or `--preset` flag is provided.
/// Returns `Err` only if the compile-time constant TOML is malformed (a build bug).
pub fn default_config() -> Result<PolicyConfig, String> {
    PolicyConfig::from_toml(DEFAULT_CONFIG_TOML)
        .map_err(|e| format!("built-in default config is invalid (this is a bug): {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_presets_parse_successfully() {
        for (name, _, toml) in PRESETS {
            let result = PolicyConfig::from_toml(toml);
            assert!(
                result.is_ok(),
                "Preset '{}' failed to parse: {}",
                name,
                result.unwrap_err()
            );
        }
    }

    #[test]
    fn test_default_config_parses() {
        let config = default_config().expect("default config should parse");
        let policies = config.to_policies();
        assert!(
            policies.len() >= 2,
            "default config should have at least 2 policies"
        );
    }

    #[test]
    fn test_load_preset_valid() {
        let config = load_preset("dev-laptop").expect("dev-laptop should load");
        let policies = config.to_policies();
        assert!(!policies.is_empty(), "dev-laptop should have policies");
    }

    #[test]
    fn test_load_preset_unknown() {
        let err = load_preset("nonexistent").unwrap_err();
        assert!(err.contains("Unknown preset"));
        assert!(err.contains("dev-laptop")); // lists available
    }

    #[test]
    fn test_list_presets_not_empty() {
        let presets = list_presets();
        assert!(!presets.is_empty());
        let names: Vec<&str> = presets.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"dev-laptop"));
        assert!(names.contains(&"ci-agent"));
        assert!(names.contains(&"sandworm-hardened"));
    }

    #[test]
    fn test_preset_toml_returns_content() {
        let toml = preset_toml("dev-laptop");
        assert!(toml.is_some());
        assert!(toml.unwrap().contains("[[policies]]"));
    }

    #[test]
    fn test_preset_toml_unknown_returns_none() {
        assert!(preset_toml("does-not-exist").is_none());
    }

    #[test]
    fn test_default_config_toml_is_valid() {
        assert!(DEFAULT_CONFIG_TOML.contains("credential"));
        assert!(DEFAULT_CONFIG_TOML.contains("[injection]"));
    }
}
