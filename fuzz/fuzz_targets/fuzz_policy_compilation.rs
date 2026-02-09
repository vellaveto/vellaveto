#![no_main]
//! Fuzz target for PolicyEngine policy compilation and evaluation.
//!
//! Tests that the policy engine handles arbitrary policy configurations
//! and action evaluations without panicking.

use libfuzzer_sys::fuzz_target;
use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, PathRules, NetworkRules};

fuzz_target!(|data: &[u8]| {
    // Try to interpret data as policy configuration
    if let Ok(s) = std::str::from_utf8(data) {
        // Create a basic policy with fuzzed values
        let parts: Vec<&str> = s.split('\n').collect();

        let policy = Policy {
            id: parts.get(0).unwrap_or(&"fuzz-policy").to_string(),
            name: parts.get(1).unwrap_or(&"Fuzz Policy").to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: Some(PathRules {
                allowed: parts.get(2).map(|p| vec![p.to_string()]).unwrap_or_default(),
                blocked: parts.get(3).map(|p| vec![p.to_string()]).unwrap_or_default(),
            }),
            network_rules: Some(NetworkRules {
                allowed_domains: parts.get(4).map(|d| vec![d.to_string()]).unwrap_or_default(),
                blocked_domains: parts.get(5).map(|d| vec![d.to_string()]).unwrap_or_default(),
                ip_rules: None,
            }),
        };

        let policies = vec![policy];

        // Create engine
        let engine = PolicyEngine::new(false);

        // Create an action with fuzzed values
        let action = Action {
            tool: parts.get(6).unwrap_or(&"fuzz_tool").to_string(),
            function: parts.get(7).unwrap_or(&"execute").to_string(),
            parameters: serde_json::json!({}),
            target_paths: parts.get(8).map(|p| vec![p.to_string()]).unwrap_or_default(),
            target_domains: parts.get(9).map(|d| vec![d.to_string()]).unwrap_or_default(),
            resolved_ips: vec![],
        };

        // Evaluate - must not panic
        let _ = engine.evaluate_action(&action, &policies);
    }
});
