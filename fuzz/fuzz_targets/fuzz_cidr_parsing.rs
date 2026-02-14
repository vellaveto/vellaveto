#![no_main]
use libfuzzer_sys::fuzz_target;
use vellaveto_types::{IpRules, NetworkRules, Policy, PolicyType};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to compile a policy with the fuzzed string as a CIDR
        let policy = Policy {
            id: "*".to_string(),
            name: "fuzz".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: Some(NetworkRules {
                allowed_domains: vec![],
                blocked_domains: vec![],
                ip_rules: Some(IpRules {
                    block_private: false,
                    blocked_cidrs: vec![s.to_string()],
                    allowed_cidrs: vec![],
                }),
            }),
        };
        // Must not panic — validation errors are expected
        let _ = vellaveto_engine::PolicyEngine::with_policies(false, &[policy]);
    }
});
