//! Property-based tests using proptest.
//!
//! Per Directive C-7: Tests critical invariants:
//! - `evaluate_action` determinism: same input → same output
//! - `normalize_path` idempotency: normalizing twice == normalizing once
//! - `extract_domain` consistency: same URL → same domain every time

use proptest::prelude::*;
use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

/// Generate arbitrary Action values for testing.
fn arb_action() -> impl Strategy<Value = Action> {
    (
        "[a-z_]{1,20}", // tool
        "[a-z_]{1,20}", // function
        prop_oneof![
            Just(json!({})),
            Just(json!({"path": "/tmp/test"})),
            Just(json!({"url": "https://example.com"})),
            Just(json!({"command": "ls -la"})),
            Just(json!({"key": "value", "nested": {"a": 1}})),
        ],
    )
        .prop_map(|(tool, function, parameters)| Action {
            tool,
            function,
            parameters,
        })
}

/// Generate a small set of policies for testing.
fn arb_policies() -> impl Strategy<Value = Vec<Policy>> {
    prop::collection::vec(arb_policy(), 1..=5).prop_map(|mut policies| {
        PolicyEngine::sort_policies(&mut policies);
        policies
    })
}

fn arb_policy() -> impl Strategy<Value = Policy> {
    (
        prop_oneof![
            Just("*:*".to_string()),
            Just("file:*".to_string()),
            Just("bash:*".to_string()),
            Just("file:read".to_string()),
            Just("net:request".to_string()),
        ],
        "[a-z ]{3,20}",
        prop_oneof![Just(PolicyType::Allow), Just(PolicyType::Deny),],
        1..=100i32,
    )
        .prop_map(|(id, name, policy_type, priority)| Policy {
            id,
            name,
            policy_type,
            priority,
        })
}

// ═══════════════════════════════════
// PROPERTY 1: evaluate_action is deterministic
// ═══════════════════════════════════

proptest! {
    #[test]
    fn evaluate_action_is_deterministic(
        action in arb_action(),
        policies in arb_policies(),
    ) {
        let engine = PolicyEngine::new(false);

        let result1 = engine.evaluate_action(&action, &policies);
        let result2 = engine.evaluate_action(&action, &policies);

        match (result1, result2) {
            (Ok(v1), Ok(v2)) => prop_assert_eq!(v1, v2,
                "Same action and policies must produce identical verdicts"),
            (Err(e1), Err(e2)) => prop_assert_eq!(e1.to_string(), e2.to_string(),
                "Same action and policies must produce identical errors"),
            (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
                prop_assert!(false, "Same input must not produce Ok then Err or vice versa");
            }
        }
    }
}

// ═══════════════════════════════════
// PROPERTY 2: normalize_path is idempotent
// ═══════════════════════════════════

proptest! {
    #[test]
    fn normalize_path_is_idempotent(
        path in prop_oneof![
            // Realistic paths
            "/[a-z/]{0,50}",
            // Paths with traversal
            "(/\\.\\./){0,5}[a-z/]{0,20}",
            // Paths with percent-encoding
            "/[a-z%0-9]{0,30}",
            // Edge cases
            Just("/".to_string()),
            Just("".to_string()),
            Just(".".to_string()),
            Just("..".to_string()),
            Just("../../../etc/passwd".to_string()),
            Just("/foo/../bar".to_string()),
            Just("/foo/./bar".to_string()),
            Just("/%2e%2e/%2e%2e/etc/passwd".to_string()),
        ],
    ) {
        let once = PolicyEngine::normalize_path(&path);
        let twice = PolicyEngine::normalize_path(&once);

        prop_assert_eq!(&once, &twice,
            "normalize_path must be idempotent: normalize(normalize(p)) == normalize(p)\n\
             input: {:?}\n\
             once:  {:?}\n\
             twice: {:?}", path, once, twice);
    }
}

// ═══════════════════════════════════
// PROPERTY 3: extract_domain is consistent
// ═══════════════════════════════════

proptest! {
    #[test]
    fn extract_domain_is_consistent(
        url in prop_oneof![
            // Standard URLs
            "https://[a-z]{3,15}\\.[a-z]{2,5}(/[a-z]{0,10}){0,3}",
            // URLs with ports
            "https://[a-z]{3,10}\\.[a-z]{2,5}:[0-9]{2,5}/[a-z]{0,10}",
            // URLs with query params
            "https://[a-z]{3,10}\\.[a-z]{2,5}/path\\?key=value",
            // URLs with userinfo
            "https://user@[a-z]{3,10}\\.[a-z]{2,5}/path",
            // Edge cases
            Just("https://example.com".to_string()),
            Just("https://sub.example.com:8080/path?q=1#frag".to_string()),
            Just("http://user:pass@host.com/path".to_string()),
            Just("example.com".to_string()),
        ],
    ) {
        let result1 = PolicyEngine::extract_domain(&url);
        let result2 = PolicyEngine::extract_domain(&url);

        prop_assert_eq!(&result1, &result2,
            "extract_domain must be consistent: same URL must always produce same domain\n\
             url:     {:?}\n\
             result1: {:?}\n\
             result2: {:?}", url, result1, result2);
    }
}

// ═══════════════════════════════════
// PROPERTY 4: normalize_path never returns raw traversal sequences
// ═══════════════════════════════════

proptest! {
    #[test]
    fn normalize_path_strips_traversal(
        prefix in "(/\\.\\./){1,5}",
        suffix in "[a-z]{0,10}",
    ) {
        let path = format!("{}{}", prefix, suffix);
        let normalized = PolicyEngine::normalize_path(&path);

        prop_assert!(!normalized.contains(".."),
            "normalize_path must remove all '..' sequences\n\
             input:      {:?}\n\
             normalized: {:?}", path, normalized);
    }
}

// ═══════════════════════════════════
// PROPERTY 5: extract_domain always returns lowercase
// ═══════════════════════════════════

proptest! {
    #[test]
    fn extract_domain_is_lowercase(
        domain in "[A-Za-z]{3,10}\\.[A-Za-z]{2,5}",
    ) {
        let url = format!("https://{}/path", domain);
        let result = PolicyEngine::extract_domain(&url);

        prop_assert_eq!(result.clone(), result.to_lowercase(),
            "extract_domain must return lowercase\n\
             url:    {:?}\n\
             result: {:?}", url, result);
    }
}

// ═══════════════════════════════════
// PROPERTY 6: evaluate_action with no policies always denies
// ═══════════════════════════════════

proptest! {
    #[test]
    fn no_policies_always_denies(action in arb_action()) {
        let engine = PolicyEngine::new(false);
        let result = engine.evaluate_action(&action, &[]);

        match result {
            Ok(sentinel_types::Verdict::Deny { .. }) => {}
            other => prop_assert!(false,
                "With no policies, evaluate_action must deny. Got: {:?}", other),
        }
    }
}

// ═══════════════════════════════════
// PROPERTY 7: normalize_path never produces parent traversal
// ═══════════════════════════════════

proptest! {
    #[test]
    fn normalize_path_no_parent_traversal(
        path in "\\PC{0,50}",
    ) {
        let normalized = PolicyEngine::normalize_path(&path);

        // The normalized path must not contain ".." as a path component
        // (i.e., "/../" or leading "../" or exactly "..").
        // Note: "..foo" is a valid filename, not a traversal.
        prop_assert!(normalized != "..",
            "normalize_path must not return bare '..' traversal\n\
             input:      {:?}\n\
             normalized: {:?}", path, normalized);
        prop_assert!(!normalized.starts_with("../"),
            "normalize_path must not start with parent traversal\n\
             input:      {:?}\n\
             normalized: {:?}", path, normalized);
        prop_assert!(!normalized.contains("/../"),
            "normalize_path must not contain parent traversal component\n\
             input:      {:?}\n\
             normalized: {:?}", path, normalized);
    }
}

// ═══════════════════════════════════
// PROPERTY 8: extract_domain never contains path components
// ═══════════════════════════════════

proptest! {
    #[test]
    fn extract_domain_no_path(
        domain in "[a-z]{3,10}\\.[a-z]{2,5}",
        path in "/[a-z]{1,20}",
    ) {
        let url = format!("https://{}{}", domain, path);
        let result = PolicyEngine::extract_domain(&url);

        prop_assert!(!result.contains('/'),
            "extract_domain must not include path components\n\
             url:    {:?}\n\
             result: {:?}", url, result);
    }
}

// ═══════════════════════════════════
// PROPERTY 9: get_param_by_path determinism
// ═══════════════════════════════════

proptest! {
    #[test]
    fn get_param_by_path_is_deterministic(
        key in "[a-z]{1,5}",
        value in "[a-z]{1,10}",
    ) {
        let params = json!({key.clone(): value.clone()});
        let r1 = PolicyEngine::get_param_by_path(&params, &key);
        let r2 = PolicyEngine::get_param_by_path(&params, &key);
        prop_assert_eq!(r1, r2,
            "get_param_by_path must be deterministic for key {:?}", key);
    }
}

// ═══════════════════════════════════
// PROPERTY 10: Non-dotted paths behave as simple get()
// ═══════════════════════════════════

proptest! {
    #[test]
    fn get_param_by_path_non_dotted_equals_get(
        key in "[a-z]{1,10}",
        value in "[a-z]{1,10}",
    ) {
        // For keys without dots, get_param_by_path should be identical to params.get()
        let params = json!({key.clone(): value.clone()});
        let path_result = PolicyEngine::get_param_by_path(&params, &key);
        let get_result = params.get(&key);
        prop_assert_eq!(path_result, get_result,
            "Non-dotted path {:?} must behave identically to Value::get()", key);
    }
}

// ═══════════════════════════════════
// PROPERTY 11: Exact key resolves when no nested equivalent exists
// ═══════════════════════════════════

proptest! {
    #[test]
    fn get_param_by_path_exact_key_resolves_alone(
        key1 in "[a-z]{1,5}",
        key2 in "[a-z]{1,5}",
        value in "[a-z]{1,10}",
    ) {
        let dotted_key = format!("{}.{}", key1, key2);
        // Only literal dotted key exists (no nested equivalent)
        let params = json!({dotted_key.clone(): value.clone()});
        let result = PolicyEngine::get_param_by_path(&params, &dotted_key);
        prop_assert_eq!(result, Some(&json!(value)),
            "Exact dotted key {:?} must resolve when no nested equivalent exists", dotted_key);
    }
}

// ═══════════════════════════════════
// PROPERTY 12: Ambiguous paths with different values return None
// ═══════════════════════════════════

proptest! {
    #[test]
    fn get_param_by_path_ambiguous_returns_none(
        key1 in "[a-z]{1,5}",
        key2 in "[a-z]{1,5}",
        val_exact in "[a-z]{1,5}",
        val_nested in "[A-Z]{1,5}", // Different case to guarantee different values
    ) {
        let dotted_key = format!("{}.{}", key1, key2);
        // Both a literal dotted key AND nested traversal exist with DIFFERENT values
        let params = json!({
            dotted_key.clone(): val_exact.clone(),
            key1.clone(): {key2.clone(): val_nested.clone()}
        });

        // Only check when values actually differ (they should since one is lowercase, one uppercase)
        let exact = params.get(&dotted_key);
        let nested = params.get(&key1).and_then(|v| v.get(&key2));
        if exact.is_some() && nested.is_some() && exact != nested {
            let result = PolicyEngine::get_param_by_path(&params, &dotted_key);
            prop_assert_eq!(result, None,
                "Ambiguous path {:?} with different values must return None (fail-closed)\n\
                 exact:  {:?}\n\
                 nested: {:?}", dotted_key, exact, nested);
        }
    }
}

// ═══════════════════════════════════
// PROPERTY 13: Strict mode with unknown tool always denies
// (C-16.2: fail-closed invariant)
// ═══════════════════════════════════

proptest! {
    #[test]
    fn strict_mode_unknown_tool_always_denies(
        tool in "[a-z]{5,15}_unknown",
        function in "[a-z]{1,10}",
    ) {
        // Policies that never match the tool (tool names are always *_unknown,
        // policies only cover "file" and "bash")
        let policies = vec![
            Policy {
                id: "file:read".to_string(),
                name: "Allow file read".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
            },
            Policy {
                id: "bash:*".to_string(),
                name: "Block bash".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
            },
        ];

        let engine = PolicyEngine::new(true); // strict mode
        let action = Action {
            tool,
            function,
            parameters: json!({}),
        };

        let result = engine.evaluate_action(&action, &policies);
        match result {
            Ok(Verdict::Deny { .. }) => {} // Expected: strict mode denies unknown tools
            other => prop_assert!(false,
                "Strict mode must deny unknown tools. Got: {:?}", other),
        }
    }
}

// ═══════════════════════════════════
// PROPERTY 14: Deny policy always beats Allow at same or higher priority
// ═══════════════════════════════════

proptest! {
    #[test]
    fn deny_at_higher_priority_always_wins(
        tool in "[a-z]{1,10}",
        function in "[a-z]{1,10}",
        deny_priority in 50..=100i32,
        allow_priority in 1..=49i32,
    ) {
        let mut policies = vec![
            Policy {
                id: "*:*".to_string(),
                name: "Allow all".to_string(),
                policy_type: PolicyType::Allow,
                priority: allow_priority,
            },
            Policy {
                id: "*:*".to_string(),
                name: "Deny all".to_string(),
                policy_type: PolicyType::Deny,
                priority: deny_priority,
            },
        ];
        PolicyEngine::sort_policies(&mut policies);

        let engine = PolicyEngine::new(false);
        let action = Action {
            tool,
            function,
            parameters: json!({}),
        };

        let result = engine.evaluate_action(&action, &policies);
        match result {
            Ok(Verdict::Deny { .. }) => {} // Expected: higher priority deny wins
            other => prop_assert!(false,
                "Deny at priority {} must beat Allow at priority {}. Got: {:?}",
                deny_priority, allow_priority, other),
        }
    }
}
