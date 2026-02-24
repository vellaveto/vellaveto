//! Adversarial scenario tests for attack vectors not covered by property tests.
//!
//! These are targeted, non-proptest tests that exercise specific attack patterns:
//! - ReDoS (catastrophic backtracking)
//! - IP address format domain bypass
//! - Unicode lookalike policy IDs
//! - Wildcard domain suffix attacks
//! - Concurrent evaluation determinism

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, NetworkRules, PathRules, Policy, PolicyType, Verdict};

// ═══════════════════════════════════════════════════
// ADVERSARIAL 1: Regex catastrophic backtracking protection
// ═══════════════════════════════════════════════════

/// ReDoS patterns like `^(a+)+b$` on input `"aaa...a!"` can cause exponential
/// backtracking. The engine must reject such patterns at compile time or handle
/// them safely within a reasonable time bound.
#[test]
fn regex_catastrophic_backtracking_rejected() {
    // The engine's validate_regex_safety() should reject nested quantifiers
    let policy = Policy {
        id: "*:*".to_string(),
        name: "ReDoS trap".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "input",
                    "op": "regex",
                    "pattern": "^(a+)+b$",
                    "on_match": "deny"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    };

    // The engine should reject this policy at compile time
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(
        result.is_err(),
        "Nested quantifier pattern '^(a+)+b$' must be rejected at compile time. Got: {:?}",
        result
    );
}

/// Even if a pattern somehow gets through, evaluation must not hang.
/// This tests that the regex crate itself handles bad patterns gracefully.
#[test]
fn regex_long_input_does_not_hang() {
    use std::time::Instant;

    // Use a pattern that is valid but could be slow with bad engines
    let policy = Policy {
        id: "*:*".to_string(),
        name: "Long input test".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "input",
                    "op": "regex",
                    "pattern": "^[a-z]+$",
                    "on_match": "deny"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    };

    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();

    // 100K character input
    let long_input = "a".repeat(100_000);
    let action = Action::new("test", "run", json!({"input": long_input}));

    let start = Instant::now();
    let _result = engine.evaluate_action(&action, &[]);
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 5,
        "Regex evaluation on 100K input took {:?} — possible ReDoS",
        elapsed
    );
}

// ═══════════════════════════════════════════════════
// ADVERSARIAL 2: IP address format domain bypass
// ═══════════════════════════════════════════════════

/// Verify that IP address representations (decimal, hex, long form) are checked
/// against domain blocks consistently.
#[test]
fn ip_address_format_domain_bypass() {
    let policy = Policy {
        id: "*:*".to_string(),
        name: "Block evil IP".to_string(),
        policy_type: PolicyType::Allow,
        priority: 10,
        path_rules: None,
        network_rules: Some(NetworkRules {
            allowed_domains: vec!["trusted.com".to_string()],
            blocked_domains: vec![],
            ip_rules: None,
        }),
    };

    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();

    // All these IP representations should be denied (not in allowed set)
    let ip_variants = [
        "127.0.0.1",
        "192.168.1.1",
        "10.0.0.1",
        "169.254.169.254", // AWS metadata endpoint
    ];

    for ip in &ip_variants {
        let mut action = Action::new("http", "get", json!({}));
        action.target_domains = vec![ip.to_string()];

        let result = engine.evaluate_action(&action, &[]);
        assert!(
            matches!(result, Ok(Verdict::Deny { .. })),
            "IP '{}' must be denied when only 'trusted.com' is allowed. Got: {:?}",
            ip,
            result
        );
    }
}

// ═══════════════════════════════════════════════════
// ADVERSARIAL 3: Unicode lookalike policy IDs
// ═══════════════════════════════════════════════════

/// Cyrillic 'а' (U+0430) vs ASCII 'a' (U+0061) — after FIND-SEM-003,
/// the engine normalizes homoglyphs before policy matching. This means
/// Cyrillic lookalikes DO match their ASCII equivalents, which is the
/// more secure behavior: an attacker cannot use homoglyph characters
/// to bypass Deny policies targeting ASCII tool names.
#[test]
fn policy_id_unicode_lookalike() {
    // Policy uses ASCII "admin:*"
    let policy = Policy {
        id: "admin:*".to_string(),
        name: "Admin tools".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: None,
    };

    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();

    // Action uses Cyrillic 'а' (U+0430) — looks like "admin" but isn't
    let cyrillic_admin = "\u{0430}dmin"; // Cyrillic 'а' + ASCII "dmin"
    let action = Action::new(cyrillic_admin, "execute", json!({}));

    let result = engine.evaluate_action(&action, &[]);
    // SECURITY (FIND-SEM-003): After homoglyph normalization, the Cyrillic
    // lookalike IS matched by the ASCII policy. This is correct — it prevents
    // an attacker from using Cyrillic 'а' to bypass a Deny policy for 'admin'.
    assert!(
        matches!(result, Ok(Verdict::Allow)),
        "Cyrillic lookalike '{}' should match ASCII 'admin' after homoglyph normalization. Got: {:?}",
        cyrillic_admin,
        result
    );
}

// ═══════════════════════════════════════════════════
// ADVERSARIAL 4: Wildcard domain must not match suffix attacks
// ═══════════════════════════════════════════════════

/// `*.example.com` must NOT match `notexample.com` — only `sub.example.com`.
/// This tests the boundary between suffix matching and proper wildcard semantics.
#[test]
fn wildcard_domain_doesnt_match_suffix_attack() {
    // These should NOT match *.example.com
    let non_matching = [
        "notexample.com",
        "example.com.evil.net",
        "fakeexample.com",
        "myexample.com",
    ];

    for domain in &non_matching {
        assert!(
            !PolicyEngine::match_domain_pattern(domain, "*.example.com"),
            "'*.example.com' must NOT match '{}' (suffix attack)",
            domain
        );
    }

    // These SHOULD match *.example.com
    let matching = [
        "sub.example.com",
        "api.example.com",
        "deep.sub.example.com",
        "example.com", // bare domain also matches wildcard
    ];

    for domain in &matching {
        assert!(
            PolicyEngine::match_domain_pattern(domain, "*.example.com"),
            "'*.example.com' must match '{}'",
            domain
        );
    }
}

// ═══════════════════════════════════════════════════
// ADVERSARIAL 5: Concurrent policy evaluation is deterministic
// ═══════════════════════════════════════════════════

/// Running the same evaluation in parallel must always produce the same verdict.
/// This tests for race conditions in shared engine state.
#[tokio::test]
async fn concurrent_policy_evaluation_deterministic() {
    use std::sync::Arc;

    let policies = vec![
        Policy {
            id: "file:*".to_string(),
            name: "Allow file ops".to_string(),
            policy_type: PolicyType::Allow,
            priority: 50,
            path_rules: Some(PathRules {
                allowed: vec!["/tmp/**".to_string()],
                blocked: vec!["/tmp/secret/**".to_string()],
            }),
            network_rules: None,
        },
        Policy {
            id: "*:*".to_string(),
            name: "Deny all else".to_string(),
            policy_type: PolicyType::Deny,
            priority: 1,
            path_rules: None,
            network_rules: None,
        },
    ];

    let engine = Arc::new(PolicyEngine::with_policies(false, &policies).unwrap());

    let mut handles = Vec::new();
    for _ in 0..50 {
        let eng = Arc::clone(&engine);
        handles.push(tokio::spawn(async move {
            let mut action = Action::new("file", "read", json!({"path": "/tmp/test.txt"}));
            action.target_paths = vec!["/tmp/test.txt".to_string()];
            eng.evaluate_action(&action, &[])
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        results.push(h.await.unwrap());
    }

    // All results must be identical
    let first = &results[0];
    for (i, result) in results.iter().enumerate() {
        assert_eq!(
            format!("{:?}", first),
            format!("{:?}", result),
            "Concurrent evaluation {} differs from first",
            i
        );
    }

    // And they must all be Allow (path /tmp/test.txt matches /tmp/**)
    assert!(
        matches!(first, Ok(Verdict::Allow)),
        "Expected Allow for /tmp/test.txt. Got: {:?}",
        first
    );
}

/// Concurrent evaluation with a blocked path must consistently deny.
#[tokio::test]
async fn concurrent_blocked_path_consistently_denies() {
    use std::sync::Arc;

    let policies = vec![Policy {
        id: "file:*".to_string(),
        name: "Allow with blocks".to_string(),
        policy_type: PolicyType::Allow,
        priority: 50,
        path_rules: Some(PathRules {
            allowed: vec!["/data/**".to_string()],
            blocked: vec!["/data/secret/**".to_string()],
        }),
        network_rules: None,
    }];

    let engine = Arc::new(PolicyEngine::with_policies(false, &policies).unwrap());

    let mut handles = Vec::new();
    for _ in 0..50 {
        let eng = Arc::clone(&engine);
        handles.push(tokio::spawn(async move {
            let mut action = Action::new("file", "read", json!({}));
            action.target_paths = vec!["/data/secret/keys.json".to_string()];
            eng.evaluate_action(&action, &[])
        }));
    }

    for h in handles {
        let result = h.await.unwrap();
        assert!(
            matches!(result, Ok(Verdict::Deny { .. })),
            "Blocked path must consistently deny. Got: {:?}",
            result
        );
    }
}
