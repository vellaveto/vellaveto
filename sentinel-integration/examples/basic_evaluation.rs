//! Basic example: create a policy and evaluate an action.
//!
//! Run with:
//!
//!   export PATH=$HOME/.cargo/bin:$PATH && cargo run -p sentinel-integration --example basic_evaluation

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType};
use serde_json::json;

fn main() {
    let engine = PolicyEngine::new(false);

    let policies = vec![
        Policy {
            id: "file:read".to_string(),
            name: "Allow file reads".to_string(),
            policy_type: PolicyType::Allow,
            priority: 0,
        },
        Policy {
            id: "file:delete".to_string(),
            name: "Block file deletes".to_string(),
            policy_type: PolicyType::Deny,
            priority: 10,
        },
    ];

    let read_action = Action {
        tool: "file".to_string(),
        function: "read".to_string(),
        parameters: json!({"path": "/etc/config"}),
    };

    match engine.evaluate_action(&read_action, &policies) {
        Ok(verdict) => println!("file:read -> {:?}", verdict),
        Err(e) => eprintln!("Error: {}", e),
    }

    let delete_action = Action {
        tool: "file".to_string(),
        function: "delete".to_string(),
        parameters: json!({"path": "/tmp/data"}),
    };

    match engine.evaluate_action(&delete_action, &policies) {
        Ok(verdict) => println!("file:delete -> {:?}", verdict),
        Err(e) => eprintln!("Error: {}", e),
    }

    let strict_engine = PolicyEngine::new(true);
    let unmatched_action = Action {
        tool: "network".to_string(),
        function: "connect".to_string(),
        parameters: json!({}),
    };

    match strict_engine.evaluate_action(&unmatched_action, &policies) {
        Ok(verdict) => println!("network:connect (strict) -> {:?}", verdict),
        Err(e) => println!("network:connect (strict) -> error: {}", e),
    }
}