// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, EvaluationTrace, Policy, PolicyType, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbstractDenySource {
    EmptyPolicies,
    MissingContext,
    NoMatch,
    PolicyDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AbstractTransition {
    StartEvaluation,
    EmptyPolicySetDeny,
    MatchMiss {
        policy_id: String,
    },
    MatchHit {
        policy_id: String,
    },
    ApplyAllow {
        policy_id: String,
    },
    ApplyContinue {
        policy_id: String,
    },
    ApplyDeny {
        policy_id: String,
        source: AbstractDenySource,
    },
    ApplyRequireApproval {
        policy_id: String,
    },
    ExhaustedNoMatch,
}

fn policy(id: &str, priority: i32, policy_type: PolicyType) -> Policy {
    Policy {
        id: id.to_string(),
        name: id.to_string(),
        policy_type,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
}

fn compiled_trace(policies: &[Policy], action: &Action) -> (Verdict, EvaluationTrace) {
    let engine = PolicyEngine::with_policies(false, policies).unwrap();
    engine.evaluate_action_traced(action).unwrap()
}

fn deny_source(reason: &str) -> AbstractDenySource {
    if reason == "No policies defined" {
        AbstractDenySource::EmptyPolicies
    } else if reason == "No matching policy" {
        AbstractDenySource::NoMatch
    } else if reason.contains("requires evaluation context") {
        AbstractDenySource::MissingContext
    } else {
        AbstractDenySource::PolicyDecision
    }
}

fn trace_to_transitions(trace: &EvaluationTrace) -> Vec<AbstractTransition> {
    let mut transitions = vec![AbstractTransition::StartEvaluation];
    let mut decided = false;

    for policy_match in &trace.matches {
        if !policy_match.tool_matched {
            transitions.push(AbstractTransition::MatchMiss {
                policy_id: policy_match.policy_id.clone(),
            });
            continue;
        }

        transitions.push(AbstractTransition::MatchHit {
            policy_id: policy_match.policy_id.clone(),
        });

        match &policy_match.verdict_contribution {
            Some(Verdict::Allow) => {
                transitions.push(AbstractTransition::ApplyAllow {
                    policy_id: policy_match.policy_id.clone(),
                });
                decided = true;
                break;
            }
            Some(Verdict::Deny { reason }) => {
                transitions.push(AbstractTransition::ApplyDeny {
                    policy_id: policy_match.policy_id.clone(),
                    source: deny_source(reason),
                });
                decided = true;
                break;
            }
            Some(Verdict::RequireApproval { .. }) => {
                transitions.push(AbstractTransition::ApplyRequireApproval {
                    policy_id: policy_match.policy_id.clone(),
                });
                decided = true;
                break;
            }
            None => {
                transitions.push(AbstractTransition::ApplyContinue {
                    policy_id: policy_match.policy_id.clone(),
                });
            }
            // Verdict is #[non_exhaustive]; treat unknown variants as deny.
            _ => {
                decided = true;
                break;
            }
        }
    }

    if decided {
        return transitions;
    }

    match &trace.verdict {
        Verdict::Deny { reason } if reason == "No policies defined" => {
            transitions.push(AbstractTransition::EmptyPolicySetDeny);
        }
        Verdict::Deny { reason } if reason == "No matching policy" => {
            transitions.push(AbstractTransition::ExhaustedNoMatch);
        }
        Verdict::Allow | Verdict::RequireApproval { .. } => {
            panic!("trace ended without a contributing policy: {trace:?}");
        }
        Verdict::Deny { .. } => {}
        // Verdict is #[non_exhaustive]; treat unknown variants as unexpected.
        _ => {
            panic!("unexpected Verdict variant in trace: {trace:?}");
        }
    }

    transitions
}

fn assert_trace_shape(trace: &EvaluationTrace) {
    assert_eq!(
        trace.policies_checked,
        trace.matches.len(),
        "trace count drifted from policy match rows"
    );
    assert_eq!(
        trace.policies_matched,
        trace.matches.iter().filter(|m| m.tool_matched).count(),
        "matched count drifted from tool_matched rows"
    );
}

fn assert_sorted_prefix(policies: &[Policy], trace: &EvaluationTrace) {
    let mut sorted = policies.to_vec();
    PolicyEngine::sort_policies(&mut sorted);
    let expected: Vec<&str> = sorted
        .iter()
        .take(trace.matches.len())
        .map(|policy| policy.id.as_str())
        .collect();
    let observed: Vec<&str> = trace
        .matches
        .iter()
        .map(|policy_match| policy_match.policy_id.as_str())
        .collect();
    assert_eq!(
        observed, expected,
        "checked policy prefix no longer refines SortedByPriority"
    );
}

#[test]
fn test_refinement_empty_policy_set_fail_closed() {
    let action = action("fs", "read");
    let (verdict, trace) = compiled_trace(&[], &action);

    assert!(matches!(verdict, Verdict::Deny { .. }));
    assert_trace_shape(&trace);
    assert_eq!(
        trace_to_transitions(&trace),
        vec![
            AbstractTransition::StartEvaluation,
            AbstractTransition::EmptyPolicySetDeny,
        ]
    );
}

#[test]
fn test_refinement_match_miss_then_allow() {
    let policies = vec![
        policy("fs:write", 100, PolicyType::Allow),
        policy("fs:read", 90, PolicyType::Allow),
    ];
    let action = action("fs", "read");
    let (verdict, trace) = compiled_trace(&policies, &action);

    assert!(matches!(verdict, Verdict::Allow));
    assert_trace_shape(&trace);
    assert_sorted_prefix(&policies, &trace);
    assert_eq!(
        trace_to_transitions(&trace),
        vec![
            AbstractTransition::StartEvaluation,
            AbstractTransition::MatchMiss {
                policy_id: "fs:write".to_string(),
            },
            AbstractTransition::MatchHit {
                policy_id: "fs:read".to_string(),
            },
            AbstractTransition::ApplyAllow {
                policy_id: "fs:read".to_string(),
            },
        ]
    );
}

#[test]
fn test_refinement_first_match_deny_from_sorted_order() {
    let policies = vec![
        policy("fs:*", 10, PolicyType::Allow),
        policy("fs:*", 100, PolicyType::Deny),
    ];
    let action = action("fs", "read");
    let (verdict, trace) = compiled_trace(&policies, &action);

    assert!(matches!(verdict, Verdict::Deny { .. }));
    assert_trace_shape(&trace);
    assert_sorted_prefix(&policies, &trace);
    assert_eq!(
        trace_to_transitions(&trace),
        vec![
            AbstractTransition::StartEvaluation,
            AbstractTransition::MatchHit {
                policy_id: "fs:*".to_string(),
            },
            AbstractTransition::ApplyDeny {
                policy_id: "fs:*".to_string(),
                source: AbstractDenySource::PolicyDecision,
            },
        ]
    );
}

#[test]
fn test_refinement_conditional_continue_then_next_policy() {
    let policies = vec![
        policy(
            "fs:read",
            100,
            PolicyType::Conditional {
                conditions: json!({
                    "on_no_match": "continue",
                    "parameter_constraints": [
                        { "param": "missing", "op": "eq", "value": "x", "on_missing": "skip" }
                    ]
                }),
            },
        ),
        policy("fs:read", 90, PolicyType::Allow),
    ];
    let action = action("fs", "read");
    let (verdict, trace) = compiled_trace(&policies, &action);

    assert!(matches!(verdict, Verdict::Allow));
    assert_trace_shape(&trace);
    assert_sorted_prefix(&policies, &trace);
    assert_eq!(
        trace_to_transitions(&trace),
        vec![
            AbstractTransition::StartEvaluation,
            AbstractTransition::MatchHit {
                policy_id: "fs:read".to_string(),
            },
            AbstractTransition::ApplyContinue {
                policy_id: "fs:read".to_string(),
            },
            AbstractTransition::MatchHit {
                policy_id: "fs:read".to_string(),
            },
            AbstractTransition::ApplyAllow {
                policy_id: "fs:read".to_string(),
            },
        ]
    );
}

#[test]
fn test_refinement_require_approval_transition() {
    let policies = vec![policy(
        "net:connect",
        100,
        PolicyType::Conditional {
            conditions: json!({
                "require_approval": true
            }),
        },
    )];
    let action = action("net", "connect");
    let (verdict, trace) = compiled_trace(&policies, &action);

    assert!(matches!(verdict, Verdict::RequireApproval { .. }));
    assert_trace_shape(&trace);
    assert_sorted_prefix(&policies, &trace);
    assert_eq!(
        trace_to_transitions(&trace),
        vec![
            AbstractTransition::StartEvaluation,
            AbstractTransition::MatchHit {
                policy_id: "net:connect".to_string(),
            },
            AbstractTransition::ApplyRequireApproval {
                policy_id: "net:connect".to_string(),
            },
        ]
    );
}

#[test]
fn test_refinement_missing_context_fail_closed() {
    let policies = vec![policy(
        "read_file:*",
        100,
        PolicyType::Conditional {
            conditions: json!({
                "context_conditions": [
                    { "type": "time_window", "start_hour": 9, "end_hour": 17 }
                ]
            }),
        },
    )];
    let action = action("read_file", "execute");
    let (verdict, trace) = compiled_trace(&policies, &action);

    assert!(matches!(verdict, Verdict::Deny { .. }));
    assert_trace_shape(&trace);
    assert_sorted_prefix(&policies, &trace);
    assert_eq!(
        trace_to_transitions(&trace),
        vec![
            AbstractTransition::StartEvaluation,
            AbstractTransition::MatchHit {
                policy_id: "read_file:*".to_string(),
            },
            AbstractTransition::ApplyDeny {
                policy_id: "read_file:*".to_string(),
                source: AbstractDenySource::MissingContext,
            },
        ]
    );
}

#[test]
fn test_refinement_exhausted_no_match() {
    let policies = vec![policy("fs:write", 100, PolicyType::Allow)];
    let action = action("fs", "read");
    let (verdict, trace) = compiled_trace(&policies, &action);

    assert!(matches!(verdict, Verdict::Deny { .. }));
    assert_trace_shape(&trace);
    assert_sorted_prefix(&policies, &trace);
    assert_eq!(
        trace_to_transitions(&trace),
        vec![
            AbstractTransition::StartEvaluation,
            AbstractTransition::MatchMiss {
                policy_id: "fs:write".to_string(),
            },
            AbstractTransition::ExhaustedNoMatch,
        ]
    );
}
