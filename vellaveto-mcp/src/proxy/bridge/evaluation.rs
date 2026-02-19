//! Policy evaluation methods for `ProxyBridge`.
//!
//! Handles evaluating tool calls and resource reads against the policy engine,
//! producing `ProxyDecision` results for the relay loop.

use super::ProxyBridge;
use super::ToolAnnotations;
use crate::extractor::{
    extract_action, extract_resource_action, make_approval_response, make_denial_response,
};
use crate::proxy::types::ProxyDecision;
use serde_json::{json, Value};
use vellaveto_types::{EvaluationContext, EvaluationTrace, Verdict};

/// Log evaluation trace details at debug level.
fn log_trace(label: &str, trace: &EvaluationTrace) {
    tracing::debug!(
        "Trace ({}): {} policies checked, {} matched, {}us",
        label,
        trace.policies_checked,
        trace.policies_matched,
        trace.duration_us
    );
}

impl ProxyBridge {
    /// Evaluate an action against policies, optionally producing a trace.
    ///
    /// When `context` is provided, uses context-aware evaluation for time windows,
    /// call limits, agent identity, and action history.
    pub(super) fn evaluate_action_inner(
        &self,
        action: &vellaveto_types::Action,
        context: Option<&EvaluationContext>,
    ) -> Result<(Verdict, Option<EvaluationTrace>), vellaveto_engine::EngineError> {
        if self.enable_trace {
            let (verdict, trace) = self
                .engine
                .evaluate_action_traced_with_context(action, context)?;
            Ok((verdict, Some(trace)))
        } else {
            let verdict =
                self.engine
                    .evaluate_action_with_context(action, &self.policies, context)?;
            Ok((verdict, None))
        }
    }

    /// Evaluate a tool call and decide whether to forward or block.
    ///
    /// If `annotations` are provided (from a prior `tools/list` response),
    /// they are included in audit metadata for the decision.
    ///
    /// Returns `(ProxyDecision, Option<EvaluationTrace>)` so callers can
    /// inject decision explanations into responses (Art 50(2)).
    pub fn evaluate_tool_call(
        &self,
        id: &Value,
        tool_name: &str,
        arguments: &Value,
        annotations: Option<&ToolAnnotations>,
        context: Option<&EvaluationContext>,
    ) -> (ProxyDecision, Option<EvaluationTrace>) {
        let action = extract_action(tool_name, arguments);

        match self.evaluate_action_inner(&action, context) {
            Ok((Verdict::Allow, trace)) => {
                // Log awareness when allowing destructive tools
                if let Some(ann) = annotations {
                    if ann.destructive_hint && !ann.read_only_hint {
                        tracing::info!(
                            "Allowing destructive tool '{}' (destructiveHint=true)",
                            tool_name
                        );
                    }
                }
                if let Some(ref t) = trace {
                    log_trace("allow", t);
                }
                (ProxyDecision::Forward, trace)
            }
            Ok((Verdict::Deny { reason }, trace)) => {
                if let Some(ref t) = trace {
                    log_trace("deny", t);
                }
                let response = make_denial_response(id, &reason);
                (
                    ProxyDecision::Block(response, Verdict::Deny { reason }),
                    trace,
                )
            }
            Ok((Verdict::RequireApproval { reason }, trace)) => {
                if let Some(ref t) = trace {
                    log_trace("approval", t);
                }
                let response = make_approval_response(id, &reason);
                (
                    ProxyDecision::Block(response, Verdict::RequireApproval { reason }),
                    trace,
                )
            }
            // Handle future Verdict variants - fail closed (deny)
            Ok((_, trace)) => {
                let reason = "Unknown verdict type - failing closed".to_string();
                (
                    ProxyDecision::Block(
                        make_denial_response(id, &reason),
                        Verdict::Deny { reason },
                    ),
                    trace,
                )
            }
            Err(e) => {
                tracing::error!("Policy evaluation error for tool '{}': {}", tool_name, e);
                let reason = "Policy evaluation failed".to_string();
                (
                    ProxyDecision::Block(
                        make_denial_response(id, &reason),
                        Verdict::Deny { reason },
                    ),
                    None,
                )
            }
        }
    }

    /// Build audit metadata for a tool call, including annotations if available.
    pub(super) fn tool_call_audit_metadata(
        tool_name: &str,
        annotations: Option<&ToolAnnotations>,
    ) -> Value {
        let mut meta = json!({"source": "proxy", "tool": tool_name});
        if let Some(ann) = annotations {
            meta["annotations"] = json!({
                "readOnlyHint": ann.read_only_hint,
                "destructiveHint": ann.destructive_hint,
                "idempotentHint": ann.idempotent_hint,
                "openWorldHint": ann.open_world_hint,
            });
        }
        meta
    }

    /// Evaluate a tool call using a pre-built Action.
    ///
    /// Used when the action needs pre-processing (e.g., DNS resolution to
    /// populate `resolved_ips`) before policy evaluation. This achieves parity
    /// with the HTTP/WebSocket/gRPC proxy handlers.
    ///
    /// SECURITY (FIND-R78-001): Added for DNS rebinding protection in stdio proxy.
    pub(super) fn evaluate_tool_call_with_action(
        &self,
        id: &Value,
        action: &vellaveto_types::Action,
        tool_name: &str,
        annotations: Option<&ToolAnnotations>,
        context: Option<&EvaluationContext>,
    ) -> (ProxyDecision, Option<EvaluationTrace>) {
        match self.evaluate_action_inner(action, context) {
            Ok((Verdict::Allow, trace)) => {
                if let Some(ann) = annotations {
                    if ann.destructive_hint && !ann.read_only_hint {
                        tracing::info!(
                            "Allowing destructive tool '{}' (destructiveHint=true)",
                            tool_name
                        );
                    }
                }
                if let Some(ref t) = trace {
                    log_trace("allow", t);
                }
                (ProxyDecision::Forward, trace)
            }
            Ok((Verdict::Deny { reason }, trace)) => {
                if let Some(ref t) = trace {
                    log_trace("deny", t);
                }
                let response = make_denial_response(id, &reason);
                (
                    ProxyDecision::Block(response, Verdict::Deny { reason }),
                    trace,
                )
            }
            Ok((Verdict::RequireApproval { reason }, trace)) => {
                if let Some(ref t) = trace {
                    log_trace("approval", t);
                }
                let response = make_approval_response(id, &reason);
                (
                    ProxyDecision::Block(response, Verdict::RequireApproval { reason }),
                    trace,
                )
            }
            // Handle future Verdict variants - fail closed (deny)
            Ok((_, trace)) => {
                let reason = "Unknown verdict type - failing closed".to_string();
                (
                    ProxyDecision::Block(
                        make_denial_response(id, &reason),
                        Verdict::Deny { reason },
                    ),
                    trace,
                )
            }
            Err(e) => {
                tracing::error!("Policy evaluation error for tool '{}': {}", tool_name, e);
                let reason = "Policy evaluation failed".to_string();
                (
                    ProxyDecision::Block(
                        make_denial_response(id, &reason),
                        Verdict::Deny { reason },
                    ),
                    None,
                )
            }
        }
    }

    /// Evaluate a `resources/read` using a pre-built Action.
    ///
    /// SECURITY (FIND-R78-001): Added for DNS rebinding protection in stdio proxy.
    pub(super) fn evaluate_resource_read_with_action(
        &self,
        id: &Value,
        action: &vellaveto_types::Action,
        uri: &str,
        context: Option<&EvaluationContext>,
    ) -> ProxyDecision {
        match self.evaluate_action_inner(action, context) {
            Ok((Verdict::Allow, trace)) => {
                if let Some(ref t) = trace {
                    log_trace("resource_read allow", t);
                }
                ProxyDecision::Forward
            }
            Ok((Verdict::Deny { reason }, _)) => {
                let response = make_denial_response(id, &reason);
                ProxyDecision::Block(response, Verdict::Deny { reason })
            }
            Ok((Verdict::RequireApproval { reason }, _)) => {
                let response = make_approval_response(id, &reason);
                ProxyDecision::Block(response, Verdict::RequireApproval { reason })
            }
            // Handle future Verdict variants - fail closed (deny)
            Ok((_, _)) => {
                let reason = "Unknown verdict type - failing closed".to_string();
                ProxyDecision::Block(make_denial_response(id, &reason), Verdict::Deny { reason })
            }
            Err(e) => {
                tracing::error!("Policy evaluation error for resource '{}': {}", uri, e);
                let reason = "Policy evaluation failed".to_string();
                ProxyDecision::Block(make_denial_response(id, &reason), Verdict::Deny { reason })
            }
        }
    }

    /// Evaluate a `resources/read` request and decide whether to forward or block.
    pub fn evaluate_resource_read(
        &self,
        id: &Value,
        uri: &str,
        context: Option<&EvaluationContext>,
    ) -> ProxyDecision {
        let action = extract_resource_action(uri);

        match self.evaluate_action_inner(&action, context) {
            Ok((Verdict::Allow, trace)) => {
                if let Some(ref t) = trace {
                    log_trace("resource_read allow", t);
                }
                ProxyDecision::Forward
            }
            Ok((Verdict::Deny { reason }, _)) => {
                let response = make_denial_response(id, &reason);
                ProxyDecision::Block(response, Verdict::Deny { reason })
            }
            Ok((Verdict::RequireApproval { reason }, _)) => {
                let response = make_approval_response(id, &reason);
                ProxyDecision::Block(response, Verdict::RequireApproval { reason })
            }
            // Handle future Verdict variants - fail closed (deny)
            Ok((_, _)) => {
                let reason = "Unknown verdict type - failing closed".to_string();
                ProxyDecision::Block(make_denial_response(id, &reason), Verdict::Deny { reason })
            }
            Err(e) => {
                tracing::error!("Policy evaluation error for resource '{}': {}", uri, e);
                let reason = "Policy evaluation failed".to_string();
                ProxyDecision::Block(make_denial_response(id, &reason), Verdict::Deny { reason })
            }
        }
    }
}
