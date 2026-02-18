//! McpService gRPC implementation.
//!
//! Implements the tonic-generated `McpService` trait with the same policy
//! evaluation pipeline as the HTTP and WebSocket handlers:
//! 1. Convert proto → JSON
//! 2. Classify message
//! 3. Evaluate policy (tool calls, resource reads)
//! 4. Audit
//! 5. Forward to upstream
//! 6. DLP/injection scan response
//! 7. Convert JSON → proto

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use vellaveto_mcp::extractor::{self, MessageType};
use vellaveto_mcp::inspection::{
    inspect_for_injection, scan_parameters_for_secrets, scan_response_for_secrets,
};
use vellaveto_mcp::output_validation::ValidationResult;
use vellaveto_types::{Action, EvaluationContext, Verdict};

use super::convert::{
    json_to_proto_response, make_proto_denial_response, make_proto_error_response,
    proto_request_to_json,
};
use super::interceptors::{
    contains_dangerous_chars, extract_or_generate_request_id, extract_session_id,
};
use super::proto::{
    mcp_service_server::McpService, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse,
    SubscribeRequest,
};
use super::upstream::UpstreamForwarder;
use super::ProxyState;
use crate::proxy::call_chain::{
    build_current_agent_entry, check_privilege_escalation, MAX_ACTION_HISTORY, MAX_CALL_COUNT_TOOLS,
};
use crate::proxy_metrics::record_dlp_finding;

/// Global gRPC metrics counters.
static GRPC_REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static GRPC_MESSAGES_TOTAL: AtomicU64 = AtomicU64::new(0);

fn record_grpc_request() {
    // SECURITY (FIND-R55-GRPC-012): SeqCst on security-adjacent metrics counters
    // to ensure visibility across threads for rate limiting and audit decisions.
    GRPC_REQUESTS_TOTAL.fetch_add(1, Ordering::SeqCst);
    metrics::counter!("vellaveto_grpc_requests_total").increment(1);
}

fn record_grpc_message(direction: &str) {
    // SECURITY (FIND-R55-GRPC-012): SeqCst on security-adjacent metrics counters.
    GRPC_MESSAGES_TOTAL.fetch_add(1, Ordering::SeqCst);
    metrics::counter!(
        "vellaveto_grpc_messages_total",
        "direction" => direction.to_string()
    )
    .increment(1);
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn grpc_requests_count() -> u64 {
    GRPC_REQUESTS_TOTAL.load(Ordering::Relaxed)
}

/// The MCP gRPC service implementation.
pub struct McpGrpcService {
    state: Arc<ProxyState>,
    upstream: UpstreamForwarder,
    /// SECURITY (FIND-R55-GRPC-010): Per-stream message rate limit (messages/sec).
    /// 0 means unlimited.
    stream_message_rate_limit: u32,
}

impl McpGrpcService {
    pub fn new(state: Arc<ProxyState>, stream_message_rate_limit: u32) -> Self {
        let upstream = UpstreamForwarder::new(state.clone());
        Self {
            state,
            upstream,
            stream_message_rate_limit,
        }
    }

    /// Evaluate a single JSON-RPC request through the policy pipeline.
    ///
    /// Returns the response proto. Policy denials and transport errors are
    /// encoded as JSON-RPC error responses inside a successful gRPC status
    /// (matching HTTP/WS behavior).
    async fn evaluate_request(
        &self,
        proto_req: &JsonRpcRequest,
        session_id: &str,
    ) -> JsonRpcResponse {
        // 1. Convert proto → JSON
        let json_req = match proto_request_to_json(proto_req) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("gRPC proto→JSON conversion failed: {}", e);
                return make_proto_error_response(proto_req, -32603, "Internal conversion error");
            }
        };

        // SECURITY (FIND-R54-004): Reject gRPC messages with control/Unicode format
        // characters. Parity with HTTP body check and WS frame check (FIND-R53-WS-004).
        if json_contains_dangerous_chars(&json_req, 0) {
            tracing::warn!(
                session_id = %session_id,
                "SECURITY: Rejected gRPC message with control/Unicode format characters"
            );
            return make_proto_error_response(
                proto_req,
                -32600,
                "Message contains control characters",
            );
        }

        // 2. Classify
        let classified = extractor::classify_message(&json_req);

        // 3. Process by message type
        match classified {
            MessageType::ToolCall {
                ref id,
                ref tool_name,
                ref arguments,
            } => {
                self.handle_tool_call(proto_req, &json_req, session_id, id, tool_name, arguments)
                    .await
            }
            MessageType::ResourceRead { ref id, ref uri } => {
                self.handle_resource_read(proto_req, &json_req, session_id, id, uri)
                    .await
            }
            MessageType::SamplingRequest { id: _ } => {
                if !self.state.sampling_config.enabled {
                    return make_proto_denial_response(proto_req, "Sampling requests are disabled");
                }
                self.forward_and_scan(proto_req, &json_req, session_id)
                    .await
            }
            MessageType::ElicitationRequest { .. } => {
                // SECURITY (FIND-R54-GRPC-007): Inspect elicitation requests.
                // Parity with HTTP handler's elicitation interception (handlers.rs:1843).
                let params = json_req.get("params").cloned().unwrap_or(json!({}));
                let elicitation_verdict = {
                    let mut session_ref = self.state.sessions.get_mut(session_id);
                    let current_count = session_ref
                        .as_ref()
                        .map(|s| s.elicitation_count)
                        .unwrap_or(0);
                    let verdict = vellaveto_mcp::elicitation::inspect_elicitation(
                        &params,
                        &self.state.elicitation_config,
                        current_count,
                    );
                    if matches!(
                        verdict,
                        vellaveto_mcp::elicitation::ElicitationVerdict::Allow
                    ) {
                        if let Some(ref mut s) = session_ref {
                            s.elicitation_count = s.elicitation_count.saturating_add(1);
                        }
                    }
                    verdict
                };
                match elicitation_verdict {
                    vellaveto_mcp::elicitation::ElicitationVerdict::Allow => {
                        self.forward_and_scan(proto_req, &json_req, session_id)
                            .await
                    }
                    vellaveto_mcp::elicitation::ElicitationVerdict::Deny { reason } => {
                        tracing::warn!(
                            "Blocked elicitation/create in gRPC session {}: {}",
                            session_id,
                            reason
                        );
                        make_proto_denial_response(
                            proto_req,
                            "elicitation/create blocked by policy",
                        )
                    }
                }
            }
            MessageType::ProgressNotification { .. } => {
                self.forward_and_scan(proto_req, &json_req, session_id)
                    .await
            }
            MessageType::TaskRequest {
                ref id,
                ref task_method,
                ref task_id,
            } => {
                self.handle_task_request(
                    proto_req,
                    &json_req,
                    session_id,
                    id,
                    task_method,
                    task_id.as_deref(),
                )
                .await
            }
            MessageType::ExtensionMethod {
                ref id,
                ref extension_id,
                ref method,
            } => {
                self.handle_extension_method(
                    proto_req,
                    &json_req,
                    session_id,
                    id,
                    extension_id,
                    method,
                )
                .await
            }
            MessageType::Batch => make_proto_error_response(
                proto_req,
                -32600,
                "JSON-RPC batch requests are not supported",
            ),
            MessageType::Invalid { ref reason, .. } => {
                make_proto_error_response(proto_req, -32600, reason)
            }
            MessageType::PassThrough => {
                // SECURITY (FIND-R55-GRPC-005): Audit log PassThrough messages.
                // Parity with HTTP handler (handlers.rs:1731-1757) and WS handler
                // (websocket/mod.rs:1809-1838). PassThrough bypasses policy evaluation
                // but must have an audit trail for observability.
                let method_name = json_req
                    .get("method")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown");
                let action = Action::new("passthrough", method_name, json!({}));
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Allow,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "event": "pass_through_forwarded",
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC pass-through: {}", e);
                }
                self.forward_and_scan(proto_req, &json_req, session_id)
                    .await
            }
        }
    }

    /// Handle a tool call: extract action, evaluate policy, audit, forward or deny.
    async fn handle_tool_call(
        &self,
        proto_req: &JsonRpcRequest,
        json_req: &Value,
        session_id: &str,
        _id: &Value,
        tool_name: &str,
        arguments: &Value,
    ) -> JsonRpcResponse {
        // SECURITY (FIND-R54-005): Strict MCP tool name validation.
        // Parity with HTTP handler (handlers.rs:354).
        if self.state.streamable_http.strict_tool_name_validation {
            if let Err(e) = vellaveto_types::validate_mcp_tool_name(tool_name) {
                tracing::warn!(
                    "SECURITY: Rejecting invalid gRPC tool name '{}': {}",
                    tool_name,
                    e
                );
                return make_proto_error_response(
                    proto_req,
                    -32602,
                    &format!("Invalid tool name: {}", e),
                );
            }
        }

        // SECURITY (FIND-R53-GRPC-001): DLP scan parameters for secret exfiltration.
        // Parity with HTTP handler (handlers.rs:457) and WS (websocket/mod.rs:700).
        let dlp_findings = scan_parameters_for_secrets(arguments);
        if !dlp_findings.is_empty() {
            for finding in &dlp_findings {
                record_dlp_finding(&finding.pattern_name);
            }

            let patterns: Vec<String> = dlp_findings
                .iter()
                .map(|f| format!("{}:{}", f.pattern_name, f.location))
                .collect();

            tracing::warn!(
                "SECURITY: Secrets in gRPC tool call parameters! Session: {}, Tool: {}, Findings: {:?}",
                session_id,
                tool_name,
                patterns,
            );

            let action = extractor::extract_action(tool_name, arguments);
            let verdict = Verdict::Deny {
                reason: format!("DLP blocked: secret detected in parameters: {:?}", patterns),
            };
            if let Err(e) = self
                .state
                .audit
                .log_entry(
                    &action,
                    &verdict,
                    json!({
                        "source": "grpc_proxy",
                        "session": session_id,
                        "transport": "grpc",
                        "event": "grpc_parameter_dlp_alert",
                        "findings": patterns,
                    }),
                )
                .await
            {
                tracing::warn!("Failed to audit gRPC parameter DLP: {}", e);
            }

            return make_proto_denial_response(
                proto_req,
                &format!("DLP blocked: secret detected in parameters: {:?}", patterns),
            );
        }

        // SECURITY (FIND-R53-GRPC-002): Rug-pull detection — block calls to tools
        // with changed annotations since initial tools/list.
        // Parity with HTTP handler (handlers.rs:404-434) and WS (websocket/mod.rs:682).
        let is_flagged = self
            .state
            .sessions
            .get_mut(session_id)
            .map(|s| s.flagged_tools.contains(tool_name))
            .unwrap_or(false);

        if is_flagged {
            let action = extractor::extract_action(tool_name, arguments);
            let verdict = Verdict::Deny {
                reason: format!(
                    "Tool '{}' blocked: annotations changed since initial tools/list (rug-pull detected)",
                    tool_name
                ),
            };
            if let Err(e) = self
                .state
                .audit
                .log_entry(
                    &action,
                    &verdict,
                    json!({
                        "source": "grpc_proxy",
                        "session": session_id,
                        "transport": "grpc",
                        "event": "rug_pull_tool_blocked",
                        "tool": tool_name,
                    }),
                )
                .await
            {
                tracing::warn!("Failed to audit gRPC rug-pull block: {}", e);
            }

            return make_proto_denial_response(
                proto_req,
                &format!(
                    "Tool '{}' blocked: annotations changed since initial tools/list (rug-pull detected)",
                    tool_name
                ),
            );
        }

        // SECURITY (FIND-R53-GRPC-003): Memory poisoning detection — block requests
        // when replayed response data is detected in parameters.
        // Parity with HTTP handler (handlers.rs:512-570) and WS (websocket/mod.rs:751-810).
        if let Some(mut session) = self.state.sessions.get_mut(session_id) {
            let poisoning_matches = session.memory_tracker.check_parameters(arguments);
            if !poisoning_matches.is_empty() {
                for m in &poisoning_matches {
                    tracing::warn!(
                        "SECURITY: Memory poisoning detected in gRPC tool '{}' (session {}): \
                         param '{}' contains replayed data (fingerprint: {})",
                        tool_name,
                        session_id,
                        m.param_location,
                        m.fingerprint
                    );
                }
                let action = extractor::extract_action(tool_name, arguments);
                let deny_reason = format!(
                    "Memory poisoning detected: {} replayed data fragment(s) in tool '{}'",
                    poisoning_matches.len(),
                    tool_name
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Deny {
                            reason: deny_reason.clone(),
                        },
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "event": "memory_poisoning_detected",
                            "matches": poisoning_matches.len(),
                            "tool": tool_name,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC memory poisoning: {}", e);
                }

                // Drop session borrow before returning
                drop(session);

                return make_proto_denial_response(proto_req, &deny_reason);
            }
        }

        let action = extractor::extract_action(tool_name, arguments);

        // SECURITY (FIND-R54-006): Circuit breaker check.
        // Parity with HTTP handler (handlers.rs:576) and WS (websocket/mod.rs:892).
        if let Some(ref circuit_breaker) = self.state.circuit_breaker {
            if let Err(reason) = circuit_breaker.can_proceed(tool_name) {
                tracing::warn!(
                    "SECURITY: gRPC circuit breaker open for tool '{}' in session {}: {}",
                    tool_name,
                    session_id,
                    reason
                );
                let verdict = Verdict::Deny {
                    reason: format!("Circuit breaker open: {}", reason),
                };
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "event": "circuit_breaker_rejected",
                            "tool": tool_name,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC circuit breaker rejection: {}", e);
                }
                return make_proto_denial_response(
                    proto_req,
                    "Service temporarily unavailable — circuit breaker open",
                );
            }
        }

        // SECURITY (FIND-R54-007): Tool registry trust check.
        // Parity with HTTP handler (handlers.rs:621) and WS (websocket/mod.rs:936).
        if let Some(ref registry) = self.state.tool_registry {
            let trust = registry.check_trust_level(tool_name).await;
            match trust {
                vellaveto_mcp::tool_registry::TrustLevel::Unknown => {
                    registry.register_unknown(tool_name).await;
                    let verdict = Verdict::Deny {
                        reason: "Unknown tool requires approval".to_string(),
                    };
                    if let Err(e) = self
                        .state
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({
                                "source": "grpc_proxy",
                                "session": session_id,
                                "transport": "grpc",
                                "registry": "unknown_tool",
                                "tool": tool_name,
                            }),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit gRPC unknown tool: {}", e);
                    }
                    return make_proto_denial_response(proto_req, "Approval required");
                }
                vellaveto_mcp::tool_registry::TrustLevel::Untrusted { score: _ } => {
                    let verdict = Verdict::Deny {
                        reason: "Untrusted tool requires approval".to_string(),
                    };
                    if let Err(e) = self
                        .state
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({
                                "source": "grpc_proxy",
                                "session": session_id,
                                "transport": "grpc",
                                "registry": "untrusted_tool",
                                "tool": tool_name,
                            }),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit gRPC untrusted tool: {}", e);
                    }
                    return make_proto_denial_response(proto_req, "Approval required");
                }
                vellaveto_mcp::tool_registry::TrustLevel::Trusted => {
                    // Trusted — proceed to engine evaluation
                }
            }
        }

        let ctx = self.build_evaluation_context(session_id);

        let verdict = match self.state.engine.evaluate_action_with_context(
            &action,
            &self.state.policies,
            Some(&ctx),
        ) {
            Ok(v) => v,
            Err(e) => {
                // Fail-closed: engine errors produce Deny
                tracing::error!(session_id = %session_id, "Policy evaluation error: {}", e);
                Verdict::Deny {
                    reason: format!("Policy evaluation failed: {}", e),
                }
            }
        };

        match &verdict {
            Verdict::Allow => {
                // Phase 21: ABAC refinement — only runs when ABAC engine is configured
                if let Some(ref abac) = self.state.abac_engine {
                    let principal_id = ctx.agent_id.as_deref().unwrap_or("anonymous");
                    let principal_type = ctx
                        .agent_identity
                        .as_ref()
                        .and_then(|aid| aid.claims.get("type"))
                        .and_then(|v: &serde_json::Value| v.as_str())
                        .unwrap_or("Agent");
                    let session_risk = self
                        .state
                        .sessions
                        .get_mut(session_id)
                        .and_then(|s| s.risk_score.clone());
                    let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                        eval_ctx: &ctx,
                        principal_type,
                        principal_id,
                        risk_score: session_risk.as_ref(),
                    };
                    match abac.evaluate(&action, &abac_ctx) {
                        vellaveto_engine::abac::AbacDecision::Deny { policy_id, reason } => {
                            let deny_verdict = Verdict::Deny {
                                reason: format!("ABAC denied by {}: {}", policy_id, reason),
                            };
                            if let Err(e) = self
                                .state
                                .audit
                                .log_entry(
                                    &action,
                                    &deny_verdict,
                                    json!({
                                        "source": "grpc_proxy",
                                        "session": session_id,
                                        "transport": "grpc",
                                        "abac_policy": policy_id,
                                    }),
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit gRPC ABAC deny: {}", e);
                            }
                            return make_proto_denial_response(
                                proto_req,
                                &format!("ABAC denied by {}: {}", policy_id, reason),
                            );
                        }
                        vellaveto_engine::abac::AbacDecision::Allow { policy_id } => {
                            if let Some(ref la) = self.state.least_agency {
                                la.record_usage(
                                    principal_id,
                                    session_id,
                                    &policy_id,
                                    tool_name,
                                    "",
                                );
                            }
                        }
                        vellaveto_engine::abac::AbacDecision::NoMatch => {
                            // Fall through — existing Allow stands
                        }
                        #[allow(unreachable_patterns)] // AbacDecision is #[non_exhaustive]
                        _ => {
                            // Future variants — fail-closed (deny)
                            tracing::warn!("Unknown AbacDecision variant — fail-closed");
                        }
                    }
                }

                // SECURITY (FIND-R54-002): Privilege escalation check.
                // Parity with HTTP handler (handlers.rs:762).
                let call_chain = self
                    .state
                    .sessions
                    .get_mut(session_id)
                    .map(|s| s.current_call_chain.clone())
                    .unwrap_or_default();
                if !call_chain.is_empty() {
                    let current_agent_id = ctx.agent_id.as_deref();
                    let priv_check = check_privilege_escalation(
                        &self.state.engine,
                        &self.state.policies,
                        &action,
                        &call_chain,
                        current_agent_id,
                    );
                    if priv_check.escalation_detected {
                        let internal_reason = format!(
                            "Privilege escalation detected: agent '{}' would be denied ({})",
                            priv_check
                                .escalating_from_agent
                                .as_deref()
                                .unwrap_or("unknown"),
                            priv_check
                                .upstream_deny_reason
                                .as_deref()
                                .unwrap_or("unknown reason")
                        );
                        if let Err(e) = self
                            .state
                            .audit
                            .log_entry(
                                &action,
                                &Verdict::Deny {
                                    reason: internal_reason,
                                },
                                json!({
                                    "source": "grpc_proxy",
                                    "session": session_id,
                                    "transport": "grpc",
                                    "event": "privilege_escalation_blocked",
                                    "escalating_from_agent": priv_check.escalating_from_agent,
                                    "upstream_deny_reason": priv_check.upstream_deny_reason,
                                }),
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit gRPC privilege escalation: {}", e);
                        }
                        return make_proto_denial_response(
                            proto_req,
                            "Denied by policy: privilege escalation detected",
                        );
                    }
                }

                // Touch session and update call_counts/action_history
                if let Some(mut session) = self.state.sessions.get_mut(session_id) {
                    session.touch();
                    // SECURITY (FIND-R54-003): Update call_counts and action_history on Allow.
                    // Without this, context-aware policies (max_calls_in_window,
                    // ForbiddenActionSequence) are ineffective on the gRPC transport.
                    if session.call_counts.len() < MAX_CALL_COUNT_TOOLS
                        || session.call_counts.contains_key(tool_name)
                    {
                        *session
                            .call_counts
                            .entry(tool_name.to_string())
                            .or_insert(0) += 1;
                    }
                    if session.action_history.len() >= MAX_ACTION_HISTORY {
                        session.action_history.pop_front();
                    }
                    session.action_history.push_back(tool_name.to_string());
                }

                // Audit the allow
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Allow,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC allow: {}", e);
                }

                // Forward and scan response
                self.forward_and_scan(proto_req, json_req, session_id).await
            }
            Verdict::Deny { reason } => {
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC deny: {}", e);
                }
                make_proto_denial_response(proto_req, reason)
            }
            Verdict::RequireApproval { reason, .. } => {
                let deny_reason = format!("Requires approval: {}", reason);
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Deny {
                            reason: deny_reason.clone(),
                        },
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC approval request: {}", e);
                }
                make_proto_denial_response(proto_req, &deny_reason)
            }
            // Fail-closed: unknown Verdict variants produce Deny
            _ => make_proto_denial_response(proto_req, "Unknown verdict — fail-closed"),
        }
    }

    /// Handle a resource read: extract action, evaluate, forward or deny.
    async fn handle_resource_read(
        &self,
        proto_req: &JsonRpcRequest,
        json_req: &Value,
        session_id: &str,
        _id: &Value,
        uri: &str,
    ) -> JsonRpcResponse {
        let action = extractor::extract_resource_action(uri);
        let ctx = self.build_evaluation_context(session_id);

        let verdict = match self.state.engine.evaluate_action_with_context(
            &action,
            &self.state.policies,
            Some(&ctx),
        ) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(session_id = %session_id, "Resource policy evaluation error: {}", e);
                Verdict::Deny {
                    reason: format!("Policy evaluation failed: {}", e),
                }
            }
        };

        match verdict {
            Verdict::Allow => self.forward_and_scan(proto_req, json_req, session_id).await,
            _ => {
                let reason = match &verdict {
                    Verdict::Deny { reason } => reason.clone(),
                    _ => "Resource access denied".to_string(),
                };
                make_proto_denial_response(proto_req, &reason)
            }
        }
    }

    /// Forward a request to upstream and scan the response for secrets/injection.
    async fn forward_and_scan(
        &self,
        proto_req: &JsonRpcRequest,
        json_req: &Value,
        session_id: &str,
    ) -> JsonRpcResponse {
        // Forward
        let response_json = match self.upstream.forward_json(json_req).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!(session_id = %session_id, "Upstream forwarding error: {}", e);
                return make_proto_error_response(proto_req, -32603, "Upstream error");
            }
        };

        // SECURITY (FIND-R55-GRPC-002): Track whether DLP or injection findings
        // were detected, to skip memory_tracker recording for tainted responses.
        // Parity with HTTP handler (inspection.rs:638-641).
        let mut dlp_found = false;
        let mut injection_found = false;

        // DLP scan response
        if self.state.response_dlp_enabled {
            let dlp_findings = scan_response_for_secrets(&response_json);
            if !dlp_findings.is_empty() {
                dlp_found = true;
                for finding in &dlp_findings {
                    record_dlp_finding(&finding.pattern_name);
                }

                let patterns: Vec<String> = dlp_findings
                    .iter()
                    .map(|f| format!("{}:{}", f.pattern_name, f.location))
                    .collect();

                tracing::warn!(
                    "SECURITY: Secrets in gRPC response! Session: {}, Findings: {:?}",
                    session_id,
                    patterns,
                );

                let verdict = if self.state.response_dlp_blocking {
                    Verdict::Deny {
                        reason: format!("gRPC response DLP blocked: {:?}", patterns),
                    }
                } else {
                    Verdict::Allow
                };

                let action = Action::new(
                    "vellaveto",
                    "grpc_response_dlp_scan",
                    json!({
                        "findings": patterns,
                        "session": session_id,
                        "transport": "grpc",
                    }),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "grpc_proxy",
                            "event": "grpc_response_dlp_alert",
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC DLP: {}", e);
                }

                if self.state.response_dlp_blocking {
                    return make_proto_error_response(
                        proto_req,
                        -32001,
                        "Response blocked by DLP policy",
                    );
                }
            }
        }

        // Injection scan response
        if !self.state.injection_disabled {
            let text_to_scan = extract_scannable_text(&response_json);
            if !text_to_scan.is_empty() {
                let injection_matches: Vec<String> =
                    if let Some(ref scanner) = self.state.injection_scanner {
                        scanner
                            .inspect(&text_to_scan)
                            .into_iter()
                            .map(|s| s.to_string())
                            .collect()
                    } else {
                        inspect_for_injection(&text_to_scan)
                            .into_iter()
                            .map(|s| s.to_string())
                            .collect()
                    };

                if !injection_matches.is_empty() {
                    injection_found = true;
                    tracing::warn!(
                        "SECURITY: Injection in gRPC response! Session: {}, Patterns: {:?}",
                        session_id,
                        injection_matches,
                    );

                    let verdict = if self.state.injection_blocking {
                        Verdict::Deny {
                            reason: format!(
                                "gRPC response injection blocked: {:?}",
                                injection_matches
                            ),
                        }
                    } else {
                        Verdict::Allow
                    };

                    let action = Action::new(
                        "vellaveto",
                        "grpc_response_injection",
                        json!({
                            "matched_patterns": injection_matches,
                            "session": session_id,
                            "transport": "grpc",
                        }),
                    );
                    if let Err(e) = self
                        .state
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({
                                "source": "grpc_proxy",
                                "event": "grpc_injection_detected",
                            }),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit gRPC injection: {}", e);
                    }

                    if self.state.injection_blocking {
                        return make_proto_error_response(
                            proto_req,
                            -32001,
                            "Response blocked: injection detected",
                        );
                    }
                }
            }
        }

        // SECURITY (FIND-R55-GRPC-002): Record response for memory poisoning tracking.
        // Parity with HTTP handler (inspection.rs:638-641) and WS handler (relay.rs:2398).
        // Skip recording when injection or DLP findings were detected (even in log-only
        // mode) to avoid poisoning the tracker with known-malicious data.
        if !injection_found && !dlp_found {
            if let Some(mut session) = self.state.sessions.get_mut(session_id) {
                session.memory_tracker.record_response(&response_json);
            }
        }

        // SECURITY (FIND-R53-GRPC-004): Output schema validation.
        // Parity with WS handler (websocket/mod.rs:2327-2370).
        if let Some(method) = json_req.get("method").and_then(|m| m.as_str()) {
            if method == "tools/call" {
                let tool_name = json_req
                    .get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                if !tool_name.is_empty() {
                    match self
                        .state
                        .output_schema_registry
                        .validate(tool_name, &response_json)
                    {
                        ValidationResult::Invalid { violations } => {
                            tracing::warn!(
                                "SECURITY: gRPC output schema violation for tool '{}': {:?}",
                                tool_name,
                                violations,
                            );

                            let action = Action::new(
                                "vellaveto",
                                "output_schema_violation",
                                json!({
                                    "tool": tool_name,
                                    "violations": violations,
                                    "session": session_id,
                                    "transport": "grpc",
                                }),
                            );
                            if let Err(e) = self
                                .state
                                .audit
                                .log_entry(
                                    &action,
                                    &Verdict::Deny {
                                        reason: format!(
                                            "gRPC structuredContent validation failed: {:?}",
                                            violations
                                        ),
                                    },
                                    json!({
                                        "source": "grpc_proxy",
                                        "event": "output_schema_violation_grpc",
                                    }),
                                )
                                .await
                            {
                                tracing::warn!(
                                    "Failed to audit gRPC output schema violation: {}",
                                    e
                                );
                            }
                        }
                        ValidationResult::Valid => {
                            tracing::debug!(
                                "gRPC structuredContent validated for tool '{}'",
                                tool_name
                            );
                        }
                        ValidationResult::NoSchema => {}
                    }
                }
            }
        }

        // Convert response JSON to proto
        match json_to_proto_response(&response_json) {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("gRPC JSON→proto response conversion failed: {}", e);
                make_proto_error_response(proto_req, -32603, "Response conversion error")
            }
        }
    }

    /// Handle a task request: extract action, evaluate policy, audit, forward or deny.
    async fn handle_task_request(
        &self,
        proto_req: &JsonRpcRequest,
        json_req: &Value,
        session_id: &str,
        _id: &Value,
        task_method: &str,
        task_id: Option<&str>,
    ) -> JsonRpcResponse {
        let action = extractor::extract_task_action(task_method, task_id);
        let ctx = self.build_evaluation_context(session_id);

        let verdict = match self.state.engine.evaluate_action_with_context(
            &action,
            &self.state.policies,
            Some(&ctx),
        ) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(session_id = %session_id, "Task policy evaluation error: {}", e);
                Verdict::Deny {
                    reason: format!("Policy evaluation failed: {}", e),
                }
            }
        };

        match &verdict {
            Verdict::Allow => {
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Allow,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "task_method": task_method,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC task allow: {}", e);
                }
                self.forward_and_scan(proto_req, json_req, session_id).await
            }
            Verdict::Deny { reason } => {
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "task_method": task_method,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC task deny: {}", e);
                }
                make_proto_denial_response(proto_req, reason)
            }
            Verdict::RequireApproval { reason, .. } => {
                let deny_reason = format!("Requires approval: {}", reason);
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Deny {
                            reason: deny_reason.clone(),
                        },
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "task_method": task_method,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC task approval request: {}", e);
                }
                make_proto_denial_response(proto_req, &deny_reason)
            }
            _ => make_proto_denial_response(proto_req, "Unknown verdict — fail-closed"),
        }
    }

    /// Handle an extension method: extract action, evaluate policy, audit, forward or deny.
    async fn handle_extension_method(
        &self,
        proto_req: &JsonRpcRequest,
        json_req: &Value,
        session_id: &str,
        _id: &Value,
        extension_id: &str,
        method: &str,
    ) -> JsonRpcResponse {
        let params = json_req.get("params").cloned().unwrap_or(json!({}));
        let action = extractor::extract_extension_action(extension_id, method, &params);
        let ctx = self.build_evaluation_context(session_id);

        let verdict = match self.state.engine.evaluate_action_with_context(
            &action,
            &self.state.policies,
            Some(&ctx),
        ) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(session_id = %session_id, "Extension policy evaluation error: {}", e);
                Verdict::Deny {
                    reason: format!("Policy evaluation failed: {}", e),
                }
            }
        };

        match &verdict {
            Verdict::Allow => {
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Allow,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "extension_id": extension_id,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC extension allow: {}", e);
                }
                self.forward_and_scan(proto_req, json_req, session_id).await
            }
            Verdict::Deny { reason } => {
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "extension_id": extension_id,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC extension deny: {}", e);
                }
                make_proto_denial_response(proto_req, reason)
            }
            _ => {
                let reason = match &verdict {
                    Verdict::RequireApproval { reason, .. } => {
                        format!("Requires approval: {}", reason)
                    }
                    _ => "Extension call denied — fail-closed".to_string(),
                };
                make_proto_denial_response(proto_req, &reason)
            }
        }
    }

    /// Build an EvaluationContext for policy evaluation.
    ///
    /// SECURITY (FIND-R54-002): Now includes `agent_identity` and `call_chain`
    /// from the session, matching the HTTP handler's `build_evaluation_context`
    /// (call_chain.rs:82). Without these, context-aware policies that check
    /// agent identity or call chain depth are ineffective on gRPC.
    fn build_evaluation_context(&self, session_id: &str) -> EvaluationContext {
        let mut ctx = EvaluationContext::default();

        if let Some(session) = self.state.sessions.get_mut(session_id) {
            ctx.call_counts = session.call_counts.clone();
            ctx.previous_actions = session.action_history.iter().cloned().collect();
            if let Some(ref agent_id) = session.oauth_subject {
                ctx.agent_id = Some(agent_id.clone());
            }
            ctx.agent_identity = session.agent_identity.clone();
            ctx.call_chain = session.current_call_chain.clone();
        }

        ctx
    }
}

/// SECURITY (FIND-R54-004): Recursively check a JSON value for control or
/// Unicode format characters in string values and object keys.
/// Bounded by depth to prevent stack overflow on deeply nested inputs.
fn json_contains_dangerous_chars(val: &Value, depth: usize) -> bool {
    if depth > 64 {
        return true; // fail-closed on excessive nesting
    }
    match val {
        Value::String(s) => contains_dangerous_chars(s),
        Value::Array(arr) => arr
            .iter()
            .any(|v| json_contains_dangerous_chars(v, depth + 1)),
        Value::Object(map) => {
            map.keys().any(|k| contains_dangerous_chars(k))
                || map
                    .values()
                    .any(|v| json_contains_dangerous_chars(v, depth + 1))
        }
        _ => false,
    }
}

/// Extract scannable text from a JSON-RPC response for injection scanning.
/// Same logic as the WebSocket transport's `extract_scannable_text`.
fn extract_scannable_text(json_val: &Value) -> String {
    let mut text_parts = Vec::new();

    if let Some(result) = json_val.get("result") {
        if let Some(content) = result.get("content").and_then(|c| c.as_array()) {
            for item in content {
                if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                    text_parts.push(text.to_string());
                }
            }
        }
        if let Some(instructions) = result.get("instructionsForUser").and_then(|i| i.as_str()) {
            text_parts.push(instructions.to_string());
        }
        if let Some(structured) = result.get("structuredContent") {
            text_parts.push(structured.to_string());
        }
    }

    if let Some(error) = json_val.get("error") {
        if let Some(msg) = error.get("message").and_then(|m| m.as_str()) {
            text_parts.push(msg.to_string());
        }
        if let Some(data) = error.get("data") {
            text_parts.push(data.to_string());
        }
    }

    text_parts.join("\n")
}

#[tonic::async_trait]
impl McpService for McpGrpcService {
    /// Unary call: one JSON-RPC request → one JSON-RPC response.
    async fn call(
        &self,
        request: Request<JsonRpcRequest>,
    ) -> Result<Response<JsonRpcResponse>, Status> {
        record_grpc_request();
        record_grpc_message("unary_request");

        let metadata = request.metadata().clone();
        let session_id = extract_session_id(&metadata)
            .unwrap_or_else(|| self.state.sessions.get_or_create(None));
        let _request_id = extract_or_generate_request_id(&metadata);

        // SECURITY (FIND-R54-GRPC-003): Per-request OAuth token expiry check.
        // Matches WS handler's per-message token expiry check (websocket/mod.rs:443).
        {
            let token_expired = self
                .state
                .sessions
                .get_mut(&session_id)
                .and_then(|s| {
                    s.token_expires_at.map(|exp| {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        now >= exp
                    })
                })
                .unwrap_or(false);
            if token_expired {
                tracing::warn!(
                    session_id = %session_id,
                    "SECURITY: OAuth token expired during gRPC session"
                );
                return Err(Status::unauthenticated("Token expired"));
            }
        }

        // SECURITY (FIND-R54-GRPC-005): Extract and validate agent identity.
        // Parity with HTTP handler's validate_agent_identity (auth.rs:345).
        if let Some(identity_token) = super::interceptors::extract_agent_identity_token(&metadata) {
            if let Some(ref oauth_validator) = self.state.oauth {
                match oauth_validator
                    .validate_token(&format!("Bearer {}", identity_token))
                    .await
                {
                    Ok(claims) => {
                        let identity = vellaveto_types::AgentIdentity {
                            issuer: if claims.iss.is_empty() {
                                None
                            } else {
                                Some(claims.iss.clone())
                            },
                            subject: if claims.sub.is_empty() {
                                None
                            } else {
                                Some(claims.sub.clone())
                            },
                            claims: Default::default(),
                        };
                        if let Some(mut session) = self.state.sessions.get_mut(&session_id) {
                            session.agent_identity = Some(identity);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("gRPC agent identity JWT validation failed: {}", e);
                        return Err(Status::unauthenticated("Invalid agent identity token"));
                    }
                }
            }
        }

        // SECURITY (FIND-R54-002): Sync call chain from metadata to session.
        // Parity with HTTP handler's sync_session_call_chain_from_headers.
        {
            let upstream_chain = super::interceptors::extract_call_chain_from_metadata(
                &metadata,
                &self.state.limits,
            );
            if let Some(mut session) = self.state.sessions.get_mut(&session_id) {
                session.current_call_chain = upstream_chain;
            }
        }

        let proto_req = request.into_inner();
        let response = self.evaluate_request(&proto_req, &session_id).await;

        record_grpc_message("unary_response");
        Ok(Response::new(response))
    }

    type StreamCallStream = ReceiverStream<Result<JsonRpcResponse, Status>>;

    /// Bidirectional streaming: per-message policy evaluation.
    async fn stream_call(
        &self,
        request: Request<Streaming<JsonRpcRequest>>,
    ) -> Result<Response<Self::StreamCallStream>, Status> {
        let metadata = request.metadata().clone();
        let session_id = extract_session_id(&metadata)
            .unwrap_or_else(|| self.state.sessions.get_or_create(None));

        // SECURITY (FIND-R54-GRPC-005): Extract agent identity at stream start.
        if let Some(identity_token) = super::interceptors::extract_agent_identity_token(&metadata) {
            if let Some(ref oauth_validator) = self.state.oauth {
                match oauth_validator
                    .validate_token(&format!("Bearer {}", identity_token))
                    .await
                {
                    Ok(claims) => {
                        let identity = vellaveto_types::AgentIdentity {
                            issuer: if claims.iss.is_empty() {
                                None
                            } else {
                                Some(claims.iss.clone())
                            },
                            subject: if claims.sub.is_empty() {
                                None
                            } else {
                                Some(claims.sub.clone())
                            },
                            claims: Default::default(),
                        };
                        if let Some(mut session) = self.state.sessions.get_mut(&session_id) {
                            session.agent_identity = Some(identity);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("gRPC stream agent identity JWT validation failed: {}", e);
                        return Err(Status::unauthenticated("Invalid agent identity token"));
                    }
                }
            }
        }

        // SECURITY (FIND-R54-002): Sync call chain from metadata at stream start.
        {
            let upstream_chain = super::interceptors::extract_call_chain_from_metadata(
                &metadata,
                &self.state.limits,
            );
            if let Some(mut session) = self.state.sessions.get_mut(&session_id) {
                session.current_call_chain = upstream_chain;
            }
        }

        let mut stream = request.into_inner();
        let (tx, rx) = mpsc::channel(32);

        let state = self.state.clone();
        let upstream = self.upstream.clone();
        let stream_rate_limit = self.stream_message_rate_limit;

        tokio::spawn(async move {
            let svc = McpGrpcService {
                state,
                upstream,
                stream_message_rate_limit: stream_rate_limit,
            };

            // SECURITY (FIND-R55-GRPC-010): Per-message rate limiting for streaming RPCs.
            // Uses a counter-per-second window matching the WS handler's check_rate_limit
            // (websocket/mod.rs:2507). SeqCst ordering for security-critical counter.
            let rate_counter = AtomicU64::new(0);
            let rate_window_start = std::sync::Mutex::new(std::time::Instant::now());

            while let Ok(Some(proto_req)) = stream.message().await {
                record_grpc_message("stream_request");

                // SECURITY (FIND-R55-GRPC-010): Check per-message rate limit.
                if stream_rate_limit > 0 {
                    let now = std::time::Instant::now();
                    let mut start = rate_window_start.lock().unwrap_or_else(|e| e.into_inner());
                    let within_limit =
                        if now.duration_since(*start) >= std::time::Duration::from_secs(1) {
                            *start = now;
                            rate_counter.store(1, Ordering::SeqCst);
                            true
                        } else {
                            let count = rate_counter
                                .fetch_add(1, Ordering::SeqCst)
                                .saturating_add(1);
                            count <= stream_rate_limit as u64
                        };
                    if !within_limit {
                        tracing::warn!(
                            session_id = %session_id,
                            limit = stream_rate_limit,
                            "SECURITY: gRPC stream rate limit exceeded, closing stream"
                        );
                        let _ = tx
                            .send(Err(Status::resource_exhausted(
                                "Stream rate limit exceeded",
                            )))
                            .await;
                        break;
                    }
                }

                // SECURITY (FIND-R54-GRPC-003): Per-message OAuth token expiry check.
                {
                    let token_expired = svc
                        .state
                        .sessions
                        .get_mut(&session_id)
                        .and_then(|s| {
                            s.token_expires_at.map(|exp| {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                now >= exp
                            })
                        })
                        .unwrap_or(false);
                    if token_expired {
                        tracing::warn!(
                            session_id = %session_id,
                            "SECURITY: OAuth token expired during gRPC stream"
                        );
                        let _ = tx.send(Err(Status::unauthenticated("Token expired"))).await;
                        break;
                    }
                }

                let response = svc.evaluate_request(&proto_req, &session_id).await;
                record_grpc_message("stream_response");

                if tx.send(Ok(response)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type SubscribeStream = ReceiverStream<Result<JsonRpcNotification, Status>>;

    /// Server-streaming: subscribe to notifications from upstream.
    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let metadata = request.metadata().clone();
        let session_id = extract_session_id(&metadata)
            .unwrap_or_else(|| self.state.sessions.get_or_create(None));
        let subscribe_req = request.into_inner();

        let (tx, rx) = mpsc::channel(32);

        let _state = self.state.clone();

        // Forward subscription to upstream via HTTP as a long-lived request
        // For now, if upstream doesn't support gRPC streaming, we return an empty stream.
        // When upstream_grpc_url is configured, we could relay notifications from the upstream
        // gRPC server. This is a placeholder for future upstream gRPC streaming support.
        tokio::spawn(async move {
            tracing::info!(
                session_id = %session_id,
                methods = ?subscribe_req.methods,
                "gRPC notification subscription opened"
            );

            // Keep the stream open until the client disconnects
            // In a full implementation, this would relay from upstream notifications
            let _ = tx.closed().await;

            tracing::info!(
                session_id = %session_id,
                "gRPC notification subscription closed"
            );
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
