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
use super::interceptors::{extract_or_generate_request_id, extract_session_id};
use super::proto::{
    mcp_service_server::McpService, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse,
    SubscribeRequest,
};
use super::upstream::UpstreamForwarder;
use super::ProxyState;
use crate::proxy_metrics::record_dlp_finding;

/// Global gRPC metrics counters.
static GRPC_REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static GRPC_MESSAGES_TOTAL: AtomicU64 = AtomicU64::new(0);

fn record_grpc_request() {
    GRPC_REQUESTS_TOTAL.fetch_add(1, Ordering::Relaxed);
    metrics::counter!("vellaveto_grpc_requests_total").increment(1);
}

fn record_grpc_message(direction: &str) {
    GRPC_MESSAGES_TOTAL.fetch_add(1, Ordering::Relaxed);
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
}

impl McpGrpcService {
    pub fn new(state: Arc<ProxyState>) -> Self {
        let upstream = UpstreamForwarder::new(state.clone());
        Self { state, upstream }
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
            MessageType::ElicitationRequest { .. } | MessageType::ProgressNotification { .. } => {
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
                    }
                }

                // Touch session
                if let Some(mut session) = self.state.sessions.get_mut(session_id) {
                    session.touch();
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

        // DLP scan response
        if self.state.response_dlp_enabled {
            let dlp_findings = scan_response_for_secrets(&response_json);
            if !dlp_findings.is_empty() {
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
    fn build_evaluation_context(&self, session_id: &str) -> EvaluationContext {
        let mut ctx = EvaluationContext::default();

        if let Some(session) = self.state.sessions.get_mut(session_id) {
            ctx.call_counts = session.call_counts.clone();
            ctx.previous_actions = session.action_history.iter().cloned().collect();
            if let Some(ref agent_id) = session.oauth_subject {
                ctx.agent_id = Some(agent_id.clone());
            }
        }

        ctx
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

        let mut stream = request.into_inner();
        let (tx, rx) = mpsc::channel(32);

        let state = self.state.clone();
        let upstream = self.upstream.clone();

        tokio::spawn(async move {
            let svc = McpGrpcService { state, upstream };

            while let Ok(Some(proto_req)) = stream.message().await {
                record_grpc_message("stream_request");

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
