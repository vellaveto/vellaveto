//! HTTP handler functions: handle_mcp_post, handle_mcp_delete,
//! and handle_protected_resource_metadata.

use axum::{
    extract::{OriginalUri, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use bytes::Bytes;
use serde_json::{json, Value};
use vellaveto_mcp::extractor::{self, make_denial_response, MessageType};
use vellaveto_mcp::inspection::{
    inspect_for_injection, scan_notification_for_secrets, scan_parameters_for_secrets,
    scan_response_for_secrets,
};
use vellaveto_types::{is_unicode_format_char, Action, EvaluationContext, Verdict};

use super::auth::{
    build_effective_request_uri, validate_agent_identity, validate_api_key, validate_oauth,
};
use super::call_chain::{
    build_audit_context, build_audit_context_with_chain, build_current_agent_entry,
    build_evaluation_context, check_privilege_escalation, sync_session_call_chain_from_headers,
    track_pending_tool_call, validate_call_chain_header, MAX_ACTION_HISTORY, MAX_CALL_COUNT_TOOLS,
};
use super::helpers::resolve_domains;
use super::inspection::{attach_session_header, attach_trace_header};
use super::origin::validate_origin;
use super::trace_propagation;
use super::upstream::{
    canonicalize_body, forward_to_upstream, forward_to_upstream_url, make_jsonrpc_error,
};
use super::{
    McpQueryParams, ProxyState, TrustedProxyContext, MCP_PROTOCOL_VERSION_HEADER, MCP_SESSION_ID,
    SUPPORTED_PROTOCOL_VERSIONS,
};
use crate::proxy_metrics::record_dlp_finding;

// NOTE: MAX_RESPONSE_BODY_SIZE and MAX_SSE_EVENT_SIZE are now configurable
// via state.limits.max_response_body_bytes and state.limits.max_sse_event_bytes.
// See vellaveto_config::LimitsConfig for documentation and defaults.

/// FIND-R56-HTTP-007: Maximum length for MCP session IDs.
/// Server-generated IDs are UUIDs (36 chars); anything over 128 is suspicious.
const MAX_SESSION_ID_LENGTH: usize = 128;

/// Main POST /mcp handler.
///
/// Implements the Streamable HTTP transport:
/// 1. Validate OAuth token (if configured)
/// 2. Parse JSON-RPC body
/// 3. Manage session via Mcp-Session-Id header
/// 4. Classify and evaluate the message
/// 5. Forward allowed requests to upstream, return denials directly
pub async fn handle_mcp_post(
    State(state): State<ProxyState>,
    OriginalUri(original_uri): OriginalUri,
    Query(params): Query<McpQueryParams>,
    proxy_ctx: Option<Extension<TrustedProxyContext>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // SECURITY (R8-HTTP-2): Validate Content-Type is application/json.
    // The MCP Streamable HTTP spec requires JSON content. Rejecting other
    // content types prevents bypass of WAF rules and request smuggling.
    if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
        if !ct.starts_with("application/json") {
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32700,
                        "message": "Content-Type must be application/json"
                    }
                })),
            )
                .into_response();
        }
    }
    // If Content-Type is absent, allow it for backwards compatibility with
    // clients that don't set headers (POST body is still parsed as JSON).

    // MCP 2025-11-25: Validate MCP-Protocol-Version header on inbound request.
    // Missing header is allowed for backwards compatibility (logged at debug level).
    // Unrecognized versions are rejected with 400 Bad Request (fail-closed).
    if let Some(version_hdr) = headers.get(MCP_PROTOCOL_VERSION_HEADER) {
        match version_hdr.to_str() {
            Ok(version) if SUPPORTED_PROTOCOL_VERSIONS.contains(&version) => {
                // Valid version, continue processing
            }
            Ok(version) => {
                tracing::warn!(
                    "Unsupported MCP protocol version: '{}', supported: {:?}",
                    version,
                    SUPPORTED_PROTOCOL_VERSIONS
                );
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32600,
                            "message": format!(
                                "Unsupported MCP protocol version. Supported versions: {}",
                                SUPPORTED_PROTOCOL_VERSIONS.join(", ")
                            )
                        },
                        "id": null
                    })),
                )
                    .into_response();
            }
            Err(_) => {
                tracing::warn!("Invalid UTF-8 in {} header", MCP_PROTOCOL_VERSION_HEADER);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32600,
                            "message": "Invalid MCP-Protocol-Version header encoding"
                        },
                        "id": null
                    })),
                )
                    .into_response();
            }
        }
    } else {
        tracing::debug!(
            "Inbound request missing {} header",
            MCP_PROTOCOL_VERSION_HEADER
        );
    }

    // CSRF / DNS rebinding origin validation (TASK-015)
    if let Err(response) = validate_origin(&headers, &state.bind_addr, &state.allowed_origins) {
        return response;
    }

    // API key validation (if configured) — fast check before OAuth
    if let Err(response) = validate_api_key(&state, &headers) {
        return response;
    }

    // SECURITY (FIND-R73-SRV-011): Validate session ID length and reject control/format
    // characters before OAuth, matching the DELETE handler pattern.
    // SECURITY (FIND-R86-001): Also reject Unicode format characters (zero-width, bidi)
    // for parity with gRPC and WebSocket handlers.
    let client_session_id = headers
        .get(MCP_SESSION_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|id| {
            id.len() <= MAX_SESSION_ID_LENGTH
                && !id
                    .chars()
                    .any(|c| c.is_control() || is_unicode_format_char(c))
        });

    // If the header was present but filtered out, return 400.
    if headers.get(MCP_SESSION_ID).is_some() && client_session_id.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid session ID"}, "id": null})),
        )
            .into_response();
    }

    // OAuth 2.1 token validation (if configured)
    let from_trusted_proxy = proxy_ctx
        .map(|Extension(ctx)| ctx.from_trusted_proxy)
        .unwrap_or(false);
    let effective_uri =
        build_effective_request_uri(&headers, state.bind_addr, &original_uri, from_trusted_proxy);
    let oauth_claims =
        match validate_oauth(&state, &headers, "POST", &effective_uri, client_session_id).await {
            Ok(claims) => claims,
            Err(response) => return response,
        };

    // OWASP ASI07: Agent identity attestation via X-Agent-Identity JWT
    let agent_identity = match validate_agent_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };

    // SECURITY (R36-PROXY-2): Extract the authenticated principal for self-approval
    // prevention. Without this, approval_store.create() receives None as requested_by,
    // which bypasses the self-approval check.
    let requested_by = oauth_claims.as_ref().map(|c| c.sub.clone());

    // Phase 28: Extract W3C Trace Context from incoming request headers.
    // Creates a new trace context if none is present (fail-open for observability).
    let incoming_trace = trace_propagation::extract_trace_context(&headers);
    let (vellaveto_trace_ctx, _vellaveto_span_id) =
        trace_propagation::create_vellaveto_span(&incoming_trace);

    // Defense-in-depth: reject JSON with duplicate keys before parsing.
    // Prevents parser-disagreement attacks (CVE-2017-12635, CVE-2020-16250)
    // where the proxy evaluates one key value but upstream sees another.
    if let Ok(raw_str) = std::str::from_utf8(&body) {
        if let Some(dup_key) = vellaveto_mcp::framing::find_duplicate_json_key(raw_str) {
            tracing::warn!(
                "SECURITY: Rejected JSON-RPC message with duplicate key: \"{}\"",
                dup_key
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32700,
                        "message": "Parse error: duplicate JSON key detected"
                    },
                    "id": null
                })),
            )
                .into_response();
        }
    }

    // Parse the JSON-RPC body
    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!("JSON-RPC parse error: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32700,
                        "message": "Parse error: invalid JSON"
                    },
                    "id": null
                })),
            )
                .into_response();
        }
    };

    // Session management
    let session_id = state.sessions.get_or_create(client_session_id);

    // SECURITY (R15-OAUTH-2): Atomic session ownership check + bind.
    if let Some(ref claims) = oauth_claims {
        if let Some(mut session) = state.sessions.get_mut(&session_id) {
            match &session.oauth_subject {
                Some(owner) if owner != &claims.sub => {
                    tracing::warn!(
                        "SECURITY: Session fixation attempt blocked — session {} owned by '{}', request from '{}'",
                        session_id, owner, claims.sub
                    );
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "error": {"code": -32001, "message": "Session owned by another user"},
                            "id": null
                        })),
                    )
                        .into_response();
                }
                None => {
                    session.oauth_subject = Some(claims.sub.clone());
                    if claims.exp > 0 {
                        session.token_expires_at = Some(claims.exp);
                    }
                }
                _ => {
                    // SECURITY (R23-PROXY-6): Use the EARLIEST token expiry
                    // to prevent a long-lived token from extending a session
                    // that was originally bound to a short-lived token.
                    if claims.exp > 0 {
                        session.token_expires_at = Some(
                            session
                                .token_expires_at
                                .map_or(claims.exp, |existing| existing.min(claims.exp)),
                        );
                    }
                }
            }
        }
    }

    // SECURITY (FIND-R55-HTTP-002): Touch session to update last_activity timestamp
    // and increment request_count. Parity with GET handler (line 3015) and WS handler.
    if let Some(mut session) = state.sessions.get_mut(&session_id) {
        session.touch();
    }

    // OWASP ASI07: Store agent identity in session for context-aware evaluation
    if let Some(ref identity) = agent_identity {
        if let Some(mut session) = state.sessions.get_mut(&session_id) {
            session.agent_identity = Some(identity.clone());
        }
    }

    // Determine if we should pass through the Authorization header to upstream
    let auth_header_for_upstream = if state
        .oauth
        .as_ref()
        .is_some_and(|v| v.config().pass_through)
    {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    } else {
        None
    };

    // OWASP ASI08: Reject malformed X-Upstream-Agents headers for all requests.
    // Previously this validation only ran on a subset of message types
    // (tools/call, resources/read, tasks/*), allowing malformed headers to pass
    // through on other MCP methods.
    // SECURITY (FIND-R44-052): This pre-match check validates the call chain
    // header for ALL message types (ToolCall, ResourceRead, TaskRequest, etc.).
    // Per-arm validate_call_chain_header calls are therefore unnecessary and
    // have been removed to avoid dead code.
    if let Err(reason) = validate_call_chain_header(&headers, &state.limits) {
        let method = msg
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        let action = Action::new(
            "vellaveto",
            "invalid_call_chain_header",
            json!({
                "method": method,
                "reason": reason,
            }),
        );
        let verdict = Verdict::Deny {
            reason: format!("Invalid upstream call chain header: {}", reason),
        };
        if let Err(e) = state
            .audit
            .log_entry(
                &action,
                &verdict,
                build_audit_context(
                    &session_id,
                    json!({
                        "event": "invalid_call_chain_header",
                        "method": method,
                        "reason": reason,
                    }),
                    &oauth_claims,
                ),
            )
            .await
        {
            tracing::warn!("Failed to audit invalid call-chain header: {}", e);
        }

        // SECURITY (FIND-046): Generic message to client; detailed reason in server log.
        tracing::warn!(reason = %reason, "Call chain validation failed");
        let error_response = json!({
            "jsonrpc": "2.0",
            "id": msg.get("id").cloned().unwrap_or(Value::Null),
            "error": {
                "code": -32600,
                "message": "Invalid request"
            }
        });
        return attach_session_header(
            (StatusCode::OK, Json(error_response)).into_response(),
            &session_id,
        );
    }

    // Classify the message using shared extractor
    match extractor::classify_message(&msg) {
        MessageType::ToolCall {
            id,
            tool_name,
            arguments,
        } => {
            // MCP 2025-11-25: Strict tool name validation (Phase 30).
            // When enabled, reject tool names that don't conform to the spec format.
            if state.streamable_http.strict_tool_name_validation {
                if let Err(e) = vellaveto_types::validate_mcp_tool_name(&tool_name) {
                    tracing::warn!(
                        "SECURITY: Rejecting invalid tool name '{}': {}",
                        tool_name,
                        e
                    );
                    let error_response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32602,
                            "message": format!("Invalid tool name: {}", e),
                        }
                    });
                    return attach_session_header(
                        (StatusCode::OK, Json(error_response)).into_response(),
                        &session_id,
                    );
                }
            }

            // NOTE (FIND-R44-052): validate_call_chain_header is handled by the
            // pre-match check above (line ~289). No per-arm call needed here.

            // OWASP ASI08: Extract call chain from upstream agents header
            // The header contains the chain of agents that have processed this request
            // BEFORE reaching us. This is the "upstream" chain used for depth checking.
            let upstream_chain = sync_session_call_chain_from_headers(
                &state.sessions,
                &session_id,
                &headers,
                state.call_chain_hmac_key.as_ref(),
                &state.limits,
            );

            // Build the full call chain by appending this request's context.
            // This includes ourselves and is used for audit purposes.
            let current_agent_id = oauth_claims.as_ref().map(|c| c.sub.as_str());
            let mut full_call_chain = upstream_chain.clone();
            if !upstream_chain.is_empty() || current_agent_id.is_some() {
                // Only add to chain if this is a multi-hop scenario or we have agent identity
                full_call_chain.push(build_current_agent_entry(
                    current_agent_id,
                    &tool_name,
                    "execute",
                    state.call_chain_hmac_key.as_ref(),
                ));
            }

            // Check rug-pull flags — block calls to tools with changed annotations
            let is_flagged = state
                .sessions
                .get_mut(&session_id)
                .map(|s| s.flagged_tools.contains(&tool_name))
                .unwrap_or(false);

            if is_flagged {
                let action = extractor::extract_action(&tool_name, &arguments);
                let verdict = Verdict::Deny {
                    reason: format!(
                        "Tool '{}' blocked: annotations changed since initial tools/list (rug-pull detected)",
                        tool_name
                    ),
                };
                if let Err(e) = state
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        build_audit_context_with_chain(
                            &session_id,
                            json!({"tool": tool_name, "event": "rug_pull_tool_blocked"}),
                            &oauth_claims,
                            &full_call_chain,
                        ),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit rug-pull block: {}", e);
                }

                // SECURITY (FIND-R112-009): Generic client message — the tool name
                // is NOT included. Detailed tool name is in the audit verdict only.
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32001,
                        "message": "Denied: annotation change detected (rug-pull protection)",
                    }
                });
                return attach_session_header(
                    (StatusCode::OK, Json(error_response)).into_response(),
                    &session_id,
                );
            }

            // P2: DLP scan parameters for secret exfiltration
            // SECURITY (R8-HTTP-3): Block tool calls with detected secrets,
            // matching the behavior of task request DLP scanning. Previously
            // findings were only logged and the request was forwarded.
            let dlp_findings = scan_parameters_for_secrets(&arguments);
            if !dlp_findings.is_empty() {
                // IMPROVEMENT_PLAN 1.1: Record DLP metrics
                for finding in &dlp_findings {
                    record_dlp_finding(&finding.pattern_name);
                }
                let patterns: Vec<String> = dlp_findings
                    .iter()
                    .map(|f| format!("{} at {}", f.pattern_name, f.location))
                    .collect();
                // SECURITY (R37-PROXY-3): Keep detailed reason for audit, generic for client
                let audit_reason =
                    format!("DLP: secrets detected in tool parameters: {:?}", patterns);
                tracing::warn!(
                    "SECURITY: DLP blocking tool '{}' in session {}: {}",
                    tool_name,
                    session_id,
                    audit_reason
                );
                let dlp_action = extractor::extract_action(&tool_name, &arguments);
                if let Err(e) = state
                    .audit
                    .log_entry(
                        &dlp_action,
                        &Verdict::Deny {
                            reason: audit_reason.clone(),
                        },
                        build_audit_context(
                            &session_id,
                            json!({
                                "event": "dlp_secret_blocked",
                                "tool": tool_name,
                                "findings": patterns,
                            }),
                            &oauth_claims,
                        ),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit DLP finding: {}", e);
                }
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32001,
                        "message": "Request blocked: security policy violation",
                    }
                });
                return attach_session_header(
                    (StatusCode::OK, Json(error_response)).into_response(),
                    &session_id,
                );
            }

            // OWASP ASI06: Check for memory poisoning (replayed response data in params)
            // SECURITY (R26-PROXY-2): Block requests when poisoning is detected (was log-only).
            if let Some(session) = state.sessions.get_mut(&session_id) {
                let poisoning_matches = session.memory_tracker.check_parameters(&arguments);
                if !poisoning_matches.is_empty() {
                    for m in &poisoning_matches {
                        tracing::warn!(
                            "SECURITY: Memory poisoning detected in tool '{}' (session {}): \
                             param '{}' contains replayed data (fingerprint: {})",
                            tool_name,
                            session_id,
                            m.param_location,
                            m.fingerprint
                        );
                    }
                    let action = extractor::extract_action(&tool_name, &arguments);
                    let deny_reason = format!(
                        "Memory poisoning detected: {} replayed data fragment(s) in tool '{}'",
                        poisoning_matches.len(),
                        tool_name
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &action,
                            &Verdict::Deny {
                                reason: deny_reason.clone(),
                            },
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "memory_poisoning_detected",
                                    "matches": poisoning_matches.len(),
                                    "tool": tool_name,
                                }),
                                &oauth_claims,
                            ),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit memory poisoning: {}", e);
                    }
                    let error_response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Request blocked: security policy violation",
                        }
                    });
                    return attach_session_header(
                        (StatusCode::OK, Json(error_response)).into_response(),
                        &session_id,
                    );
                }
            }

            let mut action = extractor::extract_action(&tool_name, &arguments);

            // =========================================================
            // Phase 3.1: Circuit Breaker Check (OWASP ASI08)
            // =========================================================
            // Check if the circuit is open for this tool. If so, reject the
            // request immediately without forwarding to upstream.
            if let Some(ref circuit_breaker) = state.circuit_breaker {
                if let Err(reason) = circuit_breaker.can_proceed(&tool_name) {
                    tracing::warn!(
                        "SECURITY: Circuit breaker open for tool '{}' in session {}: {}",
                        tool_name,
                        session_id,
                        reason
                    );
                    let verdict = Verdict::Deny {
                        reason: format!("Circuit breaker open: {}", reason),
                    };
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({
                                "source": "http_proxy",
                                "session": &session_id,
                                "event": "circuit_breaker_rejected",
                                "tool": tool_name,
                            }),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit circuit breaker rejection: {}", e);
                    }
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Service temporarily unavailable — circuit breaker open",
                        }
                    });
                    return attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    );
                }
            }

            // Tool registry check: if enabled, unknown or untrusted tools
            // require approval before engine evaluation. This runs before the
            // shard lock to avoid holding it during async registry reads.
            if let Some(ref registry) = state.tool_registry {
                let trust = registry.check_trust_level(&tool_name).await;
                match trust {
                    vellaveto_mcp::tool_registry::TrustLevel::Unknown => {
                        registry.register_unknown(&tool_name).await;
                        // SECURITY (FIND-045): Generic message to client; detailed reason in audit log only.
                        let reason = "Approval required".to_string();
                        let verdict = Verdict::RequireApproval {
                            reason: reason.clone(),
                        };
                        if let Err(e) = state.audit.log_entry(
                            &action,
                            &verdict,
                            json!({"source": "http_proxy", "session": &session_id, "registry": "unknown_tool"}),
                        ).await {
                            tracing::error!("AUDIT FAILURE: {}", e);
                        }
                        // Create pending approval if store is configured
                        let approval_id = if let Some(ref store) = state.approval_store {
                            store
                                .create(action.clone(), reason.clone(), requested_by.clone())
                                .await
                                .ok()
                        } else {
                            None
                        };
                        let error_data = json!({"verdict": "require_approval", "reason": reason, "approval_id": approval_id});
                        let response = make_denial_response(&id, &error_data.to_string());
                        return attach_session_header(
                            (StatusCode::OK, Json(response)).into_response(),
                            &session_id,
                        );
                    }
                    vellaveto_mcp::tool_registry::TrustLevel::Untrusted { score } => {
                        // SECURITY (FIND-045): Don't leak trust scores to clients.
                        // Detailed reason (including score) goes to audit log only.
                        tracing::info!(tool = %tool_name, score = score, "Tool trust score below threshold");
                        let reason = "Approval required".to_string();
                        let verdict = Verdict::RequireApproval {
                            reason: reason.clone(),
                        };
                        if let Err(e) = state.audit.log_entry(
                            &action,
                            &verdict,
                            json!({"source": "http_proxy", "session": &session_id, "registry": "untrusted_tool"}),
                        ).await {
                            tracing::error!("AUDIT FAILURE: {}", e);
                        }
                        let approval_id = if let Some(ref store) = state.approval_store {
                            store
                                .create(action.clone(), reason.clone(), requested_by.clone())
                                .await
                                .ok()
                        } else {
                            None
                        };
                        let error_data = json!({"verdict": "require_approval", "reason": reason, "approval_id": approval_id});
                        let response = make_denial_response(&id, &error_data.to_string());
                        return attach_session_header(
                            (StatusCode::OK, Json(response)).into_response(),
                            &session_id,
                        );
                    }
                    vellaveto_mcp::tool_registry::TrustLevel::Trusted => {
                        // Trusted — proceed to engine evaluation
                    }
                }
            }

            // DNS rebinding protection: resolve target domains to IPs when any
            // policy has ip_rules configured.
            if state.engine.has_ip_rules() {
                resolve_domains(&mut action).await;
            }

            // SECURITY (R19-TOCTOU): Combine context read, evaluation, and session
            // update into a single block that holds the DashMap shard lock. Without
            // this, concurrent requests clone the same call_counts snapshot, all pass
            // max_calls evaluation, and all increment — bypassing rate limits.
            //
            // This is safe because engine evaluation is synchronous (no await) and
            // fast (<5ms). The shard lock is released when `session` drops.
            let eval_result = if let Some(mut session) = state.sessions.get_mut(&session_id) {
                let eval_ctx = EvaluationContext {
                    timestamp: None,
                    agent_id: session.oauth_subject.clone(),
                    agent_identity: session.agent_identity.clone(),
                    call_counts: session.call_counts.clone(),
                    previous_actions: session.action_history.iter().cloned().collect(),
                    call_chain: session.current_call_chain.clone(),
                    tenant_id: None,
                    verification_tier: None,
                    capability_token: None,
                    session_state: None,
                };

                let result = if params.trace && state.trace_enabled {
                    state
                        .engine
                        .evaluate_action_traced_with_context(&action, Some(&eval_ctx))
                        .map(|(v, t)| (v, Some(t)))
                } else {
                    state
                        .engine
                        .evaluate_action_with_context(&action, &state.policies, Some(&eval_ctx))
                        .map(|v| (v, None))
                };

                // Atomically update session while still holding the shard lock
                if let Ok((Verdict::Allow, _)) = &result {
                    // SECURITY (FIND-045): Cap call_counts to prevent unbounded HashMap growth.
                    if session.call_counts.len() < MAX_CALL_COUNT_TOOLS
                        || session.call_counts.contains_key(&tool_name)
                    {
                        // SECURITY (FIND-R108-003): Use saturating_add to prevent
                        // wrapping to zero which would bypass call-limit policies.
                        let count = session.call_counts.entry(tool_name.clone()).or_insert(0);
                        *count = count.saturating_add(1);
                    }
                    if session.action_history.len() >= MAX_ACTION_HISTORY {
                        session.action_history.pop_front();
                    }
                    session.action_history.push_back(tool_name.clone());
                }

                result
            } else {
                // No session found: evaluate without context
                if params.trace && state.trace_enabled {
                    state
                        .engine
                        .evaluate_action_traced_with_context(&action, None)
                        .map(|(v, t)| (v, Some(t)))
                } else {
                    state
                        .engine
                        .evaluate_action_with_context(&action, &state.policies, None)
                        .map(|v| (v, None))
                }
            };

            match eval_result {
                Ok((Verdict::Allow, trace)) => {
                    // OWASP ASI08: Check for privilege escalation before forwarding
                    let priv_check = check_privilege_escalation(
                        &state.engine,
                        &state.policies,
                        &action,
                        &full_call_chain,
                        current_agent_id,
                    );

                    if priv_check.escalation_detected {
                        // SECURITY (R33-PROXY-1): Internal deny reason contains policy details
                        // (upstream agent name + deny reason). Log the full details in the
                        // audit trail but return a generic message to the client.
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
                        let verdict = Verdict::Deny {
                            reason: internal_reason.clone(),
                        };

                        // Audit the privilege escalation with full details
                        if let Err(e) = state
                            .audit
                            .log_entry(
                                &action,
                                &verdict,
                                build_audit_context_with_chain(
                                    &session_id,
                                    json!({
                                        "tool": tool_name,
                                        "event": "privilege_escalation_blocked",
                                        "escalating_from_agent": priv_check.escalating_from_agent,
                                        "upstream_deny_reason": priv_check.upstream_deny_reason,
                                    }),
                                    &oauth_claims,
                                    &full_call_chain,
                                ),
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit privilege escalation: {}", e);
                        }

                        // Return generic message to client — no policy details leaked
                        let response = json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32001,
                                "message": "Denied by policy: privilege escalation detected"
                            }
                        });
                        return attach_session_header(
                            (StatusCode::OK, Json(response)).into_response(),
                            &session_id,
                        );
                    }

                    // Phase 21: ABAC refinement — only runs when ABAC engine is configured.
                    // If the PolicyEngine allowed the action, ABAC may still deny it
                    // based on principal/action/resource/condition constraints.
                    if let Some(ref abac) = state.abac_engine {
                        let abac_eval_ctx = build_evaluation_context(&state.sessions, &session_id)
                            .unwrap_or_default();
                        let principal_id = abac_eval_ctx.agent_id.as_deref().unwrap_or("anonymous");
                        let principal_type = abac_eval_ctx
                            .agent_identity
                            .as_ref()
                            .and_then(|id| id.claims.get("type"))
                            .and_then(|v: &serde_json::Value| v.as_str())
                            .unwrap_or("Agent");
                        let session_risk = state
                            .sessions
                            .get_mut(&session_id)
                            .and_then(|s| s.risk_score.clone());
                        let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                            eval_ctx: &abac_eval_ctx,
                            principal_type,
                            principal_id,
                            risk_score: session_risk.as_ref(),
                        };

                        match abac.evaluate(&action, &abac_ctx) {
                            vellaveto_engine::abac::AbacDecision::Deny { policy_id, reason } => {
                                let verdict = Verdict::Deny {
                                    reason: reason.clone(),
                                };
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &verdict,
                                        build_audit_context_with_chain(
                                            &session_id,
                                            serde_json::json!({
                                                "tool": tool_name,
                                                "event": "abac_deny",
                                                "abac_policy_id": policy_id,
                                            }),
                                            &oauth_claims,
                                            &full_call_chain,
                                        ),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit ABAC deny: {}", e);
                                }
                                let response = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": {
                                        "code": -32001,
                                        "message": "Denied by policy"
                                    }
                                });
                                return attach_session_header(
                                    (StatusCode::OK, Json(response)).into_response(),
                                    &session_id,
                                );
                            }
                            vellaveto_engine::abac::AbacDecision::Allow { policy_id } => {
                                // Record for least-agency tracking
                                if let Some(ref la) = state.least_agency {
                                    la.record_usage(
                                        principal_id,
                                        &session_id,
                                        &policy_id,
                                        &tool_name,
                                        &action.function,
                                    );
                                }
                            }
                            vellaveto_engine::abac::AbacDecision::NoMatch => {
                                // Fall through — existing Allow verdict stands
                            }
                            #[allow(unreachable_patterns)] // AbacDecision is #[non_exhaustive]
                            _ => {
                                // SECURITY (FIND-R74-002): Future variants — fail-closed (deny).
                                // Must return a deny response, not fall through to Allow path.
                                tracing::warn!("Unknown AbacDecision variant — fail-closed");
                                let response = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": {
                                        "code": -32001,
                                        "message": "Denied by policy"
                                    }
                                });
                                return attach_session_header(
                                    (StatusCode::OK, Json(response)).into_response(),
                                    &session_id,
                                );
                            }
                        }
                    }

                    // Record tool call in registry on Allow (for trust score tracking)
                    if let Some(ref registry) = state.tool_registry {
                        registry.record_call(&tool_name).await;
                    }

                    // Forward to upstream — canonicalize if configured (KL2 TOCTOU fix)
                    let forward_body = match canonicalize_body(&state, &msg, body) {
                        Some(b) => b,
                        None => {
                            return make_jsonrpc_error(
                                msg.get("id"),
                                -32603,
                                "Internal error: canonicalization failed",
                            )
                        }
                    };
                    // Track request->tool mapping so response validation can resolve
                    // tool context even when upstream omits result._meta.tool.
                    track_pending_tool_call(&state.sessions, &session_id, &id, &tool_name);

                    // Phase 20: Gateway routing — resolve backend URL before forwarding
                    let gateway_decision = if let Some(ref gw) = state.gateway {
                        match gw.route(&tool_name) {
                            Some(decision) => {
                                tracing::debug!(
                                    tool = %tool_name,
                                    backend = %decision.backend_id,
                                    "Gateway routed"
                                );
                                Some(decision)
                            }
                            None => {
                                // All backends unhealthy — fail-closed
                                let _ = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &Verdict::Deny {
                                            reason: "No healthy backend available".into(),
                                        },
                                        json!({"event": "gateway_no_backend", "tool": tool_name}),
                                    )
                                    .await;
                                return attach_session_header(
                                    make_jsonrpc_error(
                                        msg.get("id"),
                                        -32000,
                                        "Upstream unavailable",
                                    ),
                                    &session_id,
                                );
                            }
                        }
                    } else {
                        None
                    };

                    // Phase 29: Cross-transport smart fallback path.
                    // When enabled and transport_health is available, try
                    // each transport in priority order before giving up.
                    if state.transport_config.cross_transport_fallback {
                        if let Some(ref health_tracker) = state.transport_health {
                            let client_pref_header = headers
                                .get(super::MCP_TRANSPORT_PREFERENCE_HEADER)
                                .and_then(|v| v.to_str().ok())
                                .map(super::discovery::parse_transport_preference);
                            let priorities = super::discovery::resolve_transport_priority(
                                &tool_name,
                                client_pref_header.as_deref(),
                                &state.transport_config,
                            );

                            let targets = build_transport_targets(
                                &state,
                                gateway_decision.as_ref(),
                                &priorities,
                            );

                            if !targets.is_empty() {
                                let per_attempt = std::time::Duration::from_secs(
                                    state.transport_config.fallback_timeout_secs,
                                );
                                let total = per_attempt.saturating_mul(priorities.len() as u32);

                                let mut chain = super::smart_fallback::SmartFallbackChain::new(
                                    &state.http_client,
                                    health_tracker,
                                    per_attempt,
                                    total,
                                );
                                if state.transport_config.stdio_fallback_enabled {
                                    if let Some(ref cmd) = state.transport_config.stdio_command {
                                        chain = chain.with_stdio(cmd.clone());
                                    }
                                }

                                match chain
                                    .execute(&targets, forward_body.clone(), &headers)
                                    .await
                                {
                                    Ok(result) => {
                                        // SECURITY (FIND-R43-013): Block dangerous status codes from smart fallback upstream.
                                        // 3xx can enable SSRF via redirect, 1xx are informational (incomplete),
                                        // and 407 (Proxy Authentication Required) leaks proxy topology.
                                        let safe_status = if (300..400).contains(&result.status)
                                            || result.status < 200
                                            || result.status == 407
                                        {
                                            tracing::warn!(
                                                status = result.status,
                                                "smart fallback upstream returned suspicious status — mapping to 502"
                                            );
                                            502
                                        } else {
                                            result.status
                                        };

                                        // Record gateway health on success.
                                        if let Some(ref gw) = state.gateway {
                                            if let Some(ref decision) = gateway_decision {
                                                gw.record_success(&decision.backend_id);
                                            }
                                        }
                                        // Audit if fallback occurred (>1 attempt).
                                        if result.history.attempts.len() > 1 {
                                            let _ = state
                                                .audit
                                                .log_entry(
                                                    &action,
                                                    &Verdict::Allow,
                                                    json!({
                                                        "event": "cross_transport_fallback",
                                                        "tool": tool_name,
                                                        "transport_used": format!("{:?}", result.transport_used),
                                                        "attempts": result.history.attempts.len(),
                                                        "total_duration_ms": result.history.total_duration_ms,
                                                    }),
                                                )
                                                .await;
                                        }

                                        // SECURITY (FIND-R44-002): Run the same DLP and injection
                                        // inspection on smart-fallback responses that
                                        // forward_to_upstream_url applies. Without this, an
                                        // attacker who controls a fallback transport can exfiltrate
                                        // secrets or inject prompts undetected.
                                        let response_bytes = result.response;
                                        if let Ok(response_json) =
                                            serde_json::from_slice::<Value>(&response_bytes)
                                        {
                                            // DLP: scan for secrets
                                            if state.response_dlp_enabled {
                                                let dlp_findings =
                                                    scan_response_for_secrets(&response_json);
                                                if !dlp_findings.is_empty() {
                                                    for finding in &dlp_findings {
                                                        record_dlp_finding(&finding.pattern_name);
                                                    }
                                                    let patterns: Vec<String> = dlp_findings
                                                        .iter()
                                                        .map(|f| {
                                                            format!(
                                                                "{}:{}",
                                                                f.pattern_name, f.location
                                                            )
                                                        })
                                                        .collect();
                                                    tracing::warn!(
                                                        "SECURITY: Secrets detected in smart-fallback response! \
                                                         Session: {}, Findings: {:?}, Blocking: {}",
                                                        session_id,
                                                        patterns,
                                                        state.response_dlp_blocking,
                                                    );
                                                    if state.response_dlp_blocking {
                                                        let verdict = Verdict::Deny {
                                                            reason: format!(
                                                                "Smart-fallback response DLP blocked: {:?}",
                                                                patterns
                                                            ),
                                                        };
                                                        let _ = state
                                                            .audit
                                                            .log_entry(
                                                                &action,
                                                                &verdict,
                                                                json!({
                                                                    "source": "http_proxy",
                                                                    "event": "smart_fallback_dlp_blocked",
                                                                    "blocked": true,
                                                                    "findings": patterns,
                                                                }),
                                                            )
                                                            .await;
                                                        return attach_session_header(
                                                            StatusCode::BAD_GATEWAY.into_response(),
                                                            &session_id,
                                                        );
                                                    }
                                                }
                                            }

                                            // Injection: scan result text for prompt injection
                                            if !state.injection_disabled {
                                                if let Some(result_val) =
                                                    response_json.get("result")
                                                {
                                                    let text_to_inspect =
                                                        super::inspection::extract_text_from_result(
                                                            result_val,
                                                        );
                                                    if !text_to_inspect.is_empty() {
                                                        let matches: Vec<String> =
                                                            if let Some(ref scanner) =
                                                                state.injection_scanner
                                                            {
                                                                scanner
                                                                    .inspect(&text_to_inspect)
                                                                    .into_iter()
                                                                    .map(|s| s.to_string())
                                                                    .collect()
                                                            } else {
                                                                inspect_for_injection(
                                                                    &text_to_inspect,
                                                                )
                                                                .into_iter()
                                                                .map(|s| s.to_string())
                                                                .collect()
                                                            };
                                                        if !matches.is_empty() {
                                                            tracing::warn!(
                                                                "SECURITY: Prompt injection in smart-fallback response! \
                                                                 Session: {}, Patterns: {:?}",
                                                                session_id,
                                                                matches,
                                                            );
                                                            if state.injection_blocking {
                                                                let verdict = Verdict::Deny {
                                                                    reason: format!(
                                                                        "Smart-fallback response injection blocked: {:?}",
                                                                        matches
                                                                    ),
                                                                };
                                                                let _ = state
                                                                    .audit
                                                                    .log_entry(
                                                                        &action,
                                                                        &verdict,
                                                                        json!({
                                                                            "source": "http_proxy",
                                                                            "event": "smart_fallback_injection_blocked",
                                                                            "patterns": matches,
                                                                        }),
                                                                    )
                                                                    .await;
                                                                return attach_session_header(
                                                                    StatusCode::BAD_GATEWAY
                                                                        .into_response(),
                                                                    &session_id,
                                                                );
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            // Non-JSON response from smart fallback — log warning
                                            // but still forward (some responses may be non-JSON).
                                            tracing::warn!(
                                                "Smart-fallback response is not valid JSON — \
                                                 DLP/injection scanning skipped (session: {})",
                                                session_id,
                                            );
                                        }

                                        let response = axum::response::Response::builder()
                                            .status(safe_status)
                                            .header("content-type", "application/json")
                                            .body(axum::body::Body::from(response_bytes))
                                            .unwrap_or_else(|_| {
                                                StatusCode::BAD_GATEWAY.into_response()
                                            });
                                        let response = attach_session_header(response, &session_id);
                                        return attach_trace_header(response, trace);
                                    }
                                    Err(e) => {
                                        // All transports failed — fail-closed.
                                        if let Some(ref gw) = state.gateway {
                                            if let Some(ref decision) = gateway_decision {
                                                gw.record_failure(&decision.backend_id);
                                            }
                                        }
                                        tracing::warn!(
                                            tool = %tool_name,
                                            "cross-transport fallback failed: {}",
                                            e,
                                        );
                                        let _ = state
                                            .audit
                                            .log_entry(
                                                &action,
                                                &Verdict::Deny {
                                                    reason: format!("all transports failed: {}", e),
                                                },
                                                json!({
                                                    "event": "cross_transport_fallback_failed",
                                                    "tool": tool_name,
                                                }),
                                            )
                                            .await;
                                        return attach_session_header(
                                            make_jsonrpc_error(
                                                msg.get("id"),
                                                -32000,
                                                "Upstream unavailable",
                                            ),
                                            &session_id,
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // Phase 28: Build upstream trace headers.
                    // For gateway mode, create a gateway child span so each
                    // backend gets its own traceparent with the gateway as parent.
                    let response = if let Some(ref decision) = gateway_decision {
                        let gw_child = vellaveto_trace_ctx.child();
                        let (gw_tp, gw_ts) =
                            trace_propagation::build_upstream_headers(&gw_child, "allow");
                        forward_to_upstream_url(
                            &state,
                            &decision.upstream_url,
                            &session_id,
                            forward_body,
                            auth_header_for_upstream.as_deref(),
                            Some((gw_tp.as_str(), gw_ts.as_deref())),
                            None,
                        )
                        .await
                    } else {
                        let (up_tp, up_ts) = trace_propagation::build_upstream_headers(
                            &vellaveto_trace_ctx,
                            "allow",
                        );
                        forward_to_upstream(
                            &state,
                            &session_id,
                            forward_body,
                            auth_header_for_upstream.as_deref(),
                            Some((up_tp.as_str(), up_ts.as_deref())),
                        )
                        .await
                    };

                    // Phase 20: Record backend health from response
                    if let Some(ref gw) = state.gateway {
                        if let Some(ref decision) = gateway_decision {
                            if response.status().is_server_error() {
                                gw.record_failure(&decision.backend_id);
                            } else {
                                gw.record_success(&decision.backend_id);
                            }
                        }
                    }

                    let response = attach_session_header(response, &session_id);
                    attach_trace_header(response, trace)
                }
                Ok((Verdict::Deny { ref reason }, trace)) => {
                    let reason = reason.clone();
                    let verdict = Verdict::Deny {
                        reason: reason.clone(),
                    };

                    // Audit the denial
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            build_audit_context_with_chain(
                                &session_id,
                                json!({"tool": tool_name}),
                                &oauth_claims,
                                &full_call_chain,
                            ),
                        )
                        .await
                    {
                        tracing::warn!("Audit log failed: {}", e);
                    }

                    let mut response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            // SECURITY (R39-PROXY-1): Generic message — detailed reason
                            // is in the audit log, not leaked to the client.
                            "message": "Denied by policy"
                        }
                    });
                    if let Some(t) = &trace {
                        response["trace"] = serde_json::to_value(t).unwrap_or(Value::Null);
                    }
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
                Ok((Verdict::RequireApproval { ref reason }, trace)) => {
                    let reason = reason.clone();
                    let verdict = Verdict::RequireApproval {
                        reason: reason.clone(),
                    };

                    // Create pending approval if store is configured
                    let approval_id = if let Some(ref store) = state.approval_store {
                        match store
                            .create(action.clone(), reason.clone(), requested_by.clone())
                            .await
                        {
                            Ok(id) => {
                                tracing::info!(
                                    "Created pending approval {} for tool '{}'",
                                    id,
                                    tool_name
                                );
                                Some(id)
                            }
                            Err(e) => {
                                // Fail-closed: log error but still return RequireApproval
                                tracing::error!("Failed to create approval (fail-closed): {}", e);
                                None
                            }
                        }
                    } else {
                        None
                    };

                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            build_audit_context_with_chain(
                                &session_id,
                                json!({"tool": tool_name}),
                                &oauth_claims,
                                &full_call_chain,
                            ),
                        )
                        .await
                    {
                        tracing::warn!("Audit log failed: {}", e);
                    }

                    let mut response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32002,
                            // SECURITY (R39-PROXY-1): Generic message — detailed reason
                            // is in the data field for the approval flow, not leaked.
                            "message": "Approval required",
                            "data": {
                                "type": "approval_required",
                                "reason": reason
                            }
                        }
                    });
                    if let Some(aid) = approval_id {
                        if let Some(data) =
                            response.get_mut("error").and_then(|e| e.get_mut("data"))
                        {
                            data["approval_id"] = Value::String(aid);
                        }
                    }
                    if let Some(t) = &trace {
                        response["trace"] = serde_json::to_value(t).unwrap_or(Value::Null);
                    }
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
                // Handle future Verdict variants - fail closed (deny)
                Ok((_, _trace)) => {
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Unknown verdict - failing closed"
                        }
                    });
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
                Err(e) => {
                    tracing::error!("Policy evaluation error for tool '{}': {}", tool_name, e);
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Policy evaluation failed"
                        }
                    });
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
            }
        }
        MessageType::ResourceRead { id, uri } => {
            // NOTE (FIND-R44-052): validate_call_chain_header is handled by the
            // pre-match check above (line ~289). No per-arm call needed here.

            // Keep per-request call-chain context in sync for resource policy checks.
            sync_session_call_chain_from_headers(
                &state.sessions,
                &session_id,
                &headers,
                state.call_chain_hmac_key.as_ref(),
                &state.limits,
            );

            // SECURITY (R27-PROXY-2): Check for memory poisoning in resource URI.
            // ResourceRead is a likely exfiltration vector: a poisoned tool response
            // says "read this file" and the agent issues resources/read for that URI.
            if let Some(session) = state.sessions.get_mut(&session_id) {
                let uri_params = serde_json::json!({"uri": uri});
                let poisoning_matches = session.memory_tracker.check_parameters(&uri_params);
                if !poisoning_matches.is_empty() {
                    for m in &poisoning_matches {
                        tracing::warn!(
                            "SECURITY: Memory poisoning detected in resources/read (session {}): \
                             param '{}' contains replayed data (fingerprint: {})",
                            session_id,
                            m.param_location,
                            m.fingerprint
                        );
                    }
                    let action = extractor::extract_resource_action(&uri);
                    let deny_reason = format!(
                        "Memory poisoning detected: {} replayed data fragment(s) in resources/read",
                        poisoning_matches.len()
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &action,
                            &Verdict::Deny {
                                reason: deny_reason.clone(),
                            },
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "memory_poisoning_detected",
                                    "matches": poisoning_matches.len(),
                                    "uri": uri,
                                }),
                                &oauth_claims,
                            ),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit memory poisoning: {}", e);
                    }
                    let error_response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Request blocked: security policy violation"
                        }
                    });
                    return attach_session_header(
                        (StatusCode::OK, Json(error_response)).into_response(),
                        &session_id,
                    );
                }
            }

            // SECURITY (FIND-R112-005): Rug-pull detection for resource URIs.
            // If the upstream server was flagged (annotations changed since initial tools/list),
            // block resource reads from that server. The URI itself is checked against the
            // flagged_tools set, which contains both tool names and server identifiers recorded
            // during rug-pull detection.
            let is_flagged = state
                .sessions
                .get_mut(&session_id)
                .map(|s| s.flagged_tools.contains(uri.as_str()))
                .unwrap_or(false);
            if is_flagged {
                let action = extractor::extract_resource_action(&uri);
                let verdict = Verdict::Deny {
                    reason: format!(
                        "Resource '{}' blocked: server flagged by rug-pull detection",
                        uri
                    ),
                };
                if let Err(e) = state
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        build_audit_context(
                            &session_id,
                            json!({
                                "event": "rug_pull_resource_blocked",
                                "uri": uri,
                            }),
                            &oauth_claims,
                        ),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit resource rug-pull block: {}", e);
                }
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32001,
                        "message": "Denied by policy",
                    }
                });
                return attach_session_header(
                    (StatusCode::OK, Json(error_response)).into_response(),
                    &session_id,
                );
            }

            // SECURITY (FIND-R112-001): DLP scan on resource URI.
            // ResourceRead is a known exfiltration vector; the URI may encode secrets
            // (e.g., file:///proc/self/environ, paths with embedded API keys). Mirror
            // the ToolCall DLP scanning pattern to catch secret leakage in the URI.
            {
                let uri_params = serde_json::json!({"uri": &uri});
                let dlp_findings = scan_parameters_for_secrets(&uri_params);
                if !dlp_findings.is_empty() {
                    for finding in &dlp_findings {
                        record_dlp_finding(&finding.pattern_name);
                    }
                    let patterns: Vec<String> = dlp_findings
                        .iter()
                        .map(|f| format!("{} at {}", f.pattern_name, f.location))
                        .collect();
                    let audit_reason =
                        format!("DLP: secrets detected in resource URI: {:?}", patterns);
                    tracing::warn!(
                        "SECURITY: DLP blocking resource read '{}' in session {}: {}",
                        uri,
                        session_id,
                        audit_reason
                    );
                    let dlp_action = extractor::extract_resource_action(&uri);
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &dlp_action,
                            &Verdict::Deny {
                                reason: audit_reason.clone(),
                            },
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "dlp_secret_blocked",
                                    "uri": uri,
                                    "findings": patterns,
                                }),
                                &oauth_claims,
                            ),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit resource DLP finding: {}", e);
                    }
                    let error_response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Request blocked: sensitive content detected",
                        }
                    });
                    return attach_session_header(
                        (StatusCode::OK, Json(error_response)).into_response(),
                        &session_id,
                    );
                }
            }

            let mut action = extractor::extract_resource_action(&uri);

            // DNS rebinding protection for resource reads
            if state.engine.has_ip_rules() {
                resolve_domains(&mut action).await;
            }

            // SECURITY (FIND-R112-004): Circuit breaker check for resource reads.
            // Mirror ToolCall circuit breaker pattern to prevent resource reads from
            // hammering a failing upstream server.
            if let Some(ref circuit_breaker) = state.circuit_breaker {
                if let Err(reason) = circuit_breaker.can_proceed(uri.as_str()) {
                    tracing::warn!(
                        "SECURITY: Circuit breaker open for resource '{}' in session {}: {}",
                        uri,
                        session_id,
                        reason
                    );
                    let verdict = Verdict::Deny {
                        reason: format!("Circuit breaker open: {}", reason),
                    };
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "circuit_breaker_rejected",
                                    "uri": uri,
                                }),
                                &oauth_claims,
                            ),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit resource circuit breaker rejection: {}", e);
                    }
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Service temporarily unavailable — circuit breaker open",
                        }
                    });
                    return attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    );
                }
            }

            // SECURITY (FIND-R112-002): Build evaluation context and run policy evaluation
            // inside a single `state.sessions.get_mut` block to eliminate the TOCTOU gap.
            // Without this, concurrent requests clone the same call_counts snapshot, all pass
            // max_calls evaluation, and all increment — bypassing rate limits.
            // Mirror the ToolCall TOCTOU fix (R19-TOCTOU).
            let eval_result = if let Some(mut session) = state.sessions.get_mut(&session_id) {
                let eval_ctx = EvaluationContext {
                    timestamp: None,
                    agent_id: session.oauth_subject.clone(),
                    agent_identity: session.agent_identity.clone(),
                    call_counts: session.call_counts.clone(),
                    previous_actions: session.action_history.iter().cloned().collect(),
                    call_chain: session.current_call_chain.clone(),
                    tenant_id: None,
                    verification_tier: None,
                    capability_token: None,
                    session_state: None,
                };

                let result = if params.trace && state.trace_enabled {
                    state
                        .engine
                        .evaluate_action_traced_with_context(&action, Some(&eval_ctx))
                        .map(|(v, t)| (v, Some(t)))
                } else {
                    state
                        .engine
                        .evaluate_action_with_context(&action, &state.policies, Some(&eval_ctx))
                        .map(|v| (v, None))
                };

                // Atomically update session while still holding the shard lock
                if let Ok((Verdict::Allow, _)) = &result {
                    let resource_key = format!(
                        "resources/read:{}",
                        uri.chars().take(128).collect::<String>()
                    );
                    if session.call_counts.len() < MAX_CALL_COUNT_TOOLS
                        || session.call_counts.contains_key(&resource_key)
                    {
                        let count = session.call_counts.entry(resource_key).or_insert(0);
                        *count = count.saturating_add(1);
                    }
                    if session.action_history.len() >= MAX_ACTION_HISTORY {
                        session.action_history.pop_front();
                    }
                    session.action_history.push_back("resources/read".to_string());
                }

                result
            } else {
                // No session found: evaluate without context
                if params.trace && state.trace_enabled {
                    state
                        .engine
                        .evaluate_action_traced_with_context(&action, None)
                        .map(|(v, t)| (v, Some(t)))
                } else {
                    state
                        .engine
                        .evaluate_action_with_context(&action, &state.policies, None)
                        .map(|v| (v, None))
                }
            };

            match eval_result {
                Ok((Verdict::Allow, trace)) => {
                    // SECURITY (FIND-R112-003): ABAC refinement for resource reads.
                    // Mirror ToolCall ABAC evaluation (R21-PROXY-2): if the PolicyEngine
                    // allowed the action, ABAC may still deny it based on principal/action/
                    // resource/condition constraints.
                    if let Some(ref abac) = state.abac_engine {
                        let abac_eval_ctx =
                            build_evaluation_context(&state.sessions, &session_id)
                                .unwrap_or_default();
                        let principal_id =
                            abac_eval_ctx.agent_id.as_deref().unwrap_or("anonymous");
                        let principal_type = abac_eval_ctx
                            .agent_identity
                            .as_ref()
                            .and_then(|id| id.claims.get("type"))
                            .and_then(|v: &serde_json::Value| v.as_str())
                            .unwrap_or("Agent");
                        let session_risk = state
                            .sessions
                            .get_mut(&session_id)
                            .and_then(|s| s.risk_score.clone());
                        let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                            eval_ctx: &abac_eval_ctx,
                            principal_type,
                            principal_id,
                            risk_score: session_risk.as_ref(),
                        };
                        match abac.evaluate(&action, &abac_ctx) {
                            vellaveto_engine::abac::AbacDecision::Deny { policy_id, reason } => {
                                let verdict = Verdict::Deny {
                                    reason: reason.clone(),
                                };
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &verdict,
                                        build_audit_context(
                                            &session_id,
                                            serde_json::json!({
                                                "uri": uri,
                                                "event": "abac_deny",
                                                "abac_policy_id": policy_id,
                                            }),
                                            &oauth_claims,
                                        ),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit resource ABAC deny: {}", e);
                                }
                                let response = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": {
                                        "code": -32001,
                                        "message": "Denied by policy"
                                    }
                                });
                                return attach_session_header(
                                    (StatusCode::OK, Json(response)).into_response(),
                                    &session_id,
                                );
                            }
                            vellaveto_engine::abac::AbacDecision::Allow { .. } => {
                                // ABAC allow — proceed to forward
                            }
                            vellaveto_engine::abac::AbacDecision::NoMatch => {
                                // Fall through — existing Allow verdict stands
                            }
                            #[allow(unreachable_patterns)]
                            _ => {
                                // SECURITY: Future variants — fail-closed (deny).
                                tracing::warn!(
                                    "Unknown AbacDecision variant in resource_read — fail-closed"
                                );
                                let response = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": {
                                        "code": -32001,
                                        "message": "Denied by policy"
                                    }
                                });
                                return attach_session_header(
                                    (StatusCode::OK, Json(response)).into_response(),
                                    &session_id,
                                );
                            }
                        }
                    }

                    // Canonicalize if configured (KL2 TOCTOU fix)
                    let forward_body = match canonicalize_body(&state, &msg, body) {
                        Some(b) => b,
                        None => {
                            return make_jsonrpc_error(
                                msg.get("id"),
                                -32603,
                                "Internal error: canonicalization failed",
                            )
                        }
                    };
                    let (up_tp, up_ts) =
                        trace_propagation::build_upstream_headers(&vellaveto_trace_ctx, "allow");
                    let response = forward_to_upstream(
                        &state,
                        &session_id,
                        forward_body,
                        auth_header_for_upstream.as_deref(),
                        Some((up_tp.as_str(), up_ts.as_deref())),
                    )
                    .await;
                    let response = attach_session_header(response, &session_id);
                    attach_trace_header(response, trace)
                }
                Ok((verdict, trace)) => {
                    let (code, reason) = match &verdict {
                        Verdict::Deny { reason } => (-32001, reason.clone()),
                        Verdict::RequireApproval { reason } => (-32002, reason.clone()),
                        Verdict::Allow => (-32001, "Unexpected Allow verdict".to_string()),
                        // Handle future variants - fail closed
                        _ => (-32001, "Unknown verdict - failing closed".to_string()),
                    };

                    // Create pending approval for RequireApproval verdicts
                    let approval_id = if matches!(&verdict, Verdict::RequireApproval { .. }) {
                        if let Some(ref store) = state.approval_store {
                            match store
                                .create(action.clone(), reason.clone(), requested_by.clone())
                                .await
                            {
                                Ok(aid) => {
                                    tracing::info!(
                                        "Created pending approval {} for resource '{}'",
                                        aid,
                                        uri
                                    );
                                    Some(aid)
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "Failed to create approval for resource: {}",
                                        e
                                    );
                                    None
                                }
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            build_audit_context(
                                &session_id,
                                json!({"resource_uri": uri}),
                                &oauth_claims,
                            ),
                        )
                        .await
                    {
                        tracing::warn!("Audit log failed: {}", e);
                    }

                    // SECURITY (R38-PROXY-4): Use generic message in client-facing
                    // response to avoid leaking policy names, blocked domains, CIDR
                    // ranges, etc. Detailed reason is preserved in the audit log above.
                    let generic_message = if code == -32002 {
                        "Approval required"
                    } else {
                        "Denied by policy"
                    };
                    let mut response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": code,
                            "message": generic_message,
                            "data": {
                                "type": if code == -32002 { "approval_required" } else { "denied" }
                            }
                        }
                    });
                    if let Some(aid) = approval_id {
                        if let Some(data) =
                            response.get_mut("error").and_then(|e| e.get_mut("data"))
                        {
                            data["approval_id"] = Value::String(aid);
                        }
                    }
                    if let Some(t) = &trace {
                        response["trace"] = serde_json::to_value(t).unwrap_or(Value::Null);
                    }
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
                Err(e) => {
                    tracing::error!("Policy evaluation error for resource '{}': {}", uri, e);
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Policy evaluation failed"
                        }
                    });
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
            }
        }
        MessageType::SamplingRequest { id } => {
            let params = msg.get("params").cloned().unwrap_or(json!({}));
            // SECURITY (FIND-R125-001): Per-session sampling rate limit parity with elicitation.
            // Atomically read + increment while holding the DashMap lock.
            let sampling_verdict = {
                let mut session_ref = state.sessions.get_mut(&session_id);
                let current_count = session_ref
                    .as_ref()
                    .map(|s| s.sampling_count)
                    .unwrap_or(0);
                let verdict = vellaveto_mcp::elicitation::inspect_sampling(
                    &params,
                    &state.sampling_config,
                    current_count,
                );
                if matches!(
                    verdict,
                    vellaveto_mcp::elicitation::SamplingVerdict::Allow
                ) {
                    if let Some(ref mut s) = session_ref {
                        s.sampling_count = s.sampling_count.saturating_add(1);
                    }
                }
                verdict
            };
            match sampling_verdict {
                vellaveto_mcp::elicitation::SamplingVerdict::Allow => {
                    // SECURITY (R21-PROXY-2): Use canonicalize_body() consistently
                    // (fail-closed). Previous inline fallback to body.clone() reopened
                    // the TOCTOU gap that canonicalization is designed to close.
                    let forward_body = match canonicalize_body(&state, &msg, body.clone()) {
                        Some(b) => b,
                        None => {
                            return make_jsonrpc_error(
                                msg.get("id"),
                                -32603,
                                "Internal error: canonicalization failed",
                            );
                        }
                    };
                    let (up_tp, up_ts) =
                        trace_propagation::build_upstream_headers(&vellaveto_trace_ctx, "allow");
                    let response = forward_to_upstream(
                        &state,
                        &session_id,
                        forward_body,
                        auth_header_for_upstream.as_deref(),
                        Some((up_tp.as_str(), up_ts.as_deref())),
                    )
                    .await;
                    attach_session_header(response, &session_id)
                }
                vellaveto_mcp::elicitation::SamplingVerdict::Deny { reason } => {
                    tracing::warn!(
                        "Blocked sampling/createMessage in session {}: {}",
                        session_id,
                        reason
                    );

                    let action = Action::new(
                        "vellaveto",
                        "sampling_interception",
                        json!({"method": "sampling/createMessage", "session": session_id, "reason": &reason}),
                    );
                    let verdict = Verdict::Deny {
                        reason: reason.clone(),
                    };
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({"source": "http_proxy", "event": "sampling_interception"}),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit sampling interception: {}", e);
                    }

                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            // SECURITY (R39-PROXY-3): Generic message — detailed reason
                            // is in the audit log, not leaked to the client.
                            "message": "sampling/createMessage blocked by policy"
                        }
                    });
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
            }
        }
        MessageType::PassThrough => {
            // Forward — includes initialize, tools/list, notifications, etc.
            // SECURITY: Audit pass-through requests for visibility. These bypass
            // policy evaluation but must have an audit trail.
            let method_name = msg
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            let action = Action::new(
                "vellaveto",
                "pass_through",
                json!({
                    "method": method_name,
                    "session": &session_id,
                }),
            );
            if let Err(e) = state
                .audit
                .log_entry(
                    &action,
                    &Verdict::Allow,
                    json!({"source": "http_proxy", "event": "pass_through_forwarded"}),
                )
                .await
            {
                tracing::warn!("Failed to audit pass-through request: {}", e);
            }

            // SECURITY (R18-NOTIF-DLP, R29-PROXY-3): Scan ALL PassThrough
            // params for secrets, not just notifications. An agent could
            // exfiltrate secrets via prompts/get, completion/complete, or any
            // PassThrough method's parameters.
            // SECURITY (FIND-R97-001): Remove method gate — JSON-RPC responses
            // (sampling/elicitation replies) have no `method` field but carry
            // data in `result`. Parity with stdio proxy FIND-R96-001.
            if state.response_dlp_enabled {
                let mut dlp_findings = scan_notification_for_secrets(&msg);
                // SECURITY (FIND-R97-001): Also scan `result` field for responses.
                if let Some(result_val) = msg.get("result") {
                    dlp_findings.extend(scan_parameters_for_secrets(result_val));
                }
                // SECURITY (FIND-R83-006): Cap combined findings from params+result
                // scans to maintain per-scan invariant (1000).
                dlp_findings.truncate(1000);
                if !dlp_findings.is_empty() {
                    // IMPROVEMENT_PLAN 1.1: Record DLP metrics
                    for finding in &dlp_findings {
                        record_dlp_finding(&finding.pattern_name);
                    }
                    let patterns: Vec<String> = dlp_findings
                        .iter()
                        .map(|f| format!("{}:{}", f.pattern_name, f.location))
                        .collect();
                    tracing::warn!(
                        "SECURITY: Secrets detected in notification params! \
                         Session: {}, Method: {}, Findings: {:?}",
                        session_id,
                        method_name,
                        patterns
                    );
                    let verdict = if state.response_dlp_blocking {
                        Verdict::Deny {
                            reason: format!(
                                "Notification blocked: secrets detected ({:?})",
                                patterns
                            ),
                        }
                    } else {
                        Verdict::Allow
                    };
                    let n_action = Action::new(
                        "vellaveto",
                        "notification_dlp_scan",
                        json!({
                            "findings": patterns,
                            "method": method_name,
                            "session": session_id,
                        }),
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &n_action,
                            &verdict,
                            json!({
                                "source": "http_proxy",
                                "event": "notification_dlp_alert",
                                "blocked": state.response_dlp_blocking,
                            }),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit notification DLP: {}", e);
                    }
                    if state.response_dlp_blocking {
                        return make_jsonrpc_error(
                            msg.get("id"),
                            -32002,
                            "Notification blocked: secrets detected in parameters",
                        );
                    }
                }
            }

            // SECURITY (FIND-R112-008): Injection scanning on PassThrough parameters.
            // Parity with WebSocket handler (websocket/mod.rs:600-677) which scans ALL
            // incoming messages. An agent could inject prompt injection payloads via
            // any PassThrough method's parameters (prompts/get, completion/complete, etc.).
            if !state.injection_disabled {
                let scannable = extract_passthrough_text_for_injection(&msg);
                if !scannable.is_empty() {
                    let injection_matches: Vec<String> =
                        if let Some(ref scanner) = state.injection_scanner {
                            scanner
                                .inspect(&scannable)
                                .into_iter()
                                .map(|s| s.to_string())
                                .collect()
                        } else {
                            inspect_for_injection(&scannable)
                                .into_iter()
                                .map(|s| s.to_string())
                                .collect()
                        };

                    if !injection_matches.is_empty() {
                        tracing::warn!(
                            "SECURITY: Injection in HTTP passthrough params! \
                             Session: {}, Method: {}, Patterns: {:?}",
                            session_id,
                            method_name,
                            injection_matches,
                        );

                        let verdict = if state.injection_blocking {
                            Verdict::Deny {
                                reason: format!(
                                    "PassThrough injection blocked: {:?}",
                                    injection_matches
                                ),
                            }
                        } else {
                            Verdict::Allow
                        };

                        let inj_action = Action::new(
                            "vellaveto",
                            "passthrough_injection_scan",
                            json!({
                                "matched_patterns": injection_matches,
                                "method": method_name,
                                "session": session_id,
                            }),
                        );
                        if let Err(e) = state
                            .audit
                            .log_entry(
                                &inj_action,
                                &verdict,
                                json!({
                                    "source": "http_proxy",
                                    "event": "passthrough_injection_detected",
                                    "blocking": state.injection_blocking,
                                }),
                            )
                            .await
                        {
                            tracing::warn!(
                                "Failed to audit passthrough injection: {}",
                                e
                            );
                        }

                        if state.injection_blocking {
                            return make_jsonrpc_error(
                                msg.get("id"),
                                -32001,
                                "Request blocked: security policy violation",
                            );
                        }
                    }
                }
            }

            // Canonicalize if configured (KL2 TOCTOU fix)
            let forward_body = match canonicalize_body(&state, &msg, body) {
                Some(b) => b,
                None => {
                    return make_jsonrpc_error(
                        msg.get("id"),
                        -32603,
                        "Internal error: canonicalization failed",
                    )
                }
            };
            let (up_tp, up_ts) =
                trace_propagation::build_upstream_headers(&vellaveto_trace_ctx, "allow");
            let response = forward_to_upstream(
                &state,
                &session_id,
                forward_body,
                auth_header_for_upstream.as_deref(),
                Some((up_tp.as_str(), up_ts.as_deref())),
            )
            .await;

            attach_session_header(response, &session_id)
        }
        MessageType::ElicitationRequest { id } => {
            // SECURITY (R38-PROXY-2): Pre-increment elicitation count while
            // holding the DashMap lock to prevent TOCTOU concurrent bypass.
            // Previous approach: read count → release lock → forward → increment
            // allowed concurrent requests to all read the same count and bypass.
            // New approach: read + increment atomically, then rollback on failure.
            let params = msg.get("params").cloned().unwrap_or(json!({}));
            let elicitation_verdict = {
                let mut session_ref = state.sessions.get_mut(&session_id);
                let current_count = session_ref
                    .as_ref()
                    .map(|s| s.elicitation_count)
                    .unwrap_or(0);
                let verdict = vellaveto_mcp::elicitation::inspect_elicitation(
                    &params,
                    &state.elicitation_config,
                    current_count,
                );
                // Pre-increment while holding the lock to close the TOCTOU gap
                if matches!(
                    verdict,
                    vellaveto_mcp::elicitation::ElicitationVerdict::Allow
                ) {
                    if let Some(ref mut s) = session_ref {
                        // SECURITY (FIND-R51-008): Use saturating_add for consistency.
                        s.elicitation_count = s.elicitation_count.saturating_add(1);
                    }
                }
                verdict
            };
            match elicitation_verdict {
                vellaveto_mcp::elicitation::ElicitationVerdict::Allow => {
                    // SECURITY (R21-PROXY-2): Use canonicalize_body() consistently
                    // (fail-closed). Previous inline fallback to body.clone() reopened
                    // the TOCTOU gap that canonicalization is designed to close.
                    let forward_body = match canonicalize_body(&state, &msg, body.clone()) {
                        Some(b) => b,
                        None => {
                            // Rollback the pre-incremented count on failure
                            if let Some(mut s) = state.sessions.get_mut(&session_id) {
                                s.elicitation_count = s.elicitation_count.saturating_sub(1);
                            }
                            return make_jsonrpc_error(
                                msg.get("id"),
                                -32603,
                                "Internal error: canonicalization failed",
                            );
                        }
                    };
                    let (up_tp, up_ts) =
                        trace_propagation::build_upstream_headers(&vellaveto_trace_ctx, "allow");
                    let response = forward_to_upstream(
                        &state,
                        &session_id,
                        forward_body,
                        auth_header_for_upstream.as_deref(),
                        Some((up_tp.as_str(), up_ts.as_deref())),
                    )
                    .await;

                    // SECURITY (R38-PROXY-2): Rollback the pre-incremented count
                    // if upstream rejects the request, so failed requests don't
                    // consume the elicitation budget.
                    if !response.status().is_success() {
                        if let Some(mut s) = state.sessions.get_mut(&session_id) {
                            s.elicitation_count = s.elicitation_count.saturating_sub(1);
                        }
                    }

                    attach_session_header(response, &session_id)
                }
                vellaveto_mcp::elicitation::ElicitationVerdict::Deny { reason } => {
                    tracing::warn!(
                        "Blocked elicitation/create in session {}: {}",
                        session_id,
                        reason
                    );

                    let action = Action::new(
                        "vellaveto",
                        "elicitation_interception",
                        json!({"method": "elicitation/create", "session": session_id, "reason": &reason}),
                    );
                    let verdict = Verdict::Deny {
                        reason: reason.clone(),
                    };
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({"source": "http_proxy", "event": "elicitation_interception"}),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit elicitation interception: {}", e);
                    }

                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            // SECURITY (R39-PROXY-3): Generic message — detailed reason
                            // is in the audit log, not leaked to the client.
                            "message": "elicitation/create blocked by policy"
                        }
                    });
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
            }
        }
        MessageType::TaskRequest {
            id,
            task_method,
            task_id,
        } => {
            // NOTE (FIND-R44-052): validate_call_chain_header is handled by the
            // pre-match check above (line ~289). No per-arm call needed here.

            // Keep per-request call-chain context in sync for task policy checks.
            sync_session_call_chain_from_headers(
                &state.sessions,
                &session_id,
                &headers,
                state.call_chain_hmac_key.as_ref(),
                &state.limits,
            );

            // R4-1 FIX: Evaluate task requests against policies.
            // Task responses (especially tasks/get) can contain tool results
            // with sensitive data. tasks/cancel can disrupt workflows.
            tracing::debug!(
                "Task request in session {}: {} (task_id: {:?})",
                session_id,
                task_method,
                task_id
            );

            // SECURITY (R27-PROXY-2): Check for memory poisoning in task params.
            let task_params_for_poison = msg.get("params").cloned().unwrap_or(json!({}));
            if let Some(session) = state.sessions.get_mut(&session_id) {
                let poisoning_matches = session
                    .memory_tracker
                    .check_parameters(&task_params_for_poison);
                if !poisoning_matches.is_empty() {
                    for m in &poisoning_matches {
                        tracing::warn!(
                            "SECURITY: Memory poisoning detected in task '{}' (session {}): \
                             param '{}' contains replayed data (fingerprint: {})",
                            task_method,
                            session_id,
                            m.param_location,
                            m.fingerprint
                        );
                    }
                    let action = extractor::extract_task_action(&task_method, task_id.as_deref());
                    let deny_reason = format!(
                        "Memory poisoning detected: {} replayed data fragment(s) in task '{}'",
                        poisoning_matches.len(),
                        task_method
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &action,
                            &Verdict::Deny {
                                reason: deny_reason.clone(),
                            },
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "memory_poisoning_detected",
                                    "matches": poisoning_matches.len(),
                                    "task_method": task_method,
                                }),
                                &oauth_claims,
                            ),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit memory poisoning: {}", e);
                    }
                    let error_response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Request blocked: security policy violation"
                        }
                    });
                    return attach_session_header(
                        (StatusCode::OK, Json(error_response)).into_response(),
                        &session_id,
                    );
                }
            }

            // R4-1: DLP scan task request parameters for secret exfiltration.
            // An agent could embed secrets in the task_id field to exfiltrate
            // them via task management operations.
            let task_params = msg.get("params").cloned().unwrap_or(json!({}));
            let dlp_findings = scan_parameters_for_secrets(&task_params);
            if !dlp_findings.is_empty() {
                // IMPROVEMENT_PLAN 1.1: Record DLP metrics
                for finding in &dlp_findings {
                    record_dlp_finding(&finding.pattern_name);
                }
                tracing::warn!(
                    "SECURITY: DLP alert for task '{}' in session {}: {:?}",
                    task_method,
                    session_id,
                    dlp_findings
                        .iter()
                        .map(|f| &f.pattern_name)
                        .collect::<Vec<_>>()
                );
                let dlp_action = extractor::extract_task_action(&task_method, task_id.as_deref());
                let patterns: Vec<String> = dlp_findings
                    .iter()
                    .map(|f| format!("{} at {}", f.pattern_name, f.location))
                    .collect();
                // SECURITY (R37-PROXY-3): Keep detailed reason for audit, generic for client
                let audit_reason = format!("DLP: secrets detected in task request: {:?}", patterns);
                if let Err(e) = state
                    .audit
                    .log_entry(
                        &dlp_action,
                        &Verdict::Deny {
                            reason: audit_reason.clone(),
                        },
                        build_audit_context(
                            &session_id,
                            json!({
                                "event": "dlp_secret_detected_task",
                                "task_method": task_method,
                                "findings": patterns,
                            }),
                            &oauth_claims,
                        ),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit DLP finding: {}", e);
                }
                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32001,
                        "message": "Request blocked: security policy violation",
                    }
                });
                return attach_session_header(
                    (StatusCode::OK, Json(response)).into_response(),
                    &session_id,
                );
            }

            let action = extractor::extract_task_action(&task_method, task_id.as_deref());

            let eval_ctx = build_evaluation_context(&state.sessions, &session_id);

            let eval_result = if params.trace && state.trace_enabled {
                state
                    .engine
                    .evaluate_action_traced_with_context(&action, eval_ctx.as_ref())
                    .map(|(v, t)| (v, Some(t)))
            } else {
                state
                    .engine
                    .evaluate_action_with_context(&action, &state.policies, eval_ctx.as_ref())
                    .map(|v| (v, None))
            };

            match eval_result {
                Ok((Verdict::Allow, trace)) => {
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &action,
                            &Verdict::Allow,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "task_request_forwarded",
                                    "task_method": task_method,
                                    "task_id": task_id,
                                }),
                                &oauth_claims,
                            ),
                        )
                        .await
                    {
                        tracing::warn!("Audit log failed: {}", e);
                    }

                    let forward_body = match canonicalize_body(&state, &msg, body) {
                        Some(b) => b,
                        None => {
                            return make_jsonrpc_error(
                                msg.get("id"),
                                -32603,
                                "Internal error: canonicalization failed",
                            )
                        }
                    };
                    let (up_tp, up_ts) =
                        trace_propagation::build_upstream_headers(&vellaveto_trace_ctx, "allow");
                    let response = forward_to_upstream(
                        &state,
                        &session_id,
                        forward_body,
                        auth_header_for_upstream.as_deref(),
                        Some((up_tp.as_str(), up_ts.as_deref())),
                    )
                    .await;
                    let response = attach_trace_header(response, trace);
                    attach_session_header(response, &session_id)
                }
                Ok((Verdict::Deny { reason }, trace)) => {
                    let verdict = Verdict::Deny {
                        reason: reason.clone(),
                    };
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "task_request_denied",
                                    "task_method": task_method,
                                    "task_id": task_id,
                                }),
                                &oauth_claims,
                            ),
                        )
                        .await
                    {
                        tracing::warn!("Audit log failed: {}", e);
                    }
                    // SECURITY (R38-PROXY-4): Use generic message in client-facing
                    // response to avoid leaking policy names, blocked domains, CIDR
                    // ranges, etc. Detailed reason is preserved in the audit log above.
                    let mut response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Denied by policy",
                            "data": {
                                "type": "policy_denial"
                            }
                        }
                    });
                    if let Some(t) = trace {
                        response["trace"] = serde_json::to_value(t).unwrap_or(Value::Null);
                    }
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
                Ok((Verdict::RequireApproval { reason }, trace)) => {
                    let verdict = Verdict::RequireApproval {
                        reason: reason.clone(),
                    };
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "task_request_requires_approval",
                                    "task_method": task_method,
                                    "task_id": task_id,
                                }),
                                &oauth_claims,
                            ),
                        )
                        .await
                    {
                        tracing::warn!("Audit log failed: {}", e);
                    }
                    // SECURITY (R38-PROXY-4): Use generic message in client-facing
                    // response. Detailed reason is preserved in the audit log above.
                    let mut response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32002,
                            "message": "Approval required",
                            "data": {
                                "type": "approval_required"
                            }
                        }
                    });
                    if let Some(t) = trace {
                        response["trace"] = serde_json::to_value(t).unwrap_or(Value::Null);
                    }
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
                // Handle future Verdict variants - fail closed (deny)
                Ok((_, _trace)) => {
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Unknown verdict - failing closed"
                        }
                    });
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
                Err(e) => {
                    // Fail-closed: evaluation error → deny
                    tracing::error!("Policy evaluation error for task '{}': {}", task_method, e);
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Policy evaluation failed"
                        }
                    });
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
            }
        }
        MessageType::Batch => {
            tracing::warn!("Rejected JSON-RPC batch request in session {}", session_id);
            // SECURITY: Audit batch rejection (R4-12).
            let batch_action = Action::new(
                "vellaveto",
                "batch_rejected",
                json!({
                    "session": &session_id,
                }),
            );
            if let Err(e) = state
                .audit
                .log_entry(
                    &batch_action,
                    &Verdict::Deny {
                        reason: "JSON-RPC batching not supported".to_string(),
                    },
                    json!({"source": "http_proxy", "event": "batch_rejected"}),
                )
                .await
            {
                tracing::warn!("Failed to audit batch rejection: {}", e);
            }
            // SECURITY (FIND-R92-001): Use BATCH_NOT_ALLOWED for parity with
            // make_batch_error_response() and correct semantic error code.
            let response = json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": vellaveto_types::json_rpc::BATCH_NOT_ALLOWED,
                    "message": "JSON-RPC batching is not supported (MCP 2025-06-18)"
                }
            });
            attach_session_header(
                (StatusCode::OK, Json(response)).into_response(),
                &session_id,
            )
        }
        MessageType::ProgressNotification { .. } => {
            // Progress notifications are upstream→client; if received from client, forward as-is
            let forward_body = match canonicalize_body(&state, &msg, body) {
                Some(b) => b,
                None => {
                    return make_jsonrpc_error(
                        msg.get("id"),
                        -32603,
                        "Internal error: canonicalization failed",
                    )
                }
            };
            let (up_tp, up_ts) =
                trace_propagation::build_upstream_headers(&vellaveto_trace_ctx, "allow");
            let response = forward_to_upstream(
                &state,
                &session_id,
                forward_body,
                auth_header_for_upstream.as_deref(),
                Some((up_tp.as_str(), up_ts.as_deref())),
            )
            .await;
            attach_session_header(response, &session_id)
        }
        MessageType::ExtensionMethod {
            ref id,
            ref extension_id,
            ref method,
        } => {
            // Policy-evaluate extension method calls
            let params = msg.get("params").cloned().unwrap_or(json!({}));

            // SECURITY (FIND-R116-001): DLP scan extension method parameters.
            // Parity with gRPC handle_extension_method (service.rs:1542).
            let dlp_findings = scan_parameters_for_secrets(&params);
            if !dlp_findings.is_empty() {
                for finding in &dlp_findings {
                    record_dlp_finding(&finding.pattern_name);
                }
                let patterns: Vec<String> = dlp_findings
                    .iter()
                    .map(|f| format!("{}:{}", f.pattern_name, f.location))
                    .collect();
                tracing::warn!(
                    "SECURITY: Secrets in HTTP extension method parameters! Session: {}, Extension: {}:{}, Findings: {:?}",
                    session_id, extension_id, method, patterns,
                );
                let action = extractor::extract_extension_action(extension_id, method, &params);
                let audit_verdict = Verdict::Deny {
                    reason: format!("DLP blocked: secret detected in extension parameters: {:?}", patterns),
                };
                if let Err(e) = state.audit.log_entry(
                    &action, &audit_verdict,
                    build_audit_context(&session_id, json!({
                        "event": "extension_parameter_dlp_alert",
                        "extension_id": extension_id, "method": method, "findings": patterns,
                    }), &oauth_claims),
                ).await {
                    tracing::warn!("Failed to audit extension parameter DLP: {}", e);
                }
                return make_jsonrpc_error(Some(id), -32001, "Denied by policy");
            }

            // SECURITY (FIND-R116-001): Memory poisoning detection for extension params.
            // Parity with gRPC handle_extension_method (service.rs:1574).
            if let Some(session) = state.sessions.get_mut(&session_id) {
                let poisoning_matches = session.memory_tracker.check_parameters(&params);
                if !poisoning_matches.is_empty() {
                    for m in &poisoning_matches {
                        tracing::warn!(
                            "SECURITY: Memory poisoning in HTTP extension '{}:{}' (session {}): \
                             param '{}' replayed data (fingerprint: {})",
                            extension_id, method, session_id, m.param_location, m.fingerprint
                        );
                    }
                    let action = extractor::extract_extension_action(extension_id, method, &params);
                    let deny_reason = format!(
                        "Memory poisoning detected: {} replayed data fragment(s) in extension '{}:{}'",
                        poisoning_matches.len(), extension_id, method
                    );
                    if let Err(e) = state.audit.log_entry(
                        &action,
                        &Verdict::Deny { reason: deny_reason.clone() },
                        build_audit_context(&session_id, json!({
                            "event": "memory_poisoning_detected",
                            "matches": poisoning_matches.len(),
                            "extension_id": extension_id, "method": method,
                        }), &oauth_claims),
                    ).await {
                        tracing::warn!("Failed to audit extension memory poisoning: {}", e);
                    }
                    return make_jsonrpc_error(Some(id), -32001, "Denied by policy");
                }
            }

            let action = extractor::extract_extension_action(extension_id, method, &params);
            let eval_ctx = build_evaluation_context(&state.sessions, &session_id);

            let verdict = match state.engine.evaluate_action_with_context(
                &action,
                &state.policies,
                eval_ctx.as_ref(),
            ) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(
                        session_id = %session_id,
                        "Extension policy evaluation error: {}", e
                    );
                    Verdict::Deny {
                        reason: format!("Policy evaluation failed: {}", e),
                    }
                }
            };

            match verdict {
                Verdict::Allow => {
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &action,
                            &Verdict::Allow,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "extension_method_allowed",
                                    "extension_id": extension_id,
                                    "method": method,
                                }),
                                &oauth_claims,
                            ),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit extension allow: {}", e);
                    }
                    let forward_body = match canonicalize_body(&state, &msg, body) {
                        Some(b) => b,
                        None => {
                            return make_jsonrpc_error(
                                msg.get("id"),
                                -32603,
                                "Internal error: canonicalization failed",
                            )
                        }
                    };
                    let (up_tp, up_ts) =
                        trace_propagation::build_upstream_headers(&vellaveto_trace_ctx, "allow");
                    let response = forward_to_upstream(
                        &state,
                        &session_id,
                        forward_body,
                        auth_header_for_upstream.as_deref(),
                        Some((up_tp.as_str(), up_ts.as_deref())),
                    )
                    .await;
                    attach_session_header(response, &session_id)
                }
                _ => {
                    let reason = match &verdict {
                        Verdict::Deny { reason } => reason.clone(),
                        Verdict::RequireApproval { reason, .. } => {
                            format!("Requires approval: {}", reason)
                        }
                        _ => "Extension call denied — fail-closed".to_string(),
                    };
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "extension_method_denied",
                                    "extension_id": extension_id,
                                    "method": method,
                                    "reason": &reason,
                                }),
                                &oauth_claims,
                            ),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit extension deny: {}", e);
                    }
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Denied by policy"
                        }
                    });
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
            }
        }
        MessageType::Invalid { id, reason } => {
            // SECURITY (FIND-R80-001): Log the detailed reason at warn level but do NOT
            // include attacker-controlled `reason` in the client response. This prevents
            // information leakage that could help attackers craft better payloads.
            tracing::warn!("Invalid JSON-RPC request: {}", reason);
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32600,
                    "message": "Invalid JSON-RPC request"
                }
            });
            attach_session_header(
                (StatusCode::OK, Json(response)).into_response(),
                &session_id,
            )
        }
    }
}

/// DELETE /mcp handler — session termination (MCP spec).
///
/// When OAuth is configured, verifies that the authenticated user owns the
/// session before allowing deletion. Prevents cross-user session termination.
pub async fn handle_mcp_delete(
    State(state): State<ProxyState>,
    OriginalUri(original_uri): OriginalUri,
    proxy_ctx: Option<Extension<TrustedProxyContext>>,
    headers: HeaderMap,
) -> Response {
    // CSRF / DNS rebinding origin validation (TASK-015)
    if let Err(response) = validate_origin(&headers, &state.bind_addr, &state.allowed_origins) {
        return response;
    }

    // API key validation (if configured) — fast check before OAuth
    if let Err(response) = validate_api_key(&state, &headers) {
        return response;
    }

    // SECURITY (FIND-R44-053): Reject oversized session IDs to prevent
    // memory abuse or hash-flooding attacks. Server-generated IDs are UUIDs
    // (36 chars); anything over MAX_SESSION_ID_LENGTH is suspicious.
    // SECURITY (FIND-R86-001): Also reject Unicode format characters for
    // parity with gRPC and WebSocket handlers.
    let session_id = headers
        .get(MCP_SESSION_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|id| {
            id.len() <= MAX_SESSION_ID_LENGTH
                && !id
                    .chars()
                    .any(|c| c.is_control() || is_unicode_format_char(c))
        });

    // If the header was present but filtered out due to length or control chars, return 400.
    if headers.get(MCP_SESSION_ID).is_some() && session_id.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid session ID"})),
        )
            .into_response();
    }

    // OAuth 2.1 token validation (if configured)
    let from_trusted_proxy = proxy_ctx
        .map(|Extension(ctx)| ctx.from_trusted_proxy)
        .unwrap_or(false);
    let effective_uri =
        build_effective_request_uri(&headers, state.bind_addr, &original_uri, from_trusted_proxy);
    let oauth_claims =
        match validate_oauth(&state, &headers, "DELETE", &effective_uri, session_id).await {
            Ok(claims) => claims,
            Err(response) => return response,
        };

    match session_id {
        Some(id) => {
            // Session ownership check: when OAuth is active, only the session
            // owner can delete their session. Prevents User A from terminating
            // User B's session by guessing the UUID.
            if let Some(ref claims) = oauth_claims {
                if let Some(session) = state.sessions.get_mut(id) {
                    if let Some(ref owner) = session.oauth_subject {
                        if owner != &claims.sub {
                            tracing::warn!(
                                "SECURITY: User '{}' attempted to delete session {} owned by '{}'",
                                claims.sub,
                                id,
                                owner
                            );
                            return (
                                StatusCode::FORBIDDEN,
                                Json(json!({"error": "Session owned by another user"})),
                            )
                                .into_response();
                        }
                    }
                    // Drop the session lock before removing
                    drop(session);
                }
            }

            if state.sessions.remove(id) {
                tracing::info!("Session terminated: {}", id);
                // SECURITY (FIND-R55-HTTP-004): Audit session termination for SOC 2 CC6.1.
                {
                    let audit_action = vellaveto_types::Action {
                        tool: "session".to_string(),
                        function: "terminate".to_string(),
                        parameters: serde_json::Value::Object(serde_json::Map::new()),
                        target_paths: Vec::new(),
                        target_domains: Vec::new(),
                        resolved_ips: Vec::new(),
                    };
                    if let Err(e) = state
                        .audit
                        .log_entry(
                            &audit_action,
                            &vellaveto_types::Verdict::Allow,
                            serde_json::json!({
                                "session_id": id,
                                "transport": "http",
                                "event": "session_terminated",
                            }),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit session termination: {}", e);
                    }
                }
                // MCP spec: 204 No Content on successful session termination
                StatusCode::NO_CONTENT.into_response()
            } else {
                tracing::debug!("DELETE for unknown session: {}", id);
                StatusCode::NOT_FOUND.into_response()
            }
        }
        None => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing Mcp-Session-Id header"})),
        )
            .into_response(),
    }
}

/// GET /.well-known/oauth-protected-resource handler (RFC 9728).
///
/// Returns protected resource metadata when OAuth is configured, enabling
/// clients to discover authorization requirements before making requests.
pub async fn handle_protected_resource_metadata(State(state): State<ProxyState>) -> Response {
    match &state.oauth {
        Some(validator) => {
            let config = validator.config();
            let mut metadata = serde_json::json!({
                "resource": config.expected_resource.as_deref().unwrap_or(&config.audience),
                "authorization_servers": [config.issuer],
                "scopes_supported": config.required_scopes,
                "bearer_methods_supported": ["header"],
                "resource_documentation": "https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization"
            });
            if config.dpop_mode != crate::oauth::DpopMode::Off {
                metadata["dpop_signing_alg_values_supported"] =
                    serde_json::json!(config.dpop_allowed_algorithms);
            }
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                Json(metadata),
            )
                .into_response()
        }
        None => {
            // OAuth not configured — return 404 as there's no protected resource
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

/// Build transport targets for the smart fallback chain (Phase 29).
///
/// In gateway mode, uses `BackendConfig.transport_urls` for per-transport endpoints.
/// In single-server mode, derives targets from `upstream_url`, `grpc_port`, and
/// WebSocket path conventions.
pub(crate) fn build_transport_targets(
    state: &ProxyState,
    gateway_decision: Option<&vellaveto_types::RoutingDecision>,
    priorities: &[vellaveto_types::TransportProtocol],
) -> Vec<super::smart_fallback::TransportTarget> {
    use vellaveto_types::TransportProtocol;

    let mut targets = Vec::new();

    if let Some(ref gw) = state.gateway {
        // Gateway mode: use backend transport_urls.
        if let Some(decision) = gateway_decision {
            let config = gw.backend_config(&decision.backend_id);
            for proto in priorities {
                let url = config
                    .and_then(|c| c.transport_urls.get(proto))
                    .cloned()
                    .unwrap_or_else(|| {
                        // Fall back to the primary backend URL for HTTP.
                        if *proto == TransportProtocol::Http {
                            decision.upstream_url.clone()
                        } else {
                            String::new()
                        }
                    });
                if !url.is_empty() {
                    targets.push(super::smart_fallback::TransportTarget {
                        protocol: *proto,
                        url,
                        upstream_id: decision.backend_id.clone(),
                    });
                }
            }
        }
    } else {
        // Single-server mode: derive from upstream_url + grpc_port.
        for proto in priorities {
            let url = match proto {
                TransportProtocol::Http => state.upstream_url.clone(),
                TransportProtocol::Grpc => {
                    if let Some(grpc_port) = state.grpc_port {
                        // Extract host from upstream_url via simple string parsing.
                        let host =
                            extract_host_from_url(&state.upstream_url).unwrap_or("127.0.0.1");
                        // SECURITY (FIND-R43-029): Wrap IPv6 addresses in brackets
                        // to produce valid URLs (e.g., "http://[::1]:50051").
                        if host.contains(':') {
                            format!("http://[{}]:{}", host, grpc_port)
                        } else {
                            format!("http://{}:{}", host, grpc_port)
                        }
                    } else {
                        continue;
                    }
                }
                TransportProtocol::WebSocket => {
                    // SECURITY (FIND-R43-014): Only replace scheme prefix, not occurrences in path/query.
                    let ws_url = if state.upstream_url.starts_with("https://") {
                        format!("wss://{}", &state.upstream_url["https://".len()..])
                    } else if state.upstream_url.starts_with("http://") {
                        format!("ws://{}", &state.upstream_url["http://".len()..])
                    } else {
                        state.upstream_url.clone()
                    };
                    if ws_url.ends_with("/mcp") {
                        format!("{}/ws", ws_url)
                    } else {
                        format!("{}/ws", ws_url.trim_end_matches('/'))
                    }
                }
                TransportProtocol::Stdio => "stdio://local".to_string(),
            };
            targets.push(super::smart_fallback::TransportTarget {
                protocol: *proto,
                url,
                upstream_id: "default".to_string(),
            });
        }
    }

    targets
}

/// Extract host from a URL string without the `url` crate.
/// Returns the host portion (between `://` and the next `/` or `:`).
///
/// SECURITY (FIND-R42-003): Handles userinfo (`user:pass@host`) by stripping
/// everything before the last `@` in the authority component. Also handles
/// IPv6 addresses in brackets (`[::1]:8080`).
pub(crate) fn extract_host_from_url(url: &str) -> Option<&str> {
    let after_scheme = url.find("://").map(|i| &url[i + 3..]).unwrap_or(url);
    // SECURITY (FIND-R44-004): Strip fragment before authority parsing.
    // Fragments (#...) are not part of the authority per RFC 3986 but
    // if present they can cause discrepancy between this parser and reqwest.
    let no_fragment = after_scheme.split('#').next().unwrap_or(after_scheme);
    // Strip path and query to get authority component.
    let authority = no_fragment.split('/').next().unwrap_or(no_fragment);
    // SECURITY (FIND-R42-003): Strip userinfo (user:pass@host) to prevent
    // SSRF via @-smuggling (e.g., "http://safe@evil/path").
    // SECURITY (FIND-R43-023): Also handle URL-encoded @ (%40) in authority
    // to prevent bypass of userinfo stripping (e.g., "http://safe%40evil/path").
    let host_port = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => match authority.rfind("%40") {
            Some(i) => &authority[i + 3..],
            None => authority,
        },
    };
    // Handle IPv6 addresses in brackets (e.g., "[::1]:8080").
    if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        let ipv6 = &host_port[1..end];
        if ipv6.is_empty() {
            return None;
        }
        // SECURITY (FIND-R44-051): Strip IPv6 zone ID (e.g., "fe80::1%25eth0"
        // → "fe80::1"). Zone IDs are link-local scope identifiers encoded as
        // %25<zone> in URIs (RFC 6874). Strip them so the raw IPv6 address is
        // matched against allow-lists without the interface suffix.
        let ipv6 = ipv6.split("%25").next().unwrap_or(ipv6);
        if ipv6.is_empty() {
            return None;
        }
        return Some(ipv6);
    }
    // SECURITY (FIND-R44-023): Reject host_port containing percent-encoded
    // special characters (%25xx). Double-encoding like %2540 (which decodes to
    // %40, then @) can bypass the userinfo stripping above. Fail-closed: any
    // %25 in the non-bracketed host_port is suspicious and rejected.
    // NOTE: This check is placed after the IPv6 bracket branch because %25
    // is legitimately used for zone IDs in bracketed IPv6 addresses (RFC 6874).
    if host_port.contains("%25") {
        return None;
    }
    // IPv4 or hostname: strip port.
    let host = host_port.split(':').next().unwrap_or(host_port);
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

// ═══════════════════════════════════════════════════
// GET /mcp — SSE Resumability (MCP 2025-11-25, Phase 30)
// ═══════════════════════════════════════════════════

/// Header name for SSE resumption.
const LAST_EVENT_ID_HEADER: &str = "last-event-id";

/// GET /mcp handler for SSE stream initiation/resumption.
///
/// MCP 2025-11-25 requires servers to support GET /mcp for clients to
/// initiate or resume SSE streams. The client sends `Accept: text/event-stream`
/// and optionally `Last-Event-ID` for resumption.
///
/// Gated behind `streamable_http.resumability_enabled` — returns 405 when disabled.
///
/// SECURITY (R45): Full security peer to `handle_mcp_post` — includes session
/// ownership binding, agent identity validation, call chain validation, audit
/// logging, and gateway mode rejection (no tool-based routing for SSE resumption).
pub async fn handle_mcp_get(
    State(state): State<ProxyState>,
    OriginalUri(original_uri): OriginalUri,
    proxy_ctx: Option<Extension<TrustedProxyContext>>,
    headers: HeaderMap,
) -> Response {
    // Gate: resumability must be enabled
    // SECURITY (FIND-R45-013): Generic error message — do not leak config details.
    if !state.streamable_http.resumability_enabled {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            Json(json!({
                "error": "Method not allowed"
            })),
        )
            .into_response();
    }

    // Validate Accept header — must request text/event-stream
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !accept.contains("text/event-stream") {
        return (
            StatusCode::NOT_ACCEPTABLE,
            Json(json!({
                "error": "Not acceptable"
            })),
        )
            .into_response();
    }

    // MCP 2025-11-25: Validate MCP-Protocol-Version header (same as POST path).
    // SECURITY (FIND-R45-013): Use JSON-RPC error format consistent with POST.
    if let Some(version_hdr) = headers.get(MCP_PROTOCOL_VERSION_HEADER) {
        match version_hdr.to_str() {
            Ok(version) if SUPPORTED_PROTOCOL_VERSIONS.contains(&version) => {}
            Ok(version) => {
                tracing::warn!("GET /mcp: Unsupported MCP protocol version: '{}'", version,);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32600,
                            "message": format!(
                                "Unsupported MCP protocol version. Supported versions: {}",
                                SUPPORTED_PROTOCOL_VERSIONS.join(", ")
                            )
                        },
                        "id": null
                    })),
                )
                    .into_response();
            }
            Err(_) => {
                tracing::warn!("Invalid UTF-8 in {} header", MCP_PROTOCOL_VERSION_HEADER);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32600,
                            "message": "Invalid MCP-Protocol-Version header encoding"
                        },
                        "id": null
                    })),
                )
                    .into_response();
            }
        }
    }

    // CSRF / DNS rebinding origin validation (same as POST)
    if let Err(response) = validate_origin(&headers, &state.bind_addr, &state.allowed_origins) {
        return response;
    }

    // API key validation (same as POST)
    if let Err(response) = validate_api_key(&state, &headers) {
        return response;
    }

    // SECURITY (FIND-R73-SRV-011): Validate session ID length and reject control chars
    // before OAuth, matching the DELETE and POST handler patterns.
    // SECURITY (FIND-R86-001): Also reject Unicode format characters for
    // parity with gRPC and WebSocket handlers.
    let client_session_id = headers
        .get(MCP_SESSION_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|id| {
            id.len() <= MAX_SESSION_ID_LENGTH
                && !id
                    .chars()
                    .any(|c| c.is_control() || is_unicode_format_char(c))
        });

    if headers.get(MCP_SESSION_ID).is_some() && client_session_id.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid session ID"})),
        )
            .into_response();
    }

    // OAuth 2.1 token validation (FIND-R45-001: extract claims for session binding)
    let from_trusted_proxy = proxy_ctx
        .map(|Extension(ctx)| ctx.from_trusted_proxy)
        .unwrap_or(false);
    let effective_uri =
        build_effective_request_uri(&headers, state.bind_addr, &original_uri, from_trusted_proxy);
    let oauth_claims =
        match validate_oauth(&state, &headers, "GET", &effective_uri, client_session_id).await {
            Ok(claims) => claims,
            Err(response) => return response,
        };

    // SECURITY (FIND-R45-002): Agent identity attestation via X-Agent-Identity JWT
    // (same as POST path). Without this, GET requests bypass identity validation.
    let agent_identity = match validate_agent_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };

    // Extract and validate Last-Event-ID
    let last_event_id = headers
        .get(LAST_EVENT_ID_HEADER)
        .and_then(|v| v.to_str().ok());

    // SECURITY: Fail-closed on oversized event IDs
    if let Some(event_id) = last_event_id {
        if event_id.len() > state.streamable_http.max_event_id_length {
            tracing::warn!(
                "SECURITY: Rejecting oversized Last-Event-ID ({} bytes, max {})",
                event_id.len(),
                state.streamable_http.max_event_id_length
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Invalid request"
                })),
            )
                .into_response();
        }
        // SECURITY (FIND-R45-010): Reject event IDs with control characters.
        // Also reject URL-scheme prefixes to prevent SSRF via upstream event ID parsing.
        // SECURITY (FIND-R86-001): Also reject Unicode format characters for
        // parity with gRPC and WebSocket handlers.
        if event_id
            .chars()
            .any(|c| c.is_control() || is_unicode_format_char(c))
        {
            tracing::warn!("SECURITY: Rejecting Last-Event-ID with control/format characters");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Invalid request"
                })),
            )
                .into_response();
        }
    }

    // Session management (session ID length validated inside get_or_create)
    let session_id = state.sessions.get_or_create(client_session_id);

    // SECURITY (FIND-R45-001): Atomic session ownership check + bind.
    // Without this, an attacker can hijack another user's SSE stream by
    // providing their session ID in the GET request.
    if let Some(ref claims) = oauth_claims {
        if let Some(mut session) = state.sessions.get_mut(&session_id) {
            match &session.oauth_subject {
                Some(owner) if owner != &claims.sub => {
                    tracing::warn!(
                        "SECURITY: Session fixation attempt on GET blocked — session {} owned by '{}', request from '{}'",
                        session_id, owner, claims.sub
                    );
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "error": {"code": -32001, "message": "Session owned by another user"},
                            "id": null
                        })),
                    )
                        .into_response();
                }
                None => {
                    session.oauth_subject = Some(claims.sub.clone());
                    if claims.exp > 0 {
                        session.token_expires_at = Some(claims.exp);
                    }
                }
                _ => {
                    // SECURITY (R23-PROXY-6): Use the EARLIEST token expiry
                    if claims.exp > 0 {
                        session.token_expires_at = Some(
                            session
                                .token_expires_at
                                .map_or(claims.exp, |existing| existing.min(claims.exp)),
                        );
                    }
                }
            }
        }
    }

    // SECURITY (FIND-R45-002): Store agent identity in session for context-aware evaluation
    if let Some(ref identity) = agent_identity {
        if let Some(mut session) = state.sessions.get_mut(&session_id) {
            session.agent_identity = Some(identity.clone());
        }
    }

    // SECURITY (FIND-R45-003): Validate call chain header (same as POST pre-match check).
    // Without this, malformed X-Upstream-Agents headers pass through on GET.
    if let Err(reason) = validate_call_chain_header(&headers, &state.limits) {
        let action = Action::new(
            "vellaveto",
            "invalid_call_chain_header",
            json!({
                "method": "GET /mcp",
                "reason": reason,
            }),
        );
        let verdict = Verdict::Deny {
            reason: format!("Invalid upstream call chain header: {}", reason),
        };
        if let Err(e) = state
            .audit
            .log_entry(
                &action,
                &verdict,
                build_audit_context(
                    &session_id,
                    json!({
                        "event": "invalid_call_chain_header",
                        "method": "GET /mcp",
                        "reason": reason,
                    }),
                    &oauth_claims,
                ),
            )
            .await
        {
            tracing::warn!("Failed to audit invalid call-chain header on GET: {}", e);
        }
        tracing::warn!(reason = %reason, "GET /mcp: Call chain validation failed");
        return attach_session_header(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32600, "message": "Invalid request"},
                    "id": null
                })),
            )
                .into_response(),
            &session_id,
        );
    }

    // SECURITY (FIND-R45-009 + FIND-R45-014): Touch session to update
    // activity timestamp and increment request_count. Without this, GET
    // requests don't extend session lifetime and aren't counted for rate
    // limiting, enabling DoS via repeated reconnections (FIND-R45-011).
    if let Some(mut session) = state.sessions.get_mut(&session_id) {
        session.touch();
    }

    // SECURITY (FIND-R45-008): Reject GET in gateway mode. SSE resumption
    // reconnects to a session-scoped stream, but in gateway mode the backend
    // is determined per-tool-call. Without session-scoped backend tracking,
    // we cannot route the GET to the correct upstream.
    if state.gateway.is_some() {
        tracing::warn!(
            "GET /mcp not supported in gateway mode — backend selection requires tool routing"
        );
        return attach_session_header(
            (
                StatusCode::NOT_IMPLEMENTED,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": "SSE resumability not available in gateway mode"
                    },
                    "id": null
                })),
            )
                .into_response(),
            &session_id,
        );
    }

    // Phase 28: Extract W3C Trace Context
    let incoming_trace = trace_propagation::extract_trace_context(&headers);
    let (vellaveto_trace_ctx, _vellaveto_span_id) =
        trace_propagation::create_vellaveto_span(&incoming_trace);

    // Determine Authorization header for upstream
    let auth_header_for_upstream = if state
        .oauth
        .as_ref()
        .is_some_and(|v| v.config().pass_through)
    {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    } else {
        None
    };

    let (up_tp, up_ts) = trace_propagation::build_upstream_headers(&vellaveto_trace_ctx, "sse_get");

    // SECURITY (FIND-R45-004): Audit log the SSE resumption request.
    // Without this, GET /mcp requests leave no audit trail, preventing
    // forensic analysis and compliance evidence.
    let sse_action = Action::new(
        "vellaveto",
        "sse_resumption",
        json!({
            "session": &session_id,
            "has_last_event_id": last_event_id.is_some(),
        }),
    );
    if let Err(e) = state
        .audit
        .log_entry(
            &sse_action,
            &Verdict::Allow,
            build_audit_context(
                &session_id,
                json!({
                    "event": "sse_get_request",
                    "last_event_id_present": last_event_id.is_some(),
                }),
                &oauth_claims,
            ),
        )
        .await
    {
        tracing::warn!("Failed to audit SSE GET request: {}", e);
    }

    // Forward GET to upstream
    let response = super::upstream::forward_get_to_upstream(
        &state,
        &session_id,
        auth_header_for_upstream.as_deref(),
        Some((up_tp.as_str(), up_ts.as_deref())),
        last_event_id,
    )
    .await;

    attach_session_header(response, &session_id)
}

/// Extract scannable text from a PassThrough JSON-RPC message for injection scanning.
///
/// SECURITY (FIND-R112-008): Recursively extracts string values from `params` and
/// `result` fields. Bounded to prevent memory amplification from deeply nested or
/// highly branched JSON structures.
fn extract_passthrough_text_for_injection(msg: &Value) -> String {
    const MAX_DEPTH: usize = 10;
    const MAX_PARTS: usize = 1000;
    let mut parts = Vec::new();

    // Scan params (client→upstream direction)
    if let Some(params) = msg.get("params") {
        extract_strings_for_injection(params, &mut parts, 0, MAX_DEPTH, MAX_PARTS);
    }
    // Scan result (upstream→client direction, e.g. sampling/elicitation responses)
    if let Some(result) = msg.get("result") {
        extract_strings_for_injection(result, &mut parts, 0, MAX_DEPTH, MAX_PARTS);
    }

    parts.join("\n")
}

/// Recursively extract string values from a JSON value with depth and count bounds.
fn extract_strings_for_injection(
    val: &Value,
    parts: &mut Vec<String>,
    depth: usize,
    max_depth: usize,
    max_parts: usize,
) {
    if depth > max_depth || parts.len() >= max_parts {
        return;
    }
    match val {
        Value::String(s) => parts.push(s.clone()),
        Value::Array(arr) => {
            for item in arr {
                extract_strings_for_injection(item, parts, depth + 1, max_depth, max_parts);
            }
        }
        Value::Object(map) => {
            for (_key, v) in map {
                extract_strings_for_injection(v, parts, depth + 1, max_depth, max_parts);
            }
        }
        _ => {}
    }
}
