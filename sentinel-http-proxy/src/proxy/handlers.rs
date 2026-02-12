//! HTTP handler functions: handle_mcp_post, handle_mcp_delete,
//! and handle_protected_resource_metadata.

use axum::{
    extract::{OriginalUri, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use bytes::Bytes;
use sentinel_mcp::extractor::{self, make_denial_response, MessageType};
use sentinel_mcp::inspection::{scan_notification_for_secrets, scan_parameters_for_secrets};
use sentinel_types::{Action, EvaluationContext, Verdict};
use serde_json::{json, Value};

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
use super::upstream::{canonicalize_body, forward_to_upstream, make_jsonrpc_error};
use super::{
    McpQueryParams, ProxyState, TrustedProxyContext, MCP_PROTOCOL_VERSION_HEADER, MCP_SESSION_ID,
    SUPPORTED_PROTOCOL_VERSIONS,
};
use crate::proxy_metrics::record_dlp_finding;

// NOTE: MAX_RESPONSE_BODY_SIZE and MAX_SSE_EVENT_SIZE are now configurable
// via state.limits.max_response_body_bytes and state.limits.max_sse_event_bytes.
// See sentinel_config::LimitsConfig for documentation and defaults.

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
                                "Unsupported MCP protocol version '{}'. Supported versions: {}",
                                version,
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

    let client_session_id = headers.get(MCP_SESSION_ID).and_then(|v| v.to_str().ok());

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

    // Defense-in-depth: reject JSON with duplicate keys before parsing.
    // Prevents parser-disagreement attacks (CVE-2017-12635, CVE-2020-16250)
    // where the proxy evaluates one key value but upstream sees another.
    if let Ok(raw_str) = std::str::from_utf8(&body) {
        if let Some(dup_key) = sentinel_mcp::framing::find_duplicate_json_key(raw_str) {
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
    if let Err(reason) = validate_call_chain_header(&headers, &state.limits) {
        let method = msg
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        let action = Action::new(
            "sentinel",
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
            if let Err(reason) = validate_call_chain_header(&headers, &state.limits) {
                let action = extractor::extract_action(&tool_name, &arguments);
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
                                "tool": tool_name,
                                "event": "invalid_call_chain_header",
                                "reason": reason,
                            }),
                            &oauth_claims,
                        ),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit invalid call-chain header: {}", e);
                }

                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32600,
                        "message": format!("Invalid request: {}", reason)
                    }
                });
                return attach_session_header(
                    (StatusCode::OK, Json(error_response)).into_response(),
                    &session_id,
                );
            }

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

                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32001,
                        "message": format!(
                            "Denied by Sentinel: Tool '{}' blocked due to annotation change (rug-pull protection)",
                            tool_name
                        ),
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
                    sentinel_mcp::tool_registry::TrustLevel::Unknown => {
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
                    sentinel_mcp::tool_registry::TrustLevel::Untrusted { score } => {
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
                    sentinel_mcp::tool_registry::TrustLevel::Trusted => {
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
                        *session.call_counts.entry(tool_name.clone()).or_insert(0) += 1;
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
                    let response = forward_to_upstream(
                        &state,
                        &session_id,
                        forward_body,
                        auth_header_for_upstream.as_deref(),
                    )
                    .await;
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
            if let Err(reason) = validate_call_chain_header(&headers, &state.limits) {
                let action = extractor::extract_resource_action(&uri);
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
                                "resource_uri": uri,
                                "reason": reason,
                            }),
                            &oauth_claims,
                        ),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit invalid call-chain header: {}", e);
                }

                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32600,
                        "message": format!("Invalid request: {}", reason)
                    }
                });
                return attach_session_header(
                    (StatusCode::OK, Json(error_response)).into_response(),
                    &session_id,
                );
            }

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

            let mut action = extractor::extract_resource_action(&uri);

            // DNS rebinding protection for resource reads
            if state.engine.has_ip_rules() {
                resolve_domains(&mut action).await;
            }

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
                    let response = forward_to_upstream(
                        &state,
                        &session_id,
                        forward_body,
                        auth_header_for_upstream.as_deref(),
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
            let sampling_verdict =
                sentinel_mcp::elicitation::inspect_sampling(&params, &state.sampling_config);
            match sampling_verdict {
                sentinel_mcp::elicitation::SamplingVerdict::Allow => {
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
                    let response = forward_to_upstream(
                        &state,
                        &session_id,
                        forward_body,
                        auth_header_for_upstream.as_deref(),
                    )
                    .await;
                    attach_session_header(response, &session_id)
                }
                sentinel_mcp::elicitation::SamplingVerdict::Deny { reason } => {
                    tracing::warn!(
                        "Blocked sampling/createMessage in session {}: {}",
                        session_id,
                        reason
                    );

                    let action = Action::new(
                        "sentinel",
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
                "sentinel",
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
            if state.response_dlp_enabled && msg.get("method").is_some() {
                let dlp_findings = scan_notification_for_secrets(&msg);
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
                        "sentinel",
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
            let response = forward_to_upstream(
                &state,
                &session_id,
                forward_body,
                auth_header_for_upstream.as_deref(),
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
                let verdict = sentinel_mcp::elicitation::inspect_elicitation(
                    &params,
                    &state.elicitation_config,
                    current_count,
                );
                // Pre-increment while holding the lock to close the TOCTOU gap
                if matches!(
                    verdict,
                    sentinel_mcp::elicitation::ElicitationVerdict::Allow
                ) {
                    if let Some(ref mut s) = session_ref {
                        s.elicitation_count += 1;
                    }
                }
                verdict
            };
            match elicitation_verdict {
                sentinel_mcp::elicitation::ElicitationVerdict::Allow => {
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
                    let response = forward_to_upstream(
                        &state,
                        &session_id,
                        forward_body,
                        auth_header_for_upstream.as_deref(),
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
                sentinel_mcp::elicitation::ElicitationVerdict::Deny { reason } => {
                    tracing::warn!(
                        "Blocked elicitation/create in session {}: {}",
                        session_id,
                        reason
                    );

                    let action = Action::new(
                        "sentinel",
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
            if let Err(reason) = validate_call_chain_header(&headers, &state.limits) {
                let action = extractor::extract_task_action(&task_method, task_id.as_deref());
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
                                "task_method": task_method,
                                "task_id": task_id,
                                "reason": reason,
                            }),
                            &oauth_claims,
                        ),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit invalid call-chain header: {}", e);
                }

                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32600,
                        "message": format!("Invalid request: {}", reason)
                    }
                });
                return attach_session_header(
                    (StatusCode::OK, Json(error_response)).into_response(),
                    &session_id,
                );
            }

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
                    let response = forward_to_upstream(
                        &state,
                        &session_id,
                        forward_body,
                        auth_header_for_upstream.as_deref(),
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
                "sentinel",
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
            let response = json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": -32600,
                    "message": "JSON-RPC batching is not supported (MCP 2025-06-18)"
                }
            });
            attach_session_header(
                (StatusCode::OK, Json(response)).into_response(),
                &session_id,
            )
        }
        MessageType::Invalid { id, reason } => {
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32600,
                    "message": format!("Invalid request: {}", reason)
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

    let session_id = headers.get(MCP_SESSION_ID).and_then(|v| v.to_str().ok());

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
