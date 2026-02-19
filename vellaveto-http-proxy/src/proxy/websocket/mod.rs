//! WebSocket transport for MCP JSON-RPC messages (SEP-1288).
//!
//! Implements a WebSocket reverse proxy that sits between MCP clients and
//! an upstream MCP server. WebSocket messages (text frames) are parsed as
//! JSON-RPC, classified via `vellaveto_mcp::extractor`, evaluated against
//! loaded policies, and forwarded to the upstream server.
//!
//! Security invariants:
//! - **Fail-closed**: Unparseable messages close the connection (code 1008).
//! - **No binary frames**: Only text frames are accepted (code 1003 for binary).
//! - **Session binding**: Each WS connection is bound to exactly one session.
//! - **Canonicalization**: Re-serialized JSON forwarded (TOCTOU defense).

use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, State,
    },
    http::HeaderMap,
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use vellaveto_mcp::extractor::{self, MessageType};
use vellaveto_mcp::inspection::{
    inspect_for_injection, scan_notification_for_secrets, scan_parameters_for_secrets,
    scan_response_for_secrets, scan_text_for_secrets,
};
use vellaveto_mcp::output_validation::ValidationResult;
use vellaveto_types::{Action, EvaluationContext, Verdict};

use super::auth::{validate_agent_identity, validate_api_key, validate_oauth};
use super::call_chain::{
    check_privilege_escalation, sync_session_call_chain_from_headers, take_tracked_tool_call,
    track_pending_tool_call,
};
use super::origin::validate_origin;
use super::ProxyState;
use crate::proxy_metrics::record_dlp_finding;

/// Configuration for WebSocket transport.
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// Maximum message size in bytes (default: 1 MB).
    pub max_message_size: usize,
    /// Idle timeout in seconds — close connection after inactivity (default: 300s).
    pub idle_timeout_secs: u64,
    /// Maximum messages per second per connection for client-to-upstream (default: 100).
    pub message_rate_limit: u32,
    /// Maximum messages per second per connection for upstream-to-client (default: 500).
    /// SECURITY (FIND-R46-WS-003): Rate limits on the upstream→client direction prevent
    /// a malicious upstream from flooding the client with responses.
    pub upstream_rate_limit: u32,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_message_size: 1_048_576,
            idle_timeout_secs: 300,
            message_rate_limit: 100,
            upstream_rate_limit: 500,
        }
    }
}

/// WebSocket close codes per RFC 6455.
const CLOSE_POLICY_VIOLATION: u16 = 1008;
const CLOSE_UNSUPPORTED_DATA: u16 = 1003;
/// Close code for oversized messages. Used by axum's `max_message_size`
/// automatically; kept here for documentation and test assertions.
#[cfg(test)]
const CLOSE_MESSAGE_TOO_BIG: u16 = 1009;
const CLOSE_NORMAL: u16 = 1000;

/// Global WebSocket metrics counters.
static WS_CONNECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static WS_MESSAGES_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Record WebSocket connection metric.
fn record_ws_connection() {
    WS_CONNECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
    metrics::counter!("vellaveto_ws_connections_total").increment(1);
}

/// Record WebSocket message metric.
fn record_ws_message(direction: &str) {
    WS_MESSAGES_TOTAL.fetch_add(1, Ordering::Relaxed);
    metrics::counter!(
        "vellaveto_ws_messages_total",
        "direction" => direction.to_string()
    )
    .increment(1);
}

/// Get current connection count (for testing).
#[cfg(test)]
pub(crate) fn ws_connections_count() -> u64 {
    WS_CONNECTIONS_TOTAL.load(Ordering::Relaxed)
}

/// Get current message count (for testing).
#[cfg(test)]
pub(crate) fn ws_messages_count() -> u64 {
    WS_MESSAGES_TOTAL.load(Ordering::Relaxed)
}

/// Query parameters for the WebSocket upgrade endpoint.
#[derive(Debug, serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct WsQueryParams {
    /// Optional session ID for session resumption.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// Handle WebSocket upgrade request at `/mcp/ws`.
///
/// Authenticates the request, validates origin, creates/resumes a session,
/// and upgrades the HTTP connection to a WebSocket.
pub async fn handle_ws_upgrade(
    State(state): State<ProxyState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    query: axum::extract::Query<WsQueryParams>,
    ws: WebSocketUpgrade,
) -> Response {
    // 1. Validate origin (CSRF / DNS rebinding defense)
    if let Err(resp) = validate_origin(&headers, &state.bind_addr, &state.allowed_origins) {
        return resp;
    }

    // 2. Authenticate before upgrade (API key or OAuth)
    if let Err(resp) = validate_api_key(&state, &headers) {
        return resp;
    }

    // SECURITY (FIND-R53-WS-001): Validate OAuth token at upgrade time.
    // Parity with HTTP POST (handlers.rs:154) and GET (handlers.rs:2864).
    // Without this, WS connections bypass token expiry checks.
    let oauth_claims = match validate_oauth(
        &state,
        &headers,
        "GET",
        &super::auth::build_effective_request_uri(
            &headers,
            state.bind_addr,
            &axum::http::Uri::from_static("/mcp/ws"),
            false,
        ),
        query.session_id.as_deref(),
    )
    .await
    {
        Ok(claims) => claims,
        Err(response) => return response,
    };

    // SECURITY (FIND-R53-WS-002): Validate agent identity at upgrade time.
    // Parity with HTTP POST (handlers.rs:160) and GET (handlers.rs:2871).
    let _agent_identity = match validate_agent_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };

    // SECURITY (FIND-R55-WS-004, FIND-R81-001): Validate session_id length and
    // control characters from query parameter. Parity with HTTP POST/GET handlers
    // (handlers.rs:154, handlers.rs:2928) which reject control chars.
    let ws_session_id = query
        .session_id
        .as_deref()
        .filter(|id| !id.is_empty() && id.len() <= 128 && !id.chars().any(|c| c.is_control()));

    // 3. Get or create session
    let session_id = state.sessions.get_or_create(ws_session_id);

    // SECURITY (FIND-R53-WS-003): Session ownership binding — prevent session fixation.
    // Parity with HTTP GET (handlers.rs:2914-2953).
    if let Some(ref claims) = oauth_claims {
        if let Some(mut session) = state.sessions.get_mut(&session_id) {
            match &session.oauth_subject {
                Some(owner) if owner != &claims.sub => {
                    tracing::warn!(
                        session_id = %session_id,
                        owner = %owner,
                        requester = %claims.sub,
                        "WS upgrade rejected: session owned by different principal"
                    );
                    return axum::response::IntoResponse::into_response((
                        axum::http::StatusCode::FORBIDDEN,
                        axum::Json(json!({
                            "error": "Session belongs to another principal"
                        })),
                    ));
                }
                None => {
                    // Bind session to this OAuth subject
                    session.oauth_subject = Some(claims.sub.clone());
                    // SECURITY (FIND-R73-SRV-006): Store token expiry, matching
                    // HTTP POST handler pattern to enforce token lifetime.
                    if claims.exp > 0 {
                        session.token_expires_at = Some(claims.exp);
                    }
                }
                _ => {
                    // Already owned by this principal — use earliest expiry
                    // SECURITY (FIND-R73-SRV-006): Parity with HTTP POST handler
                    // (R23-PROXY-6) — prevent long-lived tokens from extending
                    // sessions originally bound to short-lived tokens.
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

    // SECURITY (FIND-R46-006): Validate and extract call chain from upgrade headers.
    // The call chain is synced once during upgrade and reused for all messages
    // in this WebSocket connection.
    if let Err(reason) = super::call_chain::validate_call_chain_header(&headers, &state.limits) {
        tracing::warn!(
            session_id = %session_id,
            "WS upgrade rejected: invalid call chain header: {}",
            reason
        );
        return axum::response::IntoResponse::into_response((
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(json!({
                "error": "Invalid request"
            })),
        ));
    }
    sync_session_call_chain_from_headers(
        &state.sessions,
        &session_id,
        &headers,
        state.call_chain_hmac_key.as_ref(),
        &state.limits,
    );

    let ws_config = state.ws_config.clone().unwrap_or_default();

    // Phase 28: Extract W3C Trace Context from the HTTP upgrade request headers.
    // The trace_id is used for correlating all audit entries during this WS session.
    let trace_ctx = super::trace_propagation::extract_trace_context(&headers);
    let ws_trace_id = trace_ctx
        .trace_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string().replace('-', ""));

    tracing::info!(
        session_id = %session_id,
        trace_id = %ws_trace_id,
        peer = %addr,
        "WebSocket upgrade accepted"
    );

    // 4. Configure and upgrade
    ws.max_message_size(ws_config.max_message_size)
        .on_upgrade(move |socket| {
            handle_ws_connection(socket, state, session_id, ws_config, addr, ws_trace_id)
        })
}

/// Handle an established WebSocket connection.
///
/// Establishes an upstream WS connection, then relays messages bidirectionally
/// with policy enforcement on client→upstream messages and DLP/injection
/// scanning on upstream→client messages.
async fn handle_ws_connection(
    client_ws: WebSocket,
    state: ProxyState,
    session_id: String,
    ws_config: WebSocketConfig,
    peer_addr: SocketAddr,
    trace_id: String,
) {
    record_ws_connection();
    let start = std::time::Instant::now();
    tracing::debug!(
        session_id = %session_id,
        trace_id = %trace_id,
        "WebSocket connection established with trace context"
    );

    // Connect to upstream — use gateway default backend if configured
    let upstream_url = if let Some(ref gw) = state.gateway {
        match gw.route("") {
            Some(d) => convert_to_ws_url(&d.upstream_url),
            None => {
                tracing::error!(session_id = %session_id, "No healthy upstream for WebSocket");
                let (mut client_sink, _) = client_ws.split();
                let _ = client_sink
                    .send(Message::Close(Some(CloseFrame {
                        code: CLOSE_POLICY_VIOLATION,
                        reason: "No healthy upstream available".into(),
                    })))
                    .await;
                return;
            }
        }
    } else {
        convert_to_ws_url(&state.upstream_url)
    };
    let upstream_ws = match connect_upstream_ws(&upstream_url).await {
        Ok(ws) => ws,
        Err(e) => {
            tracing::error!(
                session_id = %session_id,
                "Failed to connect to upstream WebSocket: {}",
                e
            );
            // Send close frame to client
            let (mut client_sink, _) = client_ws.split();
            let _ = client_sink
                .send(Message::Close(Some(CloseFrame {
                    code: CLOSE_POLICY_VIOLATION,
                    reason: "Upstream connection failed".into(),
                })))
                .await;
            return;
        }
    };

    let (client_sink, client_stream) = client_ws.split();
    let (upstream_sink, upstream_stream) = upstream_ws.split();

    // Wrap sinks in Arc<Mutex> for shared access
    let client_sink = Arc::new(Mutex::new(client_sink));
    let upstream_sink = Arc::new(Mutex::new(upstream_sink));

    // Rate limiter state: track messages in the current second window
    let rate_counter = Arc::new(AtomicU64::new(0));
    let rate_window_start = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));

    // SECURITY (FIND-R46-WS-003): Separate rate limiter for upstream→client direction
    let upstream_rate_counter = Arc::new(AtomicU64::new(0));
    let upstream_rate_window_start = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));

    let idle_timeout = Duration::from_secs(ws_config.idle_timeout_secs);

    // Client → Vellaveto → Upstream relay
    let client_to_upstream = {
        let state = state.clone();
        let session_id = session_id.clone();
        let client_sink = client_sink.clone();
        let upstream_sink = upstream_sink.clone();
        let rate_counter = rate_counter.clone();
        let rate_window_start = rate_window_start.clone();
        let ws_config = ws_config.clone();

        relay_client_to_upstream(
            client_stream,
            client_sink,
            upstream_sink,
            state,
            session_id,
            ws_config,
            rate_counter,
            rate_window_start,
        )
    };

    // Upstream → Vellaveto → Client relay
    let upstream_to_client = {
        let state = state.clone();
        let session_id = session_id.clone();
        let client_sink = client_sink.clone();
        let ws_config = ws_config.clone();

        relay_upstream_to_client(
            upstream_stream,
            client_sink,
            state,
            session_id,
            ws_config,
            upstream_rate_counter,
            upstream_rate_window_start,
        )
    };

    // Run both relay loops with idle timeout
    tokio::select! {
        _ = client_to_upstream => {
            tracing::debug!(session_id = %session_id, "Client stream ended");
        }
        _ = upstream_to_client => {
            tracing::debug!(session_id = %session_id, "Upstream stream ended");
        }
        _ = tokio::time::sleep(idle_timeout) => {
            tracing::info!(
                session_id = %session_id,
                "WebSocket idle timeout ({}s), closing",
                ws_config.idle_timeout_secs
            );
        }
    }

    // Clean shutdown: close both sides
    {
        let mut sink = client_sink.lock().await;
        let _ = sink
            .send(Message::Close(Some(CloseFrame {
                code: CLOSE_NORMAL,
                reason: "Session ended".into(),
            })))
            .await;
    }
    {
        let mut sink = upstream_sink.lock().await;
        let _ = sink.close().await;
    }

    let duration = start.elapsed();
    metrics::histogram!("vellaveto_ws_connection_duration_seconds").record(duration.as_secs_f64());

    tracing::info!(
        session_id = %session_id,
        peer = %peer_addr,
        duration_secs = duration.as_secs(),
        "WebSocket connection closed"
    );
}

/// Relay messages from client to upstream with policy enforcement.
#[allow(clippy::too_many_arguments)]
async fn relay_client_to_upstream(
    mut client_stream: futures_util::stream::SplitStream<WebSocket>,
    client_sink: Arc<Mutex<futures_util::stream::SplitSink<WebSocket, Message>>>,
    upstream_sink: Arc<
        Mutex<
            futures_util::stream::SplitSink<
                tokio_tungstenite::WebSocketStream<
                    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
                >,
                tokio_tungstenite::tungstenite::Message,
            >,
        >,
    >,
    state: ProxyState,
    session_id: String,
    ws_config: WebSocketConfig,
    rate_counter: Arc<AtomicU64>,
    rate_window_start: Arc<std::sync::Mutex<std::time::Instant>>,
) {
    while let Some(msg_result) = client_stream.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(session_id = %session_id, "Client WS error: {}", e);
                break;
            }
        };

        record_ws_message("client_to_upstream");

        // SECURITY (FIND-R52-WS-003): Per-message OAuth token expiry check.
        // After WebSocket upgrade, the HTTP auth middleware no longer runs.
        // A token that expires mid-connection must be rejected to prevent
        // indefinite access via a long-lived WebSocket.
        {
            let token_expired = state
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
                    "SECURITY: OAuth token expired during WebSocket session, closing"
                );
                let error = json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32001,
                        "message": "Session expired"
                    },
                    "id": null
                });
                let error_text = serde_json::to_string(&error)
                    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32001,"message":"Session expired"},"id":null}"#.to_string());
                let mut sink = client_sink.lock().await;
                let _ = sink.send(Message::Text(error_text.into())).await;
                let _ = sink
                    .send(Message::Close(Some(CloseFrame {
                        code: CLOSE_POLICY_VIOLATION,
                        reason: "Token expired".into(),
                    })))
                    .await;
                break;
            }
        }

        match msg {
            Message::Text(text) => {
                // Rate limiting
                if !check_rate_limit(
                    &rate_counter,
                    &rate_window_start,
                    ws_config.message_rate_limit,
                ) {
                    tracing::warn!(
                        session_id = %session_id,
                        "WebSocket rate limit exceeded, closing"
                    );
                    let mut sink = client_sink.lock().await;
                    let _ = sink
                        .send(Message::Close(Some(CloseFrame {
                            code: CLOSE_POLICY_VIOLATION,
                            reason: "Rate limit exceeded".into(),
                        })))
                        .await;
                    break;
                }

                // SECURITY (FIND-R46-005): Reject JSON with duplicate keys before parsing.
                // Prevents parser-disagreement attacks (CVE-2017-12635, CVE-2020-16250)
                // where the proxy evaluates one key value but upstream sees another.
                if let Some(dup_key) = vellaveto_mcp::framing::find_duplicate_json_key(&text) {
                    tracing::warn!(
                        session_id = %session_id,
                        "SECURITY: Rejected WS message with duplicate key: \"{}\"",
                        dup_key
                    );
                    let mut sink = client_sink.lock().await;
                    let _ = sink
                        .send(Message::Close(Some(CloseFrame {
                            code: CLOSE_POLICY_VIOLATION,
                            reason: "Duplicate JSON key detected".into(),
                        })))
                        .await;
                    break;
                }

                // SECURITY (FIND-R53-WS-004): Reject WS messages with control characters.
                // Parity with HTTP GET event_id validation (handlers.rs:2899).
                // Control chars in JSON-RPC messages can be used for log injection
                // or to bypass string-based security checks.
                if text.chars().any(|c| {
                    // Allow standard JSON whitespace (\t, \n, \r) but reject other
                    // ASCII control chars and Unicode format chars (FIND-R54-011).
                    // SECURITY: Also detect zero-width, bidi overrides, BOM
                    // that could bypass string-based security checks.
                    (c.is_control() && c != '\n' && c != '\r' && c != '\t')
                        || matches!(c,
                            '\u{200B}'..='\u{200F}' |
                            '\u{202A}'..='\u{202E}' |
                            '\u{2060}'..='\u{2069}' |
                            '\u{FEFF}'
                        )
                }) {
                    tracing::warn!(
                        session_id = %session_id,
                        "SECURITY: Rejected WS message with control characters"
                    );
                    let error =
                        make_ws_error_response(None, -32600, "Message contains control characters");
                    let mut sink = client_sink.lock().await;
                    let _ = sink.send(Message::Text(error.into())).await;
                    continue;
                }

                // Parse JSON
                let parsed: Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(_) => {
                        tracing::warn!(
                            session_id = %session_id,
                            "Unparseable JSON in WebSocket text frame, closing (fail-closed)"
                        );
                        let mut sink = client_sink.lock().await;
                        let _ = sink
                            .send(Message::Close(Some(CloseFrame {
                                code: CLOSE_POLICY_VIOLATION,
                                reason: "Invalid JSON".into(),
                            })))
                            .await;
                        break;
                    }
                };

                // SECURITY (FIND-R46-WS-001): Injection scanning on client→upstream text frames.
                // The HTTP proxy scans request bodies for injection; the WebSocket proxy must
                // do the same to maintain security parity. Fail-closed: if injection is detected
                // and blocking is enabled, deny the message.
                if !state.injection_disabled {
                    let scannable = extract_scannable_text_from_request(&parsed);
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
                                "SECURITY: Injection in WS client request! Session: {}, Patterns: {:?}",
                                session_id,
                                injection_matches,
                            );

                            let verdict = if state.injection_blocking {
                                Verdict::Deny {
                                    reason: format!(
                                        "WS request injection blocked: {:?}",
                                        injection_matches
                                    ),
                                }
                            } else {
                                Verdict::Allow
                            };

                            let action = Action::new(
                                "vellaveto",
                                "ws_request_injection",
                                json!({
                                    "matched_patterns": injection_matches,
                                    "session": session_id,
                                    "transport": "websocket",
                                    "direction": "client_to_upstream",
                                }),
                            );
                            if let Err(e) = state
                                .audit
                                .log_entry(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "ws_proxy",
                                        "event": "ws_request_injection_detected",
                                    }),
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit WS request injection: {}", e);
                            }

                            if state.injection_blocking {
                                let id = parsed.get("id");
                                let error = make_ws_error_response(
                                    id,
                                    -32001,
                                    "Request blocked: injection detected",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }
                    }
                }

                // Classify and evaluate
                let classified = extractor::classify_message(&parsed);
                match classified {
                    MessageType::ToolCall {
                        ref id,
                        ref tool_name,
                        ref arguments,
                    } => {
                        // SECURITY (FIND-R46-009): Strict tool name validation (MCP 2025-11-25).
                        // When enabled, reject tool names that don't conform to the spec format.
                        if state.streamable_http.strict_tool_name_validation {
                            if let Err(e) = vellaveto_types::validate_mcp_tool_name(tool_name) {
                                tracing::warn!(
                                    session_id = %session_id,
                                    "SECURITY: Rejecting invalid WS tool name '{}': {}",
                                    tool_name,
                                    e
                                );
                                let error =
                                    make_ws_error_response(Some(id), -32602, "Invalid tool name");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        let mut action = extractor::extract_action(tool_name, arguments);

                        // SECURITY (FIND-R75-002): DNS resolution for IP-based policy evaluation.
                        // Parity with HTTP handler (handlers.rs:717). Without this, policies
                        // using ip_rules are completely bypassed on the WebSocket transport.
                        if state.engine.has_ip_rules() {
                            super::helpers::resolve_domains(&mut action).await;
                        }

                        // SECURITY (FIND-R46-006): Call chain validation and privilege escalation check.
                        // Extract X-Upstream-Agents from the initial WS upgrade headers stored in session.
                        // For WebSocket, we sync the call chain once during upgrade and reuse it.
                        let upstream_chain = {
                            let session_ref = state.sessions.get_mut(&session_id);
                            session_ref
                                .map(|s| s.current_call_chain.clone())
                                .unwrap_or_default()
                        };
                        let current_agent_id = {
                            let session_ref = state.sessions.get_mut(&session_id);
                            session_ref.and_then(|s| s.oauth_subject.clone())
                        };

                        // SECURITY (FIND-R46-006): Privilege escalation detection.
                        if !upstream_chain.is_empty() {
                            let priv_check = check_privilege_escalation(
                                &state.engine,
                                &state.policies,
                                &action,
                                &upstream_chain,
                                current_agent_id.as_deref(),
                            );
                            if priv_check.escalation_detected {
                                let verdict = Verdict::Deny {
                                    reason: format!(
                                        "Privilege escalation: agent '{}' would be denied",
                                        priv_check
                                            .escalating_from_agent
                                            .as_deref()
                                            .unwrap_or("unknown")
                                    ),
                                };
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "privilege_escalation_blocked",
                                            "escalating_from_agent": priv_check.escalating_from_agent,
                                            "upstream_deny_reason": priv_check.upstream_deny_reason,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS privilege escalation: {}",
                                        e
                                    );
                                }
                                let error =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // SECURITY (FIND-R46-007): Rug-pull detection.
                        // Block calls to tools whose annotations changed since initial tools/list.
                        let is_flagged = state
                            .sessions
                            .get_mut(&session_id)
                            .map(|s| s.flagged_tools.contains(tool_name))
                            .unwrap_or(false);
                        if is_flagged {
                            let verdict = Verdict::Deny {
                                reason: format!(
                                    "Tool '{}' blocked: annotations changed (rug-pull detected)",
                                    tool_name
                                ),
                            };
                            if let Err(e) = state
                                .audit
                                .log_entry(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "ws_proxy",
                                        "session": session_id,
                                        "transport": "websocket",
                                        "event": "rug_pull_tool_blocked",
                                        "tool": tool_name,
                                    }),
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit WS rug-pull block: {}", e);
                            }
                            let error =
                                make_ws_error_response(Some(id), -32001, "Denied by policy");
                            let mut sink = client_sink.lock().await;
                            let _ = sink.send(Message::Text(error.into())).await;
                            continue;
                        }

                        // SECURITY (FIND-R52-WS-001): DLP scan parameters for secret exfiltration.
                        // Matches HTTP handler's DLP check to maintain security parity.
                        {
                            let dlp_findings = scan_parameters_for_secrets(arguments);
                            // SECURITY (FIND-R55-WS-001): DLP on request params always blocks,
                            // matching HTTP handler. Previously gated on injection_blocking flag.
                            if !dlp_findings.is_empty() {
                                for finding in &dlp_findings {
                                    record_dlp_finding(&finding.pattern_name);
                                }
                                let patterns: Vec<String> = dlp_findings
                                    .iter()
                                    .map(|f| format!("{} at {}", f.pattern_name, f.location))
                                    .collect();
                                let audit_reason = format!(
                                    "DLP: secrets detected in tool parameters: {:?}",
                                    patterns
                                );
                                tracing::warn!(
                                    "SECURITY: DLP blocking WS tool '{}' in session {}: {}",
                                    tool_name,
                                    session_id,
                                    audit_reason
                                );
                                let dlp_action = extractor::extract_action(tool_name, arguments);
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &dlp_action,
                                        &Verdict::Deny {
                                            reason: audit_reason,
                                        },
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "dlp_secret_blocked",
                                            "tool": tool_name,
                                            "findings": patterns,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS DLP finding: {}", e);
                                }
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "Request blocked: security policy violation",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // SECURITY (FIND-R52-WS-002): Memory poisoning detection.
                        // Check if tool call parameters contain replayed response data,
                        // matching the HTTP handler's memory poisoning check.
                        {
                            let poisoning_detected = state
                                .sessions
                                .get_mut(&session_id)
                                .and_then(|session| {
                                    let matches =
                                        session.memory_tracker.check_parameters(arguments);
                                    if !matches.is_empty() {
                                        for m in &matches {
                                            tracing::warn!(
                                                "SECURITY: Memory poisoning detected in WS tool '{}' (session {}): \
                                                 param '{}' contains replayed data (fingerprint: {})",
                                                tool_name,
                                                session_id,
                                                m.param_location,
                                                m.fingerprint
                                            );
                                        }
                                        Some(matches.len())
                                    } else {
                                        None
                                    }
                                });
                            if let Some(match_count) = poisoning_detected {
                                let poison_action = extractor::extract_action(tool_name, arguments);
                                let deny_reason = format!(
                                    "Memory poisoning detected: {} replayed data fragment(s) in tool '{}'",
                                    match_count, tool_name
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &poison_action,
                                        &Verdict::Deny {
                                            reason: deny_reason,
                                        },
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "memory_poisoning_detected",
                                            "matches": match_count,
                                            "tool": tool_name,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS memory poisoning: {}", e);
                                }
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "Request blocked: security policy violation",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // SECURITY (FIND-R46-008): Circuit breaker check.
                        // If the circuit is open for this tool, reject immediately.
                        if let Some(ref circuit_breaker) = state.circuit_breaker {
                            if let Err(reason) = circuit_breaker.can_proceed(tool_name) {
                                tracing::warn!(
                                    session_id = %session_id,
                                    "SECURITY: WS circuit breaker open for tool '{}': {}",
                                    tool_name,
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
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "circuit_breaker_rejected",
                                            "tool": tool_name,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS circuit breaker rejection: {}",
                                        e
                                    );
                                }
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "Service temporarily unavailable",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // SECURITY (FIND-R46-013): Tool registry trust check.
                        // If tool registry is configured, check trust level before evaluation.
                        if let Some(ref registry) = state.tool_registry {
                            let trust = registry.check_trust_level(tool_name).await;
                            match trust {
                                vellaveto_mcp::tool_registry::TrustLevel::Unknown => {
                                    registry.register_unknown(tool_name).await;
                                    let verdict = Verdict::Deny {
                                        reason: "Unknown tool requires approval".to_string(),
                                    };
                                    if let Err(e) = state
                                        .audit
                                        .log_entry(
                                            &action,
                                            &verdict,
                                            json!({
                                                "source": "ws_proxy",
                                                "session": session_id,
                                                "transport": "websocket",
                                                "registry": "unknown_tool",
                                                "tool": tool_name,
                                            }),
                                        )
                                        .await
                                    {
                                        tracing::warn!("Failed to audit WS unknown tool: {}", e);
                                    }
                                    let approval_reason = "Approval required";
                                    let approval_id = create_ws_approval(
                                        &state,
                                        &session_id,
                                        &action,
                                        approval_reason,
                                    )
                                    .await;
                                    let error = make_ws_error_response_with_data(
                                        Some(id),
                                        -32001,
                                        approval_reason,
                                        Some(json!({
                                            "verdict": "require_approval",
                                            "reason": approval_reason,
                                            "approval_id": approval_id,
                                        })),
                                    );
                                    let mut sink = client_sink.lock().await;
                                    let _ = sink.send(Message::Text(error.into())).await;
                                    continue;
                                }
                                vellaveto_mcp::tool_registry::TrustLevel::Untrusted {
                                    score: _,
                                } => {
                                    let verdict = Verdict::Deny {
                                        reason: "Untrusted tool requires approval".to_string(),
                                    };
                                    if let Err(e) = state
                                        .audit
                                        .log_entry(
                                            &action,
                                            &verdict,
                                            json!({
                                                "source": "ws_proxy",
                                                "session": session_id,
                                                "transport": "websocket",
                                                "registry": "untrusted_tool",
                                                "tool": tool_name,
                                            }),
                                        )
                                        .await
                                    {
                                        tracing::warn!("Failed to audit WS untrusted tool: {}", e);
                                    }
                                    let approval_reason = "Approval required";
                                    let approval_id = create_ws_approval(
                                        &state,
                                        &session_id,
                                        &action,
                                        approval_reason,
                                    )
                                    .await;
                                    let error = make_ws_error_response_with_data(
                                        Some(id),
                                        -32001,
                                        approval_reason,
                                        Some(json!({
                                            "verdict": "require_approval",
                                            "reason": approval_reason,
                                            "approval_id": approval_id,
                                        })),
                                    );
                                    let mut sink = client_sink.lock().await;
                                    let _ = sink.send(Message::Text(error.into())).await;
                                    continue;
                                }
                                vellaveto_mcp::tool_registry::TrustLevel::Trusted => {
                                    // Trusted — proceed to engine evaluation
                                }
                            }
                        }

                        let ctx = build_ws_evaluation_context(&state, &session_id);
                        let verdict = match state.engine.evaluate_action_with_context(
                            &action,
                            &state.policies,
                            Some(&ctx),
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                // Fail-closed: engine errors produce Deny
                                tracing::error!(
                                    session_id = %session_id,
                                    "Policy evaluation error: {}",
                                    e
                                );
                                Verdict::Deny {
                                    reason: format!("Policy evaluation failed: {}", e),
                                }
                            }
                        };

                        match verdict {
                            Verdict::Allow => {
                                // Phase 21: ABAC refinement — only runs when ABAC engine is configured
                                if let Some(ref abac) = state.abac_engine {
                                    let principal_id =
                                        ctx.agent_id.as_deref().unwrap_or("anonymous");
                                    let principal_type = ctx
                                        .agent_identity
                                        .as_ref()
                                        .and_then(|aid| aid.claims.get("type"))
                                        .and_then(|v: &serde_json::Value| v.as_str())
                                        .unwrap_or("Agent");
                                    let session_risk = state
                                        .sessions
                                        .get_mut(&session_id)
                                        .and_then(|s| s.risk_score.clone());
                                    let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                                        eval_ctx: &ctx,
                                        principal_type,
                                        principal_id,
                                        risk_score: session_risk.as_ref(),
                                    };
                                    match abac.evaluate(&action, &abac_ctx) {
                                        vellaveto_engine::abac::AbacDecision::Deny {
                                            policy_id,
                                            reason,
                                        } => {
                                            let deny_verdict = Verdict::Deny {
                                                reason: format!(
                                                    "ABAC denied by {}: {}",
                                                    policy_id, reason
                                                ),
                                            };
                                            if let Err(e) = state
                                                .audit
                                                .log_entry(
                                                    &action,
                                                    &deny_verdict,
                                                    json!({
                                                        "source": "ws_proxy",
                                                        "session": session_id,
                                                        "transport": "websocket",
                                                        "abac_policy": policy_id,
                                                    }),
                                                )
                                                .await
                                            {
                                                tracing::warn!(
                                                    "Failed to audit WS ABAC deny: {}",
                                                    e
                                                );
                                            }
                                            // SECURITY (FIND-R46-012): Generic message to client;
                                            // detailed reason (ABAC policy_id, reason) is in
                                            // the audit log only.
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32001,
                                                "Denied by policy",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                        vellaveto_engine::abac::AbacDecision::Allow {
                                            policy_id,
                                        } => {
                                            if let Some(ref la) = state.least_agency {
                                                la.record_usage(
                                                    principal_id,
                                                    &session_id,
                                                    &policy_id,
                                                    tool_name,
                                                    "",
                                                );
                                            }
                                        }
                                        vellaveto_engine::abac::AbacDecision::NoMatch => {
                                            // Fall through — existing Allow stands
                                        }
                                        #[allow(unreachable_patterns)]
                                        // AbacDecision is #[non_exhaustive]
                                        _ => {
                                            // SECURITY (FIND-R74-002): Future variants — fail-closed (deny).
                                            // Must send deny and continue, not fall through to Allow path.
                                            tracing::warn!(
                                                "Unknown AbacDecision variant — fail-closed"
                                            );
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32001,
                                                "Denied by policy",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                }

                                // SECURITY (FIND-R46-013): Record tool call in registry on Allow
                                if let Some(ref registry) = state.tool_registry {
                                    registry.record_call(tool_name).await;
                                }

                                // Touch session and update call_counts/action_history
                                if let Some(mut session) = state.sessions.get_mut(&session_id) {
                                    session.touch();
                                    // SECURITY (FIND-R54-003): Update call_counts and action_history
                                    // on Allow. Without this, context-aware policies
                                    // (max_calls_in_window, ForbiddenActionSequence) are
                                    // ineffective on the WebSocket transport.
                                    use crate::proxy::call_chain::{
                                        MAX_ACTION_HISTORY, MAX_CALL_COUNT_TOOLS,
                                    };
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
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &Verdict::Allow,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS allow: {}", e);
                                }

                                // Canonicalize and forward
                                let forward_text = if state.canonicalize {
                                    match serde_json::to_string(&parsed) {
                                        Ok(canonical) => canonical,
                                        Err(e) => {
                                            tracing::error!(
                                                "SECURITY: WS canonicalization failed: {}",
                                                e
                                            );
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32603,
                                                "Internal error",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                } else {
                                    text.to_string()
                                };

                                // Track request→response mapping for output-schema
                                // enforcement when upstream omits result._meta.tool.
                                track_pending_tool_call(
                                    &state.sessions,
                                    &session_id,
                                    id,
                                    tool_name,
                                );

                                let mut sink = upstream_sink.lock().await;
                                if let Err(e) = sink
                                    .send(tokio_tungstenite::tungstenite::Message::Text(
                                        forward_text.into(),
                                    ))
                                    .await
                                {
                                    tracing::error!(
                                        session_id = %session_id,
                                        "Failed to forward to upstream: {}",
                                        e
                                    );
                                    break;
                                }
                            }
                            Verdict::Deny { ref reason } => {
                                // Audit the denial with detailed reason
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS deny: {}", e);
                                }

                                // SECURITY (FIND-R46-012): Generic message to client.
                                // Detailed reason is in the audit log only.
                                let _ = reason; // used in audit above
                                let error =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                            }
                            Verdict::RequireApproval { ref reason, .. } => {
                                // Treat as deny for audit, but preserve approval semantics.
                                let deny_reason = format!("Requires approval: {}", reason);
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &Verdict::Deny {
                                            reason: deny_reason.clone(),
                                        },
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS approval request: {}", e);
                                }
                                let approval_reason = "Approval required";
                                let approval_id =
                                    create_ws_approval(&state, &session_id, &action, reason).await;
                                let error = make_ws_error_response_with_data(
                                    Some(id),
                                    -32001,
                                    approval_reason,
                                    Some(json!({
                                        "verdict": "require_approval",
                                        "reason": approval_reason,
                                        "approval_id": approval_id,
                                    })),
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                            }
                            // Fail-closed: unknown Verdict variants produce Deny
                            _ => {
                                let error =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                            }
                        }
                    }
                    MessageType::ResourceRead { ref id, ref uri } => {
                        // SECURITY (FIND-R74-007): Check for memory poisoning in resource URI.
                        // ResourceRead is a likely exfiltration vector: a poisoned tool response
                        // says "read this file" and the agent issues resources/read for that URI.
                        // Parity with HTTP handler (handlers.rs:1472).
                        {
                            let poisoning_detected = state
                                .sessions
                                .get_mut(&session_id)
                                .and_then(|session| {
                                    let uri_params = json!({"uri": uri});
                                    let matches =
                                        session.memory_tracker.check_parameters(&uri_params);
                                    if !matches.is_empty() {
                                        for m in &matches {
                                            tracing::warn!(
                                                "SECURITY: Memory poisoning detected in WS resources/read (session {}): \
                                                 param '{}' contains replayed data (fingerprint: {})",
                                                session_id,
                                                m.param_location,
                                                m.fingerprint
                                            );
                                        }
                                        Some(matches.len())
                                    } else {
                                        None
                                    }
                                });
                            if let Some(match_count) = poisoning_detected {
                                let poison_action = extractor::extract_resource_action(uri);
                                let deny_reason = format!(
                                    "Memory poisoning detected: {} replayed data fragment(s) in resources/read",
                                    match_count
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &poison_action,
                                        &Verdict::Deny {
                                            reason: deny_reason.clone(),
                                        },
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "memory_poisoning_detected",
                                            "matches": match_count,
                                            "uri": uri,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS resource memory poisoning: {}",
                                        e
                                    );
                                }
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "Request blocked: security policy violation",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // Build action for resource read
                        let mut action = extractor::extract_resource_action(uri);

                        // SECURITY (FIND-R75-002): DNS resolution for resource reads.
                        // Parity with HTTP handler (handlers.rs:1543).
                        if state.engine.has_ip_rules() {
                            super::helpers::resolve_domains(&mut action).await;
                        }

                        let ctx = build_ws_evaluation_context(&state, &session_id);
                        let verdict = match state.engine.evaluate_action_with_context(
                            &action,
                            &state.policies,
                            Some(&ctx),
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::error!(
                                    session_id = %session_id,
                                    "Resource policy evaluation error: {}",
                                    e
                                );
                                Verdict::Deny {
                                    reason: format!("Policy evaluation failed: {}", e),
                                }
                            }
                        };

                        match verdict {
                            Verdict::Allow => {
                                // SECURITY (FIND-R46-WS-004): Audit log allowed resource reads
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &Verdict::Allow,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "resource_uri": uri,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS resource read allow: {}", e);
                                }

                                // SECURITY (FIND-R46-011): Fail-closed on canonicalization
                                // failure. Do NOT fall back to original text.
                                let forward_text = if state.canonicalize {
                                    match serde_json::to_string(&parsed) {
                                        Ok(canonical) => canonical,
                                        Err(e) => {
                                            tracing::error!(
                                                "SECURITY: WS resource canonicalization failed: {}",
                                                e
                                            );
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32603,
                                                "Internal error",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                } else {
                                    text.to_string()
                                };
                                let mut sink = upstream_sink.lock().await;
                                if let Err(e) = sink
                                    .send(tokio_tungstenite::tungstenite::Message::Text(
                                        forward_text.into(),
                                    ))
                                    .await
                                {
                                    tracing::error!("Failed to forward resource read: {}", e);
                                    break;
                                }
                            }
                            _ => {
                                // SECURITY (FIND-R46-012): Generic message to client.
                                // Detailed reason is preserved in audit log above.
                                let error =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                            }
                        }
                    }
                    MessageType::Batch => {
                        // Reject batches per MCP spec
                        let error = json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32600,
                                "message": "JSON-RPC batch requests are not supported"
                            },
                            "id": null
                        });
                        let error_text = serde_json::to_string(&error)
                            .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Batch not supported"},"id":null}"#.to_string());
                        let mut sink = client_sink.lock().await;
                        let _ = sink.send(Message::Text(error_text.into())).await;
                    }
                    MessageType::Invalid { ref id, ref reason } => {
                        let error = make_ws_error_response(Some(id), -32600, reason);
                        let mut sink = client_sink.lock().await;
                        let _ = sink.send(Message::Text(error.into())).await;
                    }
                    MessageType::SamplingRequest { ref id } => {
                        // SECURITY (FIND-R74-006): Call inspect_sampling() for full
                        // verdict (enabled + model filter + tool output check),
                        // matching HTTP handler parity (handlers.rs:1681).
                        let params = parsed.get("params").cloned().unwrap_or(json!({}));
                        let sampling_verdict =
                            vellaveto_mcp::elicitation::inspect_sampling(
                                &params,
                                &state.sampling_config,
                            );
                        match sampling_verdict {
                            vellaveto_mcp::elicitation::SamplingVerdict::Allow => {
                                // Forward allowed sampling request
                                // SECURITY (FIND-R48-001): Fail-closed on canonicalization failure.
                                // Falling back to original text would create a TOCTOU gap.
                                let forward_text = if state.canonicalize {
                                    match serde_json::to_string(&parsed) {
                                        Ok(canonical) => canonical,
                                        Err(e) => {
                                            tracing::error!(
                                                "SECURITY: WS sampling canonicalization failed: {}",
                                                e
                                            );
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32603,
                                                "Internal error",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ = sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                } else {
                                    text.to_string()
                                };
                                let mut sink = upstream_sink.lock().await;
                                let _ = sink
                                    .send(tokio_tungstenite::tungstenite::Message::Text(
                                        forward_text.into(),
                                    ))
                                    .await;
                            }
                            vellaveto_mcp::elicitation::SamplingVerdict::Deny { reason } => {
                                tracing::warn!(
                                    session_id = %session_id,
                                    "Blocked WS sampling/createMessage: {}",
                                    reason
                                );
                                let action = Action::new(
                                    "vellaveto",
                                    "ws_sampling_interception",
                                    json!({
                                        "method": "sampling/createMessage",
                                        "session": session_id,
                                        "transport": "websocket",
                                        "reason": &reason,
                                    }),
                                );
                                let verdict = Verdict::Deny {
                                    reason: reason.clone(),
                                };
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "event": "ws_sampling_interception",
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS sampling interception: {}",
                                        e
                                    );
                                }
                                // SECURITY: Generic message to client — detailed reason
                                // is in the audit log, not leaked to the client.
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "sampling/createMessage blocked by policy",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                            }
                        }
                    }
                    MessageType::TaskRequest {
                        ref id,
                        ref task_method,
                        ref task_id,
                    } => {
                        // SECURITY (FIND-R76-001): Memory poisoning detection on task params.
                        // Parity with HTTP handler (handlers.rs:2027-2084). Agents could
                        // exfiltrate poisoned data via task management operations.
                        {
                            let task_params = parsed.get("params").cloned().unwrap_or(json!({}));
                            let poisoning_detected = state
                                .sessions
                                .get_mut(&session_id)
                                .and_then(|session| {
                                    let matches =
                                        session.memory_tracker.check_parameters(&task_params);
                                    if !matches.is_empty() {
                                        for m in &matches {
                                            tracing::warn!(
                                                "SECURITY: Memory poisoning detected in WS task '{}' (session {}): \
                                                 param '{}' contains replayed data (fingerprint: {})",
                                                task_method,
                                                session_id,
                                                m.param_location,
                                                m.fingerprint
                                            );
                                        }
                                        Some(matches.len())
                                    } else {
                                        None
                                    }
                                });
                            if let Some(match_count) = poisoning_detected {
                                let poison_action =
                                    extractor::extract_task_action(task_method, task_id.as_deref());
                                let deny_reason = format!(
                                    "Memory poisoning detected: {} replayed data fragment(s) in task '{}'",
                                    match_count, task_method
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &poison_action,
                                        &Verdict::Deny {
                                            reason: deny_reason,
                                        },
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "memory_poisoning_detected",
                                            "matches": match_count,
                                            "task_method": task_method,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS task memory poisoning: {}", e);
                                }
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "Request blocked: security policy violation",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // SECURITY (FIND-R76-001): DLP scan task request parameters.
                        // Parity with HTTP handler (handlers.rs:2086-2145). Agents could
                        // embed secrets in task_id or params to exfiltrate them.
                        {
                            let task_params = parsed.get("params").cloned().unwrap_or(json!({}));
                            let dlp_findings = scan_parameters_for_secrets(&task_params);
                            if !dlp_findings.is_empty() {
                                for finding in &dlp_findings {
                                    record_dlp_finding(&finding.pattern_name);
                                }
                                let patterns: Vec<String> = dlp_findings
                                    .iter()
                                    .map(|f| format!("{} at {}", f.pattern_name, f.location))
                                    .collect();
                                tracing::warn!(
                                    "SECURITY: DLP blocking WS task '{}' in session {}: {:?}",
                                    task_method,
                                    session_id,
                                    patterns
                                );
                                let dlp_action =
                                    extractor::extract_task_action(task_method, task_id.as_deref());
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &dlp_action,
                                        &Verdict::Deny {
                                            reason: format!(
                                                "DLP: secrets detected in task request: {:?}",
                                                patterns
                                            ),
                                        },
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "dlp_secret_detected_task",
                                            "task_method": task_method,
                                            "findings": patterns,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS task DLP: {}", e);
                                }
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "Request blocked: security policy violation",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // Policy-evaluate task requests (async operations)
                        let action =
                            extractor::extract_task_action(task_method, task_id.as_deref());
                        let ctx = build_ws_evaluation_context(&state, &session_id);
                        let verdict = match state.engine.evaluate_action_with_context(
                            &action,
                            &state.policies,
                            Some(&ctx),
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::error!(
                                    session_id = %session_id,
                                    "Task policy evaluation error: {}", e
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
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "task_method": task_method,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS task allow: {}", e);
                                }
                                // SECURITY (FIND-R48-001): Fail-closed on canonicalization failure.
                                let forward_text = if state.canonicalize {
                                    match serde_json::to_string(&parsed) {
                                        Ok(canonical) => canonical,
                                        Err(e) => {
                                            tracing::error!(
                                                "SECURITY: WS task canonicalization failed: {}",
                                                e
                                            );
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32603,
                                                "Internal error",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                } else {
                                    text.to_string()
                                };
                                let mut sink = upstream_sink.lock().await;
                                if let Err(e) = sink
                                    .send(tokio_tungstenite::tungstenite::Message::Text(
                                        forward_text.into(),
                                    ))
                                    .await
                                {
                                    tracing::error!("Failed to forward task request: {}", e);
                                    break;
                                }
                            }
                            Verdict::Deny { ref reason } => {
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &Verdict::Deny {
                                            reason: reason.clone(),
                                        },
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "task_method": task_method,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS task deny: {}", e);
                                }
                                // SECURITY (FIND-R55-WS-005): Generic denial message to prevent
                                // leaking policy names/details. Detailed reason is in audit log.
                                let denial =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial.into())).await;
                            }
                            Verdict::RequireApproval { ref reason, .. } => {
                                let deny_reason = format!("Requires approval: {}", reason);
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &Verdict::Deny {
                                            reason: deny_reason,
                                        },
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "task_method": task_method,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS task approval request: {}",
                                        e
                                    );
                                }
                                let approval_reason = "Approval required";
                                let approval_id =
                                    create_ws_approval(&state, &session_id, &action, reason).await;
                                let denial = make_ws_error_response_with_data(
                                    Some(id),
                                    -32001,
                                    approval_reason,
                                    Some(json!({
                                        "verdict": "require_approval",
                                        "reason": approval_reason,
                                        "approval_id": approval_id,
                                    })),
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial.into())).await;
                            }
                            _ => {
                                let denial =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial.into())).await;
                            }
                        }
                    }
                    MessageType::ExtensionMethod {
                        ref id,
                        ref extension_id,
                        ref method,
                    } => {
                        // Policy-evaluate extension method calls
                        let params = parsed.get("params").cloned().unwrap_or(json!({}));
                        let action =
                            extractor::extract_extension_action(extension_id, method, &params);
                        let ctx = build_ws_evaluation_context(&state, &session_id);
                        let verdict = match state.engine.evaluate_action_with_context(
                            &action,
                            &state.policies,
                            Some(&ctx),
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
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "extension_id": extension_id,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS extension allow: {}", e);
                                }
                                // SECURITY (FIND-R48-001): Fail-closed on canonicalization failure.
                                let forward_text = if state.canonicalize {
                                    match serde_json::to_string(&parsed) {
                                        Ok(canonical) => canonical,
                                        Err(e) => {
                                            tracing::error!("SECURITY: WS extension canonicalization failed: {}", e);
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32603,
                                                "Internal error",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                } else {
                                    text.to_string()
                                };
                                let mut sink = upstream_sink.lock().await;
                                if let Err(e) = sink
                                    .send(tokio_tungstenite::tungstenite::Message::Text(
                                        forward_text.into(),
                                    ))
                                    .await
                                {
                                    tracing::error!("Failed to forward extension request: {}", e);
                                    break;
                                }
                            }
                            Verdict::Deny { ref reason } => {
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &Verdict::Deny {
                                            reason: reason.clone(),
                                        },
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "extension_id": extension_id,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS extension deny: {}", e);
                                }
                                let denial = extractor::make_denial_response(id, reason.as_str());
                                let denial_text = serde_json::to_string(&denial)
                                    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32001,"message":"Denied"}}"#.to_string());
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial_text.into())).await;
                            }
                            Verdict::RequireApproval { ref reason, .. } => {
                                let deny_reason = format!("Requires approval: {}", reason);
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &Verdict::Deny {
                                            reason: deny_reason,
                                        },
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "extension_id": extension_id,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS extension approval request: {}",
                                        e
                                    );
                                }
                                let approval_reason = "Approval required";
                                let approval_id =
                                    create_ws_approval(&state, &session_id, &action, reason).await;
                                let denial = make_ws_error_response_with_data(
                                    Some(id),
                                    -32001,
                                    approval_reason,
                                    Some(json!({
                                        "verdict": "require_approval",
                                        "reason": approval_reason,
                                        "approval_id": approval_id,
                                    })),
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial.into())).await;
                            }
                            _ => {
                                let denial =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial.into())).await;
                            }
                        }
                    }
                    MessageType::ElicitationRequest { ref id } => {
                        // SECURITY (FIND-R46-010): Policy checks for elicitation requests.
                        // Match the HTTP POST handler's elicitation inspection logic.
                        let params = parsed.get("params").cloned().unwrap_or(json!({}));
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
                                let action = Action::new(
                                    "vellaveto",
                                    "ws_forward_message",
                                    json!({
                                        "message_type": "elicitation_request",
                                        "session": session_id,
                                        "transport": "websocket",
                                        "direction": "client_to_upstream",
                                    }),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &Verdict::Allow,
                                        json!({
                                            "source": "ws_proxy",
                                            "event": "ws_elicitation_forwarded",
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS elicitation: {}", e);
                                }

                                // SECURITY (FIND-R48-001): Fail-closed on canonicalization failure.
                                let forward_text = if state.canonicalize {
                                    match serde_json::to_string(&parsed) {
                                        Ok(canonical) => canonical,
                                        Err(e) => {
                                            tracing::error!("SECURITY: WS elicitation canonicalization failed: {}", e);
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32603,
                                                "Internal error",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                } else {
                                    text.to_string()
                                };
                                let mut sink = upstream_sink.lock().await;
                                if let Err(e) = sink
                                    .send(tokio_tungstenite::tungstenite::Message::Text(
                                        forward_text.into(),
                                    ))
                                    .await
                                {
                                    // Rollback pre-incremented count on forward failure
                                    if let Some(mut s) = state.sessions.get_mut(&session_id) {
                                        s.elicitation_count = s.elicitation_count.saturating_sub(1);
                                    }
                                    tracing::error!("Failed to forward elicitation: {}", e);
                                    break;
                                }
                            }
                            vellaveto_mcp::elicitation::ElicitationVerdict::Deny { reason } => {
                                tracing::warn!(
                                    session_id = %session_id,
                                    "Blocked WS elicitation/create: {}",
                                    reason
                                );
                                let action = Action::new(
                                    "vellaveto",
                                    "ws_elicitation_interception",
                                    json!({
                                        "method": "elicitation/create",
                                        "session": session_id,
                                        "transport": "websocket",
                                        "reason": &reason,
                                    }),
                                );
                                let verdict = Verdict::Deny {
                                    reason: reason.clone(),
                                };
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "event": "ws_elicitation_interception",
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS elicitation interception: {}",
                                        e
                                    );
                                }
                                // SECURITY (FIND-R46-012, FIND-R55-WS-006): Generic message to client.
                                let error =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                            }
                        }
                    }
                    MessageType::PassThrough | MessageType::ProgressNotification { .. } => {
                        // SECURITY (FIND-R76-003): DLP scan PassThrough params for secrets.
                        // Parity with HTTP handler (handlers.rs:1795-1859). Agents could
                        // exfiltrate secrets via prompts/get, completion/complete, or any
                        // PassThrough method's parameters.
                        if state.response_dlp_enabled && parsed.get("method").is_some() {
                            let dlp_findings = scan_notification_for_secrets(&parsed);
                            if !dlp_findings.is_empty() {
                                for finding in &dlp_findings {
                                    record_dlp_finding(&finding.pattern_name);
                                }
                                let patterns: Vec<String> = dlp_findings
                                    .iter()
                                    .map(|f| format!("{}:{}", f.pattern_name, f.location))
                                    .collect();
                                tracing::warn!(
                                    "SECURITY: Secrets in WS passthrough params! Session: {}, Findings: {:?}",
                                    session_id,
                                    patterns
                                );
                                let n_action = Action::new(
                                    "vellaveto",
                                    "notification_dlp_scan",
                                    json!({
                                        "findings": patterns,
                                        "session": session_id,
                                        "transport": "websocket",
                                    }),
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
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &n_action,
                                        &verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "event": "notification_dlp_alert",
                                            "blocked": state.response_dlp_blocking,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS passthrough DLP: {}", e);
                                }
                                if state.response_dlp_blocking {
                                    // Drop the message silently (passthrough has no id to respond to)
                                    continue;
                                }
                            }
                        }

                        // SECURITY (FIND-R46-WS-004): Audit log forwarded passthrough/notification messages
                        let msg_type = match &classified {
                            MessageType::ProgressNotification { .. } => "progress_notification",
                            _ => "passthrough",
                        };
                        let action = Action::new(
                            "vellaveto",
                            "ws_forward_message",
                            json!({
                                "message_type": msg_type,
                                "session": session_id,
                                "transport": "websocket",
                                "direction": "client_to_upstream",
                            }),
                        );
                        if let Err(e) = state
                            .audit
                            .log_entry(
                                &action,
                                &Verdict::Allow,
                                json!({
                                    "source": "ws_proxy",
                                    "event": "ws_message_forwarded",
                                }),
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit WS passthrough: {}", e);
                        }

                        // SECURITY (FIND-R48-001): Fail-closed on canonicalization failure.
                        let forward_text = if state.canonicalize {
                            match serde_json::to_string(&parsed) {
                                Ok(canonical) => canonical,
                                Err(e) => {
                                    tracing::error!(
                                        "SECURITY: WS passthrough canonicalization failed: {}",
                                        e
                                    );
                                    continue;
                                }
                            }
                        } else {
                            text.to_string()
                        };
                        let mut sink = upstream_sink.lock().await;
                        if let Err(e) = sink
                            .send(tokio_tungstenite::tungstenite::Message::Text(
                                forward_text.into(),
                            ))
                            .await
                        {
                            tracing::error!("Failed to forward passthrough: {}", e);
                            break;
                        }
                    }
                }
            }
            Message::Binary(_data) => {
                // SECURITY: Binary frames not allowed for JSON-RPC
                tracing::warn!(
                    session_id = %session_id,
                    "Binary WebSocket frame rejected (JSON-RPC is text-only)"
                );

                // SECURITY (FIND-R46-WS-004): Audit log binary frame rejection
                let action = Action::new(
                    "vellaveto",
                    "ws_binary_frame_rejected",
                    json!({
                        "session": session_id,
                        "transport": "websocket",
                        "direction": "client_to_upstream",
                    }),
                );
                if let Err(e) = state
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Deny {
                            reason: "Binary frames not supported for JSON-RPC".to_string(),
                        },
                        json!({
                            "source": "ws_proxy",
                            "event": "ws_binary_frame_rejected",
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit WS binary frame rejection: {}", e);
                }

                let mut sink = client_sink.lock().await;
                let _ = sink
                    .send(Message::Close(Some(CloseFrame {
                        code: CLOSE_UNSUPPORTED_DATA,
                        reason: "Binary frames not supported".into(),
                    })))
                    .await;
                break;
            }
            Message::Ping(data) => {
                let mut sink = client_sink.lock().await;
                let _ = sink.send(Message::Pong(data)).await;
            }
            Message::Pong(_) => {
                // Ignored
            }
            Message::Close(_) => {
                tracing::debug!(session_id = %session_id, "Client sent close frame");
                break;
            }
        }
    }
}

/// Relay messages from upstream to client with DLP and injection scanning.
#[allow(clippy::too_many_arguments)]
async fn relay_upstream_to_client(
    mut upstream_stream: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    client_sink: Arc<Mutex<futures_util::stream::SplitSink<WebSocket, Message>>>,
    state: ProxyState,
    session_id: String,
    ws_config: WebSocketConfig,
    upstream_rate_counter: Arc<AtomicU64>,
    upstream_rate_window_start: Arc<std::sync::Mutex<std::time::Instant>>,
) {
    while let Some(msg_result) = upstream_stream.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(session_id = %session_id, "Upstream WS error: {}", e);
                break;
            }
        };

        record_ws_message("upstream_to_client");

        // SECURITY (FIND-R46-WS-003): Rate limiting on upstream→client direction.
        // A malicious or compromised upstream could flood the client with messages.
        if !check_rate_limit(
            &upstream_rate_counter,
            &upstream_rate_window_start,
            ws_config.upstream_rate_limit,
        ) {
            tracing::warn!(
                session_id = %session_id,
                "WebSocket upstream rate limit exceeded ({}/s), dropping message",
                ws_config.upstream_rate_limit,
            );

            let action = Action::new(
                "vellaveto",
                "ws_upstream_rate_limit",
                json!({
                    "session": session_id,
                    "transport": "websocket",
                    "direction": "upstream_to_client",
                    "limit": ws_config.upstream_rate_limit,
                }),
            );
            if let Err(e) = state
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: "Upstream rate limit exceeded".to_string(),
                    },
                    json!({
                        "source": "ws_proxy",
                        "event": "ws_upstream_rate_limit_exceeded",
                    }),
                )
                .await
            {
                tracing::warn!("Failed to audit WS upstream rate limit: {}", e);
            }

            metrics::counter!(
                "vellaveto_ws_upstream_rate_limited_total",
                "session" => session_id.clone()
            )
            .increment(1);

            // Drop the message (don't close the connection — upstream flood should not
            // disconnect the client, just throttle the flow)
            continue;
        }

        match msg {
            tokio_tungstenite::tungstenite::Message::Text(text) => {
                // Try to parse for scanning
                let forward = if let Ok(json_val) = serde_json::from_str::<Value>(&text) {
                    // Resolve tracked tool context for response-side schema checks.
                    let tracked_tool_name =
                        take_tracked_tool_call(&state.sessions, &session_id, json_val.get("id"));

                    // SECURITY (FIND-R75-003): Track whether DLP or injection was detected
                    // (even in log-only mode) to gate memory_tracker.record_response().
                    // Recording fingerprints from tainted responses would poison the tracker.
                    let mut dlp_found = false;
                    let mut injection_found = false;

                    // DLP scanning on responses
                    if state.response_dlp_enabled {
                        let dlp_findings = scan_response_for_secrets(&json_val);
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
                                "SECURITY: Secrets in WS response! Session: {}, Findings: {:?}",
                                session_id,
                                patterns,
                            );

                            let verdict = if state.response_dlp_blocking {
                                Verdict::Deny {
                                    reason: format!("WS response DLP blocked: {:?}", patterns),
                                }
                            } else {
                                Verdict::Allow
                            };

                            let action = Action::new(
                                "vellaveto",
                                "ws_response_dlp_scan",
                                json!({
                                    "findings": patterns,
                                    "session": session_id,
                                    "transport": "websocket",
                                }),
                            );
                            if let Err(e) = state
                                .audit
                                .log_entry(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "ws_proxy",
                                        "event": "ws_response_dlp_alert",
                                    }),
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit WS DLP: {}", e);
                            }

                            if state.response_dlp_blocking {
                                // Send error response instead
                                let id = json_val.get("id");
                                let error = make_ws_error_response(
                                    id,
                                    -32001,
                                    "Response blocked by DLP policy",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }
                    }

                    // Injection scanning
                    if !state.injection_disabled {
                        let text_to_scan = extract_scannable_text(&json_val);
                        if !text_to_scan.is_empty() {
                            let injection_matches: Vec<String> =
                                if let Some(ref scanner) = state.injection_scanner {
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
                                    "SECURITY: Injection in WS response! Session: {}, Patterns: {:?}",
                                    session_id,
                                    injection_matches,
                                );

                                let verdict = if state.injection_blocking {
                                    Verdict::Deny {
                                        reason: format!(
                                            "WS response injection blocked: {:?}",
                                            injection_matches
                                        ),
                                    }
                                } else {
                                    Verdict::Allow
                                };

                                let action = Action::new(
                                    "vellaveto",
                                    "ws_response_injection",
                                    json!({
                                        "matched_patterns": injection_matches,
                                        "session": session_id,
                                        "transport": "websocket",
                                    }),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry(
                                        &action,
                                        &verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "event": "ws_injection_detected",
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS injection: {}", e);
                                }

                                if state.injection_blocking {
                                    let id = json_val.get("id");
                                    let error = make_ws_error_response(
                                        id,
                                        -32001,
                                        "Response blocked: injection detected",
                                    );
                                    let mut sink = client_sink.lock().await;
                                    let _ = sink.send(Message::Text(error.into())).await;
                                    continue;
                                }
                            }
                        }
                    }

                    // SECURITY (FIND-R46-007): Rug-pull detection on tools/list responses.
                    // Check if this is a response to a tools/list request and extract
                    // annotations for rug-pull detection.
                    if json_val.get("result").is_some() {
                        // Check if result contains "tools" array (tools/list response)
                        if json_val
                            .get("result")
                            .and_then(|r| r.get("tools"))
                            .and_then(|t| t.as_array())
                            .is_some()
                        {
                            super::helpers::extract_annotations_from_response(
                                &json_val,
                                &session_id,
                                &state.sessions,
                                &state.audit,
                                &state.known_tools,
                            )
                            .await;

                            // Verify manifest if configured
                            if let Some(ref manifest_config) = state.manifest_config {
                                super::helpers::verify_manifest_from_response(
                                    &json_val,
                                    &session_id,
                                    &state.sessions,
                                    manifest_config,
                                    &state.audit,
                                )
                                .await;
                            }
                        }
                    }

                    // SECURITY: Enforce output schema on WS structuredContent.
                    if validate_ws_structured_content_response(
                        &json_val,
                        &state,
                        &session_id,
                        tracked_tool_name.as_deref(),
                    )
                    .await
                    {
                        let id = json_val.get("id");
                        let error = make_ws_error_response(
                            id,
                            -32001,
                            "Response blocked: output schema validation failed",
                        );
                        let mut sink = client_sink.lock().await;
                        let _ = sink.send(Message::Text(error.into())).await;
                        continue;
                    }

                    // SECURITY (FIND-R75-003): Record response fingerprints for memory
                    // poisoning detection. Parity with HTTP handler (inspection.rs:638)
                    // and gRPC handler (service.rs:968). Skip recording when DLP or
                    // injection was detected (even in log-only mode) to avoid poisoning
                    // the tracker with tainted data.
                    if !dlp_found && !injection_found {
                        if let Some(mut session) = state.sessions.get_mut(&session_id) {
                            session.memory_tracker.record_response(&json_val);
                        }
                    }

                    // SECURITY (FIND-R46-WS-004): Audit log forwarded upstream→client text messages
                    {
                        let msg_type = if json_val.get("result").is_some() {
                            "response"
                        } else if json_val.get("error").is_some() {
                            "error_response"
                        } else if json_val.get("method").is_some() {
                            "notification"
                        } else {
                            "unknown"
                        };
                        let action = Action::new(
                            "vellaveto",
                            "ws_forward_upstream_message",
                            json!({
                                "message_type": msg_type,
                                "session": session_id,
                                "transport": "websocket",
                                "direction": "upstream_to_client",
                            }),
                        );
                        if let Err(e) = state
                            .audit
                            .log_entry(
                                &action,
                                &Verdict::Allow,
                                json!({
                                    "source": "ws_proxy",
                                    "event": "ws_upstream_message_forwarded",
                                }),
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit WS upstream message forward: {}", e);
                        }
                    }

                    // SECURITY (FIND-R48-001): Fail-closed on canonicalization failure.
                    if state.canonicalize {
                        match serde_json::to_string(&json_val) {
                            Ok(canonical) => canonical,
                            Err(e) => {
                                tracing::error!(
                                    "SECURITY: WS response canonicalization failed: {}",
                                    e
                                );
                                continue;
                            }
                        }
                    } else {
                        text.to_string()
                    }
                } else {
                    // Non-JSON text — forward as-is (may be SSE-like data)
                    text.to_string()
                };

                let mut sink = client_sink.lock().await;
                if let Err(e) = sink.send(Message::Text(forward.into())).await {
                    tracing::debug!("Failed to send to client: {}", e);
                    break;
                }
            }
            tokio_tungstenite::tungstenite::Message::Binary(data) => {
                // SECURITY (FIND-R46-WS-002): DLP scanning on upstream binary frames.
                // Binary from upstream is unusual for JSON-RPC but must be scanned
                // before being dropped, to detect and audit secret exfiltration attempts
                // via binary frames.
                tracing::warn!(
                    session_id = %session_id,
                    "Unexpected binary frame from upstream ({} bytes), scanning before drop",
                    data.len(),
                );

                // DLP scan the binary data as UTF-8 lossy
                if state.response_dlp_enabled {
                    let text_repr = String::from_utf8_lossy(&data);
                    if !text_repr.is_empty() {
                        let dlp_findings = scan_text_for_secrets(&text_repr, "ws_binary_frame");
                        if !dlp_findings.is_empty() {
                            for finding in &dlp_findings {
                                record_dlp_finding(&finding.pattern_name);
                            }
                            let patterns: Vec<String> = dlp_findings
                                .iter()
                                .map(|f| format!("{}:{}", f.pattern_name, f.location))
                                .collect();

                            tracing::warn!(
                                "SECURITY: Secrets in WS upstream binary frame! Session: {}, Findings: {:?}",
                                session_id,
                                patterns,
                            );

                            let action = Action::new(
                                "vellaveto",
                                "ws_binary_dlp_scan",
                                json!({
                                    "findings": patterns,
                                    "session": session_id,
                                    "transport": "websocket",
                                    "direction": "upstream_to_client",
                                    "binary_size": data.len(),
                                }),
                            );
                            if let Err(e) = state
                                .audit
                                .log_entry(
                                    &action,
                                    &Verdict::Deny {
                                        reason: format!("WS binary frame DLP: {:?}", patterns),
                                    },
                                    json!({
                                        "source": "ws_proxy",
                                        "event": "ws_binary_dlp_alert",
                                    }),
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit WS binary DLP: {}", e);
                            }
                        }
                    }
                }

                // SECURITY (FIND-R46-WS-004): Audit log binary frame drop
                let action = Action::new(
                    "vellaveto",
                    "ws_upstream_binary_dropped",
                    json!({
                        "session": session_id,
                        "transport": "websocket",
                        "direction": "upstream_to_client",
                        "binary_size": data.len(),
                    }),
                );
                if let Err(e) = state
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Deny {
                            reason: "Binary frames not supported for JSON-RPC".to_string(),
                        },
                        json!({
                            "source": "ws_proxy",
                            "event": "ws_upstream_binary_dropped",
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit WS upstream binary drop: {}", e);
                }
            }
            tokio_tungstenite::tungstenite::Message::Ping(data) => {
                // Forward ping as pong to upstream (handled by tungstenite)
                let _ = data; // tungstenite auto-responds to pings
            }
            tokio_tungstenite::tungstenite::Message::Pong(_) => {}
            tokio_tungstenite::tungstenite::Message::Close(_) => {
                tracing::debug!(session_id = %session_id, "Upstream sent close frame");
                break;
            }
            tokio_tungstenite::tungstenite::Message::Frame(_) => {
                // Raw frame — ignore
            }
        }
    }
}

/// Convert an HTTP URL to a WebSocket URL.
///
/// `http://` → `ws://`, `https://` → `wss://`.
pub fn convert_to_ws_url(http_url: &str) -> String {
    if let Some(rest) = http_url.strip_prefix("https://") {
        format!("wss://{}", rest)
    } else if let Some(rest) = http_url.strip_prefix("http://") {
        format!("ws://{}", rest)
    } else {
        // Already ws(s):// or unknown scheme — use as-is
        http_url.to_string()
    }
}

/// Connect to an upstream WebSocket server.
///
/// Returns the split WebSocket stream or an error.
async fn connect_upstream_ws(
    url: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    String,
> {
    let connect_timeout = Duration::from_secs(10);
    match tokio::time::timeout(connect_timeout, tokio_tungstenite::connect_async(url)).await {
        Ok(Ok((ws_stream, _response))) => Ok(ws_stream),
        Ok(Err(e)) => Err(format!("WebSocket connection error: {}", e)),
        Err(_) => Err("WebSocket connection timeout (10s)".to_string()),
    }
}

/// Register output schemas and validate WS response `structuredContent`.
///
/// Returns true when the response should be blocked.
async fn validate_ws_structured_content_response(
    json_val: &Value,
    state: &ProxyState,
    session_id: &str,
    tracked_tool_name: Option<&str>,
) -> bool {
    // Keep WS behavior aligned with HTTP/SSE paths.
    state
        .output_schema_registry
        .register_from_tools_list(json_val);

    let Some(result) = json_val.get("result") else {
        return false;
    };
    let Some(structured) = result.get("structuredContent") else {
        return false;
    };

    let meta_tool_name = result
        .get("_meta")
        .and_then(|m| m.get("tool"))
        .and_then(|t| t.as_str());
    let tool_name = match (meta_tool_name, tracked_tool_name) {
        (Some(meta), Some(tracked)) if !meta.eq_ignore_ascii_case(tracked) => {
            tracing::warn!(
                "SECURITY: WS structuredContent tool mismatch (meta='{}', tracked='{}'); using tracked tool name",
                meta,
                tracked
            );
            tracked
        }
        (Some(meta), _) => meta,
        (None, Some(tracked)) => tracked,
        (None, None) => "unknown",
    };

    match state.output_schema_registry.validate(tool_name, structured) {
        ValidationResult::Invalid { violations } => {
            tracing::warn!(
                "SECURITY: WS structuredContent validation failed for tool '{}': {:?}",
                tool_name,
                violations
            );
            let action = Action::new(
                "vellaveto",
                "output_schema_violation",
                json!({
                    "tool": tool_name,
                    "violations": violations,
                    "session": session_id,
                    "transport": "websocket",
                }),
            );
            if let Err(e) = state
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: format!("WS structuredContent validation failed: {:?}", violations),
                    },
                    json!({"source": "ws_proxy", "event": "output_schema_violation_ws"}),
                )
                .await
            {
                tracing::warn!("Failed to audit WS output schema violation: {}", e);
            }
            true
        }
        ValidationResult::Valid => {
            tracing::debug!("WS structuredContent validated for tool '{}'", tool_name);
            false
        }
        ValidationResult::NoSchema => {
            tracing::debug!(
                "No output schema registered for WS tool '{}', skipping validation",
                tool_name
            );
            false
        }
    }
}

/// Build an EvaluationContext for WebSocket policy evaluation.
fn build_ws_evaluation_context(state: &ProxyState, session_id: &str) -> EvaluationContext {
    let mut ctx = EvaluationContext::default();

    if let Some(session) = state.sessions.get_mut(session_id) {
        ctx.call_counts = session.call_counts.clone();
        ctx.previous_actions = session.action_history.iter().cloned().collect();
        if let Some(ref agent_id) = session.oauth_subject {
            ctx.agent_id = Some(agent_id.clone());
        }
        // SECURITY (FIND-R74-003): Include agent_identity and call_chain for parity
        // with HTTP handler (handlers.rs:731-734) and gRPC handler (service.rs:1241-1242).
        // Without these, WS policy evaluation cannot enforce identity-based or
        // call-chain-based context conditions.
        ctx.agent_identity = session.agent_identity.clone();
        ctx.call_chain = session.current_call_chain.clone();
    }

    ctx
}

/// Check per-connection rate limit. Returns true if within limit.
fn check_rate_limit(
    counter: &AtomicU64,
    window_start: &std::sync::Mutex<std::time::Instant>,
    max_per_sec: u32,
) -> bool {
    if max_per_sec == 0 {
        return true; // No limit
    }

    let now = std::time::Instant::now();
    let mut start = window_start.lock().unwrap_or_else(|e| e.into_inner());

    if now.duration_since(*start) >= Duration::from_secs(1) {
        // Reset window
        *start = now;
        // SECURITY (FIND-R55-WS-003): Use SeqCst for security-critical rate limit counter.
        counter.store(1, Ordering::SeqCst);
        true
    } else {
        let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
        count <= max_per_sec as u64
    }
}

/// Extract scannable text from a JSON-RPC request for injection scanning.
///
/// SECURITY (FIND-R46-WS-001): Scans tool call arguments, resource URIs,
/// and sampling request content for injection payloads in the client→upstream
/// direction. Matches the HTTP proxy's request-side injection scanning.
fn extract_scannable_text_from_request(json_val: &Value) -> String {
    let mut text_parts = Vec::new();

    // Scan tool call arguments
    if let Some(params) = json_val.get("params") {
        if let Some(arguments) = params.get("arguments") {
            // Recursively extract string values from arguments
            extract_strings_recursive(arguments, &mut text_parts, 0);
        }
        // Scan resource URI
        if let Some(uri) = params.get("uri").and_then(|u| u.as_str()) {
            text_parts.push(uri.to_string());
        }
        // Scan sampling content
        if let Some(messages) = params.get("messages").and_then(|m| m.as_array()) {
            for msg in messages {
                if let Some(content) = msg.get("content") {
                    if let Some(text) = content.get("text").and_then(|t| t.as_str()) {
                        text_parts.push(text.to_string());
                    }
                }
            }
        }
        // Scan tool name (for injection in tool names)
        if let Some(name) = params.get("name").and_then(|n| n.as_str()) {
            text_parts.push(name.to_string());
        }
    }

    text_parts.join("\n")
}

/// Recursively extract string values from a JSON value, with depth and count bounds.
///
/// SECURITY (FIND-R48-007): Added MAX_PARTS to prevent memory amplification
/// from messages containing many short strings.
fn extract_strings_recursive(val: &Value, parts: &mut Vec<String>, depth: usize) {
    const MAX_DEPTH: usize = 10;
    const MAX_PARTS: usize = 1000;
    if depth > MAX_DEPTH || parts.len() >= MAX_PARTS {
        return;
    }
    match val {
        Value::String(s) => parts.push(s.clone()),
        Value::Array(arr) => {
            for item in arr {
                extract_strings_recursive(item, parts, depth + 1);
            }
        }
        Value::Object(map) => {
            for (_key, v) in map {
                extract_strings_recursive(v, parts, depth + 1);
            }
        }
        _ => {}
    }
}

/// Extract scannable text from a JSON-RPC response for injection scanning.
fn extract_scannable_text(json_val: &Value) -> String {
    let mut text_parts = Vec::new();

    // Scan result content
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

    // Scan error messages
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

/// Create a pending approval for WebSocket-denied actions when an approval store
/// is configured. Returns the pending approval ID on success.
async fn create_ws_approval(
    state: &ProxyState,
    session_id: &str,
    action: &Action,
    reason: &str,
) -> Option<String> {
    let store = state.approval_store.as_ref()?;
    let requested_by = state.sessions.get_mut(session_id).and_then(|session| {
        session
            .agent_identity
            .as_ref()
            .and_then(|identity| identity.subject.clone())
            .or_else(|| session.oauth_subject.clone())
    });
    match store
        .create(action.clone(), reason.to_string(), requested_by)
        .await
    {
        Ok(id) => Some(id),
        Err(e) => {
            tracing::error!(
                session_id = %session_id,
                "Failed to create WebSocket approval (fail-closed): {}",
                e
            );
            None
        }
    }
}

/// Build a JSON-RPC error response string for WebSocket with optional `error.data`.
fn make_ws_error_response_with_data(
    id: Option<&Value>,
    code: i64,
    message: &str,
    data: Option<Value>,
) -> String {
    let mut error = serde_json::Map::new();
    error.insert("code".to_string(), Value::from(code));
    error.insert("message".to_string(), Value::from(message));
    if let Some(data) = data {
        error.insert("data".to_string(), data);
    }
    let response = json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": Value::Object(error),
    });
    serde_json::to_string(&response).unwrap_or_else(|_| {
        format!(
            r#"{{"jsonrpc":"2.0","error":{{"code":{},"message":"{}"}},"id":null}}"#,
            code, message
        )
    })
}

/// Build a JSON-RPC error response string for WebSocket.
fn make_ws_error_response(id: Option<&Value>, code: i64, message: &str) -> String {
    make_ws_error_response_with_data(id, code, message, None)
}

#[cfg(test)]
mod tests;
