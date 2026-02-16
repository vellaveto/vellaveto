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
use vellaveto_mcp::inspection::{inspect_for_injection, scan_response_for_secrets, scan_text_for_secrets};
use vellaveto_types::{Action, EvaluationContext, Verdict};

use super::auth::validate_api_key;
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

    // 3. Get or create session
    let session_id = state.sessions.get_or_create(query.session_id.as_deref());

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
                        let action = extractor::extract_action(tool_name, arguments);
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
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32001,
                                                &format!(
                                                    "ABAC denied by {}: {}",
                                                    policy_id, reason
                                                ),
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
                                    }
                                }

                                // Touch session
                                if let Some(mut session) = state.sessions.get_mut(&session_id) {
                                    session.touch();
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
                                // Audit the denial
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

                                // Send JSON-RPC error back to client
                                let denial = extractor::make_denial_response(id, reason);
                                let denial_text = serde_json::to_string(&denial)
                                    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32001,"message":"Denied by policy"}}"#.to_string());
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial_text.into())).await;
                            }
                            Verdict::RequireApproval { ref reason, .. } => {
                                // Treat as deny for WebSocket transport
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
                                let denial = extractor::make_denial_response(id, &deny_reason);
                                let denial_text = serde_json::to_string(&denial)
                                    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32001,"message":"Requires approval"}}"#.to_string());
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial_text.into())).await;
                            }
                            // Fail-closed: unknown Verdict variants produce Deny
                            _ => {
                                let denial = extractor::make_denial_response(
                                    id,
                                    "Unknown verdict — fail-closed",
                                );
                                let denial_text = serde_json::to_string(&denial)
                                    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32001,"message":"Denied"}}"#.to_string());
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial_text.into())).await;
                            }
                        }
                    }
                    MessageType::ResourceRead { ref id, ref uri } => {
                        // Build action for resource read
                        let action = extractor::extract_resource_action(uri);
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

                                let forward_text = if state.canonicalize {
                                    serde_json::to_string(&parsed)
                                        .unwrap_or_else(|_| text.to_string())
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
                                let reason = match &verdict {
                                    Verdict::Deny { reason } => reason.clone(),
                                    _ => "Resource access denied".to_string(),
                                };
                                let denial = extractor::make_denial_response(id, &reason);
                                let denial_text = serde_json::to_string(&denial)
                                    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32001,"message":"Denied"}}"#.to_string());
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial_text.into())).await;
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
                        // Check sampling config
                        if !state.sampling_config.enabled {
                            let denial = extractor::make_denial_response(
                                id,
                                "Sampling requests are disabled",
                            );
                            let denial_text = serde_json::to_string(&denial)
                                .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32001,"message":"Sampling disabled"}}"#.to_string());
                            let mut sink = client_sink.lock().await;
                            let _ = sink.send(Message::Text(denial_text.into())).await;
                        } else {
                            // Forward allowed sampling request
                            let forward_text = if state.canonicalize {
                                serde_json::to_string(&parsed).unwrap_or_else(|_| text.to_string())
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
                    }
                    MessageType::TaskRequest {
                        ref id,
                        ref task_method,
                        ref task_id,
                    } => {
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
                                let forward_text = if state.canonicalize {
                                    serde_json::to_string(&parsed)
                                        .unwrap_or_else(|_| text.to_string())
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
                            Verdict::Deny { ref reason }
                            | Verdict::RequireApproval { ref reason, .. } => {
                                let deny_reason =
                                    if matches!(verdict, Verdict::RequireApproval { .. }) {
                                        format!("Requires approval: {}", reason)
                                    } else {
                                        reason.clone()
                                    };
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
                                            "task_method": task_method,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS task deny: {}", e);
                                }
                                let denial = extractor::make_denial_response(id, &deny_reason);
                                let denial_text = serde_json::to_string(&denial)
                                    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32001,"message":"Denied"}}"#.to_string());
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial_text.into())).await;
                            }
                            _ => {
                                let denial = extractor::make_denial_response(
                                    id,
                                    "Unknown verdict — fail-closed",
                                );
                                let denial_text = serde_json::to_string(&denial)
                                    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32001,"message":"Denied"}}"#.to_string());
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial_text.into())).await;
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
                                let forward_text = if state.canonicalize {
                                    serde_json::to_string(&parsed)
                                        .unwrap_or_else(|_| text.to_string())
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
                                let denial = extractor::make_denial_response(id, &reason);
                                let denial_text = serde_json::to_string(&denial)
                                    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32001,"message":"Denied"}}"#.to_string());
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial_text.into())).await;
                            }
                        }
                    }
                    MessageType::PassThrough
                    | MessageType::ElicitationRequest { .. }
                    | MessageType::ProgressNotification { .. } => {
                        // SECURITY (FIND-R46-WS-004): Audit log forwarded passthrough/notification messages
                        let msg_type = match &classified {
                            MessageType::ElicitationRequest { .. } => "elicitation_request",
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

                        // Forward as-is (canonicalized if enabled)
                        let forward_text = if state.canonicalize {
                            serde_json::to_string(&parsed).unwrap_or_else(|_| text.to_string())
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
                    // DLP scanning on responses
                    if state.response_dlp_enabled {
                        let dlp_findings = scan_response_for_secrets(&json_val);
                        if !dlp_findings.is_empty() {
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

                    // Canonicalize response if enabled
                    if state.canonicalize {
                        serde_json::to_string(&json_val).unwrap_or_else(|_| text.to_string())
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

/// Build an EvaluationContext for WebSocket policy evaluation.
fn build_ws_evaluation_context(state: &ProxyState, session_id: &str) -> EvaluationContext {
    let mut ctx = EvaluationContext::default();

    if let Some(session) = state.sessions.get_mut(session_id) {
        ctx.call_counts = session.call_counts.clone();
        ctx.previous_actions = session.action_history.iter().cloned().collect();
        if let Some(ref agent_id) = session.oauth_subject {
            ctx.agent_id = Some(agent_id.clone());
        }
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
        counter.store(1, Ordering::Relaxed);
        true
    } else {
        let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
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

/// Recursively extract string values from a JSON value, with depth bound.
fn extract_strings_recursive(val: &Value, parts: &mut Vec<String>, depth: usize) {
    const MAX_DEPTH: usize = 10;
    if depth > MAX_DEPTH {
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

/// Build a JSON-RPC error response string for WebSocket.
fn make_ws_error_response(id: Option<&Value>, code: i64, message: &str) -> String {
    let response = json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": {
            "code": code,
            "message": message,
        }
    });
    serde_json::to_string(&response).unwrap_or_else(|_| {
        format!(
            r#"{{"jsonrpc":"2.0","error":{{"code":{},"message":"{}"}},"id":null}}"#,
            code, message
        )
    })
}

#[cfg(test)]
mod tests;
