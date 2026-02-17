//! Session tracking, call chain management, and privilege escalation detection.

use chrono::Utc;
use serde_json::{json, Value};
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, EvaluationContext, Policy, Verdict};

use super::{HmacSha256, X_UPSTREAM_AGENTS};
use crate::oauth::OAuthClaims;
use crate::session::SessionStore;
use hmac::Mac;

use axum::http::HeaderMap;

/// Maximum entries in action_history per session (memory bound).
pub const MAX_ACTION_HISTORY: usize = 100;

/// Maximum distinct tool names tracked in call_counts per session (FIND-045).
/// Prevents unbounded HashMap growth from attacker-controlled tool names.
pub const MAX_CALL_COUNT_TOOLS: usize = 1024;

/// Maximum number of pending JSON-RPC tool call correlations per session.
/// Bounds memory if responses are malformed or never returned.
pub const MAX_PENDING_TOOL_CALLS: usize = 256;

/// Maximum canonicalized JSON-RPC id key length.
/// Oversized ids are ignored for request/response correlation.
const MAX_JSONRPC_ID_KEY_LEN: usize = 256;

/// Build a stable key for JSON-RPC id values used in request/response correlation.
pub fn jsonrpc_id_key(id: &Value) -> Option<String> {
    match id {
        Value::String(s) if s.len() <= MAX_JSONRPC_ID_KEY_LEN => Some(format!("s:{s}")),
        Value::Number(n) => {
            let n_str = n.to_string();
            if n_str.len() <= MAX_JSONRPC_ID_KEY_LEN {
                Some(format!("n:{n_str}"))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Track an outbound tool call so response handling can recover the originating tool.
pub fn track_pending_tool_call(
    sessions: &SessionStore,
    session_id: &str,
    request_id: &Value,
    tool_name: &str,
) {
    let Some(id_key) = jsonrpc_id_key(request_id) else {
        return;
    };
    if let Some(mut session) = sessions.get_mut(session_id) {
        // SECURITY: cap pending map to prevent unbounded growth on malformed traffic.
        if session.pending_tool_calls.len() >= MAX_PENDING_TOOL_CALLS {
            if let Some(oldest_key) = session.pending_tool_calls.keys().next().cloned() {
                session.pending_tool_calls.remove(&oldest_key);
            }
        }
        session
            .pending_tool_calls
            .insert(id_key, tool_name.to_string());
    }
}

/// Resolve and consume the tracked tool name for a JSON-RPC response id.
pub fn take_tracked_tool_call(
    sessions: &SessionStore,
    session_id: &str,
    response_id: Option<&Value>,
) -> Option<String> {
    let id_key = response_id.and_then(jsonrpc_id_key)?;
    sessions
        .get_mut(session_id)
        .and_then(|mut s| s.pending_tool_calls.remove(&id_key))
}

/// Build an `EvaluationContext` from the current session state.
pub fn build_evaluation_context(
    sessions: &SessionStore,
    session_id: &str,
) -> Option<EvaluationContext> {
    sessions
        .get_mut(session_id)
        .map(|session| EvaluationContext {
            timestamp: None, // Use real time (chrono::Utc::now() fallback in engine)
            agent_id: session.oauth_subject.clone(),
            agent_identity: session.agent_identity.clone(),
            call_counts: session.call_counts.clone(),
            previous_actions: session.action_history.iter().cloned().collect(),
            call_chain: session.current_call_chain.clone(),
            tenant_id: None,
            verification_tier: None,
            capability_token: None,
            session_state: None,
        })
}

/// Build audit context JSON, optionally including OAuth subject and call chain.
pub fn build_audit_context(
    session_id: &str,
    extra: Value,
    oauth_claims: &Option<OAuthClaims>,
) -> Value {
    let mut ctx = json!({"source": "http_proxy", "session": session_id});
    if let Value::Object(map) = extra {
        if let Value::Object(ref mut ctx_map) = ctx {
            for (k, v) in map {
                ctx_map.insert(k, v);
            }
        }
    }
    if let Some(claims) = oauth_claims {
        if let Value::Object(ref mut ctx_map) = ctx {
            ctx_map.insert("oauth_subject".to_string(), json!(claims.sub));
            if !claims.scope.is_empty() {
                ctx_map.insert("oauth_scopes".to_string(), json!(claims.scope));
            }
        }
    }
    ctx
}

/// Build audit context JSON with call chain for multi-agent scenarios.
pub fn build_audit_context_with_chain(
    session_id: &str,
    extra: Value,
    oauth_claims: &Option<OAuthClaims>,
    call_chain: &[vellaveto_types::CallChainEntry],
) -> Value {
    let mut ctx = build_audit_context(session_id, extra, oauth_claims);
    if !call_chain.is_empty() {
        if let Value::Object(ref mut ctx_map) = ctx {
            ctx_map.insert(
                "call_chain".to_string(),
                // FIND-R50-015: Log serialization failures instead of silently swallowing.
                serde_json::to_value(call_chain).unwrap_or_else(|e| {
                    tracing::warn!("call_chain serialization failed: {e}");
                    Value::Null
                }),
            );
        }
    }
    ctx
}

/// Validate the structural integrity of the X-Upstream-Agents header.
///
/// Returns:
/// - `Ok(())` when the header is absent (single-hop flow) or structurally valid.
/// - `Err(...)` when the header is present but malformed/oversized.
pub fn validate_call_chain_header(
    headers: &HeaderMap,
    limits: &vellaveto_config::LimitsConfig,
) -> Result<(), &'static str> {
    let raw_header = match headers.get(X_UPSTREAM_AGENTS) {
        Some(v) => v,
        None => return Ok(()),
    };

    let raw_str = raw_header
        .to_str()
        .map_err(|_| "X-Upstream-Agents header is not valid UTF-8")?;
    if raw_str.len() > limits.max_call_chain_header_bytes {
        return Err("X-Upstream-Agents header exceeds size limit");
    }

    let entries = serde_json::from_str::<Vec<vellaveto_types::CallChainEntry>>(raw_str)
        .map_err(|_| "X-Upstream-Agents header is not valid JSON array")?;
    if entries.len() > limits.max_call_chain_length {
        return Err("X-Upstream-Agents header exceeds entry limit");
    }
    Ok(())
}

/// OWASP ASI08: Extract the call chain from the X-Upstream-Agents header.
///
/// The header contains a JSON-encoded array of CallChainEntry objects representing
/// the chain of agents that have processed this request before reaching us.
/// Returns an empty Vec only when the header is missing; malformed headers are
/// rejected earlier by `validate_call_chain_header()`.
///
/// FIND-015: When an HMAC key is provided, each entry's HMAC tag is verified.
/// Entries with missing or invalid HMACs are marked as `verified = Some(false)`
/// and the `agent_id` is prefixed with `[unverified]`. Entries with valid HMACs
/// are marked as `verified = Some(true)`. When no key is provided, all entries
/// pass through without verification (backward compatible).
pub fn extract_call_chain_from_headers(
    headers: &HeaderMap,
    hmac_key: Option<&[u8; 32]>,
    limits: &vellaveto_config::LimitsConfig,
) -> Vec<vellaveto_types::CallChainEntry> {
    if let Err(reason) = validate_call_chain_header(headers, limits) {
        tracing::warn!(
            reason = reason,
            "Call chain header validation failed during extraction; dropping upstream chain"
        );
        return Vec::new();
    }

    let max_age_secs = limits.call_chain_max_age_secs as i64;

    let mut entries = match headers.get(X_UPSTREAM_AGENTS) {
        Some(raw_header) => {
            let raw_str = match raw_header.to_str() {
                Ok(raw_str) => raw_str,
                Err(_) => {
                    tracing::warn!(
                        "Call chain header became non UTF-8 after validation; dropping upstream chain"
                    );
                    return Vec::new();
                }
            };
            match serde_json::from_str::<Vec<vellaveto_types::CallChainEntry>>(raw_str) {
                Ok(parsed) => parsed,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "Call chain header became non-JSON after validation; dropping upstream chain"
                    );
                    return Vec::new();
                }
            }
        }
        None => Vec::new(),
    };

    // FIND-015: Verify HMAC on each entry when a key is configured.
    // Also validate timestamp freshness to prevent replay attacks.
    let now = Utc::now();
    if let Some(key) = hmac_key {
        for entry in &mut entries {
            // First check timestamp freshness
            let timestamp_valid = chrono::DateTime::parse_from_rfc3339(&entry.timestamp)
                .map(|ts| (now - ts.with_timezone(&Utc)).num_seconds() <= max_age_secs)
                .unwrap_or(false);

            if !timestamp_valid {
                tracing::warn!(
                    agent_id = %entry.agent_id,
                    tool = %entry.tool,
                    timestamp = %entry.timestamp,
                    "IMPROVEMENT_PLAN 2.1: Call chain entry has stale timestamp — marking as unverified"
                );
                entry.verified = Some(false);
                entry.agent_id = format!("[stale] {}", entry.agent_id);
                continue;
            }

            match &entry.hmac {
                Some(hmac_hex) => {
                    let content = call_chain_entry_signing_content(entry);
                    match verify_call_chain_hmac(key, &content, hmac_hex) {
                        Ok(true) => {
                            entry.verified = Some(true);
                        }
                        _ => {
                            // HMAC verification failed or hex decode error
                            tracing::warn!(
                                agent_id = %entry.agent_id,
                                tool = %entry.tool,
                                "FIND-015: Call chain entry has invalid HMAC — marking as unverified"
                            );
                            entry.verified = Some(false);
                            entry.agent_id = format!("[unverified] {}", entry.agent_id);
                        }
                    }
                }
                None => {
                    // No HMAC tag on entry — mark as unverified
                    tracing::warn!(
                        agent_id = %entry.agent_id,
                        tool = %entry.tool,
                        "FIND-015: Call chain entry has no HMAC tag — marking as unverified"
                    );
                    entry.verified = Some(false);
                    entry.agent_id = format!("[unverified] {}", entry.agent_id);
                }
            }
        }
    }

    entries
}

/// Parse and persist the upstream call chain for the current request.
///
/// The session stores only upstream entries (excluding this proxy's current hop)
/// so policy checks can reason about delegated caller depth consistently across
/// tool calls, task requests, and resource reads.
pub fn sync_session_call_chain_from_headers(
    sessions: &SessionStore,
    session_id: &str,
    headers: &HeaderMap,
    hmac_key: Option<&[u8; 32]>,
    limits: &vellaveto_config::LimitsConfig,
) -> Vec<vellaveto_types::CallChainEntry> {
    let upstream_chain = extract_call_chain_from_headers(headers, hmac_key, limits);
    if let Some(mut session) = sessions.get_mut(session_id) {
        session.current_call_chain = upstream_chain.clone();
    }
    upstream_chain
}

/// OWASP ASI08: Build a call chain entry for the current agent.
///
/// This entry represents the current agent (us) processing the request,
/// to be added to the chain before forwarding downstream.
///
/// FIND-015: When an HMAC key is provided, the entry is signed with
/// HMAC-SHA256 over its content (agent_id, tool, function, timestamp).
pub fn build_current_agent_entry(
    agent_id: Option<&str>,
    tool: &str,
    function: &str,
    hmac_key: Option<&[u8; 32]>,
) -> vellaveto_types::CallChainEntry {
    let mut entry = vellaveto_types::CallChainEntry {
        agent_id: agent_id.unwrap_or("unknown").to_string(),
        tool: tool.to_string(),
        function: function.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        hmac: None,
        verified: None,
    };

    // FIND-015: Sign the entry if an HMAC key is configured.
    if let Some(key) = hmac_key {
        let content = call_chain_entry_signing_content(&entry);
        if let Ok(hmac_hex) = compute_call_chain_hmac(key, &content) {
            entry.hmac = Some(hmac_hex);
            entry.verified = Some(true);
        }
    }

    entry
}

/// FIND-015: Compute the canonical signing content for a call chain entry.
///
/// SECURITY (FIND-045, FIND-043): Uses length-prefixed fields instead of pipe
/// separators to prevent field injection attacks. A tool name containing `|`
/// could shift field boundaries and create HMAC collisions with the old format.
/// Also strips both `[unverified] ` and `[stale] ` prefixes since both are
/// added post-verification and would break round-trip signing.
pub fn call_chain_entry_signing_content(entry: &vellaveto_types::CallChainEntry) -> Vec<u8> {
    // Strip any [unverified] or [stale] prefix that may have been added
    // during verification, so the content matches what was originally signed.
    let agent_id = entry
        .agent_id
        .strip_prefix("[unverified] ")
        .or_else(|| entry.agent_id.strip_prefix("[stale] "))
        .unwrap_or(&entry.agent_id);

    // Length-prefix each field (u64 LE + bytes) to prevent boundary confusion.
    let mut content = Vec::new();
    for field in &[
        agent_id,
        entry.tool.as_str(),
        entry.function.as_str(),
        entry.timestamp.as_str(),
    ] {
        content.extend_from_slice(&(field.len() as u64).to_le_bytes());
        content.extend_from_slice(field.as_bytes());
    }
    content
}

/// FIND-015: Compute HMAC-SHA256 over data, returning lowercase hex string.
/// Returns `Err` if the HMAC key is rejected (should not happen for 32-byte keys).
#[allow(clippy::result_unit_err)]
pub fn compute_call_chain_hmac(key: &[u8; 32], data: &[u8]) -> Result<String, ()> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ())?;
    mac.update(data);
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// FIND-015: Verify HMAC-SHA256 of data against expected hex string.
/// Returns `Ok(true)` if valid, `Ok(false)` if invalid, `Err` on initialization failure.
#[allow(clippy::result_unit_err)]
pub fn verify_call_chain_hmac(key: &[u8; 32], data: &[u8], expected_hex: &str) -> Result<bool, ()> {
    let expected_bytes = match hex::decode(expected_hex) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ())?;
    mac.update(data);
    Ok(mac.verify_slice(&expected_bytes).is_ok())
}

/// OWASP ASI08: Privilege escalation detection result.
#[derive(Debug)]
pub struct PrivilegeEscalationCheck {
    /// True if privilege escalation was detected.
    pub escalation_detected: bool,
    /// The agent whose policy would have denied the action.
    pub escalating_from_agent: Option<String>,
    /// The reason the upstream agent's policy would deny.
    pub upstream_deny_reason: Option<String>,
}

/// OWASP ASI08: Check for privilege escalation in multi-agent scenarios.
///
/// A privilege escalation occurs when:
/// - Agent A makes a request that would be DENIED by A's policy
/// - But A routes through Agent B whose policy ALLOWS it
///
/// This is detected by re-evaluating the action with each upstream agent's
/// identity and checking if any would have been denied.
///
/// Returns a `PrivilegeEscalationCheck` indicating whether escalation was detected
/// and which agent triggered it.
pub fn check_privilege_escalation(
    engine: &PolicyEngine,
    policies: &[Policy],
    action: &Action,
    call_chain: &[vellaveto_types::CallChainEntry],
    current_agent_id: Option<&str>,
) -> PrivilegeEscalationCheck {
    // If there's no call chain, there's no multi-hop scenario to check
    if call_chain.is_empty() {
        return PrivilegeEscalationCheck {
            escalation_detected: false,
            escalating_from_agent: None,
            upstream_deny_reason: None,
        };
    }

    // Check each upstream agent in the call chain
    for entry in call_chain {
        // Skip the current agent if they're in the chain
        if current_agent_id == Some(entry.agent_id.as_str()) {
            continue;
        }

        // Build an evaluation context as if we were the upstream agent
        let upstream_ctx = EvaluationContext {
            timestamp: None,
            agent_id: Some(entry.agent_id.clone()),
            agent_identity: None, // Upstream agent identity not yet supported in call chain
            call_counts: std::collections::HashMap::new(), // Fresh context for upstream check
            previous_actions: Vec::new(),
            call_chain: Vec::new(), // Don't recurse into chain for upstream check
            tenant_id: None,
            verification_tier: None,
            capability_token: None,
            session_state: None,
        };

        // Evaluate the action with the upstream agent's identity
        match engine.evaluate_action_with_context(action, policies, Some(&upstream_ctx)) {
            Ok(Verdict::Deny { reason }) => {
                // The upstream agent would have been denied - this is privilege escalation
                tracing::warn!(
                    "SECURITY: Privilege escalation detected! Agent '{}' would be denied: {}, \
                     but action is being executed through current agent",
                    entry.agent_id,
                    reason
                );
                return PrivilegeEscalationCheck {
                    escalation_detected: true,
                    escalating_from_agent: Some(entry.agent_id.clone()),
                    upstream_deny_reason: Some(reason),
                };
            }
            _ => {
                // Upstream agent would have been allowed, continue checking
            }
        }
    }

    PrivilegeEscalationCheck {
        escalation_detected: false,
        escalating_from_agent: None,
        upstream_deny_reason: None,
    }
}
