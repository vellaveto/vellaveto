//! MCP stdio proxy bridge.
//!
//! Sits between an agent (stdin/stdout) and a child MCP server (spawned subprocess).
//! Intercepts `tools/call` requests, evaluates them against policies, and either
//! forwards allowed calls or returns denial responses directly.

use sentinel_audit::AuditLogger;
use sentinel_engine::PolicyEngine;
use sentinel_types::{Policy, Verdict};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::BufReader;
use tokio::process::{ChildStdin, ChildStdout};

use crate::extractor::{
    classify_message, extract_action, extract_resource_action, make_approval_response,
    make_denial_response, make_invalid_response, MessageType,
};
use crate::framing::{read_message, write_message};

/// Decision after evaluating a tool call.
#[derive(Debug)]
pub enum ProxyDecision {
    /// Forward the message to the child MCP server.
    Forward,
    /// Block the message and return an error response to the agent.
    /// Carries both the JSON-RPC error response and the actual verdict for audit logging.
    Block(Value, Verdict),
}

/// Default request timeout: 30 seconds.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Tool annotations extracted from `tools/list` responses.
///
/// Per MCP spec 2025-11-25, these are behavioral hints from the server.
/// **IMPORTANT:** Annotations MUST be treated as untrusted unless the server is trusted.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ToolAnnotations {
    #[serde(default)]
    pub read_only_hint: bool,
    #[serde(default = "default_true")]
    pub destructive_hint: bool,
    #[serde(default)]
    pub idempotent_hint: bool,
    #[serde(default = "default_true")]
    pub open_world_hint: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ToolAnnotations {
    fn default() -> Self {
        Self {
            read_only_hint: false,
            destructive_hint: true,
            idempotent_hint: false,
            open_world_hint: true,
        }
    }
}

/// The proxy bridge that sits between agent and child MCP server.
pub struct ProxyBridge {
    engine: PolicyEngine,
    policies: Vec<Policy>,
    audit: Arc<AuditLogger>,
    request_timeout: Duration,
}

impl ProxyBridge {
    pub fn new(engine: PolicyEngine, policies: Vec<Policy>, audit: Arc<AuditLogger>) -> Self {
        Self {
            engine,
            policies,
            audit,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }

    /// Set the request timeout for forwarded requests.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Evaluate a tool call and decide whether to forward or block.
    pub fn evaluate_tool_call(
        &self,
        id: &Value,
        tool_name: &str,
        arguments: &Value,
    ) -> ProxyDecision {
        let action = extract_action(tool_name, arguments);

        match self.engine.evaluate_action(&action, &self.policies) {
            Ok(Verdict::Allow) => ProxyDecision::Forward,
            Ok(Verdict::Deny { reason }) => {
                let response = make_denial_response(id, &reason);
                ProxyDecision::Block(response, Verdict::Deny { reason })
            }
            Ok(Verdict::RequireApproval { reason }) => {
                let response = make_approval_response(id, &reason);
                ProxyDecision::Block(response, Verdict::RequireApproval { reason })
            }
            Err(e) => {
                let reason = format!("Policy evaluation error: {}", e);
                ProxyDecision::Block(make_denial_response(id, &reason), Verdict::Deny { reason })
            }
        }
    }

    /// Evaluate a `resources/read` request and decide whether to forward or block.
    pub fn evaluate_resource_read(&self, id: &Value, uri: &str) -> ProxyDecision {
        let action = extract_resource_action(uri);

        match self.engine.evaluate_action(&action, &self.policies) {
            Ok(Verdict::Allow) => ProxyDecision::Forward,
            Ok(Verdict::Deny { reason }) => {
                let response = make_denial_response(id, &reason);
                ProxyDecision::Block(response, Verdict::Deny { reason })
            }
            Ok(Verdict::RequireApproval { reason }) => {
                let response = make_approval_response(id, &reason);
                ProxyDecision::Block(response, Verdict::RequireApproval { reason })
            }
            Err(e) => {
                let reason = format!("Policy evaluation error: {}", e);
                ProxyDecision::Block(make_denial_response(id, &reason), Verdict::Deny { reason })
            }
        }
    }

    /// Extract tool annotations from a `tools/list` response.
    ///
    /// Parses the response result, extracts annotations per tool, and detects
    /// rug-pull attacks (tool definitions changing between calls).
    async fn extract_tool_annotations(
        response: &Value,
        known: &mut HashMap<String, ToolAnnotations>,
        audit: &AuditLogger,
    ) {
        let tools = match response
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
        {
            Some(tools) => tools,
            None => return,
        };

        let mut new_tools = 0usize;
        let mut changed_tools = Vec::new();

        for tool in tools {
            let name = match tool.get("name").and_then(|n| n.as_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            // Extract annotations (use defaults per MCP spec if absent)
            let annotations = if let Some(ann) = tool.get("annotations") {
                ToolAnnotations {
                    read_only_hint: ann
                        .get("readOnlyHint")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    destructive_hint: ann
                        .get("destructiveHint")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    idempotent_hint: ann
                        .get("idempotentHint")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    open_world_hint: ann
                        .get("openWorldHint")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                }
            } else {
                ToolAnnotations::default()
            };

            // Rug-pull detection: check if annotations changed since last tools/list
            if let Some(prev) = known.get(&name) {
                if *prev != annotations {
                    changed_tools.push(name.clone());
                    tracing::warn!(
                        "SECURITY: Tool '{}' annotations changed! Previous: {:?}, Current: {:?}. \
                         This may indicate a rug-pull attack.",
                        name, prev, annotations
                    );
                }
            } else {
                new_tools += 1;
            }

            known.insert(name, annotations);
        }

        tracing::info!(
            "tools/list: {} tools registered, {} new, {} changed",
            tools.len(),
            new_tools,
            changed_tools.len()
        );

        // Audit annotation changes as security events
        if !changed_tools.is_empty() {
            let action = sentinel_types::Action {
                tool: "sentinel".to_string(),
                function: "tool_annotation_change".to_string(),
                parameters: json!({
                    "changed_tools": changed_tools,
                    "total_tools": tools.len()
                }),
            };
            let verdict = Verdict::Deny {
                reason: format!(
                    "Tool annotation change detected for: {}",
                    changed_tools.join(", ")
                ),
            };
            if let Err(e) = audit
                .log_entry(
                    &action,
                    &verdict,
                    json!({"source": "proxy", "event": "rug_pull_detection"}),
                )
                .await
            {
                tracing::warn!("Failed to audit annotation change: {}", e);
            }
        }
    }

    /// Run the bidirectional proxy loop.
    ///
    /// Reads messages from `agent_reader` (the agent's stdout, our stdin),
    /// evaluates tool calls, forwards allowed messages to `child_stdin`,
    /// and relays responses from `child_stdout` back to `agent_writer` (our stdout).
    ///
    /// Tracks forwarded request IDs and times them out if the child doesn't
    /// respond within `request_timeout`.
    pub async fn run(
        &self,
        agent_reader: tokio::io::Stdin,
        mut agent_writer: tokio::io::Stdout,
        mut child_stdin: ChildStdin,
        child_stdout: ChildStdout,
    ) -> Result<(), ProxyError> {
        let mut agent_reader = BufReader::new(agent_reader);
        let mut child_reader = BufReader::new(child_stdout);

        // Track pending request IDs for timeout detection.
        // Key: serialized JSON-RPC id, Value: when the request was forwarded.
        let mut pending_requests: HashMap<String, Instant> = HashMap::new();

        // C-8.2: Track tools/list request IDs so we can intercept responses.
        let mut tools_list_request_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        // Store known tool annotations for rug-pull detection.
        let mut known_tool_annotations: HashMap<String, ToolAnnotations> = HashMap::new();

        // Spawn a task to relay child → agent responses
        let (response_tx, mut response_rx) = tokio::sync::mpsc::channel::<Value>(256);

        let relay_handle = tokio::spawn(async move {
            loop {
                match read_message(&mut child_reader).await {
                    Ok(Some(msg)) => {
                        if response_tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break, // Child closed stdout
                    Err(e) => {
                        tracing::error!("Error reading from child: {}", e);
                        break;
                    }
                }
            }
        });

        // Timer for periodic timeout sweeps
        let mut timeout_interval = tokio::time::interval(Duration::from_secs(5));
        timeout_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Main loop: read from agent, evaluate, forward or block
        loop {
            tokio::select! {
                // Message from agent
                agent_msg = read_message(&mut agent_reader) => {
                    match agent_msg {
                        Ok(Some(msg)) => {
                            match classify_message(&msg) {
                                MessageType::ToolCall { id, tool_name, arguments } => {
                                    match self.evaluate_tool_call(&id, &tool_name, &arguments) {
                                        ProxyDecision::Forward => {
                                            // Track this request for timeout
                                            if !id.is_null() {
                                                let id_key = id.to_string();
                                                pending_requests.insert(id_key, Instant::now());
                                            }
                                            write_message(&mut child_stdin, &msg).await
                                                .map_err(ProxyError::Framing)?;
                                        }
                                        ProxyDecision::Block(response, verdict) => {
                                            // Audit with the actual verdict (Deny or RequireApproval)
                                            let action = extract_action(&tool_name, &arguments);
                                            if let Err(e) = self.audit.log_entry(
                                                &action,
                                                &verdict,
                                                json!({"source": "proxy", "tool": tool_name}),
                                            ).await {
                                                tracing::warn!("Audit log failed: {}", e);
                                            }
                                            write_message(&mut agent_writer, &response).await
                                                .map_err(ProxyError::Framing)?;
                                        }
                                    }
                                }
                                MessageType::ResourceRead { id, uri } => {
                                    match self.evaluate_resource_read(&id, &uri) {
                                        ProxyDecision::Forward => {
                                            if !id.is_null() {
                                                let id_key = id.to_string();
                                                pending_requests.insert(id_key, Instant::now());
                                            }
                                            write_message(&mut child_stdin, &msg).await
                                                .map_err(ProxyError::Framing)?;
                                        }
                                        ProxyDecision::Block(response, verdict) => {
                                            let action = extract_resource_action(&uri);
                                            if let Err(e) = self.audit.log_entry(
                                                &action,
                                                &verdict,
                                                json!({"source": "proxy", "resource_uri": uri}),
                                            ).await {
                                                tracing::warn!("Audit log failed: {}", e);
                                            }
                                            write_message(&mut agent_writer, &response).await
                                                .map_err(ProxyError::Framing)?;
                                        }
                                    }
                                }
                                MessageType::Invalid { id, reason } => {
                                    // Invalid request — return error to agent, don't forward
                                    let response = make_invalid_response(&id, &reason);
                                    tracing::warn!("Invalid MCP request: {}", reason);
                                    write_message(&mut agent_writer, &response).await
                                        .map_err(ProxyError::Framing)?;
                                }
                                MessageType::PassThrough => {
                                    // Track passthrough requests that have an id
                                    if let Some(id) = msg.get("id") {
                                        if !id.is_null() {
                                            let id_key = id.to_string();
                                            pending_requests.insert(id_key.clone(), Instant::now());

                                            // C-8.2: Track tools/list requests for annotation extraction
                                            if msg.get("method").and_then(|m| m.as_str()) == Some("tools/list") {
                                                tools_list_request_ids.insert(id_key);
                                            }
                                        }
                                    }
                                    // Non-tool-call messages pass through unmodified
                                    write_message(&mut child_stdin, &msg).await
                                        .map_err(ProxyError::Framing)?;
                                }
                            }
                        }
                        Ok(None) => {
                            tracing::info!("Agent closed connection");
                            break;
                        }
                        Err(e) => {
                            tracing::error!("Error reading from agent: {}", e);
                            break;
                        }
                    }
                }
                // Response from child
                child_msg = response_rx.recv() => {
                    match child_msg {
                        Some(msg) => {
                            // Remove from pending requests on response
                            if let Some(id) = msg.get("id") {
                                if !id.is_null() {
                                    let id_key = id.to_string();
                                    pending_requests.remove(&id_key);

                                    // C-8.2: If this is a tools/list response, extract annotations
                                    if tools_list_request_ids.remove(&id_key) {
                                        Self::extract_tool_annotations(
                                            &msg,
                                            &mut known_tool_annotations,
                                            &self.audit,
                                        ).await;
                                    }
                                }
                            }
                            // Relay child response to agent
                            write_message(&mut agent_writer, &msg).await
                                .map_err(ProxyError::Framing)?;
                        }
                        None => {
                            tracing::info!("Child process closed");
                            break;
                        }
                    }
                }
                // Periodic timeout sweep
                _ = timeout_interval.tick() => {
                    let now = Instant::now();
                    let timed_out: Vec<String> = pending_requests
                        .iter()
                        .filter(|(_, sent_at)| now.duration_since(**sent_at) > self.request_timeout)
                        .map(|(id_key, _)| id_key.clone())
                        .collect();

                    for id_key in timed_out {
                        pending_requests.remove(&id_key);
                        // Parse the id back from its serialized form
                        let id: Value = serde_json::from_str(&id_key).unwrap_or(Value::Null);
                        tracing::warn!("Request timed out: id={}", id_key);
                        let response = json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32003,
                                "message": "Request timed out: child MCP server did not respond"
                            }
                        });
                        if let Err(e) = write_message(&mut agent_writer, &response).await {
                            tracing::error!("Failed to send timeout response: {}", e);
                        }
                    }
                }
            }
        }

        relay_handle.abort();
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("Framing error: {0}")]
    Framing(#[from] crate::framing::FramingError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_types::PolicyType;
    use serde_json::json;

    fn test_bridge(policies: Vec<Policy>) -> ProxyBridge {
        let dir = std::env::temp_dir().join("sentinel-proxy-test");
        let _ = std::fs::create_dir_all(&dir);
        let audit = Arc::new(AuditLogger::new(dir.join("test-audit.log")));
        ProxyBridge::new(PolicyEngine::new(false), policies, audit)
    }

    #[test]
    fn test_evaluate_allowed_tool_call() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
        }];
        let bridge = test_bridge(policies);
        let decision =
            bridge.evaluate_tool_call(&json!(1), "read_file", &json!({"path": "/tmp/test"}));
        assert!(matches!(decision, ProxyDecision::Forward));
    }

    #[test]
    fn test_evaluate_denied_tool_call() {
        let policies = vec![Policy {
            id: "bash:*".to_string(),
            name: "Block bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
        }];
        let bridge = test_bridge(policies);
        let decision =
            bridge.evaluate_tool_call(&json!(2), "bash", &json!({"command": "rm -rf /"}));
        match decision {
            ProxyDecision::Block(resp, verdict) => {
                assert_eq!(resp["error"]["code"], -32001);
                assert!(resp["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("Denied by policy"));
                assert!(matches!(verdict, Verdict::Deny { .. }));
            }
            _ => panic!("Expected Block"),
        }
    }

    #[test]
    fn test_evaluate_no_matching_policy_denies() {
        // Fail-closed: no matching policy → deny
        let policies = vec![Policy {
            id: "specific_tool:*".to_string(),
            name: "Allow specific".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
        }];
        let bridge = test_bridge(policies);
        let decision = bridge.evaluate_tool_call(&json!(3), "unknown_tool", &json!({}));
        assert!(matches!(decision, ProxyDecision::Block(_, _)));
    }

    #[test]
    fn test_evaluate_require_approval() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Approve all".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 100,
        }];
        let bridge = test_bridge(policies);
        let decision = bridge.evaluate_tool_call(&json!(4), "write_file", &json!({}));
        match decision {
            ProxyDecision::Block(resp, verdict) => {
                assert_eq!(resp["error"]["code"], -32002);
                assert!(resp["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("Approval required"));
                // Fix #13: Verify the actual verdict is RequireApproval, not Deny
                assert!(matches!(verdict, Verdict::RequireApproval { .. }));
            }
            _ => panic!("Expected Block"),
        }
    }

    #[test]
    fn test_evaluate_with_parameter_constraints() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Block sensitive paths".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "path",
                        "op": "glob",
                        "pattern": "/etc/**",
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 100,
        }];
        let bridge = test_bridge(policies);

        // Should be blocked
        let decision =
            bridge.evaluate_tool_call(&json!(5), "read_file", &json!({"path": "/etc/passwd"}));
        assert!(matches!(decision, ProxyDecision::Block(_, _)));

        // Should be allowed
        let decision =
            bridge.evaluate_tool_call(&json!(6), "read_file", &json!({"path": "/tmp/safe.txt"}));
        assert!(matches!(decision, ProxyDecision::Forward));
    }

    #[test]
    fn test_evaluate_empty_policies_denies() {
        let bridge = test_bridge(vec![]);
        let decision = bridge.evaluate_tool_call(&json!(7), "any_tool", &json!({}));
        assert!(matches!(decision, ProxyDecision::Block(_, _)));
    }

    // --- resources/read proxy tests ---

    #[test]
    fn test_resource_read_allowed() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
        }];
        let bridge = test_bridge(policies);
        let decision = bridge.evaluate_resource_read(&json!(10), "file:///tmp/safe.txt");
        assert!(matches!(decision, ProxyDecision::Forward));
    }

    #[test]
    fn test_resource_read_denied_by_policy() {
        let policies = vec![Policy {
            id: "resources:*".to_string(),
            name: "Block all resource reads".to_string(),
            policy_type: PolicyType::Deny,
            priority: 200,
        }];
        let bridge = test_bridge(policies);
        let decision = bridge.evaluate_resource_read(&json!(11), "file:///etc/passwd");
        match decision {
            ProxyDecision::Block(resp, verdict) => {
                assert_eq!(resp["error"]["code"], -32001);
                assert!(resp["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("Denied by policy"));
                assert!(matches!(verdict, Verdict::Deny { .. }));
            }
            _ => panic!("Expected Block"),
        }
    }

    #[test]
    fn test_resource_read_blocked_by_path_constraint() {
        let policies = vec![Policy {
            id: "resources:*".to_string(),
            name: "Block sensitive paths via resources".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "path",
                        "op": "glob",
                        "pattern": "/etc/**",
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 200,
        }];
        let bridge = test_bridge(policies);

        // file:///etc/shadow → path=/etc/shadow → blocked by glob
        let decision = bridge.evaluate_resource_read(&json!(12), "file:///etc/shadow");
        assert!(matches!(decision, ProxyDecision::Block(_, _)));

        // file:///tmp/ok.txt → path=/tmp/ok.txt → allowed
        let decision = bridge.evaluate_resource_read(&json!(13), "file:///tmp/ok.txt");
        assert!(matches!(decision, ProxyDecision::Forward));
    }

    #[test]
    fn test_resource_read_http_domain_blocked() {
        let policies = vec![Policy {
            id: "resources:*".to_string(),
            name: "Block external domains".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "url",
                        "op": "domain_match",
                        "pattern": "*.evil.com",
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 200,
        }];
        let bridge = test_bridge(policies);

        let decision = bridge.evaluate_resource_read(&json!(14), "https://data.evil.com/exfil");
        assert!(matches!(decision, ProxyDecision::Block(_, _)));
    }

    #[test]
    fn test_resource_read_no_matching_policy_denies() {
        // Fail-closed: no matching policy for resources:read → deny
        let policies = vec![Policy {
            id: "some_other_tool:*".to_string(),
            name: "Allow other tool".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
        }];
        let bridge = test_bridge(policies);
        let decision = bridge.evaluate_resource_read(&json!(15), "file:///etc/passwd");
        assert!(matches!(decision, ProxyDecision::Block(_, _)));
    }

    // --- Request timeout configuration tests ---

    #[test]
    fn test_with_timeout_configures_bridge() {
        let bridge = test_bridge(vec![]).with_timeout(Duration::from_secs(60));
        assert_eq!(bridge.request_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_default_timeout_is_30_seconds() {
        let bridge = test_bridge(vec![]);
        assert_eq!(bridge.request_timeout, Duration::from_secs(30));
    }
}
