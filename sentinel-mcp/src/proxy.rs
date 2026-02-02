//! MCP stdio proxy bridge.
//!
//! Sits between an agent (stdin/stdout) and a child MCP server (spawned subprocess).
//! Intercepts `tools/call` requests, evaluates them against policies, and either
//! forwards allowed calls or returns denial responses directly.

use sentinel_audit::AuditLogger;
use sentinel_engine::PolicyEngine;
use sentinel_types::{Policy, Verdict};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::BufReader;
use tokio::process::{ChildStdin, ChildStdout};

use crate::extractor::{
    classify_message, extract_action, make_approval_response, make_denial_response, MessageType,
};
use crate::framing::{read_message, write_message};

/// Decision after evaluating a tool call.
#[derive(Debug)]
pub enum ProxyDecision {
    /// Forward the message to the child MCP server.
    Forward,
    /// Block the message and return an error to the agent.
    Block(Value),
}

/// The proxy bridge that sits between agent and child MCP server.
pub struct ProxyBridge {
    engine: PolicyEngine,
    policies: Vec<Policy>,
    audit: Arc<AuditLogger>,
}

impl ProxyBridge {
    pub fn new(engine: PolicyEngine, policies: Vec<Policy>, audit: Arc<AuditLogger>) -> Self {
        Self {
            engine,
            policies,
            audit,
        }
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
            Ok(Verdict::Deny { reason }) => ProxyDecision::Block(make_denial_response(id, &reason)),
            Ok(Verdict::RequireApproval { reason }) => {
                ProxyDecision::Block(make_approval_response(id, &reason))
            }
            Err(e) => ProxyDecision::Block(make_denial_response(
                id,
                &format!("Policy evaluation error: {}", e),
            )),
        }
    }

    /// Run the bidirectional proxy loop.
    ///
    /// Reads messages from `agent_reader` (the agent's stdout, our stdin),
    /// evaluates tool calls, forwards allowed messages to `child_stdin`,
    /// and relays responses from `child_stdout` back to `agent_writer` (our stdout).
    pub async fn run(
        &self,
        agent_reader: tokio::io::Stdin,
        mut agent_writer: tokio::io::Stdout,
        mut child_stdin: ChildStdin,
        child_stdout: ChildStdout,
    ) -> Result<(), ProxyError> {
        let mut agent_reader = BufReader::new(agent_reader);
        let mut child_reader = BufReader::new(child_stdout);

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
                                            write_message(&mut child_stdin, &msg).await
                                                .map_err(ProxyError::Framing)?;
                                        }
                                        ProxyDecision::Block(response) => {
                                            // Audit the denial
                                            let action = extract_action(&tool_name, &arguments);
                                            let verdict = Verdict::Deny {
                                                reason: response["error"]["message"]
                                                    .as_str()
                                                    .unwrap_or("blocked")
                                                    .to_string(),
                                            };
                                            if let Err(e) = self.audit.log_entry(
                                                &action,
                                                &verdict,
                                                json!({"source": "proxy", "tool": tool_name}),
                                            ).await {
                                                tracing::warn!("Audit log failed: {}", e);
                                            }
                                            // Send denial directly to agent
                                            write_message(&mut agent_writer, &response).await
                                                .map_err(ProxyError::Framing)?;
                                        }
                                    }
                                }
                                MessageType::PassThrough => {
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
            ProxyDecision::Block(resp) => {
                assert_eq!(resp["error"]["code"], -32600);
                assert!(resp["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("Denied by policy"));
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
        assert!(matches!(decision, ProxyDecision::Block(_)));
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
            ProxyDecision::Block(resp) => {
                assert_eq!(resp["error"]["code"], -32001);
                assert!(resp["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("Approval required"));
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
        assert!(matches!(decision, ProxyDecision::Block(_)));

        // Should be allowed
        let decision =
            bridge.evaluate_tool_call(&json!(6), "read_file", &json!({"path": "/tmp/safe.txt"}));
        assert!(matches!(decision, ProxyDecision::Forward));
    }

    #[test]
    fn test_evaluate_empty_policies_denies() {
        let bridge = test_bridge(vec![]);
        let decision = bridge.evaluate_tool_call(&json!(7), "any_tool", &json!({}));
        assert!(matches!(decision, ProxyDecision::Block(_)));
    }
}
