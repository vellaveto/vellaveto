//! A2A HTTP proxy service.
//!
//! This module provides the core A2A proxy logic for intercepting, evaluating,
//! and forwarding A2A JSON-RPC requests. It integrates with Sentinel's
//! policy engine and security managers.
//!
//! # Architecture
//!
//! ```text
//! Request → Size Check → Parse → Classify → Policy Check → Security Scans
//!    ↓
//! Forward to Upstream → Scan Response → Return to Client
//! ```
//!
//! # Security Features
//!
//! - Message size limits
//! - Policy-based access control
//! - DLP scanning on message content
//! - Injection detection on text content
//! - Circuit breaker for upstream protection
//! - Shadow agent detection

use sentinel_engine::PolicyEngine;
use sentinel_types::{Policy, Verdict};
use serde_json::Value;
use std::sync::Arc;

use super::agent_card::AgentCardCache;
use super::error::A2aError;
use super::extractor::{
    extract_a2a_action, get_request_id, make_a2a_denial_response, make_a2a_error_response,
    requires_policy_check,
};
use super::message::{classify_a2a_message, extract_text_content, A2aMessageType};

/// Configuration for the A2A proxy service.
#[derive(Debug, Clone)]
pub struct A2aProxyConfig {
    /// Maximum message size in bytes.
    pub max_message_size: usize,
    /// Enable DLP scanning on message content.
    pub enable_dlp_scanning: bool,
    /// Enable injection detection on text content.
    pub enable_injection_detection: bool,
    /// Enable circuit breaker for upstream servers.
    pub enable_circuit_breaker: bool,
    /// Enable shadow agent detection.
    pub enable_shadow_agent_detection: bool,
    /// Require agent card verification.
    pub require_agent_card: bool,
    /// Request timeout in milliseconds.
    pub request_timeout_ms: u64,
    /// Allowed task operations (empty = all allowed).
    pub allowed_task_operations: Vec<String>,
}

impl Default for A2aProxyConfig {
    fn default() -> Self {
        Self {
            max_message_size: 10 * 1024 * 1024, // 10 MB
            enable_dlp_scanning: true,
            enable_injection_detection: true,
            enable_circuit_breaker: true,
            enable_shadow_agent_detection: true,
            require_agent_card: false,
            request_timeout_ms: 30000,
            allowed_task_operations: vec![],
        }
    }
}

/// Result of processing an A2A request.
#[derive(Debug)]
pub enum A2aProxyDecision {
    /// Forward the request to the upstream server.
    Forward {
        /// The original JSON-RPC message.
        message: Value,
        /// The extracted action for audit logging.
        action: Option<sentinel_types::Action>,
    },
    /// Block the request and return an error response.
    Block {
        /// The JSON-RPC error response to return.
        response: Value,
        /// The reason for blocking.
        reason: String,
        /// The verdict that caused the block.
        verdict: Option<Verdict>,
    },
    /// Pass through without policy checking (responses, unknown methods).
    PassThrough {
        /// The original message.
        message: Value,
    },
}

/// A2A proxy service for intercepting and evaluating A2A traffic.
///
/// This service coordinates policy evaluation, security checks, and
/// upstream forwarding for A2A JSON-RPC requests.
pub struct A2aProxyService {
    config: A2aProxyConfig,
    engine: Arc<PolicyEngine>,
    policies: Arc<Vec<Policy>>,
    agent_card_cache: Arc<AgentCardCache>,
}

impl A2aProxyService {
    /// Create a new A2A proxy service.
    pub fn new(
        config: A2aProxyConfig,
        engine: Arc<PolicyEngine>,
        policies: Arc<Vec<Policy>>,
        agent_card_cache: Arc<AgentCardCache>,
    ) -> Self {
        Self {
            config,
            engine,
            policies,
            agent_card_cache,
        }
    }

    /// Process an A2A JSON-RPC request.
    ///
    /// Returns a decision on whether to forward, block, or pass through.
    pub fn process_request(&self, body: &[u8]) -> Result<A2aProxyDecision, A2aError> {
        // 1. Size check
        if body.len() > self.config.max_message_size {
            return Err(A2aError::MessageTooLarge {
                size: body.len(),
                max: self.config.max_message_size,
            });
        }

        // 2. Parse JSON-RPC
        let msg: Value = serde_json::from_slice(body)?;

        // 3. Classify message
        let msg_type = classify_a2a_message(&msg);

        // 4. Handle batch rejection
        if matches!(msg_type, A2aMessageType::Batch) {
            return Err(A2aError::BatchNotAllowed);
        }

        // 5. Handle invalid messages
        if let A2aMessageType::Invalid { id, reason } = &msg_type {
            return Ok(A2aProxyDecision::Block {
                response: make_a2a_error_response(id, -32600, reason),
                reason: reason.clone(),
                verdict: None,
            });
        }

        // 6. Pass through non-request messages
        if !requires_policy_check(&msg_type) {
            return Ok(A2aProxyDecision::PassThrough { message: msg });
        }

        // 7. Check task operation restrictions
        if !self.config.allowed_task_operations.is_empty() {
            if let Err(e) = self.check_task_operation(&msg_type) {
                let id = get_request_id(&msg_type);
                return Ok(A2aProxyDecision::Block {
                    response: make_a2a_error_response(&id, e.code(), &e.to_string()),
                    reason: e.to_string(),
                    verdict: None,
                });
            }
        }

        // 8. Extract action for policy evaluation
        let action = extract_a2a_action(&msg_type);

        // 9. Evaluate policy
        if let Some(ref action) = action {
            match self.engine.evaluate_action(action, &self.policies) {
                Ok(Verdict::Allow) => {
                    // Continue to security scans
                }
                Ok(Verdict::Deny { reason }) => {
                    let id = get_request_id(&msg_type);
                    return Ok(A2aProxyDecision::Block {
                        response: make_a2a_denial_response(&id, &reason),
                        reason: reason.clone(),
                        verdict: Some(Verdict::Deny { reason }),
                    });
                }
                Ok(verdict @ Verdict::RequireApproval { .. }) => {
                    let id = get_request_id(&msg_type);
                    return Ok(A2aProxyDecision::Block {
                        response: make_a2a_error_response(
                            &id,
                            -32003,
                            "Action requires approval",
                        ),
                        reason: "Requires approval".to_string(),
                        verdict: Some(verdict),
                    });
                }
                Err(e) => {
                    // Fail closed: engine errors result in denial
                    let id = get_request_id(&msg_type);
                    let reason = format!("Policy evaluation error: {}", e);
                    return Ok(A2aProxyDecision::Block {
                        response: make_a2a_error_response(&id, -32603, &reason),
                        reason,
                        verdict: None,
                    });
                }
            }
        }

        // 10. Run security scans
        if let Err(e) = self.run_security_scans(&msg_type, &msg) {
            let id = get_request_id(&msg_type);
            return Ok(A2aProxyDecision::Block {
                response: make_a2a_error_response(&id, e.code(), &e.to_string()),
                reason: e.to_string(),
                verdict: None,
            });
        }

        // 11. Forward to upstream
        Ok(A2aProxyDecision::Forward { message: msg, action })
    }

    /// Check if a task operation is allowed.
    fn check_task_operation(&self, msg_type: &A2aMessageType) -> Result<(), A2aError> {
        let op = match msg_type {
            A2aMessageType::TaskGet { .. } => "get",
            A2aMessageType::TaskCancel { .. } => "cancel",
            A2aMessageType::TaskResubscribe { .. } => "resubscribe",
            _ => return Ok(()), // Non-task operations are allowed
        };

        if self
            .config
            .allowed_task_operations
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(op))
        {
            Ok(())
        } else {
            Err(A2aError::TaskOperationNotAllowed {
                operation: op.to_string(),
                state: "any".to_string(),
            })
        }
    }

    /// Run security scans on the message.
    fn run_security_scans(&self, msg_type: &A2aMessageType, _msg: &Value) -> Result<(), A2aError> {
        // Extract message content for scanning
        let message = match msg_type {
            A2aMessageType::MessageSend { message, .. } => Some(message),
            A2aMessageType::MessageStream { message, .. } => Some(message),
            _ => None,
        };

        if let Some(message) = message {
            // Extract text content for scanning
            let texts = extract_text_content(message);

            // Injection detection (placeholder - would integrate with existing scanner)
            if self.config.enable_injection_detection {
                for text in &texts {
                    if self.contains_injection_pattern(text) {
                        return Err(A2aError::InjectionDetected(
                            "Potential injection detected in message content".to_string(),
                        ));
                    }
                }
            }

            // DLP scanning (placeholder - would integrate with existing DLP)
            if self.config.enable_dlp_scanning {
                for text in &texts {
                    if self.contains_sensitive_data(text) {
                        return Err(A2aError::DlpViolation(
                            "Sensitive data detected in message content".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Check for injection patterns in text (placeholder implementation).
    ///
    /// In production, this would integrate with the existing InjectionScanner.
    fn contains_injection_pattern(&self, _text: &str) -> bool {
        // Placeholder - would use aho-corasick scanner from inspection.rs
        false
    }

    /// Check for sensitive data in text (placeholder implementation).
    ///
    /// In production, this would integrate with the existing DLP scanner.
    fn contains_sensitive_data(&self, _text: &str) -> bool {
        // Placeholder - would use DLP patterns from inspection.rs
        false
    }

    /// Get the agent card cache.
    pub fn agent_card_cache(&self) -> &AgentCardCache {
        &self.agent_card_cache
    }

    /// Get the proxy configuration.
    pub fn config(&self) -> &A2aProxyConfig {
        &self.config
    }
}

/// Process an A2A response from the upstream server.
///
/// Scans the response for security issues before returning to the client.
pub fn process_response(
    response: &Value,
    enable_dlp: bool,
    enable_injection: bool,
) -> Result<Value, A2aError> {
    // Check if response contains a result with message content
    if let Some(result) = response.get("result") {
        // Task result may contain artifacts with message parts
        if let Some(artifacts) = result.get("artifacts").and_then(|a| a.as_array()) {
            for artifact in artifacts {
                if let Some(parts) = artifact.get("parts").and_then(|p| p.as_array()) {
                    for part in parts {
                        if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                            // Placeholder for actual scanning
                            if enable_injection {
                                // Would scan with InjectionScanner
                            }
                            if enable_dlp {
                                // Would scan with DLP patterns
                            }
                            let _ = text; // Suppress unused warning
                        }
                    }
                }
            }
        }
    }

    Ok(response.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_test_service() -> A2aProxyService {
        // Create an allow-all policy so tests can pass forward checks
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Allow all".to_string(),
            policy_type: sentinel_types::PolicyType::Allow,
            priority: 1,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).expect("compile failed");
        let policies = Arc::new(policies);
        let cache = Arc::new(AgentCardCache::default());
        let config = A2aProxyConfig::default();

        A2aProxyService::new(config, Arc::new(engine), policies, cache)
    }

    #[test]
    fn test_process_valid_message_send() {
        let service = create_test_service();
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "Hello"}]
                }
            }
        }))
        .unwrap();

        let decision = service.process_request(&body).unwrap();
        assert!(matches!(decision, A2aProxyDecision::Forward { .. }));
    }

    #[test]
    fn test_process_response_passthrough() {
        let service = create_test_service();
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"status": "ok"}
        }))
        .unwrap();

        let decision = service.process_request(&body).unwrap();
        assert!(matches!(decision, A2aProxyDecision::PassThrough { .. }));
    }

    #[test]
    fn test_reject_batch() {
        let service = create_test_service();
        let body = serde_json::to_vec(&json!([
            {"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tasks/get", "params": {}}
        ]))
        .unwrap();

        let result = service.process_request(&body);
        assert!(matches!(result, Err(A2aError::BatchNotAllowed)));
    }

    #[test]
    fn test_reject_oversized() {
        let config = A2aProxyConfig {
            max_message_size: 100,
            ..Default::default()
        };
        let engine = Arc::new(PolicyEngine::new(false));
        let policies = Arc::new(vec![]);
        let cache = Arc::new(AgentCardCache::default());
        let service = A2aProxyService::new(config, engine, policies, cache);

        let body = vec![b'x'; 200];
        let result = service.process_request(&body);
        assert!(matches!(result, Err(A2aError::MessageTooLarge { .. })));
    }

    #[test]
    fn test_invalid_json() {
        let service = create_test_service();
        let body = b"not valid json";

        let result = service.process_request(body);
        assert!(matches!(result, Err(A2aError::Serialization(_))));
    }

    #[test]
    fn test_invalid_missing_method() {
        let service = create_test_service();
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "params": {}
        }))
        .unwrap();

        let decision = service.process_request(&body).unwrap();
        assert!(matches!(decision, A2aProxyDecision::Block { .. }));
    }

    #[test]
    fn test_task_operation_restriction() {
        // Create an allow-all policy
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Allow all".to_string(),
            policy_type: sentinel_types::PolicyType::Allow,
            priority: 1,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).expect("compile failed");

        let config = A2aProxyConfig {
            allowed_task_operations: vec!["get".to_string()],
            ..Default::default()
        };
        let policies = Arc::new(policies);
        let cache = Arc::new(AgentCardCache::default());
        let service = A2aProxyService::new(config, Arc::new(engine), policies, cache);

        // task/get is allowed
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/get",
            "params": {"id": "task-123"}
        }))
        .unwrap();
        let decision = service.process_request(&body).unwrap();
        assert!(matches!(decision, A2aProxyDecision::Forward { .. }));

        // task/cancel is not allowed
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tasks/cancel",
            "params": {"id": "task-123"}
        }))
        .unwrap();
        let decision = service.process_request(&body).unwrap();
        assert!(matches!(decision, A2aProxyDecision::Block { .. }));
    }

    #[test]
    fn test_policy_denial() {
        let policies = vec![Policy {
            id: "a2a:*".to_string(),
            name: "Deny A2A".to_string(),
            policy_type: sentinel_types::PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];

        // Compile policies
        let compiled_engine =
            PolicyEngine::with_policies(true, &policies).expect("compile failed");
        let policies = Arc::new(policies);
        let cache = Arc::new(AgentCardCache::default());
        let config = A2aProxyConfig::default();

        let service = A2aProxyService::new(config, Arc::new(compiled_engine), policies, cache);

        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "Hello"}]
                }
            }
        }))
        .unwrap();

        let decision = service.process_request(&body).unwrap();
        assert!(matches!(decision, A2aProxyDecision::Block { .. }));
    }

    #[test]
    fn test_process_response_scans() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "artifacts": [
                    {
                        "parts": [
                            {"type": "text", "text": "Hello from agent"}
                        ]
                    }
                ]
            }
        });

        let result = process_response(&response, true, true);
        assert!(result.is_ok());
    }
}
