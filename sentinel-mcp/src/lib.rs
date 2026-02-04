pub mod elicitation;
pub mod extractor;
pub mod framing;
pub mod inspection;
pub mod output_validation;
pub mod proxy;
pub mod rug_pull;

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum McpError {
    #[error("Invalid request format: {0}")]
    InvalidRequest(String),
    #[error("Method not found: {0}")]
    MethodNotFound(String),
    #[error("Engine error: {0}")]
    Engine(#[from] sentinel_engine::EngineError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Request too large: {0} bytes")]
    RequestTooLarge(usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    pub id: String,
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    pub id: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<McpErrorResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpErrorResponse {
    pub code: i32,
    pub message: String,
}

pub struct McpServer {
    // SECURITY (R13-LEG-5): Engine is behind RwLock so it can be recompiled
    // when policies change. Without recompilation, the engine has empty
    // compiled_policies and silently falls back to the legacy path, which
    // bypasses path_rules, network_rules, and context_conditions.
    engine: RwLock<PolicyEngine>,
    policies: RwLock<Vec<Policy>>,
    max_request_size: usize,
    strict_mode: bool,
    /// Custom path decode iteration limit (None = default 20).
    max_path_decode_iterations: Option<u32>,
}

impl McpServer {
    pub fn new(strict_mode: bool) -> Self {
        Self {
            engine: RwLock::new(PolicyEngine::new(strict_mode)),
            policies: RwLock::new(Vec::new()),
            max_request_size: 1_000_000, // 1MB limit
            strict_mode,
            max_path_decode_iterations: None,
        }
    }

    /// Set the maximum percent-decoding iterations for path normalization.
    pub fn set_max_path_decode_iterations(&mut self, max: u32) {
        self.max_path_decode_iterations = Some(max);
    }

    /// Recompile the engine from current policies.
    /// On failure, keeps the previous engine and logs errors.
    async fn recompile_engine(&self, policies: &[Policy]) {
        match PolicyEngine::with_policies(self.strict_mode, policies) {
            Ok(mut compiled) => {
                if let Some(max_iter) = self.max_path_decode_iterations {
                    compiled.set_max_path_decode_iterations(max_iter);
                }
                *self.engine.write().await = compiled;
            }
            Err(errors) => {
                for e in &errors {
                    tracing::warn!("McpServer policy compilation error: {}", e);
                }
                tracing::warn!("McpServer: keeping previous engine due to compilation errors");
            }
        }
    }

    pub async fn handle_request(&self, request_data: &str) -> Result<String, McpError> {
        // Size protection
        if request_data.len() > self.max_request_size {
            return Err(McpError::RequestTooLarge(request_data.len()));
        }

        let request: McpRequest = serde_json::from_str(request_data)?;
        let response = self.process_request(request).await;
        Ok(serde_json::to_string(&response)?)
    }

    async fn process_request(&self, request: McpRequest) -> McpResponse {
        let result = match request.method.as_str() {
            "evaluate_action" => self.handle_evaluate_action(request.params).await,
            "add_policy" => self.handle_add_policy(request.params).await,
            "list_policies" => self.handle_list_policies().await,
            "remove_policy" => self.handle_remove_policy(request.params).await,
            _ => Err(McpError::MethodNotFound(request.method.clone())),
        };

        match result {
            Ok(value) => McpResponse {
                id: request.id,
                result: Some(value),
                error: None,
            },
            Err(e) => McpResponse {
                id: request.id,
                result: None,
                error: Some(McpErrorResponse {
                    code: self.error_code(&e),
                    message: e.to_string(),
                }),
            },
        }
    }

    async fn handle_evaluate_action(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, McpError> {
        let action: Action = serde_json::from_value(params)?;
        let policies = self.policies.read().await;
        let engine = self.engine.read().await;
        let verdict = engine.evaluate_action(&action, &policies)?;
        Ok(serde_json::to_value(verdict)?)
    }

    async fn handle_add_policy(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, McpError> {
        let policy: Policy = serde_json::from_value(params)?;
        let mut policies = self.policies.write().await;
        policies.push(policy);
        PolicyEngine::sort_policies(&mut policies);
        // Recompile engine to use compiled path (R13-LEG-5)
        self.recompile_engine(&policies).await;
        Ok(serde_json::Value::Bool(true))
    }

    async fn handle_list_policies(&self) -> Result<serde_json::Value, McpError> {
        let policies = self.policies.read().await;
        Ok(serde_json::to_value(&*policies)?)
    }

    async fn handle_remove_policy(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, McpError> {
        let policy_id: String = serde_json::from_value(params)?;
        let mut policies = self.policies.write().await;
        let initial_len = policies.len();
        policies.retain(|p| p.id != policy_id);
        let changed = policies.len() < initial_len;
        if changed {
            // Recompile engine after policy removal (R13-LEG-5)
            self.recompile_engine(&policies).await;
        }
        Ok(serde_json::Value::Bool(changed))
    }

    fn error_code(&self, error: &McpError) -> i32 {
        match error {
            McpError::InvalidRequest(_) => -32600,
            McpError::MethodNotFound(_) => -32601,
            McpError::RequestTooLarge(_) => -32000,
            _ => -32603,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_mcp_evaluate_action() {
        let server = McpServer::new(false);

        // Add a test policy
        let add_request = json!({
            "id": "test_add",
            "method": "add_policy",
            "params": {
                "id": "bash:*",
                "name": "Block bash",
                "policy_type": "Deny",
                "priority": 100
            }
        });

        let response = server
            .handle_request(&serde_json::to_string(&add_request).unwrap())
            .await
            .unwrap();
        assert!(response.contains("\"result\":true"));

        // Test action evaluation
        let eval_request = json!({
            "id": "test_eval",
            "method": "evaluate_action",
            "params": {
                "tool": "bash",
                "function": "execute",
                "parameters": {}
            }
        });

        let response = server
            .handle_request(&serde_json::to_string(&eval_request).unwrap())
            .await
            .unwrap();
        assert!(response.contains("Deny"));
    }

    #[tokio::test]
    async fn test_mcp_request_size_protection() {
        let server = McpServer::new(false);
        let large_request = "A".repeat(2_000_000); // 2MB request

        let result = server.handle_request(&large_request).await;
        assert!(matches!(result, Err(McpError::RequestTooLarge(_))));
    }

    #[tokio::test]
    async fn test_mcp_invalid_method() {
        let server = McpServer::new(false);
        let request = json!({
            "id": "test",
            "method": "nonexistent_method",
            "params": {}
        });

        let response = server
            .handle_request(&serde_json::to_string(&request).unwrap())
            .await
            .unwrap();
        assert!(response.contains("Method not found"));
    }
}
