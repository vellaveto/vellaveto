//! LLM backend implementations for semantic guardrails (Phase 12).
//!
//! Provides different backend implementations for the `LlmEvaluator` trait:
//!
//! - `MockEvaluator`: In-memory mock for testing
//! - `OpenAiBackend`: OpenAI API (feature: `llm-cloud`)
//! - `AnthropicBackend`: Anthropic API (feature: `llm-cloud`)
//!
//! # Backend Selection
//!
//! Use the `BackendDispatcher` to select backends based on configuration:
//!
//! ```rust,ignore
//! use vellaveto_mcp::semantic_guardrails::backends::BackendDispatcher;
//!
//! let dispatcher = BackendDispatcher::new(config)?;
//! let evaluation = dispatcher.evaluate(&input).await?;
//! ```

pub mod mock;

#[cfg(feature = "llm-cloud")]
pub mod anthropic;
#[cfg(feature = "llm-cloud")]
pub mod openai;

use crate::semantic_guardrails::evaluator::{
    JailbreakDetection, LlmEvalError, LlmEvalInput, LlmEvaluation, LlmEvaluator,
};
use crate::semantic_guardrails::intent::IntentClassification;
use std::sync::Arc;
use std::time::Duration;

pub use mock::MockEvaluator;

// ═══════════════════════════════════════════════════
// BACKEND DISPATCHER
// ═══════════════════════════════════════════════════

/// Maximum number of fallback backends.
const MAX_FALLBACK_BACKENDS: usize = 10;

/// Dispatches evaluation requests to the appropriate backend.
///
/// Supports failover to secondary backends if the primary is unhealthy.
pub struct BackendDispatcher {
    /// Primary backend.
    primary: Arc<dyn LlmEvaluator>,
    /// Optional fallback backends (tried in order).
    fallbacks: Vec<Arc<dyn LlmEvaluator>>,
}

impl BackendDispatcher {
    /// Creates a dispatcher with a single backend.
    pub fn new(backend: impl LlmEvaluator + 'static) -> Self {
        Self {
            primary: Arc::new(backend),
            fallbacks: Vec::new(),
        }
    }

    /// Creates a dispatcher from a boxed evaluator.
    pub fn from_arc(backend: Arc<dyn LlmEvaluator>) -> Self {
        Self {
            primary: backend,
            fallbacks: Vec::new(),
        }
    }

    /// Adds a fallback backend.
    ///
    /// SECURITY (FIND-R114-007/IMP): Bounded at MAX_FALLBACK_BACKENDS.
    pub fn with_fallback(mut self, backend: impl LlmEvaluator + 'static) -> Self {
        if self.fallbacks.len() >= MAX_FALLBACK_BACKENDS {
            tracing::warn!(
                "BackendDispatcher: fallback backends at capacity ({}), ignoring additional",
                MAX_FALLBACK_BACKENDS
            );
            return self;
        }
        self.fallbacks.push(Arc::new(backend));
        self
    }

    /// Returns the primary backend.
    pub fn primary(&self) -> &Arc<dyn LlmEvaluator> {
        &self.primary
    }

    /// Returns the fallback backends.
    pub fn fallbacks(&self) -> &[Arc<dyn LlmEvaluator>] {
        &self.fallbacks
    }

    /// Finds a healthy backend, preferring primary.
    fn find_healthy_backend(&self) -> Option<&Arc<dyn LlmEvaluator>> {
        if self.primary.is_healthy() {
            return Some(&self.primary);
        }

        for fallback in &self.fallbacks {
            if fallback.is_healthy() {
                return Some(fallback);
            }
        }

        // Return primary even if unhealthy (let it fail)
        Some(&self.primary)
    }
}

#[async_trait::async_trait]
impl LlmEvaluator for BackendDispatcher {
    async fn evaluate(&self, input: &LlmEvalInput) -> Result<LlmEvaluation, LlmEvalError> {
        let backend = self
            .find_healthy_backend()
            .ok_or_else(|| LlmEvalError::Unhealthy("no healthy backend".to_string()))?;

        let result = backend.evaluate(input).await;

        // On failure, try fallbacks
        if result.is_err() && !self.fallbacks.is_empty() {
            for fallback in &self.fallbacks {
                if fallback.is_healthy() {
                    if let Ok(eval) = fallback.evaluate(input).await {
                        return Ok(eval);
                    }
                }
            }
        }

        result
    }

    async fn classify_intent(
        &self,
        input: &LlmEvalInput,
    ) -> Result<IntentClassification, LlmEvalError> {
        let backend = self
            .find_healthy_backend()
            .ok_or_else(|| LlmEvalError::Unhealthy("no healthy backend".to_string()))?;

        backend.classify_intent(input).await
    }

    async fn detect_jailbreak(&self, content: &str) -> Result<JailbreakDetection, LlmEvalError> {
        let backend = self
            .find_healthy_backend()
            .ok_or_else(|| LlmEvalError::Unhealthy("no healthy backend".to_string()))?;

        backend.detect_jailbreak(content).await
    }

    fn is_healthy(&self) -> bool {
        self.primary.is_healthy() || self.fallbacks.iter().any(|f| f.is_healthy())
    }

    fn backend_id(&self) -> &str {
        "dispatcher"
    }

    fn timeout(&self) -> Duration {
        self.primary.timeout()
    }
}

// ═══════════════════════════════════════════════════
// BACKEND BUILDER
// ═══════════════════════════════════════════════════

/// Builder for creating backend configurations.
#[derive(Clone, Default)]
pub struct BackendBuilder {
    backend_type: BackendType,
    timeout_ms: u64,
    api_key: Option<String>,
    model: Option<String>,
    endpoint: Option<String>,
}

/// SECURITY (FIND-R114-016): Custom Debug that redacts api_key.
impl std::fmt::Debug for BackendBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendBuilder")
            .field("backend_type", &self.backend_type)
            .field("timeout_ms", &self.timeout_ms)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("model", &self.model)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

/// Supported backend types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackendType {
    /// Mock backend for testing.
    #[default]
    Mock,
    /// OpenAI API backend.
    OpenAi,
    /// Anthropic API backend.
    Anthropic,
    /// Local GGUF model (future).
    LocalGguf,
    /// Local ONNX model (future).
    LocalOnnx,
}

impl BackendBuilder {
    /// Creates a new backend builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the backend type.
    pub fn backend_type(mut self, backend_type: BackendType) -> Self {
        self.backend_type = backend_type;
        self
    }

    /// Sets the timeout in milliseconds.
    pub fn timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Sets the API key.
    pub fn api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Sets the model name.
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Sets the endpoint URL.
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Builds the backend.
    ///
    /// Returns a boxed `LlmEvaluator` trait object.
    pub fn build(self) -> Result<Arc<dyn LlmEvaluator>, LlmEvalError> {
        match self.backend_type {
            BackendType::Mock => {
                let evaluator = MockEvaluator::new();
                Ok(Arc::new(evaluator))
            }

            #[cfg(feature = "llm-cloud")]
            BackendType::OpenAi => {
                let api_key = self.api_key.ok_or_else(|| {
                    LlmEvalError::NotConfigured("OpenAI API key required".to_string())
                })?;

                let config = openai::OpenAiConfig {
                    api_key,
                    model: self.model.unwrap_or_else(|| "gpt-4o-mini".to_string()),
                    timeout_ms: if self.timeout_ms > 0 {
                        self.timeout_ms
                    } else {
                        3000
                    },
                    max_tokens: 256,
                    endpoint: self.endpoint,
                };

                let evaluator = openai::OpenAiBackend::new(config)?;
                Ok(Arc::new(evaluator))
            }

            #[cfg(feature = "llm-cloud")]
            BackendType::Anthropic => {
                let api_key = self.api_key.ok_or_else(|| {
                    LlmEvalError::NotConfigured("Anthropic API key required".to_string())
                })?;

                let config = anthropic::AnthropicConfig {
                    api_key,
                    model: self
                        .model
                        .unwrap_or_else(|| "claude-3-haiku-20240307".to_string()),
                    timeout_ms: if self.timeout_ms > 0 {
                        self.timeout_ms
                    } else {
                        3000
                    },
                    max_tokens: 256,
                    endpoint: self.endpoint,
                };

                let evaluator = anthropic::AnthropicBackend::new(config)?;
                Ok(Arc::new(evaluator))
            }

            #[cfg(not(feature = "llm-cloud"))]
            BackendType::OpenAi | BackendType::Anthropic => Err(LlmEvalError::NotConfigured(
                "llm-cloud feature not enabled".to_string(),
            )),

            BackendType::LocalGguf | BackendType::LocalOnnx => Err(LlmEvalError::NotConfigured(
                "local model backends not yet implemented".to_string(),
            )),
        }
    }
}

// ═══════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_backend_dispatcher_uses_primary() {
        let mock = MockEvaluator::new();
        let dispatcher = BackendDispatcher::new(mock);

        let input = LlmEvalInput::new("test", "func");
        let result = dispatcher.evaluate(&input).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_backend_dispatcher_with_fallback() {
        let primary = MockEvaluator::new();
        let fallback = MockEvaluator::new();

        let dispatcher = BackendDispatcher::new(primary).with_fallback(fallback);

        assert!(dispatcher.is_healthy());
        assert_eq!(dispatcher.backend_id(), "dispatcher");
    }

    #[test]
    fn test_backend_builder_mock() {
        let backend = BackendBuilder::new()
            .backend_type(BackendType::Mock)
            .build();

        assert!(backend.is_ok());
    }

    #[test]
    fn test_backend_builder_requires_api_key() {
        #[cfg(feature = "llm-cloud")]
        {
            let result = BackendBuilder::new()
                .backend_type(BackendType::OpenAi)
                .build();

            assert!(result.is_err());
        }
    }

    #[test]
    fn test_backend_type_default() {
        assert_eq!(BackendType::default(), BackendType::Mock);
    }
}
