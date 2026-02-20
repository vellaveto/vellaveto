//! LLM evaluator trait and core types for semantic guardrails (Phase 12).
//!
//! Defines the `LlmEvaluator` trait that backend implementations must satisfy,
//! along with input/output types for semantic policy evaluation.
//!
//! # Architecture
//!
//! The evaluator follows a trait-based design to support multiple backends:
//! - Mock backend for testing
//! - OpenAI backend (GPT-4o-mini, etc.)
//! - Anthropic backend (Claude)
//! - Local GGUF/ONNX backends (future)
//!
//! # Example
//!
//! ```rust,ignore
//! use vellaveto_mcp::semantic_guardrails::{LlmEvaluator, LlmEvalInput, LlmEvaluation};
//!
//! async fn evaluate_action(evaluator: &dyn LlmEvaluator, tool: &str, params: serde_json::Value) {
//!     let input = LlmEvalInput {
//!         tool: tool.to_string(),
//!         function: "execute".to_string(),
//!         parameters: params,
//!         ..Default::default()
//!     };
//!
//!     match evaluator.evaluate(&input).await {
//!         Ok(eval) if eval.allow => println!("Action allowed"),
//!         Ok(eval) => println!("Action denied: {:?}", eval.explanation),
//!         Err(e) => println!("Evaluation failed: {}", e),
//!     }
//! }
//! ```

use crate::semantic_guardrails::intent::{Intent, IntentClassification, RiskCategory};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

// ═══════════════════════════════════════════════════
// ERROR TYPES
// ═══════════════════════════════════════════════════

/// Errors from LLM evaluation operations.
#[derive(Debug, Error)]
pub enum LlmEvalError {
    /// Backend is not configured or unavailable.
    #[error("LLM backend not configured: {0}")]
    NotConfigured(String),

    /// Backend request failed.
    #[error("LLM request failed: {0}")]
    RequestFailed(String),

    /// Backend timed out.
    #[error("LLM evaluation timed out after {0}ms")]
    Timeout(u64),

    /// Backend returned invalid response.
    #[error("Invalid LLM response: {0}")]
    InvalidResponse(String),

    /// Rate limited by backend.
    #[error("LLM rate limited: retry after {retry_after_ms:?}ms")]
    RateLimited {
        /// Suggested retry delay in milliseconds.
        retry_after_ms: Option<u64>,
    },

    /// Content was filtered by the model's safety systems.
    #[error("Content filtered by model safety systems")]
    ContentFiltered,

    /// Model returned low confidence evaluation.
    #[error("Low confidence evaluation: {confidence}")]
    LowConfidence {
        /// The confidence score returned.
        confidence: f64,
    },

    /// Input validation failed.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Backend is unhealthy (circuit breaker open).
    #[error("LLM backend unhealthy: {0}")]
    Unhealthy(String),
}

/// SECURITY (FIND-R114-009): Clamp a confidence value to [0.0, 1.0].
/// NaN and non-finite values are treated as 0.0 (fail-closed for Allow, conservative for Deny).
pub(crate) fn clamp_confidence(value: f64) -> f64 {
    if !value.is_finite() {
        return 0.0;
    }
    value.clamp(0.0, 1.0)
}

// ═══════════════════════════════════════════════════
// INPUT TYPES
// ═══════════════════════════════════════════════════

/// Input for LLM policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmEvalInput {
    /// The tool being invoked.
    pub tool: String,

    /// The function/method being called.
    pub function: String,

    /// Parameters passed to the function.
    #[serde(default)]
    pub parameters: serde_json::Value,

    /// Conversation context (recent messages).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<ContextMessage>>,

    /// Natural language policies to enforce.
    #[serde(default)]
    pub nl_policies: Vec<String>,

    /// Session identifier for intent chain tracking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Principal (user/agent) making the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,

    /// Additional metadata for evaluation.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

impl Default for LlmEvalInput {
    fn default() -> Self {
        Self {
            tool: String::new(),
            function: String::new(),
            parameters: serde_json::Value::Null,
            context: None,
            nl_policies: Vec::new(),
            session_id: None,
            principal: None,
            metadata: serde_json::Value::Null,
        }
    }
}

impl LlmEvalInput {
    /// Creates a new input for the given tool and function.
    pub fn new(tool: impl Into<String>, function: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            function: function.into(),
            ..Default::default()
        }
    }

    /// Sets the parameters.
    pub fn with_parameters(mut self, params: serde_json::Value) -> Self {
        self.parameters = params;
        self
    }

    /// Sets the session ID.
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Adds natural language policies.
    pub fn with_nl_policies(mut self, policies: Vec<String>) -> Self {
        self.nl_policies = policies;
        self
    }

    /// Adds conversation context.
    pub fn with_context(mut self, context: Vec<ContextMessage>) -> Self {
        self.context = Some(context);
        self
    }

    /// Validates the input, returning an error if invalid.
    pub fn validate(&self) -> Result<(), LlmEvalError> {
        if self.tool.is_empty() {
            return Err(LlmEvalError::InvalidInput("tool is required".to_string()));
        }
        if self.tool.len() > 256 {
            return Err(LlmEvalError::InvalidInput("tool name too long".to_string()));
        }
        if self.function.len() > 256 {
            return Err(LlmEvalError::InvalidInput(
                "function name too long".to_string(),
            ));
        }
        if self.nl_policies.len() > 50 {
            return Err(LlmEvalError::InvalidInput(
                "too many NL policies (max 50)".to_string(),
            ));
        }
        if let Some(ctx) = &self.context {
            if ctx.len() > 100 {
                return Err(LlmEvalError::InvalidInput(
                    "context too long (max 100 messages)".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// A message in the conversation context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextMessage {
    /// Role of the message sender (user, assistant, system, tool).
    pub role: String,
    /// Content of the message.
    pub content: String,
}

impl ContextMessage {
    /// Creates a new context message.
    pub fn new(role: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            content: content.into(),
        }
    }
}

// ═══════════════════════════════════════════════════
// OUTPUT TYPES
// ═══════════════════════════════════════════════════

/// Result of LLM policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmEvaluation {
    /// Whether the action is allowed.
    pub allow: bool,

    /// Confidence score for the decision (0.0 to 1.0).
    pub confidence: f64,

    /// Classified intent of the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<Intent>,

    /// Human-readable explanation of the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,

    /// Latency of the evaluation in milliseconds.
    pub latency_ms: u64,

    /// Whether the result came from cache.
    #[serde(default)]
    pub from_cache: bool,

    /// Detected security risks.
    #[serde(default)]
    pub detected_risks: Vec<RiskCategory>,

    /// Policies that matched (for debugging).
    #[serde(default)]
    pub matched_policies: Vec<String>,

    /// Backend that produced this evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_id: Option<String>,
}

impl Default for LlmEvaluation {
    fn default() -> Self {
        Self {
            allow: false, // Fail-closed
            confidence: 0.0,
            intent: None,
            explanation: None,
            latency_ms: 0,
            from_cache: false,
            detected_risks: Vec::new(),
            matched_policies: Vec::new(),
            backend_id: None,
        }
    }
}

impl LlmEvaluation {
    /// Creates a denial evaluation.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allow: false,
            confidence: 1.0,
            explanation: Some(reason.into()),
            ..Default::default()
        }
    }

    /// Creates an allow evaluation.
    pub fn allow() -> Self {
        Self {
            allow: true,
            confidence: 1.0,
            ..Default::default()
        }
    }

    /// Creates an allow evaluation with confidence.
    ///
    /// SECURITY (FIND-R114-009): NaN/Infinity/negative values are clamped to [0.0, 1.0].
    pub fn allow_with_confidence(confidence: f64) -> Self {
        Self {
            allow: true,
            confidence: clamp_confidence(confidence),
            ..Default::default()
        }
    }

    /// Sets the confidence score.
    ///
    /// SECURITY (FIND-R114-009): NaN/Infinity/negative values are clamped to [0.0, 1.0].
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = clamp_confidence(confidence);
        self
    }

    /// Sets the latency.
    pub fn with_latency(mut self, latency_ms: u64) -> Self {
        self.latency_ms = latency_ms;
        self
    }

    /// Marks as from cache.
    pub fn from_cache(mut self) -> Self {
        self.from_cache = true;
        self
    }

    /// Sets the backend ID.
    pub fn with_backend(mut self, backend_id: impl Into<String>) -> Self {
        self.backend_id = Some(backend_id.into());
        self
    }

    /// Adds detected risks.
    pub fn with_risks(mut self, risks: Vec<RiskCategory>) -> Self {
        self.detected_risks = risks;
        self
    }

    /// Sets the intent.
    pub fn with_intent(mut self, intent: Intent) -> Self {
        self.intent = Some(intent);
        self
    }
}

// ═══════════════════════════════════════════════════
// JAILBREAK DETECTION
// ═══════════════════════════════════════════════════

/// Result of jailbreak detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailbreakDetection {
    /// Whether a jailbreak attempt was detected.
    pub is_jailbreak: bool,

    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,

    /// Type of jailbreak detected (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jailbreak_type: Option<String>,

    /// Explanation of the detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,

    /// Latency of the detection in milliseconds.
    pub latency_ms: u64,
}

impl Default for JailbreakDetection {
    fn default() -> Self {
        Self {
            is_jailbreak: false,
            confidence: 0.0,
            jailbreak_type: None,
            explanation: None,
            latency_ms: 0,
        }
    }
}

impl JailbreakDetection {
    /// Creates a detection result indicating no jailbreak.
    ///
    /// SECURITY (FIND-R114-009): NaN/Infinity/negative values are clamped to [0.0, 1.0].
    pub fn safe(confidence: f64) -> Self {
        Self {
            is_jailbreak: false,
            confidence: clamp_confidence(confidence),
            ..Default::default()
        }
    }

    /// Creates a detection result indicating a jailbreak was detected.
    ///
    /// SECURITY (FIND-R114-009): NaN/Infinity/negative values are clamped to [0.0, 1.0].
    pub fn detected(jailbreak_type: impl Into<String>, confidence: f64) -> Self {
        Self {
            is_jailbreak: true,
            confidence: clamp_confidence(confidence),
            jailbreak_type: Some(jailbreak_type.into()),
            ..Default::default()
        }
    }
}

// ═══════════════════════════════════════════════════
// EVALUATOR TRAIT
// ═══════════════════════════════════════════════════

/// Trait for LLM-based policy evaluation backends.
///
/// Implementations must be `Send + Sync` to support concurrent evaluation.
/// All methods are async to support network-based backends.
#[async_trait::async_trait]
pub trait LlmEvaluator: Send + Sync {
    /// Evaluates an action against semantic policies.
    ///
    /// Returns `LlmEvaluation` with the decision and metadata.
    /// On error, returns `LlmEvalError` — callers should typically
    /// treat errors as denials (fail-closed).
    async fn evaluate(&self, input: &LlmEvalInput) -> Result<LlmEvaluation, LlmEvalError>;

    /// Classifies the intent of an action.
    ///
    /// Returns structured intent classification with confidence scores.
    async fn classify_intent(
        &self,
        input: &LlmEvalInput,
    ) -> Result<IntentClassification, LlmEvalError>;

    /// Detects jailbreak attempts in content.
    ///
    /// Analyzes the content for known jailbreak patterns.
    async fn detect_jailbreak(&self, content: &str) -> Result<JailbreakDetection, LlmEvalError>;

    /// Returns true if the backend is healthy and ready to accept requests.
    fn is_healthy(&self) -> bool;

    /// Returns the unique identifier for this backend.
    fn backend_id(&self) -> &str;

    /// Returns the configured timeout for this backend.
    fn timeout(&self) -> Duration {
        Duration::from_millis(3000)
    }
}

// ═══════════════════════════════════════════════════
// EVALUATOR WRAPPER
// ═══════════════════════════════════════════════════

/// Wrapper that adds common functionality to any evaluator.
///
/// Provides:
/// - Input validation
/// - Latency tracking
/// - Confidence threshold enforcement
pub struct SemanticGuardrailsEvaluator<E: LlmEvaluator> {
    inner: E,
    min_confidence: f64,
    fallback_on_error: FallbackBehavior,
}

/// Behavior when evaluation fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FallbackBehavior {
    /// Deny the action (fail-closed, default).
    #[default]
    Deny,
    /// Allow the action (fail-open, dangerous).
    Allow,
    /// Fall back to pattern-based matching.
    PatternMatch,
}

impl<E: LlmEvaluator> SemanticGuardrailsEvaluator<E> {
    /// Creates a new evaluator wrapper.
    pub fn new(inner: E) -> Self {
        Self {
            inner,
            min_confidence: 0.7,
            fallback_on_error: FallbackBehavior::Deny,
        }
    }

    /// Sets the minimum confidence threshold.
    pub fn with_min_confidence(mut self, confidence: f64) -> Self {
        self.min_confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Sets the fallback behavior on error.
    pub fn with_fallback(mut self, fallback: FallbackBehavior) -> Self {
        if fallback == FallbackBehavior::Allow {
            tracing::error!(
                "SECURITY WARNING: Semantic guardrails configured with fallback_on_error=allow. \
                 Evaluation failures will result in Allow verdicts (fail-open). \
                 This is dangerous in production."
            );
        }
        self.fallback_on_error = fallback;
        self
    }

    /// Returns a reference to the inner evaluator.
    pub fn inner(&self) -> &E {
        &self.inner
    }

    /// Evaluates with validation and confidence checking.
    pub async fn evaluate_with_validation(
        &self,
        input: &LlmEvalInput,
    ) -> Result<LlmEvaluation, LlmEvalError> {
        // Validate input
        input.validate()?;

        // Perform evaluation
        let start = std::time::Instant::now();
        let mut result = self.inner.evaluate(input).await?;
        result.latency_ms = start.elapsed().as_millis() as u64;

        // Check confidence threshold
        // SECURITY (FIND-R64-002): NaN confidence is treated as low-confidence (fail-closed).
        if (!result.confidence.is_finite() || result.confidence < self.min_confidence)
            && result.allow
        {
            return Err(LlmEvalError::LowConfidence {
                confidence: result.confidence,
            });
        }

        Ok(result)
    }

    /// Handles evaluation errors according to fallback behavior.
    pub fn handle_error(&self, error: &LlmEvalError) -> LlmEvaluation {
        match self.fallback_on_error {
            FallbackBehavior::Deny => LlmEvaluation::deny(format!("Evaluation failed: {}", error)),
            FallbackBehavior::Allow => {
                tracing::warn!("semantic guardrail falling back to Allow — check configuration");
                let mut eval = LlmEvaluation::allow();
                eval.explanation = Some(format!("Allowed due to fallback (error: {})", error));
                eval.confidence = 0.0;
                eval
            }
            FallbackBehavior::PatternMatch => {
                // Return a special evaluation indicating pattern match fallback
                LlmEvaluation {
                    allow: false, // Will be determined by pattern matcher
                    confidence: 0.0,
                    explanation: Some("Falling back to pattern matching".to_string()),
                    ..Default::default()
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl<E: LlmEvaluator> LlmEvaluator for SemanticGuardrailsEvaluator<E> {
    async fn evaluate(&self, input: &LlmEvalInput) -> Result<LlmEvaluation, LlmEvalError> {
        self.evaluate_with_validation(input).await
    }

    async fn classify_intent(
        &self,
        input: &LlmEvalInput,
    ) -> Result<IntentClassification, LlmEvalError> {
        input.validate()?;
        self.inner.classify_intent(input).await
    }

    async fn detect_jailbreak(&self, content: &str) -> Result<JailbreakDetection, LlmEvalError> {
        if content.is_empty() {
            return Ok(JailbreakDetection::safe(1.0));
        }
        if content.len() > 100_000 {
            return Err(LlmEvalError::InvalidInput(
                "content too long for jailbreak detection".to_string(),
            ));
        }
        self.inner.detect_jailbreak(content).await
    }

    fn is_healthy(&self) -> bool {
        self.inner.is_healthy()
    }

    fn backend_id(&self) -> &str {
        self.inner.backend_id()
    }

    fn timeout(&self) -> Duration {
        self.inner.timeout()
    }
}

// ═══════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llm_eval_input_validation() {
        let input = LlmEvalInput::default();
        assert!(input.validate().is_err()); // Empty tool

        let input = LlmEvalInput::new("tool", "func");
        assert!(input.validate().is_ok());

        let input = LlmEvalInput::new("a".repeat(300), "func");
        assert!(input.validate().is_err()); // Tool too long
    }

    #[test]
    fn test_llm_eval_input_builder() {
        let input = LlmEvalInput::new("fs", "read")
            .with_parameters(serde_json::json!({"path": "/tmp/foo"}))
            .with_session("sess123")
            .with_nl_policies(vec!["no file deletion".to_string()]);

        assert_eq!(input.tool, "fs");
        assert_eq!(input.function, "read");
        assert!(input.session_id.is_some());
        assert_eq!(input.nl_policies.len(), 1);
    }

    #[test]
    fn test_llm_evaluation_deny() {
        let eval = LlmEvaluation::deny("not allowed");
        assert!(!eval.allow);
        assert_eq!(eval.confidence, 1.0);
        assert!(eval.explanation.is_some());
    }

    #[test]
    fn test_llm_evaluation_allow() {
        let eval = LlmEvaluation::allow()
            .with_latency(50)
            .with_backend("mock")
            .with_intent(Intent::DataRead);

        assert!(eval.allow);
        assert_eq!(eval.latency_ms, 50);
        assert_eq!(eval.backend_id, Some("mock".to_string()));
        assert_eq!(eval.intent, Some(Intent::DataRead));
    }

    #[test]
    fn test_jailbreak_detection_safe() {
        let detection = JailbreakDetection::safe(0.95);
        assert!(!detection.is_jailbreak);
        assert!(detection.confidence > 0.9);
    }

    #[test]
    fn test_jailbreak_detection_detected() {
        let detection = JailbreakDetection::detected("prompt_injection", 0.85);
        assert!(detection.is_jailbreak);
        assert!(detection.jailbreak_type.is_some());
    }

    #[test]
    fn test_fallback_behavior_default() {
        assert_eq!(FallbackBehavior::default(), FallbackBehavior::Deny);
    }

    #[test]
    fn test_context_message() {
        let msg = ContextMessage::new("user", "Hello, world!");
        assert_eq!(msg.role, "user");
        assert_eq!(msg.content, "Hello, world!");
    }

    #[test]
    fn test_llm_eval_error_display() {
        let err = LlmEvalError::Timeout(3000);
        assert!(err.to_string().contains("3000"));

        let err = LlmEvalError::RateLimited {
            retry_after_ms: Some(5000),
        };
        assert!(err.to_string().contains("rate limited"));
    }

    #[test]
    fn test_llm_evaluation_serialization() {
        let eval = LlmEvaluation::allow()
            .with_intent(Intent::DataRead)
            .with_risks(vec![RiskCategory::DataLeakage]);

        let json = serde_json::to_string(&eval).expect("serialize");
        let parsed: LlmEvaluation = serde_json::from_str(&json).expect("deserialize");

        assert!(parsed.allow);
        assert_eq!(parsed.intent, Some(Intent::DataRead));
        assert_eq!(parsed.detected_risks.len(), 1);
    }

    // ═══════════════════════════════════════════════════
    // clamp_confidence TESTS (IMP-R116-017)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_clamp_confidence_nan_returns_zero() {
        assert_eq!(clamp_confidence(f64::NAN), 0.0);
    }

    #[test]
    fn test_clamp_confidence_positive_infinity_returns_zero() {
        assert_eq!(clamp_confidence(f64::INFINITY), 0.0);
    }

    #[test]
    fn test_clamp_confidence_negative_infinity_returns_zero() {
        assert_eq!(clamp_confidence(f64::NEG_INFINITY), 0.0);
    }

    #[test]
    fn test_clamp_confidence_negative_returns_zero() {
        assert_eq!(clamp_confidence(-0.5), 0.0);
    }

    #[test]
    fn test_clamp_confidence_above_one_clamps() {
        assert_eq!(clamp_confidence(1.5), 1.0);
    }

    #[test]
    fn test_clamp_confidence_valid_unchanged() {
        assert_eq!(clamp_confidence(0.5), 0.5);
        assert_eq!(clamp_confidence(0.0), 0.0);
        assert_eq!(clamp_confidence(1.0), 1.0);
    }

    #[test]
    fn test_allow_with_confidence_nan_clamped() {
        let eval = LlmEvaluation::allow_with_confidence(f64::NAN);
        assert_eq!(eval.confidence, 0.0);
    }

    #[test]
    fn test_allow_with_confidence_negative_clamped() {
        let eval = LlmEvaluation::allow_with_confidence(-1.0);
        assert_eq!(eval.confidence, 0.0);
    }

    #[test]
    fn test_allow_with_confidence_over_one_clamped() {
        let eval = LlmEvaluation::allow_with_confidence(2.0);
        assert_eq!(eval.confidence, 1.0);
    }

    #[test]
    fn test_jailbreak_safe_nan_confidence_clamped() {
        let jb = JailbreakDetection::safe(f64::NAN);
        assert_eq!(jb.confidence, 0.0);
    }

    #[test]
    fn test_jailbreak_detected_negative_confidence_clamped() {
        let jb = JailbreakDetection::detected("injection", -0.5);
        assert_eq!(jb.confidence, 0.0);
    }
}
