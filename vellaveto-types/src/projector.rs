use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Canonical tool schema (model-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalToolSchema {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Option<Value>,
}

/// Canonical tool call (model-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalToolCall {
    pub tool_name: String,
    pub arguments: Value,
    pub call_id: Option<String>,
}

/// Canonical tool response (model-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalToolResponse {
    pub call_id: Option<String>,
    pub content: Value,
    pub is_error: bool,
}

/// Model family identifier.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ModelFamily {
    Claude,
    OpenAi,
    DeepSeek,
    Qwen,
    #[default]
    Generic,
    Custom(String),
}
