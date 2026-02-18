//! Model Projector types for cross-model tool schema translation (Phase 35).
//!
//! Defines the canonical (model-agnostic) tool schema representation and
//! the per-model projected call/schema types. The projector translates
//! between model-specific formats (Claude, OpenAI, DeepSeek, Qwen, Generic)
//! and the canonical form used by the policy engine.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum serialized size of a JSON Value field in projector types.
///
/// SECURITY (FIND-R51-016): Unbounded Value fields could be used for
/// memory exhaustion via crafted payloads.
pub const MAX_PROJECTOR_VALUE_SIZE: usize = 65536;

/// Canonical tool schema (model-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalToolSchema {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Option<Value>,
}

impl CanonicalToolSchema {
    /// Validate bounds on deserialized data.
    ///
    /// SECURITY (FIND-R51-016): Checks that the serialized size of
    /// `input_schema` and `output_schema` do not exceed `MAX_PROJECTOR_VALUE_SIZE`.
    pub fn validate(&self) -> Result<(), String> {
        let input_size = serde_json::to_string(&self.input_schema)
            .map_err(|e| {
                format!(
                    "CanonicalToolSchema '{}' input_schema serialization failed: {}",
                    self.name, e
                )
            })?
            .len();
        if input_size > MAX_PROJECTOR_VALUE_SIZE {
            return Err(format!(
                "CanonicalToolSchema '{}' input_schema serialized size {} exceeds max {}",
                self.name, input_size, MAX_PROJECTOR_VALUE_SIZE
            ));
        }
        if let Some(ref output) = self.output_schema {
            let output_size = serde_json::to_string(output)
                .map_err(|e| {
                    format!(
                        "CanonicalToolSchema '{}' output_schema serialization failed: {}",
                        self.name, e
                    )
                })?
                .len();
            if output_size > MAX_PROJECTOR_VALUE_SIZE {
                return Err(format!(
                    "CanonicalToolSchema '{}' output_schema serialized size {} exceeds max {}",
                    self.name, output_size, MAX_PROJECTOR_VALUE_SIZE
                ));
            }
        }
        Ok(())
    }
}

/// Canonical tool call (model-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalToolCall {
    pub tool_name: String,
    pub arguments: Value,
    pub call_id: Option<String>,
}

impl CanonicalToolCall {
    /// Validate bounds on deserialized data.
    ///
    /// SECURITY (FIND-R51-016): Checks that the serialized size of
    /// `arguments` does not exceed `MAX_PROJECTOR_VALUE_SIZE`.
    pub fn validate(&self) -> Result<(), String> {
        let args_size = serde_json::to_string(&self.arguments)
            .map_err(|e| {
                format!(
                    "CanonicalToolCall '{}' arguments serialization failed: {}",
                    self.tool_name, e
                )
            })?
            .len();
        if args_size > MAX_PROJECTOR_VALUE_SIZE {
            return Err(format!(
                "CanonicalToolCall '{}' arguments serialized size {} exceeds max {}",
                self.tool_name, args_size, MAX_PROJECTOR_VALUE_SIZE
            ));
        }
        Ok(())
    }
}

/// Canonical tool response (model-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalToolResponse {
    pub call_id: Option<String>,
    pub content: Value,
    pub is_error: bool,
}

impl CanonicalToolResponse {
    /// Validate bounds on deserialized data.
    ///
    /// SECURITY (FIND-R51-016): Checks that the serialized size of
    /// `content` does not exceed `MAX_PROJECTOR_VALUE_SIZE`.
    pub fn validate(&self) -> Result<(), String> {
        let content_size = serde_json::to_string(&self.content)
            .map_err(|e| {
                let id = self.call_id.as_deref().unwrap_or("<none>");
                format!(
                    "CanonicalToolResponse '{}' content serialization failed: {}",
                    id, e
                )
            })?
            .len();
        if content_size > MAX_PROJECTOR_VALUE_SIZE {
            let id = self.call_id.as_deref().unwrap_or("<none>");
            return Err(format!(
                "CanonicalToolResponse '{}' content serialized size {} exceeds max {}",
                id, content_size, MAX_PROJECTOR_VALUE_SIZE
            ));
        }
        Ok(())
    }
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

impl ModelFamily {
    /// Maximum length of the `Custom` variant string.
    ///
    /// SECURITY (FIND-R51-017): Unbounded Custom(String) could be used
    /// for memory exhaustion via crafted payloads.
    pub const MAX_CUSTOM_LEN: usize = 256;

    /// Validate bounds on deserialized data.
    ///
    /// SECURITY (FIND-R51-017): Bounds the Custom variant string to
    /// `MAX_CUSTOM_LEN` characters.
    pub fn validate(&self) -> Result<(), String> {
        if let ModelFamily::Custom(ref name) = self {
            if name.len() > Self::MAX_CUSTOM_LEN {
                return Err(format!(
                    "ModelFamily::Custom name length {} exceeds max {}",
                    name.len(),
                    Self::MAX_CUSTOM_LEN
                ));
            }
        }
        Ok(())
    }
}
