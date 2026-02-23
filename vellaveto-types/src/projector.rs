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

/// Maximum length of a tool name in projector types.
///
/// SECURITY (FIND-R122-001): Matches MCP spec limit (64 chars) with margin.
pub const MAX_PROJECTOR_NAME_LENGTH: usize = 256;

/// Maximum length of a tool description in projector types.
///
/// SECURITY (FIND-R122-001): Unbounded description could cause memory
/// exhaustion during schema compression and token estimation.
pub const MAX_PROJECTOR_DESCRIPTION_LENGTH: usize = 65536;

/// Canonical tool schema (model-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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
    /// SECURITY (FIND-R122-001): Also validates `name` and `description` lengths
    /// to prevent memory exhaustion during compression/projection.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.len() > MAX_PROJECTOR_NAME_LENGTH {
            return Err(format!(
                "CanonicalToolSchema name length {} exceeds max {}",
                self.name.len(),
                MAX_PROJECTOR_NAME_LENGTH
            ));
        }
        // SECURITY (FIND-R115-004): Reject control/format chars in name field.
        if crate::core::has_dangerous_chars(&self.name)
        {
            return Err(
                "CanonicalToolSchema name contains control or format characters".to_string(),
            );
        }
        if self.description.len() > MAX_PROJECTOR_DESCRIPTION_LENGTH {
            return Err(format!(
                "CanonicalToolSchema '{}' description length {} exceeds max {}",
                self.name,
                self.description.len(),
                MAX_PROJECTOR_DESCRIPTION_LENGTH
            ));
        }
        // SECURITY (FIND-R196-002): Reject control/format chars in description field.
        // Previously only `name` was checked, allowing control char injection via description
        // which propagates into projected schemas and token estimation output.
        if crate::core::has_dangerous_chars(&self.description) {
            return Err(
                "CanonicalToolSchema description contains control or format characters".to_string(),
            );
        }
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
#[serde(deny_unknown_fields)]
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
    /// SECURITY (FIND-R122-001): Also validates `tool_name` length.
    pub fn validate(&self) -> Result<(), String> {
        if self.tool_name.len() > MAX_PROJECTOR_NAME_LENGTH {
            return Err(format!(
                "CanonicalToolCall tool_name length {} exceeds max {}",
                self.tool_name.len(),
                MAX_PROJECTOR_NAME_LENGTH
            ));
        }
        // SECURITY (FIND-R115-004): Reject control/format chars in tool_name field.
        if crate::core::has_dangerous_chars(&self.tool_name)
        {
            return Err(
                "CanonicalToolCall tool_name contains control or format characters".to_string(),
            );
        }
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
        // SECURITY (FIND-R172-005): Validate call_id for length and dangerous chars.
        if let Some(ref id) = self.call_id {
            if id.len() > MAX_PROJECTOR_NAME_LENGTH {
                return Err(format!(
                    "CanonicalToolCall call_id length {} exceeds max {}",
                    id.len(),
                    MAX_PROJECTOR_NAME_LENGTH
                ));
            }
            if crate::core::has_dangerous_chars(id) {
                return Err(
                    "CanonicalToolCall call_id contains control or format characters".to_string(),
                );
            }
        }
        Ok(())
    }
}

/// Canonical tool response (model-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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
        // SECURITY (FIND-R172-005): Validate call_id for length and dangerous chars.
        if let Some(ref id) = self.call_id {
            if id.len() > MAX_PROJECTOR_NAME_LENGTH {
                return Err(format!(
                    "CanonicalToolResponse call_id length {} exceeds max {}",
                    id.len(),
                    MAX_PROJECTOR_NAME_LENGTH
                ));
            }
            if crate::core::has_dangerous_chars(id) {
                return Err(
                    "CanonicalToolResponse call_id contains control or format characters"
                        .to_string(),
                );
            }
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
