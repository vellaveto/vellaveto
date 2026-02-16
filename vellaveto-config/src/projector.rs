use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectorConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_model_family")]
    pub default_model_family: String,
    #[serde(default = "default_auto_detect")]
    pub auto_detect_model: bool,
    #[serde(default)]
    pub compress_schemas: bool,
    #[serde(default)]
    pub max_schema_tokens: Option<usize>,
    #[serde(default = "default_repair")]
    pub repair_malformed_calls: bool,
}

fn default_model_family() -> String {
    "generic".to_string()
}

fn default_auto_detect() -> bool {
    true
}

fn default_repair() -> bool {
    true
}

const MAX_SCHEMA_TOKENS: usize = 1_000_000;
const VALID_FAMILIES: &[&str] = &["claude", "openai", "deepseek", "qwen", "generic"];

impl Default for ProjectorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_model_family: default_model_family(),
            auto_detect_model: default_auto_detect(),
            compress_schemas: false,
            max_schema_tokens: None,
            repair_malformed_calls: default_repair(),
        }
    }
}

impl ProjectorConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !VALID_FAMILIES.contains(&self.default_model_family.as_str())
            && !self.default_model_family.starts_with("custom:")
        {
            return Err(format!(
                "projector.default_model_family '{}': must be one of {:?} or 'custom:<name>'",
                self.default_model_family, VALID_FAMILIES
            ));
        }
        if let Some(tokens) = self.max_schema_tokens {
            if tokens == 0 || tokens > MAX_SCHEMA_TOKENS {
                return Err(format!(
                    "projector.max_schema_tokens must be 1..={}, got {}",
                    MAX_SCHEMA_TOKENS, tokens
                ));
            }
        }
        Ok(())
    }
}
