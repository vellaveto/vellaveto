mod claude;
pub mod compress;
mod deepseek;
mod error;
mod generic;
mod openai;
mod qwen;
pub mod repair;

pub use compress::SchemaCompressor;
pub use error::ProjectorError;
pub use repair::CallRepairer;

use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use vellaveto_types::{CanonicalToolCall, CanonicalToolResponse, CanonicalToolSchema, ModelFamily};

/// Trait for model-specific schema projection.
pub trait ModelProjection: Send + Sync {
    fn model_family(&self) -> ModelFamily;
    fn project_schema(&self, canonical: &CanonicalToolSchema) -> Result<Value, ProjectorError>;
    fn parse_call(&self, raw: &Value) -> Result<CanonicalToolCall, ProjectorError>;
    fn format_response(&self, canonical: &CanonicalToolResponse) -> Result<Value, ProjectorError>;
    fn estimate_tokens(&self, schema: &CanonicalToolSchema) -> usize;
}

/// Fail-closed token estimate returned when serialization fails.
///
/// SECURITY (FIND-R131-001): Using `unwrap_or_default()` on `serde_json::to_string()`
/// returns an empty string → 0 tokens → fail-open (compression thinks schema fits).
/// All `estimate_tokens()` implementations must return this on serialization failure
/// to trigger compression strategies as a fail-closed defense.
pub(crate) const FAILSAFE_TOKEN_ESTIMATE: usize = 100_000;

/// Maximum number of registered model projections.
const MAX_REGISTERED_PROJECTIONS: usize = 100;

/// Registry of model projections.
pub struct ProjectorRegistry {
    projections: RwLock<HashMap<ModelFamily, Arc<dyn ModelProjection>>>,
    default_family: ModelFamily,
}

impl ProjectorRegistry {
    pub fn new(default_family: ModelFamily) -> Self {
        Self {
            projections: RwLock::new(HashMap::new()),
            default_family,
        }
    }

    pub fn with_defaults(default_family: ModelFamily) -> Result<Self, ProjectorError> {
        let registry = Self::new(default_family);
        registry.register(Arc::new(claude::ClaudeProjection))?;
        registry.register(Arc::new(openai::OpenAiProjection))?;
        registry.register(Arc::new(deepseek::DeepSeekProjection))?;
        registry.register(Arc::new(qwen::QwenProjection))?;
        registry.register(Arc::new(generic::GenericProjection))?;
        Ok(registry)
    }

    /// SECURITY (FIND-R114-005/IMP): Bounded at MAX_REGISTERED_PROJECTIONS.
    pub fn register(&self, projection: Arc<dyn ModelProjection>) -> Result<(), ProjectorError> {
        let family = projection.model_family();
        let mut map = self
            .projections
            .write()
            .map_err(|_| ProjectorError::LockPoisoned)?;
        // Allow replacement of existing families, but bound new entries
        if !map.contains_key(&family) && map.len() >= MAX_REGISTERED_PROJECTIONS {
            return Err(ProjectorError::ParseError(format!(
                "ProjectorRegistry capacity exceeded ({} projections)",
                MAX_REGISTERED_PROJECTIONS
            )));
        }
        map.insert(family, projection);
        Ok(())
    }

    pub fn get(&self, family: &ModelFamily) -> Result<Arc<dyn ModelProjection>, ProjectorError> {
        let map = self
            .projections
            .read()
            .map_err(|_| ProjectorError::LockPoisoned)?;
        map.get(family)
            .cloned()
            .ok_or_else(|| ProjectorError::UnsupportedFamily(family.clone()))
    }

    pub fn get_default(&self) -> Result<Arc<dyn ModelProjection>, ProjectorError> {
        self.get(&self.default_family)
    }

    pub fn families(&self) -> Result<Vec<ModelFamily>, ProjectorError> {
        let map = self
            .projections
            .read()
            .map_err(|_| ProjectorError::LockPoisoned)?;
        Ok(map.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_registry_new_empty() {
        let reg = ProjectorRegistry::new(ModelFamily::Generic);
        assert!(reg.get(&ModelFamily::Claude).is_err());
    }

    #[test]
    fn test_registry_with_defaults_has_all_families() {
        let reg = ProjectorRegistry::with_defaults(ModelFamily::Generic).unwrap();
        assert!(reg.get(&ModelFamily::Claude).is_ok());
        assert!(reg.get(&ModelFamily::OpenAi).is_ok());
        assert!(reg.get(&ModelFamily::DeepSeek).is_ok());
        assert!(reg.get(&ModelFamily::Qwen).is_ok());
        assert!(reg.get(&ModelFamily::Generic).is_ok());
    }

    #[test]
    fn test_registry_get_default() {
        let reg = ProjectorRegistry::with_defaults(ModelFamily::Claude).unwrap();
        let proj = reg.get_default().unwrap();
        assert_eq!(proj.model_family(), ModelFamily::Claude);
    }

    #[test]
    fn test_registry_get_default_generic() {
        let reg = ProjectorRegistry::with_defaults(ModelFamily::Generic).unwrap();
        let proj = reg.get_default().unwrap();
        assert_eq!(proj.model_family(), ModelFamily::Generic);
    }

    #[test]
    fn test_registry_unsupported_family() {
        let reg = ProjectorRegistry::with_defaults(ModelFamily::Generic).unwrap();
        let result = reg.get(&ModelFamily::Custom("unknown".to_string()));
        match result {
            Err(ref e) => assert!(e.to_string().contains("unsupported")),
            Ok(_) => panic!("expected error for unknown family"),
        }
    }

    #[test]
    fn test_registry_families_returns_all() {
        let reg = ProjectorRegistry::with_defaults(ModelFamily::Generic).unwrap();
        let families = reg.families().unwrap();
        assert!(families.len() >= 5);
        assert!(families.contains(&ModelFamily::Claude));
        assert!(families.contains(&ModelFamily::OpenAi));
        assert!(families.contains(&ModelFamily::DeepSeek));
        assert!(families.contains(&ModelFamily::Qwen));
        assert!(families.contains(&ModelFamily::Generic));
    }

    #[test]
    fn test_registry_register_custom() {
        let reg = ProjectorRegistry::with_defaults(ModelFamily::Generic).unwrap();
        // Register a custom projection using GenericProjection as a stand-in
        let custom_generic = Arc::new(generic::GenericProjection);
        // This registers under Generic, which already exists, so it replaces.
        reg.register(custom_generic).unwrap();
        assert!(reg.get(&ModelFamily::Generic).is_ok());
    }

    #[test]
    fn test_registry_project_and_parse_roundtrip_claude() {
        let reg = ProjectorRegistry::with_defaults(ModelFamily::Generic).unwrap();
        let proj = reg.get(&ModelFamily::Claude).unwrap();
        let schema = CanonicalToolSchema {
            name: "test_tool".to_string(),
            description: "A test tool".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: None,
        };
        let projected = proj.project_schema(&schema).unwrap();
        assert_eq!(projected["name"], "test_tool");
    }

    #[test]
    fn test_registry_project_and_parse_roundtrip_openai() {
        let reg = ProjectorRegistry::with_defaults(ModelFamily::Generic).unwrap();
        let proj = reg.get(&ModelFamily::OpenAi).unwrap();
        let schema = CanonicalToolSchema {
            name: "tool_a".to_string(),
            description: "Tool A".to_string(),
            input_schema: json!({"type": "object", "properties": {"x": {"type": "integer"}}}),
            output_schema: None,
        };
        let projected = proj.project_schema(&schema).unwrap();
        assert_eq!(projected["function"]["name"], "tool_a");

        let call_raw = json!({
            "id": "c1",
            "type": "function",
            "function": {"name": "tool_a", "arguments": {"x": 42}}
        });
        let parsed = proj.parse_call(&call_raw).unwrap();
        assert_eq!(parsed.tool_name, "tool_a");
        assert_eq!(parsed.arguments["x"], 42);
    }

    #[test]
    fn test_registry_format_response_all_families() {
        let reg = ProjectorRegistry::with_defaults(ModelFamily::Generic).unwrap();
        let resp = CanonicalToolResponse {
            call_id: Some("test_id".to_string()),
            content: json!("result"),
            is_error: false,
        };
        for family in &[
            ModelFamily::Claude,
            ModelFamily::OpenAi,
            ModelFamily::DeepSeek,
            ModelFamily::Qwen,
            ModelFamily::Generic,
        ] {
            let proj = reg.get(family).unwrap();
            let formatted = proj.format_response(&resp).unwrap();
            assert!(
                formatted.is_object(),
                "family {:?} produced non-object",
                family
            );
        }
    }

    #[test]
    fn test_registry_estimate_tokens_all_families() {
        let reg = ProjectorRegistry::with_defaults(ModelFamily::Generic).unwrap();
        let schema = CanonicalToolSchema {
            name: "tok_test".to_string(),
            description: "Token estimation test".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: None,
        };
        for family in &[
            ModelFamily::Claude,
            ModelFamily::OpenAi,
            ModelFamily::DeepSeek,
            ModelFamily::Qwen,
            ModelFamily::Generic,
        ] {
            let proj = reg.get(family).unwrap();
            let tokens = proj.estimate_tokens(&schema);
            assert!(tokens > 0, "family {:?} returned 0 tokens", family);
        }
    }

    #[test]
    fn test_registry_get_default_when_default_not_registered() {
        let reg = ProjectorRegistry::new(ModelFamily::Custom("missing".to_string()));
        let result = reg.get_default();
        match result {
            Err(ref e) => assert!(e.to_string().contains("unsupported")),
            Ok(_) => panic!("expected error for unregistered default"),
        }
    }
}
