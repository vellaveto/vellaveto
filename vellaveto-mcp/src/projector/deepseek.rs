use serde_json::{json, Value};
use vellaveto_types::{CanonicalToolCall, CanonicalToolResponse, CanonicalToolSchema, ModelFamily};

use super::error::ProjectorError;
use super::ModelProjection;

pub struct DeepSeekProjection;

/// Delegate to the shared `first_sentence` implementation in mod.rs.
/// (IMP-R116-002: deduplicated from deepseek.rs and compress.rs copies)
fn first_sentence(desc: &str) -> &str {
    super::first_sentence(desc)
}

/// Strip `<think>...</think>` blocks and extract JSON from raw text.
/// DeepSeek R1 sometimes wraps tool calls in reasoning blocks.
fn extract_json_from_response(text: &str) -> Result<Value, ProjectorError> {
    // SECURITY (IMP-R182-002): Parity with repair.rs — bound input size to prevent
    // unbounded clone on attacker-controlled model output.
    const MAX_INPUT_SIZE: usize = 1_048_576; // 1 MiB
    if text.len() > MAX_INPUT_SIZE {
        return Err(ProjectorError::ParseError(format!(
            "input too large for DeepSeek JSON extraction: {} bytes (max {})",
            text.len(),
            MAX_INPUT_SIZE
        )));
    }
    let mut cleaned = text.to_string();

    // Remove <think>...</think> blocks (non-greedy)
    // SECURITY (FIND-R114-002/IMP): Bound iteration count to prevent DoS via
    // crafted input with many repeated <think> tags.
    // Parity with repair.rs::extract_json_from_code_block (MAX_THINK_TAG_ITERATIONS=100).
    const MAX_THINK_TAG_ITERATIONS: usize = 100;
    let mut think_iterations = 0usize;
    while let Some(start) = cleaned.find("<think>") {
        think_iterations += 1;
        if think_iterations > MAX_THINK_TAG_ITERATIONS {
            tracing::warn!(
                "extract_json_from_response: exceeded {} think-tag removal iterations, breaking",
                MAX_THINK_TAG_ITERATIONS
            );
            break;
        }
        if let Some(end) = cleaned[start..].find("</think>") {
            let end_abs = start + end + "</think>".len();
            cleaned.replace_range(start..end_abs, "");
        } else {
            // Unclosed <think> tag — remove from <think> to end
            cleaned.truncate(start);
            break;
        }
    }

    let cleaned = cleaned.trim();

    // Try direct JSON parse first
    if let Ok(v) = serde_json::from_str::<Value>(cleaned) {
        return Ok(v);
    }

    // Try extracting from markdown code blocks: ```json ... ``` or ``` ... ```
    if let Some(start) = cleaned.find("```") {
        let after_ticks = &cleaned[start + 3..];
        // Skip optional language tag
        let json_start = if let Some(stripped) = after_ticks.strip_prefix("json") {
            stripped.trim_start()
        } else {
            after_ticks
                .trim_start_matches(|c: char| c.is_alphabetic())
                .trim_start()
        };
        if let Some(end) = json_start.find("```") {
            let json_text = json_start[..end].trim();
            if let Ok(v) = serde_json::from_str::<Value>(json_text) {
                return Ok(v);
            }
        }
    }

    Err(ProjectorError::ParseError(
        "could not extract JSON from DeepSeek response".to_string(),
    ))
}

impl ModelProjection for DeepSeekProjection {
    fn model_family(&self) -> ModelFamily {
        ModelFamily::DeepSeek
    }

    fn project_schema(&self, canonical: &CanonicalToolSchema) -> Result<Value, ProjectorError> {
        let short_desc = first_sentence(&canonical.description);
        Ok(json!({
            "type": "function",
            "function": {
                "name": canonical.name,
                "description": short_desc,
                "parameters": canonical.input_schema,
            }
        }))
    }

    fn parse_call(&self, raw: &Value) -> Result<CanonicalToolCall, ProjectorError> {
        // If raw is a string, try to extract JSON (handles <think> blocks)
        let parsed = match raw {
            Value::String(s) => extract_json_from_response(s)?,
            other => other.clone(),
        };

        let obj = parsed
            .as_object()
            .ok_or_else(|| ProjectorError::ParseError("expected JSON object".to_string()))?;

        // Try OpenAI-style function call format first
        if let Some(function) = obj.get("function").and_then(|v| v.as_object()) {
            let name = function
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ProjectorError::ParseError("missing 'function.name'".to_string()))?;

            let arguments = match function.get("arguments") {
                Some(Value::String(s)) => serde_json::from_str(s).map_err(|e| {
                    ProjectorError::ParseError(format!(
                        "failed to parse 'function.arguments': {}",
                        e
                    ))
                })?,
                Some(v) => v.clone(),
                None => Value::Object(serde_json::Map::new()),
            };

            let call_id = obj.get("id").and_then(|v| v.as_str()).map(String::from);

            return Ok(CanonicalToolCall {
                tool_name: name.to_string(),
                arguments,
                call_id,
            });
        }

        // Fallback: try direct name/arguments
        let name = obj.get("name").and_then(|v| v.as_str()).ok_or_else(|| {
            ProjectorError::ParseError("missing 'name' or 'function' field".to_string())
        })?;

        let arguments = obj
            .get("arguments")
            .cloned()
            .unwrap_or(Value::Object(serde_json::Map::new()));

        let call_id = obj.get("id").and_then(|v| v.as_str()).map(String::from);

        Ok(CanonicalToolCall {
            tool_name: name.to_string(),
            arguments,
            call_id,
        })
    }

    fn format_response(&self, canonical: &CanonicalToolResponse) -> Result<Value, ProjectorError> {
        super::format_openai_style_response(canonical)
    }

    fn estimate_tokens(&self, schema: &CanonicalToolSchema) -> usize {
        // SECURITY (FIND-R131-001): Fail-closed on serialization failure.
        let json_str = match serde_json::to_string(schema) {
            Ok(s) => s,
            Err(_) => return super::FAILSAFE_TOKEN_ESTIMATE,
        };
        // DeepSeek: larger tokenizer, ~3 chars per token
        (json_str.len() as f64 / 3.0).ceil() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_schema() -> CanonicalToolSchema {
        CanonicalToolSchema {
            name: "search".to_string(),
            description: "Search the internet for information. Returns a list of results with titles and snippets.".to_string(),
            input_schema: json!({"type": "object", "properties": {"query": {"type": "string"}}}),
            output_schema: None,
        }
    }

    #[test]
    fn test_deepseek_model_family() {
        let p = DeepSeekProjection;
        assert_eq!(p.model_family(), ModelFamily::DeepSeek);
    }

    #[test]
    fn test_deepseek_project_schema_truncates_description() {
        let p = DeepSeekProjection;
        let result = p.project_schema(&sample_schema()).unwrap();
        assert_eq!(result["function"]["name"], "search");
        let desc = result["function"]["description"].as_str().unwrap();
        assert_eq!(desc, "Search the internet for information.");
        assert!(!desc.contains("Returns"));
    }

    #[test]
    fn test_deepseek_project_schema_single_sentence() {
        let p = DeepSeekProjection;
        let schema = CanonicalToolSchema {
            name: "ping".to_string(),
            description: "Ping a host".to_string(),
            input_schema: json!({}),
            output_schema: None,
        };
        let result = p.project_schema(&schema).unwrap();
        assert_eq!(result["function"]["description"], "Ping a host");
    }

    #[test]
    fn test_deepseek_project_schema_empty_description() {
        let p = DeepSeekProjection;
        let schema = CanonicalToolSchema {
            name: "noop".to_string(),
            description: "".to_string(),
            input_schema: json!({}),
            output_schema: None,
        };
        let result = p.project_schema(&schema).unwrap();
        assert_eq!(result["function"]["description"], "");
    }

    #[test]
    fn test_deepseek_parse_call_openai_format() {
        let p = DeepSeekProjection;
        let raw = json!({
            "id": "call_ds1",
            "type": "function",
            "function": {
                "name": "search",
                "arguments": {"query": "rust lang"}
            }
        });
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.tool_name, "search");
        assert_eq!(call.arguments["query"], "rust lang");
        assert_eq!(call.call_id, Some("call_ds1".to_string()));
    }

    #[test]
    fn test_deepseek_parse_call_with_think_block() {
        let p = DeepSeekProjection;
        let raw = json!("<think>I need to search for this</think>{\"name\": \"search\", \"arguments\": {\"query\": \"test\"}}");
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.tool_name, "search");
        assert_eq!(call.arguments["query"], "test");
    }

    #[test]
    fn test_deepseek_parse_call_with_markdown_code_block() {
        let p = DeepSeekProjection;
        let text = "<think>thinking...</think>\n```json\n{\"name\": \"search\", \"arguments\": {\"query\": \"hello\"}}\n```";
        let raw = json!(text);
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.tool_name, "search");
        assert_eq!(call.arguments["query"], "hello");
    }

    #[test]
    fn test_deepseek_parse_call_string_arguments() {
        let p = DeepSeekProjection;
        let raw = json!({
            "id": "call_1",
            "function": {
                "name": "search",
                "arguments": "{\"query\": \"test\"}"
            }
        });
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.arguments["query"], "test");
    }

    #[test]
    fn test_deepseek_parse_call_direct_format() {
        let p = DeepSeekProjection;
        let raw = json!({
            "name": "search",
            "arguments": {"query": "direct"}
        });
        let call = p.parse_call(&raw).unwrap();
        assert_eq!(call.tool_name, "search");
        assert_eq!(call.arguments["query"], "direct");
    }

    #[test]
    fn test_deepseek_parse_call_not_object() {
        let p = DeepSeekProjection;
        let err = p.parse_call(&json!(42)).unwrap_err();
        assert!(err.to_string().contains("object"));
    }

    #[test]
    fn test_deepseek_parse_call_invalid_string() {
        let p = DeepSeekProjection;
        let err = p.parse_call(&json!("not json at all")).unwrap_err();
        assert!(err.to_string().contains("extract JSON"));
    }

    #[test]
    fn test_deepseek_format_response() {
        let p = DeepSeekProjection;
        let resp = CanonicalToolResponse {
            call_id: Some("call_1".to_string()),
            content: json!("search results"),
            is_error: false,
        };
        let result = p.format_response(&resp).unwrap();
        assert_eq!(result["role"], "tool");
        assert_eq!(result["tool_call_id"], "call_1");
        assert_eq!(result["content"], "search results");
    }

    #[test]
    fn test_deepseek_format_response_no_id() {
        let p = DeepSeekProjection;
        let resp = CanonicalToolResponse {
            call_id: None,
            content: json!("done"),
            is_error: false,
        };
        let result = p.format_response(&resp).unwrap();
        assert!(result.get("tool_call_id").is_none());
    }

    #[test]
    fn test_deepseek_estimate_tokens() {
        let p = DeepSeekProjection;
        let tokens = p.estimate_tokens(&sample_schema());
        assert!(tokens > 0);
    }

    #[test]
    fn test_first_sentence_multiple() {
        assert_eq!(
            first_sentence("First sentence. Second sentence."),
            "First sentence."
        );
    }

    #[test]
    fn test_first_sentence_single() {
        assert_eq!(first_sentence("Only one"), "Only one");
    }

    #[test]
    fn test_first_sentence_empty() {
        assert_eq!(first_sentence(""), "");
    }

    #[test]
    fn test_first_sentence_exclamation() {
        assert_eq!(first_sentence("Wow! That is cool."), "Wow!");
    }
}
