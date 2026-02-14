//! EU AI Act Article 50 Runtime Transparency.
//!
//! Art 50(1) requires AI-mediated output to be marked so that recipients
//! know they are interacting with an AI system. Art 14 requires human
//! oversight for high-risk tools.
//!
//! This module provides two runtime features:
//! 1. **Transparency marking** — Injects `_meta.vellaveto_ai_mediated: true`
//!    into tool-call responses before forwarding to the agent.
//! 2. **Human oversight matching** — Checks whether a tool name matches
//!    configurable glob patterns for human oversight.

/// Check if a tool name matches any human oversight glob patterns.
///
/// Returns `true` if the tool matches at least one pattern. An empty
/// pattern list always returns `false`.
///
/// Patterns use simple glob matching: `*` matches any sequence of
/// characters, `?` matches a single character.
pub fn requires_human_oversight(tool: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }
    for pattern in patterns {
        if glob_match(pattern, tool) {
            return true;
        }
    }
    false
}

/// Inject transparency marking into a JSON-RPC response.
///
/// Adds `result._meta.vellaveto_ai_mediated = true` if the message
/// contains a `result` field (i.e., it's a successful response).
/// Error responses are not modified.
pub fn mark_ai_mediated(msg: &mut serde_json::Value) {
    if let Some(result) = msg.get_mut("result") {
        if let Some(obj) = result.as_object_mut() {
            let meta = obj.entry("_meta").or_insert_with(|| serde_json::json!({}));
            if let Some(meta_obj) = meta.as_object_mut() {
                meta_obj.insert(
                    "vellaveto_ai_mediated".to_string(),
                    serde_json::Value::Bool(true),
                );
            }
        }
    }
}

/// Simple glob matching supporting `*` and `?`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (plen, tlen) = (p.len(), t.len());

    let mut dp = vec![vec![false; tlen + 1]; plen + 1];
    dp[0][0] = true;

    // Handle leading `*` patterns
    for i in 1..=plen {
        if p[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }

    for i in 1..=plen {
        for j in 1..=tlen {
            if p[i - 1] == '*' {
                dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
            } else if p[i - 1] == '?' || p[i - 1] == t[j - 1] {
                dp[i][j] = dp[i - 1][j - 1];
            }
        }
    }

    dp[plen][tlen]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mark_ai_mediated_adds_meta() {
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": "hello"}
        });
        mark_ai_mediated(&mut msg);
        assert_eq!(
            msg["result"]["_meta"]["vellaveto_ai_mediated"],
            serde_json::Value::Bool(true)
        );
    }

    #[test]
    fn test_mark_ai_mediated_preserves_existing_meta() {
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": "hello",
                "_meta": {"existing_key": "value"}
            }
        });
        mark_ai_mediated(&mut msg);
        assert_eq!(
            msg["result"]["_meta"]["vellaveto_ai_mediated"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            msg["result"]["_meta"]["existing_key"],
            serde_json::Value::String("value".to_string())
        );
    }

    #[test]
    fn test_mark_ai_mediated_no_result() {
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32600, "message": "Invalid Request"}
        });
        let original = msg.clone();
        mark_ai_mediated(&mut msg);
        assert_eq!(msg, original, "error responses should not be modified");
    }

    #[test]
    fn test_mark_ai_mediated_null_result() {
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": null
        });
        let original = msg.clone();
        mark_ai_mediated(&mut msg);
        assert_eq!(msg, original, "null result should not be modified");
    }

    #[test]
    fn test_requires_human_oversight_glob_match() {
        let patterns = vec!["shell_*".to_string()];
        assert!(requires_human_oversight("shell_exec", &patterns));
        assert!(requires_human_oversight("shell_run", &patterns));
    }

    #[test]
    fn test_requires_human_oversight_no_match() {
        let patterns = vec!["shell_*".to_string()];
        assert!(!requires_human_oversight("read_file", &patterns));
        assert!(!requires_human_oversight("http_get", &patterns));
    }

    #[test]
    fn test_requires_human_oversight_empty_patterns() {
        assert!(!requires_human_oversight("shell_exec", &[]));
    }

    #[test]
    fn test_requires_human_oversight_multiple_patterns() {
        let patterns = vec![
            "shell_*".to_string(),
            "exec_*".to_string(),
            "sudo".to_string(),
        ];
        assert!(requires_human_oversight("shell_exec", &patterns));
        assert!(requires_human_oversight("exec_command", &patterns));
        assert!(requires_human_oversight("sudo", &patterns));
        assert!(!requires_human_oversight("read_file", &patterns));
    }

    #[test]
    fn test_requires_human_oversight_question_mark() {
        let patterns = vec!["db_?".to_string()];
        assert!(requires_human_oversight("db_a", &patterns));
        assert!(!requires_human_oversight("db_ab", &patterns));
        assert!(!requires_human_oversight("db_", &patterns));
    }

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("he*", "hello"));
        assert!(glob_match("*lo", "hello"));
        assert!(glob_match("h*o", "hello"));
    }
}
