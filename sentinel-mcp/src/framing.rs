//! JSON-RPC message framing for MCP stdio transport.
//!
//! MCP uses newline-delimited JSON over stdin/stdout.
//! Each message is a single line of JSON followed by a newline.

use std::collections::HashSet;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Maximum line length (1 MB). Lines exceeding this are rejected to prevent OOM.
const MAX_LINE_LENGTH: usize = 1_048_576;

/// Read a single newline-delimited JSON message from a reader.
///
/// Returns `Ok(None)` on EOF, `Ok(Some(value))` on success.
/// Empty lines are skipped (not treated as EOF).
/// Lines exceeding `MAX_LINE_LENGTH` are rejected BEFORE full allocation
/// to prevent OOM from oversized messages.
pub async fn read_message<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<Option<Value>, FramingError> {
    loop {
        let line_bytes = read_bounded_line(reader).await?;

        // EOF — no more data
        let line_bytes = match line_bytes {
            Some(b) => b,
            None => return Ok(None),
        };

        // Convert to string (MCP messages are always UTF-8 JSON)
        let line = String::from_utf8(line_bytes).map_err(|e| {
            FramingError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;

        // Fix #14: Skip empty lines instead of treating them as EOF.
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Defense-in-depth: reject JSON with duplicate keys at any nesting level.
        // serde_json uses last-key-wins, but other parsers may use first-key-wins.
        // An attacker could send {"path":"safe","path":"malicious"} to exploit
        // parser disagreement (CVE-2017-12635, CVE-2020-16250).
        if let Some(dup_key) = find_duplicate_json_key(trimmed) {
            return Err(FramingError::DuplicateKeys(dup_key));
        }

        let value: Value = serde_json::from_str(trimmed).map_err(FramingError::Json)?;

        // MCP 2025-06-18 removed JSON-RPC batching. Reject arrays at the
        // transport layer so that batch payloads never reach the classifier.
        if value.is_array() {
            return Err(FramingError::BatchNotAllowed);
        }

        return Ok(Some(value));
    }
}

/// Read a single line from the reader, bounded by MAX_LINE_LENGTH.
///
/// Uses `fill_buf`/`consume` to check accumulated size BEFORE allocating,
/// preventing OOM from oversized lines without a newline.
/// Returns `Ok(None)` on EOF, `Ok(Some(bytes))` on success.
async fn read_bounded_line<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<Option<Vec<u8>>, FramingError> {
    let mut accumulated = Vec::with_capacity(256);

    loop {
        let buf = reader.fill_buf().await.map_err(FramingError::Io)?;

        if buf.is_empty() {
            // EOF
            if accumulated.is_empty() {
                return Ok(None);
            }
            // Partial line at EOF — return what we have
            return Ok(Some(accumulated));
        }

        // Look for newline in the current buffer chunk
        match buf.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                // Found newline — check total size before allocating
                let needed = pos + 1; // include the newline
                if accumulated.len() + needed > MAX_LINE_LENGTH {
                    reader.consume(needed);
                    return Err(FramingError::LineTooLong(accumulated.len() + needed));
                }
                accumulated.extend_from_slice(&buf[..needed]);
                reader.consume(needed);
                return Ok(Some(accumulated));
            }
            None => {
                // No newline in this chunk — check total size before extending
                let chunk_len = buf.len();
                if accumulated.len() + chunk_len > MAX_LINE_LENGTH {
                    reader.consume(chunk_len);
                    return Err(FramingError::LineTooLong(accumulated.len() + chunk_len));
                }
                accumulated.extend_from_slice(buf);
                reader.consume(chunk_len);
            }
        }
    }
}

/// Write a JSON-RPC message followed by a newline to a writer.
///
/// Uses `to_vec` to serialize directly to bytes, then appends a newline
/// and writes the whole buffer in a single `write_all` call.
pub async fn write_message<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &Value,
) -> Result<(), FramingError> {
    let mut buf = serde_json::to_vec(msg).map_err(FramingError::Json)?;
    buf.push(b'\n');
    writer.write_all(&buf).await.map_err(FramingError::Io)?;
    writer.flush().await.map_err(FramingError::Io)?;
    Ok(())
}

/// Scan raw JSON for duplicate keys at any object nesting level.
///
/// Returns the first duplicate key name found, or `None` if no duplicates exist.
/// Uses a minimal state machine to track JSON string boundaries and object scopes.
///
/// This prevents parser-disagreement attacks where an attacker sends
/// `{"path":"safe","path":"malicious"}` and exploits the difference between
/// first-key-wins and last-key-wins parsers (CVE-2017-12635, CVE-2020-16250).
pub fn find_duplicate_json_key(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    // Stack of seen-key sets, one per object nesting level.
    // `None` entries represent array scopes (no key tracking needed).
    let mut stack: Vec<Option<HashSet<String>>> = Vec::new();
    // After `{` or `,` inside an object, the next string token is a key.
    let mut next_string_is_key = false;

    while i < len {
        // Skip whitespace
        while i < len && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        if i >= len {
            break;
        }

        match bytes[i] {
            b'{' => {
                stack.push(Some(HashSet::new()));
                next_string_is_key = true;
                i += 1;
            }
            b'[' => {
                stack.push(None);
                next_string_is_key = false;
                i += 1;
            }
            b'}' => {
                stack.pop();
                // Restore key expectation state: after closing an object that was
                // a value, we're no longer expecting a key.
                next_string_is_key = false;
                i += 1;
            }
            b']' => {
                stack.pop();
                next_string_is_key = false;
                i += 1;
            }
            b'"' => {
                let start = i;
                i += 1; // skip opening quote
                        // Walk through string content, handling escape sequences
                while i < len {
                    if bytes[i] == b'\\' {
                        i += 1; // skip backslash
                        if i < len {
                            if bytes[i] == b'u' {
                                // \uXXXX — skip u + 4 hex digits (6 bytes total including \)
                                i += 5.min(len - i);
                            } else {
                                i += 1; // skip single escaped char
                            }
                        }
                    } else if bytes[i] == b'"' {
                        i += 1; // skip closing quote
                        break;
                    } else {
                        i += 1;
                    }
                }

                if next_string_is_key {
                    // Extract the key using serde_json to correctly handle escapes
                    if let Ok(key_str) = std::str::from_utf8(&bytes[start..i]) {
                        if let Ok(parsed_key) = serde_json::from_str::<String>(key_str) {
                            if let Some(Some(seen_keys)) = stack.last_mut() {
                                if !seen_keys.insert(parsed_key.clone()) {
                                    return Some(parsed_key);
                                }
                            }
                        }
                    }
                    next_string_is_key = false;
                }
            }
            b':' => {
                // After a colon, the next token is a value (not a key)
                next_string_is_key = false;
                i += 1;
            }
            b',' => {
                // After a comma in an object scope, the next string is a key
                if let Some(Some(_)) = stack.last() {
                    next_string_is_key = true;
                }
                i += 1;
            }
            _ => {
                // Numbers, true, false, null — skip individual bytes
                i += 1;
            }
        }
    }

    None
}

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("I/O error: {0}")]
    Io(std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(serde_json::Error),
    #[error("Line too long: {0} bytes (max {MAX_LINE_LENGTH})")]
    LineTooLong(usize),
    #[error("Duplicate JSON key detected: \"{0}\"")]
    DuplicateKeys(String),
    #[error("JSON-RPC batching is not allowed (MCP 2025-06-18)")]
    BatchNotAllowed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_read_message_valid() {
        let data = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = BufReader::new(cursor);
        let msg = read_message(&mut reader).await.unwrap();
        assert!(msg.is_some());
        let val = msg.unwrap();
        assert_eq!(val["method"], "ping");
    }

    #[tokio::test]
    async fn test_read_message_eof() {
        let data = b"";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = BufReader::new(cursor);
        let msg = read_message(&mut reader).await.unwrap();
        assert!(msg.is_none());
    }

    #[tokio::test]
    async fn test_read_message_invalid_json() {
        let data = b"not json\n";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = BufReader::new(cursor);
        let result = read_message(&mut reader).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_write_message() {
        let mut buf = Vec::new();
        let msg = json!({"jsonrpc": "2.0", "id": 1, "result": "ok"});
        write_message(&mut buf, &msg).await.unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.ends_with('\n'));
        let parsed: Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(parsed["result"], "ok");
    }

    #[tokio::test]
    async fn test_roundtrip() {
        let msg =
            json!({"jsonrpc": "2.0", "id": 42, "method": "tools/call", "params": {"name": "read"}});

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let cursor = Cursor::new(buf);
        let mut reader = BufReader::new(cursor);
        let read_back = read_message(&mut reader).await.unwrap().unwrap();

        assert_eq!(read_back["id"], 42);
        assert_eq!(read_back["method"], "tools/call");
    }

    // === Security regression tests ===

    #[tokio::test]
    async fn test_fix6_line_too_long_rejected() {
        // Fix #6: Lines exceeding MAX_LINE_LENGTH must be rejected
        let long_payload = "x".repeat(MAX_LINE_LENGTH + 100);
        let data = format!("{}\n", long_payload);
        let cursor = Cursor::new(data.into_bytes());
        let mut reader = BufReader::new(cursor);
        let result = read_message(&mut reader).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, FramingError::LineTooLong(_)),
            "Expected LineTooLong, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_fix14_empty_line_does_not_terminate_session() {
        // Fix #14: Empty lines between valid messages must be skipped, not treated as EOF
        let data = b"\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = BufReader::new(cursor);
        let msg = read_message(&mut reader).await.unwrap();
        assert!(
            msg.is_some(),
            "Empty lines should be skipped, not terminate"
        );
        assert_eq!(msg.unwrap()["method"], "ping");
    }

    #[tokio::test]
    async fn test_fix14_only_empty_lines_returns_eof() {
        // All empty lines followed by true EOF → should return None (EOF)
        let data = b"\n\n\n";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = BufReader::new(cursor);
        let msg = read_message(&mut reader).await.unwrap();
        assert!(msg.is_none(), "Only empty lines + EOF should return None");
    }

    // === Duplicate key detection tests (Challenge #5) ===

    #[test]
    fn test_no_duplicate_keys_in_valid_json() {
        let json = r#"{"a": 1, "b": 2, "c": {"d": 3}}"#;
        assert!(find_duplicate_json_key(json).is_none());
    }

    #[test]
    fn test_detects_top_level_duplicate_key() {
        let json = r#"{"path": "safe", "path": "malicious"}"#;
        let dup = find_duplicate_json_key(json);
        assert_eq!(dup, Some("path".to_string()));
    }

    #[test]
    fn test_detects_nested_duplicate_key() {
        let json = r#"{"params": {"name": "a", "name": "b"}}"#;
        let dup = find_duplicate_json_key(json);
        assert_eq!(dup, Some("name".to_string()));
    }

    #[test]
    fn test_same_key_different_scopes_is_ok() {
        // "id" appears in two different objects — not a duplicate
        let json = r#"{"id": 1, "params": {"id": "inner"}}"#;
        assert!(find_duplicate_json_key(json).is_none());
    }

    #[test]
    fn test_no_duplicates_in_array() {
        // Arrays don't have keys, strings inside arrays aren't keys
        let json = r#"{"items": ["a", "a", "b"]}"#;
        assert!(find_duplicate_json_key(json).is_none());
    }

    #[test]
    fn test_handles_escaped_quotes_in_keys() {
        // Key with escaped quote — distinct from other keys
        let json = r#"{"a\"b": 1, "c": 2}"#;
        assert!(find_duplicate_json_key(json).is_none());
    }

    #[test]
    fn test_handles_escaped_quotes_duplicate() {
        let json = r#"{"a\"b": 1, "a\"b": 2}"#;
        let dup = find_duplicate_json_key(json);
        assert_eq!(dup, Some("a\"b".to_string()));
    }

    #[test]
    fn test_deeply_nested_duplicate() {
        let json = r#"{"a": {"b": {"c": 1, "c": 2}}}"#;
        let dup = find_duplicate_json_key(json);
        assert_eq!(dup, Some("c".to_string()));
    }

    #[test]
    fn test_mcp_tools_call_duplicate_attack() {
        // The actual attack vector: duplicate params.name in tools/call
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{"path":"/tmp"},"name":"dangerous_tool"}}"#;
        let dup = find_duplicate_json_key(json);
        assert_eq!(dup, Some("name".to_string()));
    }

    #[tokio::test]
    async fn test_read_message_rejects_duplicate_keys() {
        let data = b"{\"a\":1,\"a\":2}\n";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = BufReader::new(cursor);
        let result = read_message(&mut reader).await;
        assert!(result.is_err(), "Should reject JSON with duplicate keys");
        let err = result.unwrap_err();
        assert!(
            matches!(err, FramingError::DuplicateKeys(ref k) if k == "a"),
            "Expected DuplicateKeys(\"a\"), got {:?}",
            err
        );
    }

    #[test]
    fn test_empty_json_object_no_duplicates() {
        assert!(find_duplicate_json_key("{}").is_none());
    }

    #[test]
    fn test_mixed_arrays_and_objects() {
        let json = r#"{"a": [{"b": 1}, {"b": 2}], "c": 3}"#;
        // "b" appears in different array element objects — not duplicates
        assert!(find_duplicate_json_key(json).is_none());
    }
}
