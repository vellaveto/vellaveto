//! JSON-RPC message framing for MCP stdio transport.
//!
//! MCP uses newline-delimited JSON over stdin/stdout.
//! Each message is a single line of JSON followed by a newline.

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Read a single newline-delimited JSON message from a reader.
///
/// Returns `Ok(None)` on EOF, `Ok(Some(value))` on success.
pub async fn read_message<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<Option<Value>, FramingError> {
    let mut line = String::new();
    let bytes_read = reader
        .read_line(&mut line)
        .await
        .map_err(FramingError::Io)?;

    if bytes_read == 0 {
        return Ok(None); // EOF
    }

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let value: Value = serde_json::from_str(trimmed).map_err(FramingError::Json)?;
    Ok(Some(value))
}

/// Write a JSON-RPC message followed by a newline to a writer.
pub async fn write_message<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &Value,
) -> Result<(), FramingError> {
    let serialized = serde_json::to_string(msg).map_err(FramingError::Json)?;
    writer
        .write_all(serialized.as_bytes())
        .await
        .map_err(FramingError::Io)?;
    writer.write_all(b"\n").await.map_err(FramingError::Io)?;
    writer.flush().await.map_err(FramingError::Io)?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("I/O error: {0}")]
    Io(std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(serde_json::Error),
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
}
