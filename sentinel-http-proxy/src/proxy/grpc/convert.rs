//! Proto ↔ JSON conversion for gRPC transport.
//!
//! Converts between prost-generated protobuf types and `serde_json::Value`
//! used by the MCP extractor and policy engine. All conversion errors are
//! fail-closed — they produce `ConvertError` which the service layer maps
//! to gRPC INTERNAL status (never a pass-through).

use prost_types::value::Kind;
use serde_json::{json, Map, Number, Value};

use super::proto::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};

/// Maximum nesting depth for proto↔JSON conversion to prevent stack overflow.
const MAX_CONVERSION_DEPTH: usize = 64;

/// Errors that can occur during proto↔JSON conversion.
#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    #[error("NaN or Infinity float value in protobuf Struct")]
    InvalidFloat,

    #[error("conversion depth exceeds maximum ({MAX_CONVERSION_DEPTH})")]
    DepthExceeded,

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Convert a protobuf `JsonRpcRequest` to a `serde_json::Value`.
///
/// The resulting Value is a JSON-RPC 2.0 request object suitable for
/// `classify_message()` and `extract_action()`.
pub fn proto_request_to_json(req: &JsonRpcRequest) -> Result<Value, ConvertError> {
    let mut map = Map::new();
    map.insert("jsonrpc".to_string(), Value::String(req.jsonrpc.clone()));

    // ID: oneof int/string, or null if neither set
    let id = match &req.id_oneof {
        Some(super::proto::json_rpc_request::IdOneof::IdInt(n)) => json!(*n),
        Some(super::proto::json_rpc_request::IdOneof::IdString(s)) => json!(s),
        None => Value::Null,
    };
    map.insert("id".to_string(), id);

    map.insert("method".to_string(), Value::String(req.method.clone()));

    if let Some(ref params) = req.params {
        let params_json = prost_struct_to_json(params, 0)?;
        map.insert("params".to_string(), params_json);
    }

    Ok(Value::Object(map))
}

/// Convert a `serde_json::Value` (JSON-RPC response) to a protobuf `JsonRpcResponse`.
pub fn json_to_proto_response(val: &Value) -> Result<JsonRpcResponse, ConvertError> {
    let obj = val
        .as_object()
        .ok_or(ConvertError::MissingField("root object"))?;

    let jsonrpc = obj
        .get("jsonrpc")
        .and_then(|v| v.as_str())
        .unwrap_or("2.0")
        .to_string();

    let id_oneof = match obj.get("id") {
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                Some(super::proto::json_rpc_response::IdOneof::IdInt(i))
            } else {
                // Treat as string for non-integer numbers
                Some(super::proto::json_rpc_response::IdOneof::IdString(
                    n.to_string(),
                ))
            }
        }
        Some(Value::String(s)) => Some(super::proto::json_rpc_response::IdOneof::IdString(
            s.clone(),
        )),
        _ => None,
    };

    let result = if let Some(result_val) = obj.get("result") {
        Some(json_to_prost_struct(result_val, 0)?)
    } else {
        None
    };

    let error = if let Some(error_val) = obj.get("error") {
        Some(json_to_proto_error(error_val)?)
    } else {
        None
    };

    Ok(JsonRpcResponse {
        jsonrpc,
        id_oneof,
        result,
        error,
    })
}

/// Convert a `serde_json::Value` (JSON-RPC error object) to a protobuf `JsonRpcError`.
fn json_to_proto_error(val: &Value) -> Result<JsonRpcError, ConvertError> {
    let obj = val
        .as_object()
        .ok_or(ConvertError::MissingField("error object"))?;

    let code = obj.get("code").and_then(|v| v.as_i64()).unwrap_or(-32603) as i32;

    let message = obj
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("Internal error")
        .to_string();

    let data = if let Some(data_val) = obj.get("data") {
        Some(json_to_prost_struct(data_val, 0)?)
    } else {
        None
    };

    Ok(JsonRpcError {
        code,
        message,
        data,
    })
}

/// Convert a `prost_types::Struct` to `serde_json::Value`.
///
/// Bounded recursion with `MAX_CONVERSION_DEPTH` to prevent stack overflow
/// on deeply nested protobuf messages.
pub fn prost_struct_to_json(s: &prost_types::Struct, depth: usize) -> Result<Value, ConvertError> {
    if depth > MAX_CONVERSION_DEPTH {
        return Err(ConvertError::DepthExceeded);
    }

    let mut map = Map::new();
    for (key, value) in &s.fields {
        map.insert(key.clone(), prost_value_to_json(value, depth + 1)?);
    }
    Ok(Value::Object(map))
}

/// Convert a single `prost_types::Value` to `serde_json::Value`.
fn prost_value_to_json(v: &prost_types::Value, depth: usize) -> Result<Value, ConvertError> {
    if depth > MAX_CONVERSION_DEPTH {
        return Err(ConvertError::DepthExceeded);
    }

    match &v.kind {
        Some(Kind::NullValue(_)) => Ok(Value::Null),
        Some(Kind::NumberValue(n)) => {
            if n.is_nan() || n.is_infinite() {
                return Err(ConvertError::InvalidFloat);
            }
            // Try integer first, fall back to float
            if *n == (*n as i64) as f64 && *n >= i64::MIN as f64 && *n <= i64::MAX as f64 {
                Ok(Value::Number(Number::from(*n as i64)))
            } else {
                Number::from_f64(*n)
                    .map(Value::Number)
                    .ok_or(ConvertError::InvalidFloat)
            }
        }
        Some(Kind::StringValue(s)) => Ok(Value::String(s.clone())),
        Some(Kind::BoolValue(b)) => Ok(Value::Bool(*b)),
        Some(Kind::StructValue(s)) => prost_struct_to_json(s, depth + 1),
        Some(Kind::ListValue(list)) => {
            let items: Result<Vec<Value>, ConvertError> = list
                .values
                .iter()
                .map(|v| prost_value_to_json(v, depth + 1))
                .collect();
            Ok(Value::Array(items?))
        }
        None => Ok(Value::Null),
    }
}

/// Convert a `serde_json::Value` to `prost_types::Struct`.
///
/// If the Value is not an object, wraps it in a `{"value": ...}` envelope.
pub fn json_to_prost_struct(v: &Value, depth: usize) -> Result<prost_types::Struct, ConvertError> {
    if depth > MAX_CONVERSION_DEPTH {
        return Err(ConvertError::DepthExceeded);
    }

    match v {
        Value::Object(map) => {
            let mut fields = std::collections::BTreeMap::new();
            for (key, val) in map {
                fields.insert(key.clone(), json_to_prost_value(val, depth + 1)?);
            }
            Ok(prost_types::Struct {
                fields: fields.into_iter().collect(),
            })
        }
        // Non-object values get wrapped in a struct envelope
        other => {
            let mut fields = std::collections::BTreeMap::new();
            fields.insert("value".to_string(), json_to_prost_value(other, depth + 1)?);
            Ok(prost_types::Struct {
                fields: fields.into_iter().collect(),
            })
        }
    }
}

/// Convert a single `serde_json::Value` to `prost_types::Value`.
fn json_to_prost_value(v: &Value, depth: usize) -> Result<prost_types::Value, ConvertError> {
    if depth > MAX_CONVERSION_DEPTH {
        return Err(ConvertError::DepthExceeded);
    }

    let kind = match v {
        Value::Null => Kind::NullValue(0),
        Value::Bool(b) => Kind::BoolValue(*b),
        Value::Number(n) => {
            let f = n.as_f64().ok_or(ConvertError::InvalidFloat)?;
            Kind::NumberValue(f)
        }
        Value::String(s) => Kind::StringValue(s.clone()),
        Value::Array(arr) => {
            let values: Result<Vec<prost_types::Value>, ConvertError> = arr
                .iter()
                .map(|item| json_to_prost_value(item, depth + 1))
                .collect();
            Kind::ListValue(prost_types::ListValue { values: values? })
        }
        Value::Object(map) => {
            let mut fields = std::collections::BTreeMap::new();
            for (key, val) in map {
                fields.insert(key.clone(), json_to_prost_value(val, depth + 1)?);
            }
            Kind::StructValue(prost_types::Struct {
                fields: fields.into_iter().collect(),
            })
        }
    };

    Ok(prost_types::Value { kind: Some(kind) })
}

/// Build a JSON-RPC error response as a protobuf `JsonRpcResponse`.
///
/// Used for policy denials and internal errors. The ID is extracted from
/// the original request to correlate the response.
pub fn make_proto_error_response(
    req: &JsonRpcRequest,
    code: i32,
    message: &str,
) -> JsonRpcResponse {
    let id_oneof = match &req.id_oneof {
        Some(super::proto::json_rpc_request::IdOneof::IdInt(n)) => {
            Some(super::proto::json_rpc_response::IdOneof::IdInt(*n))
        }
        Some(super::proto::json_rpc_request::IdOneof::IdString(s)) => Some(
            super::proto::json_rpc_response::IdOneof::IdString(s.clone()),
        ),
        None => None,
    };

    let error_data_fields: std::collections::BTreeMap<String, prost_types::Value> =
        std::collections::BTreeMap::new();

    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id_oneof,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.to_string(),
            data: if error_data_fields.is_empty() {
                None
            } else {
                Some(prost_types::Struct {
                    fields: error_data_fields,
                })
            },
        }),
    }
}

/// Build a JSON-RPC denial response (code -32001) as a protobuf `JsonRpcResponse`.
pub fn make_proto_denial_response(req: &JsonRpcRequest, reason: &str) -> JsonRpcResponse {
    make_proto_error_response(req, -32001, reason)
}
