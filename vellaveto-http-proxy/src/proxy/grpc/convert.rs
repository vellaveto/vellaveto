// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

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

/// Build a JSON-RPC error response with structured `error.data`.
pub fn make_proto_error_response_with_data(
    req: &JsonRpcRequest,
    code: i32,
    message: &str,
    data: &Value,
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

    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id_oneof,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.to_string(),
            data: json_to_prost_struct(data, 0).ok(),
        }),
    }
}

/// Build a JSON-RPC denial response (code -32001) as a protobuf `JsonRpcResponse`.
pub fn make_proto_denial_response(req: &JsonRpcRequest, reason: &str) -> JsonRpcResponse {
    make_proto_error_response(req, -32001, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost_types::value::Kind;
    use serde_json::json;

    #[test]
    fn test_prost_value_to_json_large_integer_preserved() {
        let s = prost_types::Struct {
            fields: vec![(
                "big".into(),
                prost_types::Value {
                    kind: Some(Kind::NumberValue(i64::MAX as f64)),
                },
            )]
            .into_iter()
            .collect(),
        };
        let j = prost_struct_to_json(&s, 0).unwrap();
        assert!(j["big"].is_number());
    }

    #[test]
    fn test_prost_value_to_json_negative_integer() {
        let s = prost_types::Struct {
            fields: vec![(
                "neg".into(),
                prost_types::Value {
                    kind: Some(Kind::NumberValue(-42.0)),
                },
            )]
            .into_iter()
            .collect(),
        };
        let j = prost_struct_to_json(&s, 0).unwrap();
        assert_eq!(j["neg"], -42);
        assert!(j["neg"].is_i64());
    }

    #[test]
    fn test_prost_value_to_json_zero() {
        let s = prost_types::Struct {
            fields: vec![(
                "zero".into(),
                prost_types::Value {
                    kind: Some(Kind::NumberValue(0.0)),
                },
            )]
            .into_iter()
            .collect(),
        };
        assert_eq!(prost_struct_to_json(&s, 0).unwrap()["zero"], 0);
    }

    #[test]
    fn test_prost_value_to_json_empty_string() {
        let s = prost_types::Struct {
            fields: vec![(
                "s".into(),
                prost_types::Value {
                    kind: Some(Kind::StringValue(String::new())),
                },
            )]
            .into_iter()
            .collect(),
        };
        assert_eq!(prost_struct_to_json(&s, 0).unwrap()["s"], "");
    }

    #[test]
    fn test_prost_value_to_json_empty_list() {
        let s = prost_types::Struct {
            fields: vec![(
                "arr".into(),
                prost_types::Value {
                    kind: Some(Kind::ListValue(prost_types::ListValue { values: vec![] })),
                },
            )]
            .into_iter()
            .collect(),
        };
        assert_eq!(prost_struct_to_json(&s, 0).unwrap()["arr"], json!([]));
    }

    #[test]
    fn test_prost_value_to_json_mixed_list() {
        let s = prost_types::Struct {
            fields: vec![(
                "mix".into(),
                prost_types::Value {
                    kind: Some(Kind::ListValue(prost_types::ListValue {
                        values: vec![
                            prost_types::Value {
                                kind: Some(Kind::NumberValue(1.0)),
                            },
                            prost_types::Value {
                                kind: Some(Kind::StringValue("two".into())),
                            },
                            prost_types::Value {
                                kind: Some(Kind::BoolValue(false)),
                            },
                            prost_types::Value {
                                kind: Some(Kind::NullValue(0)),
                            },
                        ],
                    })),
                },
            )]
            .into_iter()
            .collect(),
        };
        let arr = prost_struct_to_json(&s, 0).unwrap()["mix"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[0], 1);
        assert_eq!(arr[1], "two");
        assert_eq!(arr[2], false);
        assert!(arr[3].is_null());
    }

    #[test]
    fn test_prost_struct_moderate_depth_accepted() {
        let mut c = prost_types::Struct {
            fields: vec![(
                "leaf".into(),
                prost_types::Value {
                    kind: Some(Kind::StringValue("ok".into())),
                },
            )]
            .into_iter()
            .collect(),
        };
        for _ in 0..20 {
            c = prost_types::Struct {
                fields: vec![(
                    "n".into(),
                    prost_types::Value {
                        kind: Some(Kind::StructValue(c)),
                    },
                )]
                .into_iter()
                .collect(),
            };
        }
        assert!(prost_struct_to_json(&c, 0).is_ok());
    }

    #[test]
    fn test_json_to_prost_struct_depth_exceeded() {
        let mut v = json!("leaf");
        for _ in 0..70 {
            v = json!({"nest": v});
        }
        assert!(json_to_prost_struct(&v, 0).is_err());
    }

    #[test]
    fn test_prost_list_depth_exceeded() {
        let mut v = prost_types::Value {
            kind: Some(Kind::StringValue("leaf".into())),
        };
        for _ in 0..70 {
            v = prost_types::Value {
                kind: Some(Kind::ListValue(prost_types::ListValue { values: vec![v] })),
            };
        }
        let s = prost_types::Struct {
            fields: vec![("deep_list".into(), v)].into_iter().collect(),
        };
        let r = prost_struct_to_json(&s, 0);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("depth"));
    }

    #[test]
    fn test_json_to_prost_value_null() {
        let r = json_to_prost_value(&json!(null), 0).unwrap();
        assert!(matches!(r.kind, Some(Kind::NullValue(0))));
    }

    #[test]
    fn test_json_to_prost_value_bool_true() {
        let r = json_to_prost_value(&json!(true), 0).unwrap();
        assert!(matches!(r.kind, Some(Kind::BoolValue(true))));
    }

    #[test]
    fn test_json_to_prost_value_bool_false() {
        let r = json_to_prost_value(&json!(false), 0).unwrap();
        assert!(matches!(r.kind, Some(Kind::BoolValue(false))));
    }

    #[test]
    fn test_json_to_prost_value_integer() {
        let r = json_to_prost_value(&json!(42), 0).unwrap();
        match &r.kind {
            Some(Kind::NumberValue(n)) => assert!((n - 42.0).abs() < f64::EPSILON),
            other => panic!("Expected NumberValue, got {other:?}"),
        }
    }

    #[test]
    fn test_json_to_prost_value_float() {
        let r = json_to_prost_value(&json!(3.14), 0).unwrap();
        match &r.kind {
            Some(Kind::NumberValue(n)) => assert!((n - 3.14).abs() < f64::EPSILON),
            other => panic!("Expected NumberValue, got {other:?}"),
        }
    }

    #[test]
    fn test_json_to_prost_value_string() {
        let r = json_to_prost_value(&json!("hello"), 0).unwrap();
        assert!(matches!(r.kind, Some(Kind::StringValue(ref s)) if s == "hello"));
    }

    #[test]
    fn test_json_to_prost_value_array() {
        let r = json_to_prost_value(&json!([1, 2, 3]), 0).unwrap();
        match &r.kind {
            Some(Kind::ListValue(list)) => assert_eq!(list.values.len(), 3),
            other => panic!("Expected ListValue, got {other:?}"),
        }
    }

    #[test]
    fn test_json_to_prost_value_object() {
        let r = json_to_prost_value(&json!({"a": 1}), 0).unwrap();
        match &r.kind {
            Some(Kind::StructValue(s)) => assert!(s.fields.contains_key("a")),
            other => panic!("Expected StructValue, got {other:?}"),
        }
    }

    #[test]
    fn test_json_to_prost_value_depth_exceeded() {
        assert!(json_to_prost_value(&json!(42), MAX_CONVERSION_DEPTH + 1).is_err());
    }

    #[test]
    fn test_json_to_prost_struct_wraps_string() {
        let s = json_to_prost_struct(&json!("hello"), 0).unwrap();
        assert!(s.fields.contains_key("value"));
        assert!(matches!(s.fields["value"].kind, Some(Kind::StringValue(ref v)) if v == "hello"));
    }

    #[test]
    fn test_json_to_prost_struct_wraps_bool() {
        let s = json_to_prost_struct(&json!(true), 0).unwrap();
        assert!(s.fields.contains_key("value"));
    }

    #[test]
    fn test_json_to_prost_struct_wraps_null() {
        let s = json_to_prost_struct(&json!(null), 0).unwrap();
        assert!(s.fields.contains_key("value"));
    }

    #[test]
    fn test_json_to_prost_struct_wraps_array() {
        let s = json_to_prost_struct(&json!([1, 2]), 0).unwrap();
        assert!(s.fields.contains_key("value"));
    }

    #[test]
    fn test_json_to_proto_response_float_id_treated_as_string() {
        let j = json!({"jsonrpc": "2.0", "id": 1.5, "result": {}});
        let r = json_to_proto_response(&j).unwrap();
        match r.id_oneof {
            Some(super::super::proto::json_rpc_response::IdOneof::IdString(s)) => {
                assert_eq!(s, "1.5")
            }
            other => panic!("Expected IdString for float ID, got {other:?}"),
        }
    }

    #[test]
    fn test_json_to_proto_response_bool_id_treated_as_none() {
        let j = json!({"jsonrpc": "2.0", "id": true, "result": {}});
        assert!(json_to_proto_response(&j).unwrap().id_oneof.is_none());
    }

    #[test]
    fn test_json_to_proto_error_defaults() {
        let j = json!({"jsonrpc": "2.0", "id": 1, "error": {}});
        let err = json_to_proto_response(&j).unwrap().error.unwrap();
        assert_eq!(err.code, -32603);
        assert_eq!(err.message, "Internal error");
    }

    #[test]
    fn test_json_to_proto_error_not_object_fails() {
        let j = json!({"jsonrpc": "2.0", "id": 1, "error": "string error"});
        assert!(json_to_proto_response(&j).is_err());
    }

    #[test]
    fn test_proto_request_to_json_empty_params() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id_oneof: Some(super::super::proto::json_rpc_request::IdOneof::IdInt(1)),
            method: "test".into(),
            params: Some(prost_types::Struct {
                fields: Default::default(),
            }),
        };
        let j = proto_request_to_json(&req).unwrap();
        assert!(j["params"].is_object());
        assert!(j["params"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_proto_request_to_json_nan_in_params_rejected() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id_oneof: Some(super::super::proto::json_rpc_request::IdOneof::IdInt(1)),
            method: "test".into(),
            params: Some(prost_types::Struct {
                fields: vec![(
                    "bad".into(),
                    prost_types::Value {
                        kind: Some(Kind::NumberValue(f64::NAN)),
                    },
                )]
                .into_iter()
                .collect(),
            }),
        };
        assert!(proto_request_to_json(&req).is_err());
    }

    #[test]
    fn test_make_proto_error_response_preserves_string_id() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id_oneof: Some(super::super::proto::json_rpc_request::IdOneof::IdString(
                "req-xyz".into(),
            )),
            method: "test".into(),
            params: None,
        };
        let resp = make_proto_error_response(&req, -32600, "Bad request");
        match resp.id_oneof {
            Some(super::super::proto::json_rpc_response::IdOneof::IdString(s)) => {
                assert_eq!(s, "req-xyz")
            }
            other => panic!("Expected IdString, got {other:?}"),
        }
    }

    #[test]
    fn test_make_proto_denial_response_code_is_minus_32001() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id_oneof: None,
            method: "test".into(),
            params: None,
        };
        let err = make_proto_denial_response(&req, "policy denial")
            .error
            .unwrap();
        assert_eq!(err.code, -32001);
        assert_eq!(err.message, "policy denial");
    }

    #[test]
    fn test_make_proto_error_response_no_data_field() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id_oneof: None,
            method: "test".into(),
            params: None,
        };
        assert!(make_proto_error_response(&req, -32600, "err")
            .error
            .unwrap()
            .data
            .is_none());
    }

    #[test]
    fn test_make_proto_error_response_with_data_preserves_struct() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id_oneof: None,
            method: "test".into(),
            params: None,
        };
        let err = make_proto_error_response_with_data(
            &req,
            -32001,
            "Approval required",
            &json!({
                "type": "approval_required",
                "approval_id": "ap-123",
            }),
        )
        .error
        .unwrap();
        let data = err.data.unwrap();
        assert!(data.fields.contains_key("type"));
        assert!(data.fields.contains_key("approval_id"));
    }

    #[test]
    fn test_convert_error_invalid_float_display() {
        let msg = ConvertError::InvalidFloat.to_string();
        assert!(msg.contains("NaN") || msg.contains("Infinity"));
    }

    #[test]
    fn test_convert_error_depth_exceeded_display() {
        let msg = ConvertError::DepthExceeded.to_string();
        assert!(msg.contains("depth"));
        assert!(msg.contains("64"));
    }

    #[test]
    fn test_convert_error_missing_field_display() {
        assert!(ConvertError::MissingField("params")
            .to_string()
            .contains("params"));
    }
}
