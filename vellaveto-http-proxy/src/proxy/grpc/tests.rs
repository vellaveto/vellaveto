//! Unit tests for gRPC transport (Phase 17.2).

use super::convert::*;
use super::interceptors::*;
use super::proto::*;
use super::upstream::*;
use super::*;
use prost_types::value::Kind;
use serde_json::json;

// ═══════════════════════════════════════════════════════════════════════
// GrpcConfig tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_grpc_config_defaults() {
    let config = GrpcConfig::default();
    assert_eq!(config.listen_addr.port(), 50051);
    assert_eq!(config.max_message_size, 4 * 1024 * 1024);
    assert!(config.upstream_grpc_url.is_none());
    assert!(config.health_enabled);
}

#[test]
fn test_grpc_config_custom_values() {
    let config = GrpcConfig {
        listen_addr: "0.0.0.0:9090".parse().unwrap(),
        max_message_size: 8 * 1024 * 1024,
        upstream_grpc_url: Some("http://upstream:50051".to_string()),
        health_enabled: false,
    };
    assert_eq!(config.listen_addr.port(), 9090);
    assert_eq!(config.max_message_size, 8 * 1024 * 1024);
    assert_eq!(
        config.upstream_grpc_url.as_deref(),
        Some("http://upstream:50051")
    );
    assert!(!config.health_enabled);
}

#[test]
fn test_grpc_config_serde_roundtrip() {
    let config = GrpcConfig {
        listen_addr: "127.0.0.1:50051".parse().unwrap(),
        max_message_size: 4194304,
        upstream_grpc_url: None,
        health_enabled: true,
    };
    let json = serde_json::to_string(&config).unwrap();
    let parsed: GrpcConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config.listen_addr, parsed.listen_addr);
    assert_eq!(config.max_message_size, parsed.max_message_size);
    assert_eq!(config.upstream_grpc_url, parsed.upstream_grpc_url);
    assert_eq!(config.health_enabled, parsed.health_enabled);
}

// ═══════════════════════════════════════════════════════════════════════
// Proto ↔ JSON conversion: proto_request_to_json
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_proto_request_to_json_tool_call() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(42)),
        method: "tools/call".to_string(),
        params: Some(prost_types::Struct {
            fields: vec![
                (
                    "name".to_string(),
                    prost_types::Value {
                        kind: Some(Kind::StringValue("read_file".to_string())),
                    },
                ),
                (
                    "arguments".to_string(),
                    prost_types::Value {
                        kind: Some(Kind::StructValue(prost_types::Struct {
                            fields: vec![(
                                "path".to_string(),
                                prost_types::Value {
                                    kind: Some(Kind::StringValue("/etc/passwd".to_string())),
                                },
                            )]
                            .into_iter()
                            .collect(),
                        })),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        }),
    };

    let json = proto_request_to_json(&req).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], 42);
    assert_eq!(json["method"], "tools/call");
    assert_eq!(json["params"]["name"], "read_file");
    assert_eq!(json["params"]["arguments"]["path"], "/etc/passwd");
}

#[test]
fn test_proto_request_to_json_string_id() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdString("abc-123".to_string())),
        method: "ping".to_string(),
        params: None,
    };

    let json = proto_request_to_json(&req).unwrap();
    assert_eq!(json["id"], "abc-123");
}

#[test]
fn test_proto_request_to_json_null_id() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: None,
        method: "notifications/initialized".to_string(),
        params: None,
    };

    let json = proto_request_to_json(&req).unwrap();
    assert!(json["id"].is_null());
}

#[test]
fn test_proto_request_to_json_no_params() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(1)),
        method: "initialize".to_string(),
        params: None,
    };

    let json = proto_request_to_json(&req).unwrap();
    assert!(json.get("params").is_none());
}

// ═══════════════════════════════════════════════════════════════════════
// Proto ↔ JSON conversion: prost_struct_to_json
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_prost_struct_to_json_all_types() {
    let s = prost_types::Struct {
        fields: vec![
            (
                "null_val".to_string(),
                prost_types::Value {
                    kind: Some(Kind::NullValue(0)),
                },
            ),
            (
                "bool_val".to_string(),
                prost_types::Value {
                    kind: Some(Kind::BoolValue(true)),
                },
            ),
            (
                "number_val".to_string(),
                prost_types::Value {
                    kind: Some(Kind::NumberValue(3.14)),
                },
            ),
            (
                "string_val".to_string(),
                prost_types::Value {
                    kind: Some(Kind::StringValue("hello".to_string())),
                },
            ),
            (
                "list_val".to_string(),
                prost_types::Value {
                    kind: Some(Kind::ListValue(prost_types::ListValue {
                        values: vec![prost_types::Value {
                            kind: Some(Kind::NumberValue(1.0)),
                        }],
                    })),
                },
            ),
        ]
        .into_iter()
        .collect(),
    };

    let json = prost_struct_to_json(&s, 0).unwrap();
    assert!(json["null_val"].is_null());
    assert_eq!(json["bool_val"], true);
    assert!((json["number_val"].as_f64().unwrap() - 3.14).abs() < f64::EPSILON);
    assert_eq!(json["string_val"], "hello");
    assert_eq!(json["list_val"][0], 1);
}

#[test]
fn test_prost_struct_to_json_nested() {
    let inner = prost_types::Struct {
        fields: vec![(
            "key".to_string(),
            prost_types::Value {
                kind: Some(Kind::StringValue("value".to_string())),
            },
        )]
        .into_iter()
        .collect(),
    };

    let outer = prost_types::Struct {
        fields: vec![(
            "nested".to_string(),
            prost_types::Value {
                kind: Some(Kind::StructValue(inner)),
            },
        )]
        .into_iter()
        .collect(),
    };

    let json = prost_struct_to_json(&outer, 0).unwrap();
    assert_eq!(json["nested"]["key"], "value");
}

#[test]
fn test_prost_struct_to_json_empty() {
    let s = prost_types::Struct {
        fields: Default::default(),
    };
    let json = prost_struct_to_json(&s, 0).unwrap();
    assert!(json.as_object().unwrap().is_empty());
}

#[test]
fn test_prost_struct_to_json_nan_rejected() {
    let s = prost_types::Struct {
        fields: vec![(
            "bad".to_string(),
            prost_types::Value {
                kind: Some(Kind::NumberValue(f64::NAN)),
            },
        )]
        .into_iter()
        .collect(),
    };

    let result = prost_struct_to_json(&s, 0);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("NaN"));
}

#[test]
fn test_prost_struct_to_json_infinity_rejected() {
    let s = prost_types::Struct {
        fields: vec![(
            "bad".to_string(),
            prost_types::Value {
                kind: Some(Kind::NumberValue(f64::INFINITY)),
            },
        )]
        .into_iter()
        .collect(),
    };

    let result = prost_struct_to_json(&s, 0);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("NaN"));
}

#[test]
fn test_prost_struct_to_json_neg_infinity_rejected() {
    let s = prost_types::Struct {
        fields: vec![(
            "bad".to_string(),
            prost_types::Value {
                kind: Some(Kind::NumberValue(f64::NEG_INFINITY)),
            },
        )]
        .into_iter()
        .collect(),
    };

    assert!(prost_struct_to_json(&s, 0).is_err());
}

#[test]
fn test_prost_value_none_kind_is_null() {
    let s = prost_types::Struct {
        fields: vec![("empty".to_string(), prost_types::Value { kind: None })]
            .into_iter()
            .collect(),
    };

    let json = prost_struct_to_json(&s, 0).unwrap();
    assert!(json["empty"].is_null());
}

#[test]
fn test_prost_struct_depth_exceeded() {
    // Build deeply nested struct
    let mut current = prost_types::Struct {
        fields: vec![(
            "leaf".to_string(),
            prost_types::Value {
                kind: Some(Kind::StringValue("deep".to_string())),
            },
        )]
        .into_iter()
        .collect(),
    };

    for _ in 0..70 {
        current = prost_types::Struct {
            fields: vec![(
                "nest".to_string(),
                prost_types::Value {
                    kind: Some(Kind::StructValue(current)),
                },
            )]
            .into_iter()
            .collect(),
        };
    }

    let result = prost_struct_to_json(&current, 0);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("depth"));
}

// ═══════════════════════════════════════════════════════════════════════
// Proto ↔ JSON conversion: integer handling
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_prost_number_integer_roundtrip() {
    let s = prost_types::Struct {
        fields: vec![(
            "count".to_string(),
            prost_types::Value {
                kind: Some(Kind::NumberValue(42.0)),
            },
        )]
        .into_iter()
        .collect(),
    };

    let json = prost_struct_to_json(&s, 0).unwrap();
    // 42.0 should be represented as integer 42
    assert_eq!(json["count"], 42);
    assert!(json["count"].is_i64());
}

#[test]
fn test_prost_number_float_roundtrip() {
    let s = prost_types::Struct {
        fields: vec![(
            "score".to_string(),
            prost_types::Value {
                kind: Some(Kind::NumberValue(3.14)),
            },
        )]
        .into_iter()
        .collect(),
    };

    let json = prost_struct_to_json(&s, 0).unwrap();
    assert!(json["score"].is_f64());
}

// ═══════════════════════════════════════════════════════════════════════
// Proto ↔ JSON conversion: json_to_proto_response
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_json_to_proto_response_success() {
    let json = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{"type": "text", "text": "hello"}]
        }
    });

    let resp = json_to_proto_response(&json).unwrap();
    assert_eq!(resp.jsonrpc, "2.0");
    assert!(matches!(
        resp.id_oneof,
        Some(json_rpc_response::IdOneof::IdInt(1))
    ));
    assert!(resp.result.is_some());
    assert!(resp.error.is_none());
}

#[test]
fn test_json_to_proto_response_error() {
    let json = json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "error": {
            "code": -32001,
            "message": "Denied by policy"
        }
    });

    let resp = json_to_proto_response(&json).unwrap();
    assert!(matches!(
        resp.id_oneof,
        Some(json_rpc_response::IdOneof::IdString(ref s)) if s == "req-1"
    ));
    assert!(resp.result.is_none());
    let err = resp.error.unwrap();
    assert_eq!(err.code, -32001);
    assert_eq!(err.message, "Denied by policy");
}

#[test]
fn test_json_to_proto_response_null_id() {
    let json = json!({
        "jsonrpc": "2.0",
        "id": null,
        "result": {}
    });

    let resp = json_to_proto_response(&json).unwrap();
    assert!(resp.id_oneof.is_none());
}

#[test]
fn test_json_to_proto_response_not_object() {
    let json = json!("not an object");
    let result = json_to_proto_response(&json);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════
// Proto ↔ JSON conversion: json_to_prost_struct
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_json_to_prost_struct_object() {
    let json = json!({"a": 1, "b": "two", "c": true, "d": null, "e": [1, 2]});
    let s = json_to_prost_struct(&json, 0).unwrap();
    assert_eq!(s.fields.len(), 5);
}

#[test]
fn test_json_to_prost_struct_non_object_wrapped() {
    let json = json!(42);
    let s = json_to_prost_struct(&json, 0).unwrap();
    assert!(s.fields.contains_key("value"));
}

#[test]
fn test_json_to_prost_struct_depth_exceeded() {
    // Build deeply nested JSON
    let mut val = json!("leaf");
    for _ in 0..70 {
        val = json!({"nest": val});
    }
    let result = json_to_prost_struct(&val, 0);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════
// Roundtrip tests: proto → json → proto
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_struct_roundtrip_all_types() {
    let original = prost_types::Struct {
        fields: vec![
            (
                "str".to_string(),
                prost_types::Value {
                    kind: Some(Kind::StringValue("hello".to_string())),
                },
            ),
            (
                "num".to_string(),
                prost_types::Value {
                    kind: Some(Kind::NumberValue(99.0)),
                },
            ),
            (
                "bool".to_string(),
                prost_types::Value {
                    kind: Some(Kind::BoolValue(false)),
                },
            ),
            (
                "null".to_string(),
                prost_types::Value {
                    kind: Some(Kind::NullValue(0)),
                },
            ),
        ]
        .into_iter()
        .collect(),
    };

    let json = prost_struct_to_json(&original, 0).unwrap();
    let roundtripped = json_to_prost_struct(&json, 0).unwrap();

    // Verify field count matches
    assert_eq!(original.fields.len(), roundtripped.fields.len());

    // Verify the json roundtrips correctly
    let json2 = prost_struct_to_json(&roundtripped, 0).unwrap();
    assert_eq!(json, json2);
}

// ═══════════════════════════════════════════════════════════════════════
// make_proto_error_response / make_proto_denial_response
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_make_proto_error_response_int_id() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(7)),
        method: "tools/call".to_string(),
        params: None,
    };

    let resp = make_proto_error_response(&req, -32603, "Internal error");
    assert_eq!(resp.jsonrpc, "2.0");
    assert!(matches!(
        resp.id_oneof,
        Some(json_rpc_response::IdOneof::IdInt(7))
    ));
    assert!(resp.result.is_none());
    let err = resp.error.unwrap();
    assert_eq!(err.code, -32603);
    assert_eq!(err.message, "Internal error");
}

#[test]
fn test_make_proto_denial_response() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdString("r1".to_string())),
        method: "tools/call".to_string(),
        params: None,
    };

    let resp = make_proto_denial_response(&req, "Policy forbids this");
    let err = resp.error.unwrap();
    assert_eq!(err.code, -32001);
    assert_eq!(err.message, "Policy forbids this");
}

#[test]
fn test_make_proto_error_response_no_id() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: None,
        method: "test".to_string(),
        params: None,
    };

    let resp = make_proto_error_response(&req, -32600, "Bad request");
    assert!(resp.id_oneof.is_none());
}

// ═══════════════════════════════════════════════════════════════════════
// Interceptors: session extraction
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_extract_session_id_present() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert(METADATA_MCP_SESSION_ID, "sess-123".parse().unwrap());
    assert_eq!(extract_session_id(&metadata), Some("sess-123".to_string()));
}

#[test]
fn test_extract_session_id_missing() {
    let metadata = tonic::metadata::MetadataMap::new();
    assert_eq!(extract_session_id(&metadata), None);
}

#[test]
fn test_extract_session_id_empty() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert(METADATA_MCP_SESSION_ID, "".parse().unwrap());
    assert_eq!(extract_session_id(&metadata), None);
}

#[test]
fn test_extract_session_id_oversized() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    let long_id = "a".repeat(300);
    metadata.insert(METADATA_MCP_SESSION_ID, long_id.parse().unwrap());
    assert_eq!(extract_session_id(&metadata), None);
}

// ═══════════════════════════════════════════════════════════════════════
// Interceptors: request ID extraction
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_extract_request_id_present() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert(METADATA_REQUEST_ID, "req-456".parse().unwrap());
    assert_eq!(
        extract_or_generate_request_id(&metadata),
        "req-456".to_string()
    );
}

#[test]
fn test_extract_request_id_generated_when_missing() {
    let metadata = tonic::metadata::MetadataMap::new();
    let id = extract_or_generate_request_id(&metadata);
    // Generated UUID should be valid
    assert!(!id.is_empty());
    assert!(uuid::Uuid::parse_str(&id).is_ok());
}

// ═══════════════════════════════════════════════════════════════════════
// Message classification via proto conversion
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_classify_tool_call_via_proto() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(1)),
        method: "tools/call".to_string(),
        params: Some(prost_types::Struct {
            fields: vec![
                (
                    "name".to_string(),
                    prost_types::Value {
                        kind: Some(Kind::StringValue("write_file".to_string())),
                    },
                ),
                (
                    "arguments".to_string(),
                    prost_types::Value {
                        kind: Some(Kind::StructValue(prost_types::Struct {
                            fields: Default::default(),
                        })),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        }),
    };

    let json = proto_request_to_json(&req).unwrap();
    let classified = vellaveto_mcp::extractor::classify_message(&json);
    assert!(matches!(
        classified,
        vellaveto_mcp::extractor::MessageType::ToolCall { .. }
    ));
}

#[test]
fn test_classify_resource_read_via_proto() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(2)),
        method: "resources/read".to_string(),
        params: Some(prost_types::Struct {
            fields: vec![(
                "uri".to_string(),
                prost_types::Value {
                    kind: Some(Kind::StringValue("file:///etc/passwd".to_string())),
                },
            )]
            .into_iter()
            .collect(),
        }),
    };

    let json = proto_request_to_json(&req).unwrap();
    let classified = vellaveto_mcp::extractor::classify_message(&json);
    assert!(matches!(
        classified,
        vellaveto_mcp::extractor::MessageType::ResourceRead { .. }
    ));
}

#[test]
fn test_classify_batch_via_proto() {
    // Batch is detected at the JSON level (array), but our proto wraps single messages.
    // If someone sends a proto with array-like content, classify_message sees an object, not a batch.
    // Batch rejection works at the JSON-RPC level before proto conversion.
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(1)),
        method: "ping".to_string(),
        params: None,
    };
    let json = proto_request_to_json(&req).unwrap();
    let classified = vellaveto_mcp::extractor::classify_message(&json);
    // ping is a passthrough, not a batch
    assert!(matches!(
        classified,
        vellaveto_mcp::extractor::MessageType::PassThrough
    ));
}

#[test]
fn test_classify_sampling_request_via_proto() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(5)),
        method: "sampling/createMessage".to_string(),
        params: Some(prost_types::Struct {
            fields: Default::default(),
        }),
    };

    let json = proto_request_to_json(&req).unwrap();
    let classified = vellaveto_mcp::extractor::classify_message(&json);
    assert!(matches!(
        classified,
        vellaveto_mcp::extractor::MessageType::SamplingRequest { .. }
    ));
}

#[test]
fn test_classify_passthrough_via_proto() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(1)),
        method: "tools/list".to_string(),
        params: None,
    };

    let json = proto_request_to_json(&req).unwrap();
    let classified = vellaveto_mcp::extractor::classify_message(&json);
    assert!(matches!(
        classified,
        vellaveto_mcp::extractor::MessageType::PassThrough
    ));
}

// ═══════════════════════════════════════════════════════════════════════
// GrpcTransportConfig tests (vellaveto-config)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_grpc_transport_config_defaults() {
    let config = vellaveto_config::GrpcTransportConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.listen_address, "127.0.0.1:50051");
    assert_eq!(config.max_message_size_bytes, 4 * 1024 * 1024);
    assert!(config.upstream_grpc_url.is_none());
    assert!(config.health_enabled);
}

#[test]
fn test_grpc_transport_config_serde() {
    let json = r#"{
        "enabled": true,
        "listen_address": "0.0.0.0:9090",
        "max_message_size_bytes": 8388608,
        "upstream_grpc_url": "http://upstream:50051",
        "health_enabled": false
    }"#;
    let config: vellaveto_config::GrpcTransportConfig = serde_json::from_str(json).unwrap();
    assert!(config.enabled);
    assert_eq!(config.listen_address, "0.0.0.0:9090");
    assert_eq!(config.max_message_size_bytes, 8388608);
    assert_eq!(
        config.upstream_grpc_url.as_deref(),
        Some("http://upstream:50051")
    );
    assert!(!config.health_enabled);
}

// ═══════════════════════════════════════════════════════════════════════
// Upstream error types
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_upstream_error_display() {
    let err = UpstreamError::HttpError("connection refused".to_string());
    assert!(err.to_string().contains("connection refused"));

    let err = UpstreamError::JsonError("unexpected token".to_string());
    assert!(err.to_string().contains("unexpected token"));

    let err = UpstreamError::GrpcError("unavailable".to_string());
    assert!(err.to_string().contains("unavailable"));

    let err = UpstreamError::NoUpstream;
    assert!(err.to_string().contains("not configured"));
}

// ═══════════════════════════════════════════════════════════════════════
// Convert error types
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_convert_error_display() {
    let err = ConvertError::InvalidFloat;
    assert!(err.to_string().contains("NaN"));

    let err = ConvertError::DepthExceeded;
    assert!(err.to_string().contains("depth"));

    let err = ConvertError::MissingField("test_field");
    assert!(err.to_string().contains("test_field"));
}

// ═══════════════════════════════════════════════════════════════════════
// Edge cases: JSON response with error+data
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_json_to_proto_response_error_with_data() {
    let json = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32001,
            "message": "Denied",
            "data": {"approval_id": "ap-123"}
        }
    });

    let resp = json_to_proto_response(&json).unwrap();
    let err = resp.error.unwrap();
    assert_eq!(err.code, -32001);
    assert!(err.data.is_some());
    let data = err.data.unwrap();
    assert!(data.fields.contains_key("approval_id"));
}

#[test]
fn test_json_to_proto_response_missing_jsonrpc() {
    let json = json!({
        "id": 1,
        "result": {}
    });

    let resp = json_to_proto_response(&json).unwrap();
    // Defaults to "2.0" when missing
    assert_eq!(resp.jsonrpc, "2.0");
}

// ═══════════════════════════════════════════════════════════════════════
// Metadata constants
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_metadata_constants() {
    assert_eq!(METADATA_AUTHORIZATION, "authorization");
    assert_eq!(METADATA_MCP_SESSION_ID, "mcp-session-id");
    assert_eq!(METADATA_AGENT_IDENTITY, "x-agent-identity");
    assert_eq!(METADATA_UPSTREAM_AGENTS, "x-upstream-agents");
    assert_eq!(METADATA_REQUEST_ID, "x-request-id");
}

// ═══════════════════════════════════════════════════════════════════════
// TaskRequest and ExtensionMethod policy enforcement tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_task_request_classification_grpc() {
    // Verify task request is classified correctly from a proto request
    let json_msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tasks/get",
        "params": {"id": "task-abc"}
    });
    let classified = vellaveto_mcp::extractor::classify_message(&json_msg);
    match classified {
        vellaveto_mcp::extractor::MessageType::TaskRequest {
            task_method,
            task_id,
            ..
        } => {
            assert_eq!(task_method, "tasks/get");
            assert_eq!(task_id, Some("task-abc".to_string()));
        }
        other => panic!("Expected TaskRequest, got {:?}", other),
    }
}

#[test]
fn test_task_request_action_extraction_grpc() {
    let action = vellaveto_mcp::extractor::extract_task_action("tasks/cancel", Some("task-123"));
    assert_eq!(action.tool, "tasks");
    assert_eq!(action.function, "cancel");
    assert_eq!(action.parameters["task_id"], "task-123");
}

#[test]
fn test_task_request_fail_closed_no_policies_grpc() {
    // With no policies, task requests should be denied (fail-closed)
    let engine = vellaveto_engine::PolicyEngine::new(false);
    let action = vellaveto_mcp::extractor::extract_task_action("tasks/get", Some("task-abc"));
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(verdict, vellaveto_types::Verdict::Deny { .. }),
        "Expected Deny with no policies, got: {:?}",
        verdict
    );
}

#[test]
fn test_extension_method_classification_grpc() {
    let json_msg = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "x-vellaveto-audit/stats",
        "params": {}
    });
    let classified = vellaveto_mcp::extractor::classify_message(&json_msg);
    match classified {
        vellaveto_mcp::extractor::MessageType::ExtensionMethod {
            extension_id,
            method,
            ..
        } => {
            assert_eq!(extension_id, "x-vellaveto-audit");
            assert_eq!(method, "x-vellaveto-audit/stats");
        }
        other => panic!("Expected ExtensionMethod, got {:?}", other),
    }
}

#[test]
fn test_extension_method_fail_closed_no_policies_grpc() {
    let engine = vellaveto_engine::PolicyEngine::new(false);
    let action = vellaveto_mcp::extractor::extract_extension_action(
        "x-vellaveto-audit",
        "x-vellaveto-audit/stats",
        &json!({}),
    );
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(verdict, vellaveto_types::Verdict::Deny { .. }),
        "Expected Deny with no policies, got: {:?}",
        verdict
    );
}
